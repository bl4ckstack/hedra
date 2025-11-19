# frozen_string_literal: true

require 'openssl'
require 'socket'
require 'uri'

module Hedra
  # Check SSL/TLS certificate validity and security
  class CertificateChecker
    EXPIRY_WARNING_DAYS = 30

    def check(url)
      uri = URI.parse(url)
      return nil unless uri.scheme == 'https'

      findings = []
      cert_info = fetch_certificate(uri.host, uri.port || 443)

      return findings unless cert_info

      # Check expiry
      days_until_expiry = ((cert_info[:not_after] - Time.now) / 86_400).to_i
      if days_until_expiry.negative?
        findings << {
          header: 'ssl-certificate',
          issue: 'SSL certificate has expired',
          severity: :critical,
          recommended_fix: 'Renew SSL certificate immediately'
        }
      elsif days_until_expiry < EXPIRY_WARNING_DAYS
        findings << {
          header: 'ssl-certificate',
          issue: "SSL certificate expires in #{days_until_expiry} days",
          severity: :warning,
          recommended_fix: 'Renew SSL certificate soon'
        }
      end

      # Check signature algorithm
      if weak_signature_algorithm?(cert_info[:signature_algorithm])
        findings << {
          header: 'ssl-certificate',
          issue: "Weak signature algorithm: #{cert_info[:signature_algorithm]}",
          severity: :warning,
          recommended_fix: 'Use SHA256 or stronger'
        }
      end

      # Check key size
      if cert_info[:key_size] && cert_info[:key_size] < 2048
        findings << {
          header: 'ssl-certificate',
          issue: "Weak key size: #{cert_info[:key_size]} bits",
          severity: :critical,
          recommended_fix: 'Use at least 2048-bit RSA or 256-bit ECC'
        }
      end

      findings
    rescue StandardError => e
      warn "Certificate check failed: #{e.message}"
      []
    end

    private

    def fetch_certificate(host, port)
      tcp_socket = TCPSocket.new(host, port)
      ssl_context = OpenSSL::SSL::SSLContext.new
      ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE
      ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, ssl_context)
      ssl_socket.connect

      cert = ssl_socket.peer_cert

      {
        subject: cert.subject.to_s,
        issuer: cert.issuer.to_s,
        not_before: cert.not_before,
        not_after: cert.not_after,
        signature_algorithm: cert.signature_algorithm,
        key_size: cert.public_key.respond_to?(:n) ? cert.public_key.n.num_bits : nil
      }
    ensure
      ssl_socket&.close
      tcp_socket&.close
    end

    def weak_signature_algorithm?(algorithm)
      weak_algorithms = %w[md5 sha1]
      weak_algorithms.any? { |weak| algorithm.downcase.include?(weak) }
    end
  end
end
