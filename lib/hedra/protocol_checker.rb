# frozen_string_literal: true

require 'openssl'
require 'socket'
require 'uri'

module Hedra
  # Check HTTP protocol version and TLS version
  class ProtocolChecker
    MINIMUM_TLS_VERSION = 'TLSv1.2'
    RECOMMENDED_TLS_VERSION = 'TLSv1.3'

    TLS_VERSION_MAP = {
      0x0300 => 'SSLv3',
      0x0301 => 'TLSv1.0',
      0x0302 => 'TLSv1.1',
      0x0303 => 'TLSv1.2',
      0x0304 => 'TLSv1.3'
    }.freeze

    def check(url, response = nil)
      findings = []
      uri = URI.parse(url)

      # Check HTTP protocol version
      if response
        findings.concat(check_http_version(response))
      end

      # Check TLS version for HTTPS
      if uri.scheme == 'https'
        findings.concat(check_tls_version(uri.host, uri.port || 443))
      elsif uri.scheme == 'http'
        findings << {
          header: 'protocol',
          issue: 'Using insecure HTTP protocol instead of HTTPS',
          severity: :critical,
          recommended_fix: 'Migrate to HTTPS with valid SSL/TLS certificate'
        }
      end

      findings
    rescue StandardError => e
      warn "Protocol check failed: #{e.message}" if ENV['DEBUG']
      []
    end

    private

    def check_http_version(response)
      findings = []

      # Try to detect HTTP version from response
      http_version = detect_http_version(response)

      case http_version
      when '1.0'
        findings << {
          header: 'protocol',
          issue: 'Using outdated HTTP/1.0 protocol',
          severity: :warning,
          recommended_fix: 'Upgrade to HTTP/2 or HTTP/3 for better performance and security'
        }
      when '1.1'
        findings << {
          header: 'protocol',
          issue: 'Using HTTP/1.1 - consider upgrading to HTTP/2 or HTTP/3',
          severity: :info,
          recommended_fix: 'Upgrade to HTTP/2 or HTTP/3 for multiplexing and improved security'
        }
      when '2', '2.0'
        # HTTP/2 is good, but HTTP/3 is better
        findings << {
          header: 'protocol',
          issue: 'Using HTTP/2 - HTTP/3 available for better performance',
          severity: :info,
          recommended_fix: 'Consider upgrading to HTTP/3 (QUIC) for improved performance'
        }
      when '3', '3.0'
        # HTTP/3 is optimal - no finding
      when nil
        # Unable to detect - skip
      else
        findings << {
          header: 'protocol',
          issue: "Unknown HTTP version: #{http_version}",
          severity: :info,
          recommended_fix: 'Verify HTTP protocol version'
        }
      end

      findings
    end

    def detect_http_version(response)
      # Try to get version from response object
      if response.respond_to?(:version)
        return response.version.to_s
      end

      # Try to detect from headers
      # HTTP/2 typically has lowercase headers
      if response.headers.keys.all? { |k| k == k.downcase }
        return '2'
      end

      # Check for HTTP/2 specific pseudo-headers
      if response.headers.keys.any? { |k| k.start_with?(':') }
        return '2'
      end

      # Check alt-svc header for HTTP/3
      if response.headers['alt-svc']&.include?('h3')
        return '3'
      end

      # Default assumption for HTTPS
      '1.1'
    rescue StandardError
      nil
    end

    def check_tls_version(host, port)
      findings = []

      tls_info = probe_tls_versions(host, port)
      return findings if tls_info.empty?

      # Check if weak protocols are supported
      weak_protocols = tls_info.select { |v| weak_tls_version?(v) }
      if weak_protocols.any?
        findings << {
          header: 'tls-version',
          issue: "Weak TLS versions supported: #{weak_protocols.join(', ')}",
          severity: :critical,
          recommended_fix: "Disable #{weak_protocols.join(', ')} and use only TLS 1.2 or higher"
        }
      end

      # Check if TLS 1.2 is the minimum
      if tls_info.include?('TLSv1.1') || tls_info.include?('TLSv1.0')
        findings << {
          header: 'tls-version',
          issue: 'TLS 1.0/1.1 supported - deprecated and insecure',
          severity: :critical,
          recommended_fix: 'Disable TLS 1.0 and 1.1, use TLS 1.2+ only'
        }
      end

      # Recommend TLS 1.3 if not supported
      unless tls_info.include?('TLSv1.3')
        findings << {
          header: 'tls-version',
          issue: 'TLS 1.3 not supported',
          severity: :info,
          recommended_fix: 'Enable TLS 1.3 for improved security and performance'
        }
      end

      # Check negotiated version
      negotiated = tls_info.last
      if negotiated && negotiated < MINIMUM_TLS_VERSION
        findings << {
          header: 'tls-version',
          issue: "Negotiated TLS version #{negotiated} is below minimum (#{MINIMUM_TLS_VERSION})",
          severity: :critical,
          recommended_fix: "Enforce minimum TLS version #{MINIMUM_TLS_VERSION}"
        }
      end

      findings
    rescue StandardError => e
      warn "TLS version check failed: #{e.message}" if ENV['DEBUG']
      []
    end

    def probe_tls_versions(host, port)
      supported_versions = []
      timeout = 5

      # Try to connect with different TLS versions
      [
        OpenSSL::SSL::TLS1_3_VERSION,
        OpenSSL::SSL::TLS1_2_VERSION,
        OpenSSL::SSL::TLS1_1_VERSION,
        OpenSSL::SSL::TLS1_VERSION
      ].each do |version|
        begin
          tcp_socket = Socket.tcp(host, port, connect_timeout: timeout)
          ssl_context = OpenSSL::SSL::SSLContext.new
          
          # Set specific TLS version
          ssl_context.min_version = version
          ssl_context.max_version = version
          ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE

          ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, ssl_context)
          ssl_socket.sync_close = true
          ssl_socket.connect

          # Get actual version
          actual_version = ssl_socket.ssl_version
          supported_versions << actual_version unless supported_versions.include?(actual_version)

          ssl_socket.close
        rescue OpenSSL::SSL::SSLError, Errno::ECONNREFUSED, Errno::ETIMEDOUT, SocketError
          # Version not supported or connection failed
          next
        rescue StandardError => e
          warn "TLS probe error for #{version}: #{e.message}" if ENV['DEBUG']
          next
        ensure
          tcp_socket&.close rescue nil
        end
      end

      supported_versions.uniq.sort
    rescue StandardError => e
      warn "TLS version probe failed: #{e.message}" if ENV['DEBUG']
      []
    end

    def weak_tls_version?(version)
      weak_versions = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.0', 'TLSv1.1']
      weak_versions.include?(version)
    end
  end
end
