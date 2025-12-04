# frozen_string_literal: true

require 'openssl'
require 'socket'
require 'uri'

module Hedra
  # Check Certificate Transparency (CT) logs
  class CtChecker
    # CT Precertificate SCTs extension OID
    CT_PRECERT_SCTS_OID = '1.3.6.1.4.1.11129.2.4.2'
    
    # SCT version
    SCT_VERSION_V1 = 0

    # Minimum recommended SCT count
    MIN_SCT_COUNT = 2

    # SCT (Signed Certificate Timestamp) sources
    SCT_SOURCES = {
      extension: 'X509v3 extension',
      ocsp: 'OCSP stapling',
      tls: 'TLS extension'
    }.freeze

    def check(url)
      findings = []
      uri = URI.parse(url)
      
      return findings unless uri.scheme == 'https'

      ct_info = check_certificate_transparency(uri.host, uri.port || 443)

      if ct_info[:scts].empty?
        findings << {
          header: 'certificate-transparency',
          issue: 'Certificate not logged in Certificate Transparency logs (no SCTs found)',
          severity: :warning,
          recommended_fix: 'Use a CA that supports Certificate Transparency or ensure CT logging is enabled'
        }
      else
        # Check number of SCTs
        sct_count = ct_info[:scts].length
        if sct_count < MIN_SCT_COUNT
          findings << {
            header: 'certificate-transparency',
            issue: "Only #{sct_count} SCT found - recommend at least #{MIN_SCT_COUNT} from different logs",
            severity: :info,
            recommended_fix: 'Ensure certificate has SCTs from multiple independent CT logs for redundancy'
          }
        end

        # Check SCT sources diversity
        sources = ct_info[:scts].map { |sct| sct[:source] }.uniq
        if sources.length == 1 && sources.first == :extension
          findings << {
            header: 'certificate-transparency',
            issue: 'All SCTs embedded in certificate only',
            severity: :info,
            recommended_fix: 'Consider adding SCTs via OCSP stapling or TLS extension for better privacy'
          }
        end

        # Check for valid SCT versions
        invalid_versions = ct_info[:scts].select { |sct| sct[:version] && sct[:version] != SCT_VERSION_V1 }
        if invalid_versions.any?
          findings << {
            header: 'certificate-transparency',
            issue: "Found SCTs with unsupported versions: #{invalid_versions.map { |s| s[:version] }.uniq.join(', ')}",
            severity: :warning,
            recommended_fix: 'Ensure all SCTs use version 1 (v1)'
          }
        end
      end

      findings
    rescue StandardError => e
      warn "Certificate Transparency check failed: #{e.message}" if ENV['DEBUG']
      warn e.backtrace.join("\n") if ENV['DEBUG']
      []
    end

    private

    def check_certificate_transparency(host, port)
      result = {
        scts: [],
        ct_enabled: false
      }

      tcp_socket = nil
      ssl_socket = nil

      begin
        tcp_socket = Socket.tcp(host, port, connect_timeout: 5)
        ssl_context = OpenSSL::SSL::SSLContext.new
        ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE

        ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, ssl_context)
        ssl_socket.sync_close = true
        ssl_socket.connect

        cert = ssl_socket.peer_cert

        # Check for SCT in certificate extensions
        scts_from_cert = extract_scts_from_certificate(cert)
        result[:scts].concat(scts_from_cert)

        # Check for SCT in OCSP response (if stapled)
        scts_from_ocsp = extract_scts_from_ocsp(ssl_socket)
        result[:scts].concat(scts_from_ocsp)

        result[:ct_enabled] = result[:scts].any?
      rescue Errno::ECONNREFUSED, Errno::ETIMEDOUT, Errno::EHOSTUNREACH, SocketError => e
        warn "CT check connection error for #{host}:#{port}: #{e.message}" if ENV['DEBUG']
      rescue OpenSSL::SSL::SSLError => e
        warn "CT check SSL error for #{host}:#{port}: #{e.message}" if ENV['DEBUG']
      rescue StandardError => e
        warn "CT check error for #{host}:#{port}: #{e.class} - #{e.message}" if ENV['DEBUG']
      ensure
        ssl_socket&.close rescue nil
        tcp_socket&.close rescue nil
      end

      result
    end

    def extract_scts_from_certificate(cert)
      scts = []

      # Look for CT Precertificate SCTs extension (OID 1.3.6.1.4.1.11129.2.4.2)
      ct_extension = cert.extensions.find { |ext| ext.oid == CT_PRECERT_SCTS_OID }

      return scts unless ct_extension

      begin
        # The extension value is DER-encoded OCTET STRING containing SCT list
        # Parse the SCT list structure
        parsed_scts = parse_sct_list(ct_extension.value)
        
        parsed_scts.each_with_index do |sct_data, index|
          scts << {
            source: :extension,
            index: index,
            version: sct_data[:version],
            log_id: sct_data[:log_id],
            timestamp: sct_data[:timestamp],
            valid: sct_data[:valid]
          }
        end
      rescue StandardError => e
        warn "Failed to parse SCTs from certificate: #{e.message}" if ENV['DEBUG']
        
        # Fallback: estimate SCT count from extension size
        sct_count = estimate_sct_count_from_size(ct_extension.value)
        sct_count.times do |i|
          scts << {
            source: :extension,
            index: i,
            version: nil,
            log_id: nil,
            timestamp: nil,
            valid: true
          }
        end
      end

      scts
    end

    def extract_scts_from_ocsp(ssl_socket)
      # OCSP stapling support in Ruby's OpenSSL binding is limited
      # This would require accessing the OCSP response from the TLS handshake
      # For now, return empty array as this requires low-level TLS access
      []
    rescue StandardError => e
      warn "Failed to extract SCTs from OCSP: #{e.message}" if ENV['DEBUG']
      []
    end

    def parse_sct_list(der_data)
      scts = []
      
      begin
        # The extension value is an OCTET STRING containing the SCT list
        # First, decode the outer OCTET STRING wrapper
        asn1 = OpenSSL::ASN1.decode(der_data)
        
        # Get the actual SCT list data
        sct_list_data = if asn1.tag == OpenSSL::ASN1::OCTET_STRING
                          asn1.value
                        else
                          der_data
                        end

        # Parse SCT list structure
        # Format: 2-byte length prefix, then concatenated SCTs
        return scts if sct_list_data.bytesize < 2

        list_length = sct_list_data.unpack1('n') # Read 2-byte big-endian length
        offset = 2

        # Parse individual SCTs
        while offset < sct_list_data.bytesize && offset < list_length + 2
          sct_data = parse_single_sct(sct_list_data, offset)
          break unless sct_data

          scts << sct_data[:sct]
          offset = sct_data[:next_offset]
        end
      rescue OpenSSL::ASN1::ASN1Error => e
        warn "ASN.1 parsing error: #{e.message}" if ENV['DEBUG']
      rescue StandardError => e
        warn "SCT list parsing error: #{e.message}" if ENV['DEBUG']
      end

      scts
    end

    def parse_single_sct(data, offset)
      # SCT structure:
      # - 2 bytes: SCT length
      # - 1 byte: version
      # - 32 bytes: log_id
      # - 8 bytes: timestamp
      # - 2 bytes: extensions length
      # - N bytes: extensions
      # - 2 bytes: signature algorithm
      # - 2 bytes: signature length
      # - M bytes: signature

      return nil if offset + 2 > data.bytesize

      sct_length = data[offset, 2].unpack1('n')
      sct_start = offset + 2
      sct_end = sct_start + sct_length

      return nil if sct_end > data.bytesize

      sct_bytes = data[sct_start...sct_end]
      
      # Parse SCT fields
      return nil if sct_bytes.bytesize < 43 # Minimum: version(1) + log_id(32) + timestamp(8) + ext_len(2)

      version = sct_bytes[0].unpack1('C')
      log_id = sct_bytes[1, 32].unpack1('H*')
      timestamp = sct_bytes[33, 8].unpack1('Q>')
      
      {
        sct: {
          version: version,
          log_id: log_id,
          timestamp: timestamp,
          valid: version == SCT_VERSION_V1
        },
        next_offset: sct_end
      }
    rescue StandardError => e
      warn "Single SCT parsing error: #{e.message}" if ENV['DEBUG']
      nil
    end

    def estimate_sct_count_from_size(extension_value)
      # Fallback estimation when parsing fails
      # SCTs are typically 100-150 bytes each
      return 0 if extension_value.nil? || extension_value.empty?

      # Try to decode as OCTET STRING first
      begin
        asn1 = OpenSSL::ASN1.decode(extension_value)
        data = asn1.value if asn1.tag == OpenSSL::ASN1::OCTET_STRING
      rescue StandardError
        data = extension_value
      end

      data_size = data.bytesize
      
      # Estimate: each SCT is roughly 120 bytes (conservative estimate)
      # Minimum 1, maximum 5 for safety
      estimated = [data_size / 120, 1].max
      [estimated, 5].min
    rescue StandardError
      1 # Default to 1 if estimation fails
    end
  end
end
