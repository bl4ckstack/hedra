# frozen_string_literal: true

require 'resolv'
require 'uri'

module Hedra
  # Check DNS security features (DNSSEC, CAA records)
  class DnsChecker
    CAA_TAG_ISSUE = 'issue'
    CAA_TAG_ISSUEWILD = 'issuewild'
    CAA_TAG_IODEF = 'iodef'

    def initialize
      @resolver = Resolv::DNS.new
    end

    def check(url)
      findings = []
      uri = URI.parse(url)
      domain = uri.host

      return findings unless domain

      # Check DNSSEC
      findings.concat(check_dnssec(domain))

      # Check CAA records
      findings.concat(check_caa_records(domain))

      findings
    rescue StandardError => e
      warn "DNS check failed: #{e.message}" if ENV['DEBUG']
      []
    end

    private

    def check_dnssec(domain)
      findings = []

      dnssec_enabled = dnssec_enabled?(domain)

      unless dnssec_enabled
        findings << {
          header: 'dnssec',
          issue: 'DNSSEC not enabled for domain',
          severity: :warning,
          recommended_fix: 'Enable DNSSEC to prevent DNS spoofing and cache poisoning attacks'
        }
      end

      findings
    rescue StandardError => e
      warn "DNSSEC check failed: #{e.message}" if ENV['DEBUG']
      [{
        header: 'dnssec',
        issue: 'Unable to verify DNSSEC status',
        severity: :info,
        recommended_fix: 'Manually verify DNSSEC configuration'
      }]
    end

    def check_caa_records(domain)
      findings = []

      caa_records = fetch_caa_records(domain)

      if caa_records.empty?
        findings << {
          header: 'caa-records',
          issue: 'No CAA records found - any CA can issue certificates',
          severity: :warning,
          recommended_fix: 'Add CAA records to restrict which CAs can issue certificates for your domain'
        }
      else
        # Validate CAA records
        findings.concat(validate_caa_records(caa_records, domain))
      end

      findings
    rescue StandardError => e
      warn "CAA check failed: #{e.message}" if ENV['DEBUG']
      [{
        header: 'caa-records',
        issue: 'Unable to query CAA records',
        severity: :info,
        recommended_fix: 'Manually verify CAA record configuration'
      }]
    end

    def dnssec_enabled?(domain)
      # Check for DNSSEC by querying DNSKEY records
      # This is a simplified check - full validation would require signature verification
      
      begin
        # Try to get DNSKEY records
        dnskey_records = query_dns(domain, Resolv::DNS::Resource::IN::ANY)
        
        # Look for RRSIG or DNSKEY records
        has_dnssec = dnskey_records.any? do |record|
          record.is_a?(String) && (record.include?('RRSIG') || record.include?('DNSKEY'))
        end

        return true if has_dnssec

        # Alternative: check if resolver supports DNSSEC validation
        # by looking for AD (Authenticated Data) flag
        # This requires a DNSSEC-validating resolver
        
        # For now, we'll do a basic check by trying to resolve with DO flag
        check_dnssec_with_dig(domain)
      rescue StandardError => e
        warn "DNSSEC detection error: #{e.message}" if ENV['DEBUG']
        false
      end
    end

    def check_dnssec_with_dig(domain)
      # Use system dig command if available for more accurate DNSSEC check
      return false unless command_available?('dig')

      output = `dig +dnssec #{domain} 2>&1`
      
      # Check for RRSIG in response
      output.include?('RRSIG') && !output.include?('SERVFAIL')
    rescue StandardError
      false
    end

    def fetch_caa_records(domain)
      caa_records = []

      # Try to fetch CAA records using Resolv
      # Note: Ruby's Resolv doesn't have built-in CAA support
      # We'll try using system tools as fallback
      
      caa_records = fetch_caa_with_dig(domain) if command_available?('dig')
      
      # If dig not available, try host command
      caa_records = fetch_caa_with_host(domain) if caa_records.empty? && command_available?('host')

      caa_records
    rescue StandardError => e
      warn "CAA fetch error: #{e.message}" if ENV['DEBUG']
      []
    end

    def fetch_caa_with_dig(domain)
      output = `dig +short CAA #{domain} 2>&1`
      return [] if output.nil? || output.empty? || output.include?('SERVFAIL')

      parse_caa_from_dig(output)
    rescue StandardError
      []
    end

    def fetch_caa_with_host(domain)
      output = `host -t CAA #{domain} 2>&1`
      return [] if output.nil? || output.empty? || output.include?('has no CAA')

      parse_caa_from_host(output)
    rescue StandardError
      []
    end

    def parse_caa_from_dig(output)
      records = []
      
      output.each_line do |line|
        line = line.strip
        next if line.empty?

        # CAA format: flags tag "value"
        # Example: 0 issue "letsencrypt.org"
        if line.match(/(\d+)\s+(\w+)\s+"([^"]+)"/)
          flags = ::Regexp.last_match(1).to_i
          tag = ::Regexp.last_match(2)
          value = ::Regexp.last_match(3)

          records << {
            flags: flags,
            tag: tag,
            value: value
          }
        end
      end

      records
    end

    def parse_caa_from_host(output)
      records = []
      
      output.each_line do |line|
        # Example: example.com has CAA record 0 issue "letsencrypt.org"
        if line.match(/has CAA record (\d+)\s+(\w+)\s+"([^"]+)"/)
          flags = ::Regexp.last_match(1).to_i
          tag = ::Regexp.last_match(2)
          value = ::Regexp.last_match(3)

          records << {
            flags: flags,
            tag: tag,
            value: value
          }
        end
      end

      records
    end

    def validate_caa_records(caa_records, domain)
      findings = []

      # Check for issue tag
      issue_records = caa_records.select { |r| r[:tag] == CAA_TAG_ISSUE }
      
      if issue_records.empty?
        findings << {
          header: 'caa-records',
          issue: 'No CAA "issue" tag found - consider adding to restrict certificate issuance',
          severity: :info,
          recommended_fix: 'Add CAA record with issue tag: example.com. CAA 0 issue "ca.example.com"'
        }
      end

      # Check for wildcard protection
      issuewild_records = caa_records.select { |r| r[:tag] == CAA_TAG_ISSUEWILD }
      
      if issuewild_records.empty? && issue_records.any?
        findings << {
          header: 'caa-records',
          issue: 'No CAA "issuewild" tag - wildcard certificates not explicitly controlled',
          severity: :info,
          recommended_fix: 'Add CAA issuewild record to control wildcard certificate issuance'
        }
      end

      # Check for incident reporting
      iodef_records = caa_records.select { |r| r[:tag] == CAA_TAG_IODEF }
      
      if iodef_records.empty?
        findings << {
          header: 'caa-records',
          issue: 'No CAA "iodef" tag for incident reporting',
          severity: :info,
          recommended_fix: 'Add CAA iodef record for certificate issuance violation notifications'
        }
      end

      # Check for overly permissive CAA
      if issue_records.any? { |r| r[:value] == ';' || r[:value].empty? }
        findings << {
          header: 'caa-records',
          issue: 'CAA record allows all CAs (empty value)',
          severity: :warning,
          recommended_fix: 'Specify explicit CA domains in CAA records'
        }
      end

      findings
    end

    def query_dns(domain, type)
      @resolver.getresources(domain, type)
    rescue StandardError
      []
    end

    def command_available?(command)
      system("which #{command} > /dev/null 2>&1")
    end
  end
end
