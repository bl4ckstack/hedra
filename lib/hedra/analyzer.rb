# frozen_string_literal: true

require 'time'

module Hedra
  class Analyzer
    SECURITY_HEADERS = {
      'content-security-policy' => {
        required: true,
        severity: :critical,
        message: 'Content-Security-Policy header is missing',
        fix: "Add CSP header: Content-Security-Policy: default-src 'self'"
      },
      'strict-transport-security' => {
        required: true,
        severity: :critical,
        message: 'Strict-Transport-Security (HSTS) header is missing',
        fix: 'Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains'
      },
      'x-frame-options' => {
        required: true,
        severity: :warning,
        message: 'X-Frame-Options header is missing',
        fix: 'Add X-Frame-Options: DENY or SAMEORIGIN'
      },
      'x-content-type-options' => {
        required: true,
        severity: :warning,
        message: 'X-Content-Type-Options header is missing',
        fix: 'Add X-Content-Type-Options: nosniff'
      },
      'referrer-policy' => {
        required: true,
        severity: :info,
        message: 'Referrer-Policy header is missing',
        fix: 'Add Referrer-Policy: strict-origin-when-cross-origin'
      },
      'permissions-policy' => {
        required: false,
        severity: :info,
        message: 'Permissions-Policy header is missing',
        fix: 'Consider adding Permissions-Policy to control browser features'
      },
      'cross-origin-opener-policy' => {
        required: false,
        severity: :info,
        message: 'Cross-Origin-Opener-Policy header is missing',
        fix: 'Add Cross-Origin-Opener-Policy: same-origin'
      },
      'cross-origin-embedder-policy' => {
        required: false,
        severity: :info,
        message: 'Cross-Origin-Embedder-Policy header is missing',
        fix: 'Add Cross-Origin-Embedder-Policy: require-corp'
      },
      'cross-origin-resource-policy' => {
        required: false,
        severity: :info,
        message: 'Cross-Origin-Resource-Policy header is missing',
        fix: 'Add Cross-Origin-Resource-Policy: same-origin'
      }
    }.freeze

    def initialize(check_certificates: true, check_security_txt: false)
      @plugin_manager = PluginManager.new
      @scorer = Scorer.new
      @certificate_checker = check_certificates ? CertificateChecker.new : nil
      @security_txt_checker = check_security_txt ? SecurityTxtChecker.new : nil
      load_custom_rules
    end

    def analyze(url, headers, http_client: nil)
      normalized_headers = normalize_headers(headers)
      findings = []

      # Check for missing required headers
      SECURITY_HEADERS.each do |header_name, config|
        next unless config[:required]

        next if normalized_headers.key?(header_name)

        findings << {
          header: header_name,
          issue: config[:message],
          severity: config[:severity],
          recommended_fix: config[:fix]
        }
      end

      # Validate header values
      findings.concat(validate_header_values(normalized_headers))

      # Apply custom rules
      findings.concat(apply_custom_rules(normalized_headers))

      # Run plugin checks
      findings.concat(@plugin_manager.run_checks(normalized_headers))

      # Check SSL certificate
      if @certificate_checker
        findings.concat(@certificate_checker.check(url))
      end

      # Check security.txt
      if @security_txt_checker && http_client
        findings.concat(@security_txt_checker.check(url, http_client))
      end

      # Calculate security score
      score = @scorer.calculate(normalized_headers, findings)

      {
        url: url,
        timestamp: Time.now.iso8601,
        headers: headers,
        findings: findings,
        score: score
      }
    end

    private

    def normalize_headers(headers)
      headers.transform_keys { |k| k.to_s.downcase }
    end

    def validate_header_values(headers)
      findings = []

      # Validate CSP
      if headers['content-security-policy']
        csp = headers['content-security-policy']
        if csp.include?('unsafe-inline') || csp.include?('unsafe-eval')
          findings << {
            header: 'content-security-policy',
            issue: 'CSP contains unsafe directives (unsafe-inline or unsafe-eval)',
            severity: :warning,
            recommended_fix: 'Remove unsafe-inline and unsafe-eval, use nonces or hashes'
          }
        end
      end

      # Validate HSTS
      if headers['strict-transport-security']
        hsts = headers['strict-transport-security']
        if hsts =~ /max-age=(\d+)/
          max_age = ::Regexp.last_match(1).to_i
          if max_age < 31_536_000
            findings << {
              header: 'strict-transport-security',
              issue: 'HSTS max-age is less than 1 year (31536000 seconds)',
              severity: :warning,
              recommended_fix: 'Set max-age to at least 31536000'
            }
          end
        end
      end

      # Validate X-Frame-Options
      if headers['x-frame-options']
        xfo = headers['x-frame-options'].upcase
        unless %w[DENY SAMEORIGIN].include?(xfo.split.first)
          findings << {
            header: 'x-frame-options',
            issue: 'X-Frame-Options has invalid value',
            severity: :warning,
            recommended_fix: 'Use DENY or SAMEORIGIN'
          }
        end
      end

      # Validate X-Content-Type-Options
      if headers['x-content-type-options']
        xcto = headers['x-content-type-options'].downcase
        unless xcto == 'nosniff'
          findings << {
            header: 'x-content-type-options',
            issue: 'X-Content-Type-Options should be "nosniff"',
            severity: :info,
            recommended_fix: 'Set to nosniff'
          }
        end
      end

      findings
    end

    def load_custom_rules
      @custom_rules = []
      config_path = File.expand_path('~/.hedra/rules.yml')
      return unless File.exist?(config_path)

      rules = YAML.load_file(config_path)
      @custom_rules = rules['rules'] || []
    rescue StandardError => e
      warn "Failed to load custom rules: #{e.message}"
    end

    def apply_custom_rules(headers)
      findings = []

      @custom_rules.each do |rule|
        header_name = rule['header'].downcase
        pattern = Regexp.new(rule['pattern']) if rule['pattern']

        if rule['type'] == 'missing' && !headers.key?(header_name)
          findings << {
            header: header_name,
            issue: rule['message'],
            severity: rule['severity'].to_sym,
            recommended_fix: rule['fix']
          }
        elsif rule['type'] == 'pattern' && headers[header_name]
          if pattern && headers[header_name] =~ pattern
            findings << {
              header: header_name,
              issue: rule['message'],
              severity: rule['severity'].to_sym,
              recommended_fix: rule['fix']
            }
          end
        end
      end

      findings
    end
  end
end
