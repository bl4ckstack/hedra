# frozen_string_literal: true

# Advanced Content Security Policy analyzer plugin
# This plugin performs deep analysis of CSP directives

module Hedra
  class AdvancedCspPlugin < Plugin
    DANGEROUS_DIRECTIVES = {
      'unsafe-inline' => 'Allows inline scripts/styles, vulnerable to XSS',
      'unsafe-eval' => 'Allows eval(), vulnerable to code injection',
      'unsafe-hashes' => 'Allows event handler attributes',
      '*' => 'Allows resources from any origin'
    }.freeze

    RECOMMENDED_DIRECTIVES = %w[
      default-src
      script-src
      style-src
      img-src
      connect-src
      font-src
      object-src
      media-src
      frame-src
      base-uri
      form-action
      frame-ancestors
    ].freeze

    def self.check(headers)
      findings = []
      csp = headers['content-security-policy']

      return findings unless csp

      # Parse CSP directives
      directives = parse_csp(csp)

      # Check for dangerous directives
      findings.concat(check_dangerous_directives(directives))

      # Check for missing recommended directives
      findings.concat(check_missing_directives(directives))

      # Check for overly permissive directives
      findings.concat(check_permissive_directives(directives))

      # Check for deprecated directives
      findings.concat(check_deprecated_directives(directives))

      # Check for nonce/hash usage
      findings.concat(check_nonce_hash_usage(directives))

      findings
    end

    def self.parse_csp(csp)
      directives = {}
      csp.split(';').each do |directive|
        parts = directive.strip.split(/\s+/)
        next if parts.empty?

        name = parts[0]
        values = parts[1..]
        directives[name] = values
      end
      directives
    end

    def self.check_dangerous_directives(directives)
      findings = []

      directives.each do |directive, values|
        values.each do |value|
          DANGEROUS_DIRECTIVES.each do |dangerous, reason|
            if value.include?(dangerous)
              findings << {
                header: 'content-security-policy',
                issue: "CSP directive '#{directive}' contains '#{dangerous}': #{reason}",
                severity: dangerous == '*' ? :warning : :critical,
                recommended_fix: "Remove '#{dangerous}' and use nonces, hashes, or strict-dynamic"
              }
            end
          end
        end
      end

      findings
    end

    def self.check_missing_directives(directives)
      findings = []
      missing = RECOMMENDED_DIRECTIVES - directives.keys

      if missing.include?('default-src')
        findings << {
          header: 'content-security-policy',
          issue: "Missing critical directive 'default-src'",
          severity: :critical,
          recommended_fix: "Add 'default-src' directive as fallback"
        }
      end

      if missing.include?('script-src')
        findings << {
          header: 'content-security-policy',
          issue: "Missing 'script-src' directive",
          severity: :warning,
          recommended_fix: "Add 'script-src' directive to control script sources"
        }
      end

      if missing.include?('object-src')
        findings << {
          header: 'content-security-policy',
          issue: "Missing 'object-src' directive",
          severity: :info,
          recommended_fix: "Add 'object-src none' to prevent plugin execution"
        }
      end

      findings
    end

    def self.check_permissive_directives(directives)
      findings = []

      directives.each do |directive, values|
        # Check for data: URIs in script-src
        if directive == 'script-src' && values.include?('data:')
          findings << {
            header: 'content-security-policy',
            issue: "script-src allows 'data:' URIs, potential XSS vector",
            severity: :warning,
            recommended_fix: "Remove 'data:' from script-src"
          }
        end

        # Check for overly broad domains
        values.each do |value|
          if value.start_with?('*.') && value.count('.') == 1
            findings << {
              header: 'content-security-policy',
              issue: "#{directive} allows all subdomains of #{value}",
              severity: :info,
              recommended_fix: "Consider restricting to specific subdomains"
            }
          end
        end
      end

      findings
    end

    def self.check_deprecated_directives(directives)
      findings = []
      deprecated = {
        'block-all-mixed-content' => 'Use upgrade-insecure-requests instead',
        'plugin-types' => 'Deprecated, use object-src none instead',
        'referrer' => 'Use Referrer-Policy header instead'
      }

      directives.keys.each do |directive|
        if deprecated.key?(directive)
          findings << {
            header: 'content-security-policy',
            issue: "Deprecated directive '#{directive}'",
            severity: :info,
            recommended_fix: deprecated[directive]
          }
        end
      end

      findings
    end

    def self.check_nonce_hash_usage(directives)
      findings = []

      %w[script-src style-src].each do |directive|
        next unless directives[directive]

        values = directives[directive]
        has_unsafe_inline = values.include?("'unsafe-inline'")
        has_nonce = values.any? { |v| v.start_with?("'nonce-") }
        has_hash = values.any? { |v| v.start_with?("'sha") }
        has_strict_dynamic = values.include?("'strict-dynamic'")

        if has_unsafe_inline && !has_nonce && !has_hash
          findings << {
            header: 'content-security-policy',
            issue: "#{directive} uses 'unsafe-inline' without nonces or hashes",
            severity: :critical,
            recommended_fix: "Use nonces or hashes instead of 'unsafe-inline'"
          }
        end

        if (has_nonce || has_hash) && !has_strict_dynamic
          findings << {
            header: 'content-security-policy',
            issue: "#{directive} uses nonces/hashes but not 'strict-dynamic'",
            severity: :info,
            recommended_fix: "Consider adding 'strict-dynamic' for better security"
          }
        end
      end

      findings
    end
  end
end
