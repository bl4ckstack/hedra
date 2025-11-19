# frozen_string_literal: true

# Comprehensive Security Plugin
# A robust all-in-one plugin that combines multiple security checks

module Hedra
  class ComprehensiveSecurityPlugin < Plugin
    def self.check(headers)
      findings = []

      # Information Disclosure Checks
      findings.concat(check_information_disclosure(headers))

      # Cookie Security Checks
      findings.concat(check_cookie_security(headers))

      # Cache Control Checks
      findings.concat(check_cache_control(headers))

      # TLS/HTTPS Checks
      findings.concat(check_tls_security(headers))

      # Additional Security Headers
      findings.concat(check_additional_headers(headers))

      findings
    end

    def self.check_information_disclosure(headers)
      findings = []

      # Server header
      if headers.key?('server')
        server_value = headers['server']
        if server_value =~ /(Apache|nginx|IIS|Microsoft|PHP|Python|Ruby|Express|Tomcat|Jetty)/i
          findings << {
            header: 'server',
            issue: "Server header discloses software: #{server_value}",
            severity: :info,
            recommended_fix: 'Remove or obfuscate Server header'
          }
        end
      end

      # X-Powered-By
      if headers.key?('x-powered-by')
        findings << {
          header: 'x-powered-by',
          issue: "Technology disclosure: #{headers['x-powered-by']}",
          severity: :warning,
          recommended_fix: 'Remove X-Powered-By header'
        }
      end

      # ASP.NET version headers
      %w[x-aspnet-version x-aspnetmvc-version].each do |header|
        next unless headers.key?(header)

        findings << {
          header: header,
          issue: 'ASP.NET version disclosure',
          severity: :warning,
          recommended_fix: "Remove #{header} header"
        }
      end

      findings
    end

    def self.check_cookie_security(headers)
      findings = []
      set_cookie_headers = headers.select { |k, _v| k.downcase == 'set-cookie' }

      return findings if set_cookie_headers.empty?

      set_cookie_headers.each_value do |value|
        cookies = value.is_a?(Array) ? value : [value]

        cookies.each do |cookie|
          findings << cookie_finding('Secure', cookie) unless cookie.match?(/;\s*Secure/i)
          findings << cookie_finding('HttpOnly', cookie) unless cookie.match?(/;\s*HttpOnly/i)
          findings << cookie_finding('SameSite', cookie) unless cookie.match?(/;\s*SameSite=/i)
        end
      end

      findings.uniq
    end

    def self.cookie_finding(flag, _cookie)
      {
        header: 'set-cookie',
        issue: "Cookie missing #{flag} flag",
        severity: flag == 'SameSite' ? :info : :warning,
        recommended_fix: "Add #{flag} flag to cookies"
      }
    end

    def self.check_cache_control(headers)
      findings = []

      unless headers.key?('cache-control')
        findings << {
          header: 'cache-control',
          issue: 'Cache-Control header missing',
          severity: :info,
          recommended_fix: 'Add Cache-Control: no-store, no-cache for sensitive pages'
        }
        return findings
      end

      cache_control = headers['cache-control'].downcase

      if cache_control.include?('public')
        findings << {
          header: 'cache-control',
          issue: 'Cache-Control allows public caching which may expose sensitive data',
          severity: :warning,
          recommended_fix: 'Use private or no-store for sensitive pages'
        }
      end

      findings
    end

    def self.check_tls_security(headers)
      findings = []

      if headers.key?('strict-transport-security')
        hsts = headers['strict-transport-security']

        unless hsts.include?('includeSubDomains')
          findings << {
            header: 'strict-transport-security',
            issue: 'HSTS missing includeSubDomains',
            severity: :warning,
            recommended_fix: 'Add includeSubDomains directive'
          }
        end

        unless hsts.include?('preload')
          findings << {
            header: 'strict-transport-security',
            issue: 'HSTS missing preload directive',
            severity: :info,
            recommended_fix: 'Add preload directive for HSTS preload list'
          }
        end
      end

      findings
    end

    def self.check_additional_headers(headers)
      findings = []

      # Check for X-DNS-Prefetch-Control
      unless headers.key?('x-dns-prefetch-control')
        findings << {
          header: 'x-dns-prefetch-control',
          issue: 'X-DNS-Prefetch-Control header missing',
          severity: :info,
          recommended_fix: 'Add X-DNS-Prefetch-Control: off to prevent DNS prefetching'
        }
      end

      # Check for X-Download-Options
      unless headers.key?('x-download-options')
        findings << {
          header: 'x-download-options',
          issue: 'X-Download-Options header missing',
          severity: :info,
          recommended_fix: 'Add X-Download-Options: noopen for IE8+ security'
        }
      end

      # Check for X-Permitted-Cross-Domain-Policies
      unless headers.key?('x-permitted-cross-domain-policies')
        findings << {
          header: 'x-permitted-cross-domain-policies',
          issue: 'X-Permitted-Cross-Domain-Policies header missing',
          severity: :info,
          recommended_fix: 'Add X-Permitted-Cross-Domain-Policies: none'
        }
      end

      findings
    end
  end
end
