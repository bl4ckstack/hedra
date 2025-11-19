# frozen_string_literal: true

# TLS Security Plugin
# Checks for TLS and HTTPS-related security headers

module Hedra
  class TlsSecurityPlugin < Plugin
    def self.check(headers)
      findings = []

      # Check for Strict-Transport-Security (HSTS) preload
      if headers.key?('strict-transport-security')
        hsts = headers['strict-transport-security']

        unless hsts.include?('preload')
          findings << {
            header: 'strict-transport-security',
            issue: 'HSTS header missing preload directive',
            severity: :info,
            recommended_fix: 'Add preload: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
          }
        end

        unless hsts.include?('includeSubDomains')
          findings << {
            header: 'strict-transport-security',
            issue: 'HSTS header missing includeSubDomains directive',
            severity: :warning,
            recommended_fix: 'Add includeSubDomains: Strict-Transport-Security: max-age=31536000; includeSubDomains'
          }
        end
      end

      # Check for Upgrade-Insecure-Requests
      unless headers.key?('content-security-policy') &&
             headers['content-security-policy'].include?('upgrade-insecure-requests')
        findings << {
          header: 'content-security-policy',
          issue: 'CSP missing upgrade-insecure-requests directive',
          severity: :info,
          recommended_fix: 'Add upgrade-insecure-requests to CSP to automatically upgrade HTTP requests to HTTPS'
        }
      end

      findings
    end
  end
end
