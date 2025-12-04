# frozen_string_literal: true

# Advanced Security Plugin
# Demonstrates integration with new security checkers

module Hedra
  class AdvancedSecurityPlugin < Plugin
    def self.check(headers)
      findings = []

      # Check for security-related response headers
      findings.concat(check_timing_headers(headers))
      findings.concat(check_feature_policy(headers))
      findings.concat(check_expect_ct(headers))
      findings.concat(check_nel_reporting(headers))

      findings
    end

    def self.check_timing_headers(headers)
      findings = []

      # Check Timing-Allow-Origin for resource timing API
      if headers.key?('timing-allow-origin')
        tao = headers['timing-allow-origin']
        if tao == '*'
          findings << {
            header: 'timing-allow-origin',
            issue: 'Timing-Allow-Origin set to wildcard exposes timing information',
            severity: :info,
            recommended_fix: 'Restrict to specific trusted origins'
          }
        end
      end

      findings
    end

    def self.check_feature_policy(headers)
      findings = []

      # Check for deprecated Feature-Policy (now Permissions-Policy)
      if headers.key?('feature-policy')
        findings << {
          header: 'feature-policy',
          issue: 'Feature-Policy header is deprecated, use Permissions-Policy',
          severity: :info,
          recommended_fix: 'Migrate to Permissions-Policy header'
        }
      end

      # Check Permissions-Policy for sensitive features
      if headers.key?('permissions-policy')
        pp = headers['permissions-policy'].downcase
        
        sensitive_features = {
          'geolocation' => 'location tracking',
          'microphone' => 'audio recording',
          'camera' => 'video recording',
          'payment' => 'payment processing',
          'usb' => 'USB device access'
        }

        sensitive_features.each do |feature, description|
          if pp.include?("#{feature}=*") || pp.include?("#{feature}=()")
            findings << {
              header: 'permissions-policy',
              issue: "Permissions-Policy allows #{description} (#{feature})",
              severity: :info,
              recommended_fix: "Restrict #{feature} to specific origins or disable with #{feature}=()"
            }
          end
        end
      end

      findings
    end

    def self.check_expect_ct(headers)
      findings = []

      # Expect-CT is deprecated but still worth checking
      if headers.key?('expect-ct')
        expect_ct = headers['expect-ct']
        
        unless expect_ct.include?('enforce')
          findings << {
            header: 'expect-ct',
            issue: 'Expect-CT header without enforce directive (report-only mode)',
            severity: :info,
            recommended_fix: 'Add enforce directive or remove header (deprecated)'
          }
        end

        # Note: Expect-CT is deprecated in favor of Certificate Transparency in Chrome 107+
        findings << {
          header: 'expect-ct',
          issue: 'Expect-CT header is deprecated',
          severity: :info,
          recommended_fix: 'Certificate Transparency is now mandatory; this header can be removed'
        }
      end

      findings
    end

    def self.check_nel_reporting(headers)
      findings = []

      # Check for Network Error Logging
      if headers.key?('nel')
        nel = headers['nel']
        
        # Validate NEL configuration
        unless nel.include?('report_to')
          findings << {
            header: 'nel',
            issue: 'NEL header missing report_to directive',
            severity: :warning,
            recommended_fix: 'Add report_to directive to specify reporting endpoint'
          }
        end

        unless nel.include?('max_age')
          findings << {
            header: 'nel',
            issue: 'NEL header missing max_age directive',
            severity: :warning,
            recommended_fix: 'Add max_age directive (e.g., max_age=86400)'
          }
        end
      end

      # Check for Reporting API
      if headers.key?('report-to')
        report_to = headers['report-to']
        
        # Basic validation
        unless report_to.include?('url')
          findings << {
            header: 'report-to',
            issue: 'Report-To header missing url field',
            severity: :warning,
            recommended_fix: 'Add url field with reporting endpoint'
          }
        end

        # Check for HTTPS endpoint
        if report_to.include?('http://') && !report_to.include?('https://')
          findings << {
            header: 'report-to',
            issue: 'Report-To endpoint uses insecure HTTP',
            severity: :warning,
            recommended_fix: 'Use HTTPS endpoint for reporting'
          }
        end
      end

      findings
    end
  end
end
