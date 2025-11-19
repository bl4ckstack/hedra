# frozen_string_literal: true

module Hedra
  # Check for security.txt file (RFC 9116)
  class SecurityTxtChecker
    SECURITY_TXT_PATHS = [
      '/.well-known/security.txt',
      '/security.txt'
    ].freeze

    def check(url, http_client)
      uri = URI.parse(url)
      base_url = "#{uri.scheme}://#{uri.host}#{uri.port && ![80, 443].include?(uri.port) ? ":#{uri.port}" : ''}"

      findings = []
      found = false

      SECURITY_TXT_PATHS.each do |path|
        begin
          response = http_client.get("#{base_url}#{path}")
          if response.status.success?
            found = true
            findings.concat(validate_security_txt(response.body.to_s))
            break
          end
        rescue StandardError
          # Continue to next path
        end
      end

      unless found
        findings << {
          header: 'security.txt',
          issue: 'security.txt file not found',
          severity: :info,
          recommended_fix: 'Add security.txt file at /.well-known/security.txt'
        }
      end

      findings
    rescue StandardError => e
      warn "security.txt check failed: #{e.message}"
      []
    end

    private

    def validate_security_txt(content)
      findings = []
      required_fields = %w[Contact]
      recommended_fields = %w[Expires]

      required_fields.each do |field|
        unless content.match?(/^#{field}:/i)
          findings << {
            header: 'security.txt',
            issue: "Missing required field: #{field}",
            severity: :warning,
            recommended_fix: "Add #{field} field to security.txt"
          }
        end
      end

      recommended_fields.each do |field|
        unless content.match?(/^#{field}:/i)
          findings << {
            header: 'security.txt',
            issue: "Missing recommended field: #{field}",
            severity: :info,
            recommended_fix: "Consider adding #{field} field to security.txt"
          }
        end
      end

      # Check expiry
      if content =~ /^Expires:\s*(.+)$/i
        begin
          expiry = Time.parse(::Regexp.last_match(1))
          if expiry < Time.now
            findings << {
              header: 'security.txt',
              issue: 'security.txt has expired',
              severity: :warning,
              recommended_fix: 'Update Expires field in security.txt'
            }
          end
        rescue StandardError
          # Invalid date format
        end
      end

      findings
    end
  end
end
