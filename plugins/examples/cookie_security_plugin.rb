# frozen_string_literal: true

# Cookie Security Plugin
# Checks for secure cookie attributes

module Hedra
  class CookieSecurityPlugin < Plugin
    def self.check(headers)
      findings = []

      # Check Set-Cookie headers
      set_cookie_headers = headers.select { |k, _v| k.downcase == 'set-cookie' }

      return findings if set_cookie_headers.empty?

      set_cookie_headers.each_value do |value|
        cookies = value.is_a?(Array) ? value : [value]
        check_cookies(cookies, findings)
      end

      findings.uniq
    end

    def self.check_cookies(cookies, findings)
      cookies.each do |cookie|
        check_secure_flag(cookie, findings)
        check_httponly_flag(cookie, findings)
        check_samesite_attribute(cookie, findings)
      end
    end

    def self.check_secure_flag(cookie, findings)
      return if cookie.match?(/;\s*Secure/i)

      findings << {
        header: 'set-cookie',
        issue: 'Cookie missing Secure flag',
        severity: :warning,
        recommended_fix: 'Add Secure flag to cookies: Set-Cookie: name=value; Secure'
      }
    end

    def self.check_httponly_flag(cookie, findings)
      return if cookie.match?(/;\s*HttpOnly/i)

      findings << {
        header: 'set-cookie',
        issue: 'Cookie missing HttpOnly flag',
        severity: :warning,
        recommended_fix: 'Add HttpOnly flag to cookies: Set-Cookie: name=value; HttpOnly'
      }
    end

    def self.check_samesite_attribute(cookie, findings)
      return if cookie.match?(/;\s*SameSite=/i)

      findings << {
        header: 'set-cookie',
        issue: 'Cookie missing SameSite attribute',
        severity: :info,
        recommended_fix: 'Add SameSite attribute: Set-Cookie: name=value; SameSite=Strict'
      }
    end
  end
end
