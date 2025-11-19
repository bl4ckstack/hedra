# frozen_string_literal: true

# Security Disclosure Plugin
# Checks for security-related headers that may leak sensitive information

module Hedra
  class SecurityDisclosurePlugin < Plugin
    def self.check(headers)
      findings = []

      # Check for Server header disclosure
      if headers.key?('server')
        server_value = headers['server']
        if server_value =~ /(Apache|nginx|IIS|Microsoft|PHP|Python|Ruby|Express|Tomcat|Jetty)/i
          findings << {
            header: 'server',
            issue: "Server header discloses software: #{server_value}",
            severity: :info,
            recommended_fix: 'Remove or obfuscate Server header to prevent information disclosure'
          }
        end
      end

      # Check for X-Powered-By header
      if headers.key?('x-powered-by')
        findings << {
          header: 'x-powered-by',
          issue: "X-Powered-By header discloses technology: #{headers['x-powered-by']}",
          severity: :warning,
          recommended_fix: 'Remove X-Powered-By header to prevent technology stack disclosure'
        }
      end

      # Check for X-AspNet-Version
      if headers.key?('x-aspnet-version')
        findings << {
          header: 'x-aspnet-version',
          issue: 'X-AspNet-Version header discloses ASP.NET version',
          severity: :warning,
          recommended_fix: 'Remove X-AspNet-Version header'
        }
      end

      # Check for X-AspNetMvc-Version
      if headers.key?('x-aspnetmvc-version')
        findings << {
          header: 'x-aspnetmvc-version',
          issue: 'X-AspNetMvc-Version header discloses ASP.NET MVC version',
          severity: :warning,
          recommended_fix: 'Remove X-AspNetMvc-Version header'
        }
      end

      # Check for Via header (proxy disclosure)
      if headers.key?('via')
        findings << {
          header: 'via',
          issue: "Via header may disclose proxy information: #{headers['via']}",
          severity: :info,
          recommended_fix: 'Consider removing or sanitizing Via header'
        }
      end

      findings
    end
  end
end
