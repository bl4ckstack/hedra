# frozen_string_literal: true

module Hedra
  # Validate CORS (Cross-Origin Resource Sharing) headers for security misconfigurations
  class CorsChecker
    DANGEROUS_ORIGINS = [
      '*',
      'null'
    ].freeze

    def check(headers, url = nil)
      findings = []

      # Check Access-Control-Allow-Origin
      if headers.key?('access-control-allow-origin')
        acao = headers['access-control-allow-origin']
        findings.concat(check_allow_origin(acao, headers))
      end

      # Check Access-Control-Allow-Credentials with wildcard
      if headers.key?('access-control-allow-credentials')
        findings.concat(check_credentials(headers))
      end

      # Check Access-Control-Allow-Methods
      if headers.key?('access-control-allow-methods')
        findings.concat(check_allow_methods(headers['access-control-allow-methods']))
      end

      # Check Access-Control-Allow-Headers
      if headers.key?('access-control-allow-headers')
        findings.concat(check_allow_headers(headers['access-control-allow-headers']))
      end

      # Check Access-Control-Max-Age
      if headers.key?('access-control-max-age')
        findings.concat(check_max_age(headers['access-control-max-age']))
      end

      # Check for missing CORS headers when others are present
      if cors_headers_present?(headers) && !headers.key?('access-control-allow-origin')
        findings << {
          header: 'access-control-allow-origin',
          issue: 'CORS headers present but Access-Control-Allow-Origin is missing',
          severity: :warning,
          recommended_fix: 'Add Access-Control-Allow-Origin header or remove other CORS headers'
        }
      end

      findings
    rescue StandardError => e
      warn "CORS check failed: #{e.message}" if ENV['DEBUG']
      []
    end

    private

    def check_allow_origin(acao, headers)
      findings = []

      # Wildcard with credentials is a critical security issue
      if acao == '*' && credentials_enabled?(headers)
        findings << {
          header: 'access-control-allow-origin',
          issue: 'CORS allows all origins (*) with credentials enabled - critical security risk',
          severity: :critical,
          recommended_fix: 'Use specific origin instead of wildcard when credentials are enabled'
        }
      elsif acao == '*'
        findings << {
          header: 'access-control-allow-origin',
          issue: 'CORS allows all origins (*) - potential security risk',
          severity: :warning,
          recommended_fix: 'Restrict to specific trusted origins'
        }
      elsif acao == 'null'
        findings << {
          header: 'access-control-allow-origin',
          issue: 'CORS allows "null" origin - security vulnerability',
          severity: :critical,
          recommended_fix: 'Never allow "null" origin, use specific origins'
        }
      elsif acao.include?(',')
        findings << {
          header: 'access-control-allow-origin',
          issue: 'Multiple origins in Access-Control-Allow-Origin (invalid syntax)',
          severity: :critical,
          recommended_fix: 'Use single origin or implement dynamic origin validation'
        }
      elsif acao.match?(%r{^https?://})
        # Valid origin, check for common issues
        if acao.start_with?('http://') && !acao.include?('localhost') && !acao.include?('127.0.0.1')
          findings << {
            header: 'access-control-allow-origin',
            issue: 'CORS allows insecure HTTP origin',
            severity: :warning,
            recommended_fix: 'Use HTTPS origins only'
          }
        end
      end

      findings
    end

    def check_credentials(headers)
      findings = []
      acac = headers['access-control-allow-credentials']

      if acac.to_s.downcase == 'true'
        acao = headers['access-control-allow-origin']
        
        if acao == '*'
          findings << {
            header: 'access-control-allow-credentials',
            issue: 'Credentials enabled with wildcard origin (invalid and dangerous)',
            severity: :critical,
            recommended_fix: 'Use specific origin when credentials are enabled'
          }
        elsif acao.nil?
          findings << {
            header: 'access-control-allow-credentials',
            issue: 'Credentials enabled without Access-Control-Allow-Origin',
            severity: :warning,
            recommended_fix: 'Add Access-Control-Allow-Origin header'
          }
        end
      elsif acac && acac.to_s.downcase != 'true'
        findings << {
          header: 'access-control-allow-credentials',
          issue: 'Invalid Access-Control-Allow-Credentials value (must be "true" or omitted)',
          severity: :warning,
          recommended_fix: 'Set to "true" or remove the header'
        }
      end

      findings
    end

    def check_allow_methods(methods)
      findings = []
      method_list = methods.to_s.upcase.split(',').map(&:strip)

      # Check for overly permissive methods
      dangerous_methods = ['TRACE', 'TRACK', 'CONNECT']
      found_dangerous = method_list & dangerous_methods

      if found_dangerous.any?
        findings << {
          header: 'access-control-allow-methods',
          issue: "Dangerous HTTP methods allowed: #{found_dangerous.join(', ')}",
          severity: :critical,
          recommended_fix: 'Remove dangerous methods (TRACE, TRACK, CONNECT)'
        }
      end

      # Check for wildcard
      if method_list.include?('*')
        findings << {
          header: 'access-control-allow-methods',
          issue: 'CORS allows all HTTP methods (*)',
          severity: :warning,
          recommended_fix: 'Specify only required methods (GET, POST, etc.)'
        }
      end

      # Check for overly permissive DELETE/PUT without proper consideration
      risky_methods = ['DELETE', 'PUT', 'PATCH']
      found_risky = method_list & risky_methods

      if found_risky.any? && method_list.length > 5
        findings << {
          header: 'access-control-allow-methods',
          issue: "Potentially risky methods allowed: #{found_risky.join(', ')}",
          severity: :info,
          recommended_fix: 'Ensure write methods are properly protected with authentication'
        }
      end

      findings
    end

    def check_allow_headers(headers_value)
      findings = []
      header_list = headers_value.to_s.downcase.split(',').map(&:strip)

      # Check for wildcard
      if header_list.include?('*')
        findings << {
          header: 'access-control-allow-headers',
          issue: 'CORS allows all headers (*)',
          severity: :warning,
          recommended_fix: 'Specify only required headers'
        }
      end

      # Check for sensitive headers
      sensitive_headers = ['authorization', 'cookie', 'x-api-key', 'x-auth-token']
      found_sensitive = header_list & sensitive_headers

      if found_sensitive.any?
        findings << {
          header: 'access-control-allow-headers',
          issue: "Sensitive headers exposed: #{found_sensitive.join(', ')}",
          severity: :info,
          recommended_fix: 'Ensure sensitive headers are only allowed for trusted origins'
        }
      end

      findings
    end

    def check_max_age(max_age)
      findings = []
      age = max_age.to_i

      if age <= 0
        findings << {
          header: 'access-control-max-age',
          issue: 'Invalid Access-Control-Max-Age value',
          severity: :info,
          recommended_fix: 'Set to positive number of seconds (e.g., 3600)'
        }
      elsif age > 86400
        findings << {
          header: 'access-control-max-age',
          issue: 'Very long preflight cache duration (>24 hours)',
          severity: :info,
          recommended_fix: 'Consider shorter duration for security updates'
        }
      end

      findings
    end

    def credentials_enabled?(headers)
      headers['access-control-allow-credentials'].to_s.downcase == 'true'
    end

    def cors_headers_present?(headers)
      cors_header_keys = [
        'access-control-allow-credentials',
        'access-control-allow-methods',
        'access-control-allow-headers',
        'access-control-max-age',
        'access-control-expose-headers'
      ]

      cors_header_keys.any? { |key| headers.key?(key) }
    end
  end
end
