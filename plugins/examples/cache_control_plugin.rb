# frozen_string_literal: true

# Cache Control Plugin
# Checks for proper cache control headers on sensitive pages

module Hedra
  class CacheControlPlugin < Plugin
    def self.check(headers)
      findings = []

      # Check for Cache-Control header
      unless headers.key?('cache-control')
        findings << {
          header: 'cache-control',
          issue: 'Cache-Control header is missing',
          severity: :info,
          recommended_fix: 'Add Cache-Control header for sensitive pages: Cache-Control: no-store, no-cache'
        }
        return findings
      end

      cache_control = headers['cache-control'].downcase

      # Check for sensitive data caching issues
      if cache_control.include?('public')
        findings << {
          header: 'cache-control',
          issue: 'Cache-Control allows public caching which may expose sensitive data',
          severity: :warning,
          recommended_fix: 'Use private or no-store for sensitive pages'
        }
      end

      # Check for no-store on sensitive pages
      unless cache_control.include?('no-store') || cache_control.include?('no-cache')
        findings << {
          header: 'cache-control',
          issue: 'Cache-Control does not prevent caching of potentially sensitive data',
          severity: :info,
          recommended_fix: 'Add no-store or no-cache directive for sensitive pages'
        }
      end

      # Check Pragma header for HTTP/1.0 compatibility
      unless headers.key?('pragma')
        findings << {
          header: 'pragma',
          issue: 'Pragma header missing (needed for HTTP/1.0 compatibility)',
          severity: :info,
          recommended_fix: 'Add Pragma: no-cache for HTTP/1.0 clients'
        }
      end

      findings
    end
  end
end
