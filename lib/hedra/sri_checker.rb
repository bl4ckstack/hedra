# frozen_string_literal: true

require 'uri'
require 'digest'

module Hedra
  # Check for Subresource Integrity (SRI) on external resources
  class SriChecker
    EXTERNAL_RESOURCE_PATTERN = /<(script|link)\s+[^>]*>/i.freeze
    SRC_PATTERN = /(?:src|href)=["']([^"']+)["']/i.freeze
    INTEGRITY_PATTERN = /integrity=["']([^"']+)["']/i.freeze
    CROSSORIGIN_PATTERN = /crossorigin(?:=["']([^"']+)["'])?/i.freeze

    def initialize(http_client: nil)
      @http_client = http_client
    end

    def check(url, html_content = nil)
      findings = []
      
      # Fetch HTML if not provided
      html_content ||= fetch_html(url)
      return findings unless html_content

      base_uri = URI.parse(url)
      external_resources = extract_external_resources(html_content, base_uri)

      return findings if external_resources.empty?

      external_resources.each do |resource|
        next if resource[:has_integrity]

        findings << {
          header: 'subresource-integrity',
          issue: "External #{resource[:type]} missing SRI: #{truncate_url(resource[:url])}",
          severity: :warning,
          recommended_fix: "Add integrity attribute with hash: integrity=\"sha384-...\" crossorigin=\"anonymous\""
        }
      end

      # Check for crossorigin without integrity
      external_resources.each do |resource|
        if resource[:has_integrity] && !resource[:has_crossorigin]
          findings << {
            header: 'subresource-integrity',
            issue: "SRI without crossorigin attribute: #{truncate_url(resource[:url])}",
            severity: :info,
            recommended_fix: 'Add crossorigin="anonymous" when using integrity attribute'
          }
        end
      end

      findings
    rescue StandardError => e
      warn "SRI check failed: #{e.message}" if ENV['DEBUG']
      []
    end

    private

    def fetch_html(url)
      return nil unless @http_client

      response = @http_client.get(url)
      content_type = response.headers['Content-Type'].to_s
      
      # Only process HTML content
      return nil unless content_type.include?('text/html')

      response.body.to_s
    rescue StandardError => e
      warn "Failed to fetch HTML for SRI check: #{e.message}" if ENV['DEBUG']
      nil
    end

    def extract_external_resources(html, base_uri)
      resources = []
      
      html.scan(EXTERNAL_RESOURCE_PATTERN) do |match|
        tag = match[0]
        full_tag = ::Regexp.last_match(0)
        
        # Extract src/href
        src_match = full_tag.match(SRC_PATTERN)
        next unless src_match

        resource_url = src_match[1]
        next if resource_url.nil? || resource_url.empty?

        # Skip data URIs, inline scripts, and relative URLs to same origin
        next if resource_url.start_with?('data:', 'blob:', '#', 'javascript:')
        
        # Resolve relative URLs
        absolute_url = resolve_url(resource_url, base_uri)
        next unless absolute_url

        # Check if external
        resource_uri = URI.parse(absolute_url)
        next if same_origin?(base_uri, resource_uri)

        # Check for integrity and crossorigin attributes
        has_integrity = full_tag.match?(INTEGRITY_PATTERN)
        has_crossorigin = full_tag.match?(CROSSORIGIN_PATTERN)

        resources << {
          type: tag.downcase,
          url: absolute_url,
          has_integrity: has_integrity,
          has_crossorigin: has_crossorigin
        }
      rescue URI::InvalidURIError
        # Skip invalid URIs
        next
      end

      resources.uniq { |r| r[:url] }
    end

    def resolve_url(url, base_uri)
      return url if url.match?(%r{^https?://})

      if url.start_with?('//')
        "#{base_uri.scheme}:#{url}"
      elsif url.start_with?('/')
        "#{base_uri.scheme}://#{base_uri.host}#{base_uri.port && ![80, 443].include?(base_uri.port) ? ":#{base_uri.port}" : ''}#{url}"
      else
        # Relative URL
        base_path = base_uri.path.split('/')[0..-2].join('/')
        "#{base_uri.scheme}://#{base_uri.host}#{base_uri.port && ![80, 443].include?(base_uri.port) ? ":#{base_uri.port}" : ''}#{base_path}/#{url}"
      end
    rescue StandardError
      nil
    end

    def same_origin?(uri1, uri2)
      uri1.scheme == uri2.scheme &&
        uri1.host == uri2.host &&
        (uri1.port || default_port(uri1.scheme)) == (uri2.port || default_port(uri2.scheme))
    end

    def default_port(scheme)
      scheme == 'https' ? 443 : 80
    end

    def truncate_url(url, max_length = 60)
      return url if url.length <= max_length

      "#{url[0...max_length]}..."
    end
  end
end
