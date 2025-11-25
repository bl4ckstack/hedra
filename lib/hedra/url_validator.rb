# frozen_string_literal: true

require 'uri'

module Hedra
  # URL validation and sanitization
  class UrlValidator
    ALLOWED_SCHEMES = %w[http https].freeze
    MAX_URL_LENGTH = 2048
    DANGEROUS_CHARS = ['<', '>', '"', '{', '}', '|', '\\', '^', '`', '[', ']'].freeze

    class << self
      def valid?(url)
        return false if url.nil? || url.empty?
        return false if url.length > MAX_URL_LENGTH

        uri = parse_url(url)
        return false unless uri
        return false unless ALLOWED_SCHEMES.include?(uri.scheme)
        return false unless valid_host?(uri.host)
        return false if contains_dangerous_chars?(url)

        true
      rescue StandardError
        false
      end

      def validate!(url)
        raise Error, 'URL cannot be empty' if url.nil? || url.empty?
        raise Error, "URL too long (max #{MAX_URL_LENGTH} characters)" if url.length > MAX_URL_LENGTH

        uri = parse_url(url)
        raise Error, 'Invalid URL format' unless uri
        raise Error, "Invalid scheme: #{uri.scheme}. Only HTTP/HTTPS allowed" unless ALLOWED_SCHEMES.include?(uri.scheme)
        raise Error, 'Invalid or missing host' unless valid_host?(uri.host)
        raise Error, 'URL contains dangerous characters' if contains_dangerous_chars?(url)

        uri
      end

      def sanitize(url)
        url = url.strip
        url = "https://#{url}" unless url.start_with?('http://', 'https://')
        url
      end

      def normalize(url)
        uri = parse_url(url)
        return url unless uri

        # Remove default ports
        port = if (uri.scheme == 'http' && uri.port == 80) || (uri.scheme == 'https' && uri.port == 443)
                 nil
               else
                 uri.port
               end

        # Rebuild URL
        normalized = "#{uri.scheme}://#{uri.host}"
        normalized += ":#{port}" if port
        normalized += uri.path if uri.path && uri.path != '/'
        normalized += "?#{uri.query}" if uri.query
        normalized
      end

      private

      def parse_url(url)
        URI.parse(url)
      rescue URI::InvalidURIError
        nil
      end

      def valid_host?(host)
        return false if host.nil? || host.empty?
        return false if host.length > 253 # Max domain length

        # Check for valid hostname format
        return false if host.start_with?('.') || host.end_with?('.')
        return false if host.include?('..')

        # Check for localhost/private IPs in production
        return false if host == 'localhost'
        return false if host.start_with?('127.', '10.', '192.168.', '172.')

        true
      end

      def contains_dangerous_chars?(url)
        DANGEROUS_CHARS.any? { |char| url.include?(char) }
      end
    end
  end
end
