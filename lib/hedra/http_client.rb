# frozen_string_literal: true

require 'http'
require 'uri'

module Hedra
  class HttpClient
    DEFAULT_USER_AGENT = "Hedra/#{VERSION} Security Header Analyzer".freeze
    MAX_RETRIES = 3
    RETRY_DELAY = 1
    MAX_REDIRECTS = 10

    def initialize( # rubocop:disable Metrics/ParameterLists
      timeout: 10, proxy: nil, user_agent: nil, follow_redirects: true, verbose: false, max_retries: MAX_RETRIES
    )
      @timeout = timeout
      @proxy = proxy
      @user_agent = user_agent || DEFAULT_USER_AGENT
      @follow_redirects = follow_redirects
      @verbose = verbose
      @max_retries = max_retries
    end

    def get(url, redirect_count: 0)
      retries = 0

      begin
        log "Fetching #{url}..."

        client = build_client
        response = client.get(url)

        if @follow_redirects && response.status.redirect?
          raise NetworkError, "Too many redirects (#{MAX_REDIRECTS})" if redirect_count >= MAX_REDIRECTS

          location = response.headers['Location']
          location = resolve_redirect_url(url, location)
          log "Following redirect to #{location}"
          return get(location, redirect_count: redirect_count + 1)
        end

        raise NetworkError, "HTTP #{response.status}: #{response.status.reason}" unless response.status.success?

        log "Success: #{response.status}"
        response
      rescue HTTP::Error, Errno::ECONNREFUSED, Errno::ETIMEDOUT, Errno::EHOSTUNREACH => e
        retries += 1
        if retries <= @max_retries && retryable_error?(e)
          delay = RETRY_DELAY * (2**(retries - 1))
          log "Retry #{retries}/#{@max_retries} after #{delay}s: #{e.message}"
          sleep delay
          retry
        end

        raise NetworkError, "Failed after #{@max_retries} retries: #{e.message}"
      end
    end

    private

    def build_client
      client = HTTP
               .timeout(connect: @timeout, read: @timeout)
               .headers('User-Agent' => @user_agent)

      if @proxy
        proxy_uri = URI.parse(@proxy)
        client = client.via(proxy_uri.host, proxy_uri.port, proxy_uri.user, proxy_uri.password)
      end

      client
    end

    def resolve_redirect_url(base_url, location)
      # Handle relative redirects
      return location if location.start_with?('http://', 'https://')

      base_uri = URI.parse(base_url)
      port_part = if base_uri.port && ![80, 443].include?(base_uri.port)
                    ":#{base_uri.port}"
                  else
                    ''
                  end

      if location.start_with?('/')
        "#{base_uri.scheme}://#{base_uri.host}#{port_part}#{location}"
      else
        # Relative to current path
        base_path = base_uri.path.split('/')[0..-2].join('/')
        "#{base_uri.scheme}://#{base_uri.host}#{port_part}#{base_path}/#{location}"
      end
    end

    def retryable_error?(error)
      # Retry on network errors, timeouts, but not on HTTP errors like 404
      error.is_a?(HTTP::TimeoutError) ||
        error.is_a?(HTTP::ConnectionError) ||
        error.is_a?(Errno::ECONNREFUSED) ||
        error.is_a?(Errno::ETIMEDOUT) ||
        error.is_a?(Errno::EHOSTUNREACH) ||
        error.is_a?(Errno::ECONNRESET) ||
        error.is_a?(Errno::EPIPE)
    end

    def log(message)
      puts "[HTTP] #{message}" if @verbose
    end
  end
end
