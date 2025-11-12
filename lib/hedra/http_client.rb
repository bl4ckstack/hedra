# frozen_string_literal: true

require 'http'
require 'uri'

module Hedra
  class HttpClient
    DEFAULT_USER_AGENT = "Hedra/#{VERSION} Security Header Analyzer".freeze
    MAX_RETRIES = 3
    RETRY_DELAY = 1

    def initialize(timeout: 10, proxy: nil, user_agent: nil, follow_redirects: false, verbose: false)
      @timeout = timeout
      @proxy = proxy
      @user_agent = user_agent || DEFAULT_USER_AGENT
      @follow_redirects = follow_redirects
      @verbose = verbose
    end

    def get(url)
      retries = 0

      begin
        log "Fetching #{url}..."

        client = build_client
        response = client.get(url)

        if @follow_redirects && response.status.redirect?
          location = response.headers['Location']
          log "Following redirect to #{location}"
          return get(location)
        end

        raise NetworkError, "HTTP #{response.status}: #{response.status.reason}" unless response.status.success?

        log "Success: #{response.status}"
        response
      rescue HTTP::Error, Errno::ECONNREFUSED, Errno::ETIMEDOUT => e
        retries += 1
        raise NetworkError, "Failed after #{MAX_RETRIES} retries: #{e.message}" unless retries <= MAX_RETRIES

        delay = RETRY_DELAY * (2**(retries - 1))
        log "Retry #{retries}/#{MAX_RETRIES} after #{delay}s: #{e.message}"
        sleep delay
        retry
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

    def log(message)
      puts "[HTTP] #{message}" if @verbose
    end
  end
end
