# frozen_string_literal: true

module Hedra
  # Token bucket rate limiter
  class RateLimiter
    def initialize(rate_string)
      @requests, period = parse_rate(rate_string)
      @period = period_to_seconds(period)
      @tokens = @requests
      @last_refill = Time.now
      @mutex = Mutex.new
    end

    def acquire
      @mutex.synchronize do
        refill_tokens
        
        if @tokens >= 1
          @tokens -= 1
          return
        end

        # Wait until we have tokens
        sleep_time = @period / @requests
        sleep(sleep_time)
        refill_tokens
        @tokens -= 1
      end
    end

    private

    def parse_rate(rate_string)
      # Format: "10/s", "100/m", "1000/h"
      match = rate_string.match(/^(\d+)\/([smh])$/)
      raise Error, "Invalid rate format: #{rate_string}" unless match

      [match[1].to_i, match[2]]
    end

    def period_to_seconds(period)
      case period
      when 's' then 1
      when 'm' then 60
      when 'h' then 3600
      else 1
      end
    end

    def refill_tokens
      now = Time.now
      elapsed = now - @last_refill
      
      tokens_to_add = (elapsed / @period) * @requests
      @tokens = [@tokens + tokens_to_add, @requests].min
      @last_refill = now
    end
  end
end
