# frozen_string_literal: true

module Hedra
  # Circuit breaker pattern to prevent cascading failures
  class CircuitBreaker
    FAILURE_THRESHOLD = 5
    TIMEOUT_SECONDS = 60
    HALF_OPEN_ATTEMPTS = 3

    attr_reader :state, :failure_count, :last_failure_time

    def initialize(failure_threshold: FAILURE_THRESHOLD, timeout: TIMEOUT_SECONDS)
      @failure_threshold = failure_threshold
      @timeout = timeout
      @failure_count = 0
      @last_failure_time = nil
      @state = :closed
      @half_open_attempts = 0
    end

    def call
      raise CircuitOpenError, 'Circuit breaker is open' if open? && !should_attempt_reset?

      if open? && should_attempt_reset?
        @state = :half_open
        @half_open_attempts = 0
      end

      begin
        result = yield
        on_success
        result
      rescue StandardError => e
        on_failure
        raise e
      end
    end

    def open?
      @state == :open
    end

    def closed?
      @state == :closed
    end

    def half_open?
      @state == :half_open
    end

    private

    def on_success
      if half_open?
        @half_open_attempts += 1
        if @half_open_attempts >= HALF_OPEN_ATTEMPTS
          @state = :closed
          @failure_count = 0
        end
      else
        @failure_count = 0
      end
    end

    def on_failure
      @failure_count += 1
      @last_failure_time = Time.now

      return unless @failure_count >= @failure_threshold

      @state = :open
    end

    def should_attempt_reset?
      @last_failure_time && (Time.now - @last_failure_time) >= @timeout
    end
  end

  class CircuitOpenError < Error; end
end
