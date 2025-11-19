# frozen_string_literal: true

module Hedra
  # Track and display progress for batch operations
  class ProgressTracker
    def initialize(total, quiet: false)
      @total = total
      @current = 0
      @quiet = quiet
      @start_time = Time.now
      @mutex = Mutex.new
    end

    def increment
      @mutex.synchronize do
        @current += 1
        update_display unless @quiet
      end
    end

    def finish
      return if @quiet

      puts "\n"
      elapsed = Time.now - @start_time
      puts "Completed #{@total} items in #{elapsed.round(2)}s"
    end

    private

    def update_display
      percentage = (@current.to_f / @total * 100).round(1)
      bar_width = 40
      filled = (bar_width * @current / @total).round
      bar = '█' * filled + '░' * (bar_width - filled)
      
      elapsed = Time.now - @start_time
      rate = @current / elapsed
      eta = (@total - @current) / rate

      print "\r[#{bar}] #{percentage}% (#{@current}/#{@total}) ETA: #{eta.round}s"
      $stdout.flush
    end
  end
end
