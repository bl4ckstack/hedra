# frozen_string_literal: true

require 'digest'
require 'json'
require 'fileutils'

module Hedra
  # Simple file-based cache for HTTP responses
  class Cache
    DEFAULT_TTL = 3600 # 1 hour

    def initialize(cache_dir: nil, ttl: DEFAULT_TTL)
      @cache_dir = cache_dir || File.join(Config::CONFIG_DIR, 'cache')
      @ttl = ttl
      FileUtils.mkdir_p(@cache_dir)
    end

    def get(key)
      cache_file = cache_path(key)
      return nil unless File.exist?(cache_file)

      data = JSON.parse(File.read(cache_file))
      return nil if expired?(data['timestamp'])

      data['value']
    rescue StandardError => e
      warn "Cache read error: #{e.message}"
      nil
    end

    def set(key, value)
      cache_file = cache_path(key)
      data = {
        'timestamp' => Time.now.to_i,
        'value' => value
      }
      File.write(cache_file, JSON.generate(data))
    rescue StandardError => e
      warn "Cache write error: #{e.message}"
    end

    def clear
      FileUtils.rm_rf(@cache_dir)
      FileUtils.mkdir_p(@cache_dir)
    end

    def clear_expired
      Dir.glob(File.join(@cache_dir, '*')).each do |file|
        data = JSON.parse(File.read(file))
        File.delete(file) if expired?(data['timestamp'])
      rescue StandardError
        # Skip invalid cache files
      end
    end

    private

    def cache_path(key)
      hash = Digest::SHA256.hexdigest(key)
      File.join(@cache_dir, hash)
    end

    def expired?(timestamp)
      (Time.now.to_i - timestamp) > @ttl
    end
  end
end
