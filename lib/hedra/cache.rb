# frozen_string_literal: true

require 'digest'
require 'json'
require 'fileutils'

module Hedra
  # Simple file-based cache for HTTP responses
  class Cache
    DEFAULT_TTL = 3600 # 1 hour
    MAX_CACHE_SIZE = 1000 # Maximum number of cache files

    def initialize(cache_dir: nil, ttl: DEFAULT_TTL, verbose: false)
      @cache_dir = cache_dir || File.join(Config::CONFIG_DIR, 'cache')
      @ttl = ttl
      @verbose = verbose
      FileUtils.mkdir_p(@cache_dir)
      cleanup_if_needed
    end

    def get(key)
      cache_file = cache_path(key)
      return nil unless File.exist?(cache_file)

      data = JSON.parse(File.read(cache_file))
      
      if expired?(data['timestamp'])
        File.delete(cache_file) # Clean up expired file immediately
        return nil
      end

      data['value']
    rescue JSON::ParserError
      # Corrupted cache file, delete it
      File.delete(cache_file) if File.exist?(cache_file)
      nil
    rescue StandardError => e
      warn "Cache read error: #{e.message}" if @verbose
      nil
    end

    def set(key, value)
      cache_file = cache_path(key)
      data = {
        'timestamp' => Time.now.to_i,
        'value' => value
      }
      
      # Atomic write to prevent corruption
      temp_file = "#{cache_file}.tmp"
      File.write(temp_file, JSON.generate(data))
      File.rename(temp_file, cache_file)
    rescue StandardError => e
      warn "Cache write error: #{e.message}" if @verbose
      File.delete(temp_file) if File.exist?(temp_file)
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

    def cleanup_if_needed
      cache_files = Dir.glob(File.join(@cache_dir, '*'))
      return if cache_files.length < MAX_CACHE_SIZE

      # Remove oldest files if cache is too large
      cache_files.sort_by { |f| File.mtime(f) }
                 .first(cache_files.length - MAX_CACHE_SIZE + 100)
                 .each { |f| File.delete(f) rescue nil }
    end
  end
end
