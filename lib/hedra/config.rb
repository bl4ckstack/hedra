# frozen_string_literal: true

require 'yaml'
require 'fileutils'

module Hedra
  class Config
    CONFIG_DIR = File.expand_path('~/.hedra')
    CONFIG_FILE = File.join(CONFIG_DIR, 'config.yml')

    DEFAULT_CONFIG = {
      'timeout' => 10,
      'concurrency' => 10,
      'follow_redirects' => true,
      'user_agent' => "Hedra/#{VERSION}",
      'proxy' => nil,
      'output_format' => 'table'
    }.freeze

    def self.load
      ensure_config_dir

      if File.exist?(CONFIG_FILE)
        YAML.load_file(CONFIG_FILE)
      else
        DEFAULT_CONFIG
      end
    rescue StandardError => e
      warn "Failed to load config: #{e.message}"
      DEFAULT_CONFIG
    end

    def self.save(config)
      ensure_config_dir
      File.write(CONFIG_FILE, YAML.dump(config))
    end

    def self.ensure_config_dir
      FileUtils.mkdir_p(CONFIG_DIR)
    end

    def self.plugin_dir
      File.join(CONFIG_DIR, 'plugins')
    end
  end
end
