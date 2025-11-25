# frozen_string_literal: true

require 'fileutils'

module Hedra
  class PluginManager
    def initialize
      @plugin_dir = Config.plugin_dir
      FileUtils.mkdir_p(@plugin_dir)
      load_plugins
    end

    def list_plugins
      Dir.glob(File.join(@plugin_dir, '*.rb')).map { |f| File.basename(f, '.rb') }
    end

    def install(path)
      raise Error, "Plugin file not found: #{path}" unless File.exist?(path)
      raise Error, "Not a Ruby file: #{path}" unless path.end_with?('.rb')

      # Validate plugin syntax before installing
      validate_plugin_syntax(path)

      plugin_name = File.basename(path)
      dest = File.join(@plugin_dir, plugin_name)
      
      # Backup existing plugin if it exists
      backup_existing_plugin(dest) if File.exist?(dest)
      
      FileUtils.cp(path, dest)
      load_plugin(dest)
    end

    def remove(name)
      plugin_file = File.join(@plugin_dir, "#{name}.rb")
      raise Error, "Plugin not found: #{name}" unless File.exist?(plugin_file)

      FileUtils.rm(plugin_file)
    end

    def run_checks(headers)
      findings = []

      @plugins.each do |plugin|
        result = plugin.check(headers)
        findings.concat(result) if result.is_a?(Array)
      rescue StandardError => e
        warn "Plugin #{plugin.class.name} failed: #{e.message}"
      end

      findings
    end

    private

    def load_plugins
      @plugins = []

      Dir.glob(File.join(@plugin_dir, '*.rb')).sort.each do |file|
        load_plugin(file)
      end
    end

    def load_plugin(file)
      require file
      # Plugins should define classes that respond to .check(headers)
    rescue StandardError => e
      warn "Failed to load plugin #{file}: #{e.message}"
    end

    def validate_plugin_syntax(path)
      code = File.read(path)
      RubyVM::InstructionSequence.compile(code)
    rescue SyntaxError => e
      raise Error, "Plugin has syntax errors: #{e.message}"
    end

    def backup_existing_plugin(dest)
      backup_path = "#{dest}.backup"
      FileUtils.cp(dest, backup_path)
    rescue StandardError => e
      warn "Failed to backup existing plugin: #{e.message}"
    end
  end

  # Base class for plugins
  class Plugin
    def self.check(headers)
      raise NotImplementedError, 'Plugins must implement .check(headers)'
    end
  end
end
