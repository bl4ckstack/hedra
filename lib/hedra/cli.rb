# frozen_string_literal: true

require 'thor'
require 'json'
require 'yaml'
require 'pastel'
require 'tty-table'

module Hedra
  class PluginCLI < Thor
    desc 'list', 'List installed plugins'
    def list
      manager = PluginManager.new
      plugins = manager.list_plugins

      if plugins.empty?
        puts 'No plugins installed.'
      else
        puts 'Installed plugins:'
        plugins.each { |p| puts "  - #{p}" }
      end
    end

    desc 'install PATH', 'Install a plugin from path'
    def install(path)
      manager = PluginManager.new
      manager.install(path)
      puts "Plugin installed: #{path}"
    rescue StandardError => e
      warn "Failed to install plugin: #{e.message}"
      exit 1
    end

    desc 'remove NAME', 'Remove an installed plugin'
    def remove(name)
      manager = PluginManager.new
      manager.remove(name)
      puts "Plugin removed: #{name}"
    rescue StandardError => e
      warn "Failed to remove plugin: #{e.message}"
      exit 1
    end
  end

  class CLI < Thor
    class_option :verbose, type: :boolean, aliases: '-v', desc: 'Verbose output'
    class_option :quiet, type: :boolean, aliases: '-q', desc: 'Quiet mode'
    class_option :debug, type: :boolean, desc: 'Enable debug logging'

    def self.exit_on_failure?
      true
    end

    desc 'scan URL_OR_FILE', 'Scan one or multiple URLs for security headers'
    option :file, type: :boolean, aliases: '-f', desc: 'Treat argument as file with URLs'
    option :concurrency, type: :numeric, aliases: '-c', default: 10, desc: 'Concurrent requests'
    option :timeout, type: :numeric, aliases: '-t', default: 10, desc: 'Request timeout in seconds'
    option :rate, type: :string, desc: 'Rate limit (e.g., 5/s)'
    option :proxy, type: :string, desc: 'HTTP/SOCKS proxy URL'
    option :user_agent, type: :string, desc: 'Custom User-Agent header'
    option :follow_redirects, type: :boolean, default: false, desc: 'Follow redirects'
    option :output, type: :string, aliases: '-o', desc: 'Output file'
    option :format, type: :string, default: 'table', desc: 'Output format (table, json, csv)'
    def scan(target)
      setup_logging
      urls = options[:file] ? read_urls_from_file(target) : [target]

      client = build_http_client
      analyzer = Analyzer.new
      results = []

      with_concurrency(urls, options[:concurrency]) do |url|
        response = client.get(url)
        result = analyzer.analyze(url, response.headers.to_h)
        results << result
        print_result(result) unless options[:quiet] || options[:output]
      rescue StandardError => e
        log_error("Failed to scan #{url}: #{e.message}")
      end

      export_results(results) if options[:output]
    end

    desc 'audit URL', 'Deep security header audit for a single URL'
    option :json, type: :boolean, desc: 'Output as JSON'
    option :output, type: :string, aliases: '-o', desc: 'Output file'
    option :proxy, type: :string, desc: 'HTTP/SOCKS proxy URL'
    option :user_agent, type: :string, desc: 'Custom User-Agent header'
    option :timeout, type: :numeric, aliases: '-t', default: 10, desc: 'Request timeout'
    def audit(url)
      setup_logging
      client = build_http_client
      analyzer = Analyzer.new

      begin
        response = client.get(url)
        result = analyzer.analyze(url, response.headers.to_h)

        if options[:json]
          output = JSON.pretty_generate(result)
          if options[:output]
            File.write(options[:output], output)
            say "Audit saved to #{options[:output]}", :green unless options[:quiet]
          else
            puts output
          end
        else
          print_detailed_result(result)
        end
      rescue StandardError => e
        log_error("Audit failed: #{e.message}")
        exit 1
      end
    end

    desc 'watch URL', 'Periodically monitor security headers'
    option :interval, type: :numeric, default: 3600, desc: 'Check interval in seconds'
    option :proxy, type: :string, desc: 'HTTP/SOCKS proxy URL'
    option :user_agent, type: :string, desc: 'Custom User-Agent header'
    def watch(url)
      setup_logging
      client = build_http_client
      analyzer = Analyzer.new

      say "Watching #{url} every #{options[:interval]} seconds. Press Ctrl+C to stop.", :cyan

      loop do
        begin
          response = client.get(url)
          result = analyzer.analyze(url, response.headers.to_h)
          print_result(result)
        rescue StandardError => e
          log_error("Watch check failed: #{e.message}")
        end
        sleep options[:interval]
      end
    rescue Interrupt
      say "\nStopped watching.", :yellow
    end

    desc 'compare URL1 URL2', 'Compare security headers between two URLs'
    option :output, type: :string, aliases: '-o', desc: 'Output file'
    def compare(url1, url2)
      setup_logging
      client = build_http_client
      analyzer = Analyzer.new

      begin
        response1 = client.get(url1)
        response2 = client.get(url2)

        result1 = analyzer.analyze(url1, response1.headers.to_h)
        result2 = analyzer.analyze(url2, response2.headers.to_h)

        print_comparison(result1, result2)
      rescue StandardError => e
        log_error("Comparison failed: #{e.message}")
        exit 1
      end
    end

    desc 'export FORMAT', 'Export previous results in specified format'
    option :output, type: :string, aliases: '-o', required: true, desc: 'Output file'
    option :input, type: :string, aliases: '-i', desc: 'Input JSON file with results'
    def export(format)
      unless %w[json csv].include?(format)
        say "Invalid format: #{format}. Use json or csv.", :red
        exit 1
      end

      results = options[:input] ? JSON.parse(File.read(options[:input])) : []
      exporter = Exporter.new
      exporter.export(results, format, options[:output])
      say "Exported to #{options[:output]}", :green unless options[:quiet]
    end

    desc 'plugin SUBCOMMAND', 'Manage plugins'
    subcommand 'plugin', Hedra::PluginCLI

    private

    def setup_logging
      @pastel = Pastel.new
      @verbose = options[:verbose]
      @debug = options[:debug]
    end

    def build_http_client
      HttpClient.new(
        timeout: options[:timeout] || 10,
        proxy: options[:proxy],
        user_agent: options[:user_agent],
        follow_redirects: options[:follow_redirects] || false,
        verbose: @verbose
      )
    end

    def read_urls_from_file(file)
      File.readlines(file).map(&:strip).reject(&:empty?)
    rescue StandardError => e
      log_error("Failed to read file #{file}: #{e.message}")
      exit 1
    end

    def with_concurrency(items, concurrency)
      require 'concurrent'
      pool = Concurrent::FixedThreadPool.new(concurrency)

      items.each do |item|
        pool.post { yield item }
      end

      pool.shutdown
      pool.wait_for_termination
    end

    def print_result(result)
      pastel = Pastel.new

      puts "\n#{pastel.bold(result[:url])}"
      puts "Score: #{score_color(result[:score])}/100"
      puts "Timestamp: #{result[:timestamp]}"

      if result[:findings].any?
        table = TTY::Table.new(
          header: %w[Header Issue Severity],
          rows: result[:findings].map do |f|
            [f[:header], f[:issue], severity_badge(f[:severity])]
          end
        )
        puts table.render(:unicode)
      else
        puts pastel.green('✓ All security headers properly configured')
      end
    end

    def print_detailed_result(result)
      pastel = Pastel.new

      puts pastel.bold.cyan("\n═══ Security Header Audit ═══")
      puts "URL: #{result[:url]}"
      puts "Timestamp: #{result[:timestamp]}"
      puts "Security Score: #{score_color(result[:score])}/100\n"

      puts pastel.bold("\nHeaders Present:")
      result[:headers].each do |name, value|
        puts "  #{pastel.cyan(name)}: #{value[0..80]}#{'...' if value.length > 80}"
      end

      if result[:findings].any?
        puts pastel.bold("\nFindings:")
        result[:findings].group_by { |f| f[:severity] }.each do |severity, findings|
          puts "\n#{severity_badge(severity)} #{severity.upcase}"
          findings.each do |f|
            puts "  • #{f[:header]}: #{f[:issue]}"
            puts "    Fix: #{f[:recommended_fix]}" if f[:recommended_fix]
          end
        end
      else
        puts pastel.green("\n✓ No issues found")
      end
    end

    def print_comparison(result1, result2)
      pastel = Pastel.new

      puts pastel.bold.cyan("\n═══ Header Comparison ═══")
      puts "URL 1: #{result1[:url]} (Score: #{result1[:score]})"
      puts "URL 2: #{result2[:url]} (Score: #{result2[:score]})"

      headers1 = result1[:headers].keys.map(&:downcase)
      headers2 = result2[:headers].keys.map(&:downcase)

      only_in_1 = headers1 - headers2
      only_in_2 = headers2 - headers1
      common = headers1 & headers2

      if only_in_1.any?
        puts pastel.yellow("\nOnly in URL 1:")
        only_in_1.each { |h| puts "  - #{h}" }
      end

      if only_in_2.any?
        puts pastel.yellow("\nOnly in URL 2:")
        only_in_2.each { |h| puts "  - #{h}" }
      end

      puts pastel.cyan("\nCommon headers: #{common.size}")
    end

    def export_results(results)
      format = options[:format] || 'json'
      exporter = Exporter.new
      exporter.export(results, format, options[:output])
      say "Results exported to #{options[:output]}", :green unless options[:quiet]
    end

    def severity_badge(severity)
      pastel = Pastel.new
      case severity.to_s
      when 'critical'
        pastel.red.bold('● CRITICAL')
      when 'warning'
        pastel.yellow.bold('● WARNING')
      when 'info'
        pastel.blue('● INFO')
      else
        severity.to_s
      end
    end

    def score_color(score)
      pastel = Pastel.new
      if score >= 80
        pastel.green.bold(score.to_s)
      elsif score >= 60
        pastel.yellow(score.to_s)
      else
        pastel.red(score.to_s)
      end
    end

    def log_error(message)
      return if options[:quiet]

      warn Pastel.new.red("ERROR: #{message}")
    end

    def say(message, color = nil)
      return if options[:quiet]

      output = color ? Pastel.new.send(color, message) : message
      puts output
    end
  end
end
