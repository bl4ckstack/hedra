# frozen_string_literal: true

require 'json'
require 'fileutils'

module Hedra
  # Manage security baselines for comparison
  class Baseline
    BASELINE_DIR = File.join(Config::CONFIG_DIR, 'baselines')

    def initialize
      FileUtils.mkdir_p(BASELINE_DIR)
    end

    def save(name, results)
      baseline_file = File.join(BASELINE_DIR, "#{sanitize_name(name)}.json")
      data = {
        name: name,
        created_at: Time.now.iso8601,
        results: results
      }
      File.write(baseline_file, JSON.pretty_generate(data))
    end

    def load(name)
      baseline_file = File.join(BASELINE_DIR, "#{sanitize_name(name)}.json")
      raise Error, "Baseline not found: #{name}" unless File.exist?(baseline_file)

      JSON.parse(File.read(baseline_file), symbolize_names: true)
    end

    def list
      Dir.glob(File.join(BASELINE_DIR, '*.json')).map do |file|
        data = JSON.parse(File.read(file), symbolize_names: true)
        {
          name: data[:name],
          created_at: data[:created_at],
          url_count: data[:results].length
        }
      end
    rescue StandardError
      []
    end

    def delete(name)
      baseline_file = File.join(BASELINE_DIR, "#{sanitize_name(name)}.json")
      raise Error, "Baseline not found: #{name}" unless File.exist?(baseline_file)

      File.delete(baseline_file)
    end

    def compare(baseline_name, current_results)
      baseline = load(baseline_name)
      baseline_results = baseline[:results]

      comparisons = []

      current_results.each do |current|
        baseline_result = baseline_results.find { |b| b[:url] == current[:url] }
        next unless baseline_result

        comparison = {
          url: current[:url],
          baseline_score: baseline_result[:score],
          current_score: current[:score],
          score_change: current[:score] - baseline_result[:score],
          new_findings: current[:findings] - baseline_result[:findings],
          resolved_findings: baseline_result[:findings] - current[:findings]
        }

        comparisons << comparison
      end

      comparisons
    end

    private

    def sanitize_name(name)
      name.gsub(/[^a-zA-Z0-9_-]/, '_')
    end
  end
end
