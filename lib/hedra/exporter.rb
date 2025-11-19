# frozen_string_literal: true

require 'json'
require 'csv'

module Hedra
  class Exporter
    def export(results, format, output_file)
      case format
      when 'json'
        export_json(results, output_file)
      when 'csv'
        export_csv(results, output_file)
      when 'html'
        export_html(results, output_file)
      else
        raise Error, "Unsupported format: #{format}"
      end
    end

    private

    def export_json(results, output_file)
      File.write(output_file, JSON.pretty_generate(results))
    end

    def export_csv(results, output_file)
      CSV.open(output_file, 'w') do |csv|
        csv << %w[URL Timestamp Score Header Issue Severity Fix]

        results.each do |result|
          if result[:findings].empty?
            csv << [result[:url], result[:timestamp], result[:score], '', 'No issues', '', '']
          else
            result[:findings].each do |finding|
              csv << [
                result[:url],
                result[:timestamp],
                result[:score],
                finding[:header],
                finding[:issue],
                finding[:severity],
                finding[:recommended_fix]
              ]
            end
          end
        end
      end
    end

    def export_html(results, output_file)
      reporter = HtmlReporter.new
      reporter.generate(results, output_file)
    end
  end
end
