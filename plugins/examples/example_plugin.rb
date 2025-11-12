# frozen_string_literal: true

# Example Hedra Plugin
# This plugin checks for a custom security header

module Hedra
  class ExamplePlugin < Plugin
    def self.check(headers)
      findings = []

      unless headers.key?('x-custom-security')
        findings << {
          header: 'x-custom-security',
          issue: 'Custom security header is missing',
          severity: :info,
          recommended_fix: 'Add X-Custom-Security header'
        }
      end

      findings
    end
  end
end
