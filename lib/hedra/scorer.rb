# frozen_string_literal: true

module Hedra
  class Scorer
    HEADER_WEIGHTS = {
      'content-security-policy' => 25,
      'strict-transport-security' => 25,
      'x-frame-options' => 15,
      'x-content-type-options' => 10,
      'referrer-policy' => 10,
      'permissions-policy' => 5,
      'cross-origin-opener-policy' => 5,
      'cross-origin-embedder-policy' => 3,
      'cross-origin-resource-policy' => 2
    }.freeze

    SEVERITY_PENALTIES = {
      critical: 20,
      warning: 10,
      info: 5
    }.freeze

    def calculate(headers, findings)
      base_score = calculate_base_score(headers)
      penalty = calculate_penalty(findings)

      score = [base_score - penalty, 0].max
      score.round
    end

    private

    def calculate_base_score(headers)
      score = 0

      HEADER_WEIGHTS.each do |header, weight|
        score += weight if headers.key?(header)
      end

      score
    end

    def calculate_penalty(findings)
      penalty = 0

      findings.each do |finding|
        severity = finding[:severity].to_sym
        penalty += SEVERITY_PENALTIES[severity] || 0
      end

      penalty
    end
  end
end
