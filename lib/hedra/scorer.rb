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
      bonus = calculate_bonus(headers)

      score = [base_score - penalty + bonus, 0].max
      [score.round, 100].min # Cap at 100
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

    def calculate_bonus(headers)
      bonus = 0

      # Bonus for HSTS with includeSubDomains
      if headers['strict-transport-security']&.include?('includeSubDomains')
        bonus += 2
      end

      # Bonus for HSTS with preload
      if headers['strict-transport-security']&.include?('preload')
        bonus += 3
      end

      # Bonus for having all recommended headers
      if HEADER_WEIGHTS.keys.all? { |h| headers.key?(h) }
        bonus += 5
      end

      bonus
    end
  end
end
