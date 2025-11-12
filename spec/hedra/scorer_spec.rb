# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Hedra::Scorer do
  let(:scorer) { described_class.new }

  describe '#calculate' do
    context 'with all security headers present' do
      let(:headers) do
        {
          'content-security-policy' => "default-src 'self'",
          'strict-transport-security' => 'max-age=31536000',
          'x-frame-options' => 'DENY',
          'x-content-type-options' => 'nosniff',
          'referrer-policy' => 'strict-origin',
          'permissions-policy' => 'geolocation=()',
          'cross-origin-opener-policy' => 'same-origin',
          'cross-origin-embedder-policy' => 'require-corp',
          'cross-origin-resource-policy' => 'same-origin'
        }
      end

      it 'returns perfect score with no findings' do
        score = scorer.calculate(headers, [])
        expect(score).to eq(100)
      end
    end

    context 'with no headers' do
      it 'returns zero score' do
        score = scorer.calculate({}, [])
        expect(score).to eq(0)
      end
    end

    context 'with critical findings' do
      let(:findings) do
        [
          { severity: :critical, issue: 'Missing CSP' },
          { severity: :critical, issue: 'Missing HSTS' }
        ]
      end

      it 'applies penalty for critical findings' do
        score = scorer.calculate({}, findings)
        expect(score).to eq(0)
      end
    end

    context 'with mixed severity findings' do
      let(:headers) do
        {
          'content-security-policy' => "default-src 'self'",
          'strict-transport-security' => 'max-age=31536000'
        }
      end

      let(:findings) do
        [
          { severity: :warning, issue: 'Weak setting' },
          { severity: :info, issue: 'Missing optional header' }
        ]
      end

      it 'calculates score with appropriate penalties' do
        score = scorer.calculate(headers, findings)
        expect(score).to be_between(30, 50)
      end
    end
  end
end
