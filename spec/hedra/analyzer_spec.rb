# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Hedra::Analyzer do
  let(:analyzer) { described_class.new }

  describe '#analyze' do
    context 'with secure headers' do
      let(:headers) do
        {
          'Content-Security-Policy' => "default-src 'self'",
          'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains',
          'X-Frame-Options' => 'DENY',
          'X-Content-Type-Options' => 'nosniff',
          'Referrer-Policy' => 'strict-origin-when-cross-origin'
        }
      end

      it 'returns high score with no critical findings' do
        result = analyzer.analyze('https://example.com', headers)

        expect(result[:score]).to be >= 80
        expect(result[:findings].select { |f| f[:severity] == :critical }).to be_empty
      end
    end

    context 'with missing critical headers' do
      let(:headers) { {} }

      it 'identifies missing CSP header' do
        result = analyzer.analyze('https://example.com', headers)

        csp_finding = result[:findings].find { |f| f[:header] == 'content-security-policy' }
        expect(csp_finding).not_to be_nil
        expect(csp_finding[:severity]).to eq(:critical)
      end

      it 'identifies missing HSTS header' do
        result = analyzer.analyze('https://example.com', headers)

        hsts_finding = result[:findings].find { |f| f[:header] == 'strict-transport-security' }
        expect(hsts_finding).not_to be_nil
        expect(hsts_finding[:severity]).to eq(:critical)
      end

      it 'returns low score' do
        result = analyzer.analyze('https://example.com', headers)
        expect(result[:score]).to be < 50
      end
    end

    context 'with insecure CSP' do
      let(:headers) do
        {
          'Content-Security-Policy' => "default-src 'self' 'unsafe-inline' 'unsafe-eval'"
        }
      end

      it 'flags unsafe CSP directives' do
        result = analyzer.analyze('https://example.com', headers)

        csp_warning = result[:findings].find do |f|
          f[:header] == 'content-security-policy' && f[:issue].include?('unsafe')
        end

        expect(csp_warning).not_to be_nil
        expect(csp_warning[:severity]).to eq(:warning)
      end
    end

    context 'with weak HSTS' do
      let(:headers) do
        {
          'Strict-Transport-Security' => 'max-age=3600'
        }
      end

      it 'flags short max-age' do
        result = analyzer.analyze('https://example.com', headers)

        hsts_warning = result[:findings].find do |f|
          f[:header] == 'strict-transport-security' && f[:issue].include?('max-age')
        end

        expect(hsts_warning).not_to be_nil
      end
    end

    context 'with invalid X-Frame-Options' do
      let(:headers) do
        {
          'X-Frame-Options' => 'INVALID'
        }
      end

      it 'flags invalid value' do
        result = analyzer.analyze('https://example.com', headers)

        xfo_warning = result[:findings].find do |f|
          f[:header] == 'x-frame-options' && f[:issue].include?('invalid')
        end

        expect(xfo_warning).not_to be_nil
      end
    end

    it 'includes timestamp in result' do
      result = analyzer.analyze('https://example.com', {})
      expect(result[:timestamp]).to match(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/)
    end

    it 'includes URL in result' do
      result = analyzer.analyze('https://example.com', {})
      expect(result[:url]).to eq('https://example.com')
    end

    it 'normalizes header names to lowercase' do
      headers = { 'Content-Security-Policy' => "default-src 'self'" }
      result = analyzer.analyze('https://example.com', headers)

      expect(result[:headers]).to have_key('Content-Security-Policy')
    end
  end
end
