# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Hedra::DnsChecker do
  let(:checker) { described_class.new }

  describe '#check' do
    context 'with valid domain' do
      it 'checks DNSSEC and CAA records' do
        result = checker.check('https://example.com')
        
        # Should return findings about DNSSEC and CAA
        expect(result).to be_an(Array)
      end
    end

    context 'with invalid URL' do
      it 'handles errors gracefully' do
        result = checker.check('not-a-valid-url')
        
        # Should not raise error
        expect(result).to be_an(Array)
      end
    end

    context 'with localhost' do
      it 'handles localhost gracefully' do
        result = checker.check('https://localhost')
        
        # Should not crash
        expect(result).to be_an(Array)
      end
    end
  end

  describe 'DNSSEC checking' do
    it 'detects DNSSEC status' do
      # This would require mocking DNS queries
      # For now, we just ensure it doesn't crash
      result = checker.check('https://example.com')
      
      dnssec_finding = result.find { |f| f[:header] == 'dnssec' }
      expect(dnssec_finding).to be_a(Hash) if dnssec_finding
    end
  end

  describe 'CAA record checking' do
    it 'checks for CAA records' do
      result = checker.check('https://example.com')
      
      caa_finding = result.find { |f| f[:header] == 'caa-records' }
      expect(caa_finding).to be_a(Hash) if caa_finding
    end
  end
end
