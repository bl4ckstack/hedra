# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Hedra::ProtocolChecker do
  let(:checker) { described_class.new }

  describe '#check' do
    context 'with HTTP URL' do
      it 'flags insecure HTTP protocol' do
        result = checker.check('http://example.com')
        
        finding = result.find { |f| f[:issue].include?('insecure HTTP') }
        expect(finding).not_to be_nil
        expect(finding[:severity]).to eq(:critical)
      end
    end

    context 'with HTTPS URL' do
      it 'checks TLS version' do
        # This test requires actual network connection
        # In real scenario, we'd mock the TLS connection
        result = checker.check('https://example.com')
        
        # Should not have HTTP protocol error
        http_finding = result.find { |f| f[:issue].include?('insecure HTTP protocol') }
        expect(http_finding).to be_nil
      end
    end

    context 'with HTTP/1.0 response' do
      let(:response) { double('response', version: '1.0') }

      it 'flags outdated HTTP/1.0' do
        result = checker.check('https://example.com', response)
        
        finding = result.find { |f| f[:issue].include?('HTTP/1.0') }
        expect(finding).not_to be_nil
        expect(finding[:severity]).to eq(:warning)
      end
    end

    context 'with HTTP/1.1 response' do
      let(:response) { double('response', version: '1.1') }

      it 'suggests upgrading to HTTP/2' do
        result = checker.check('https://example.com', response)
        
        finding = result.find { |f| f[:issue].include?('HTTP/1.1') }
        expect(finding).not_to be_nil
        expect(finding[:severity]).to eq(:info)
      end
    end

    context 'with HTTP/2 response' do
      let(:response) { double('response', version: '2') }

      it 'suggests HTTP/3 as improvement' do
        result = checker.check('https://example.com', response)
        
        finding = result.find { |f| f[:issue].include?('HTTP/2') }
        expect(finding).not_to be_nil
        expect(finding[:severity]).to eq(:info)
      end
    end

    context 'with HTTP/3 response' do
      let(:response) { double('response', version: '3') }

      it 'does not flag HTTP/3' do
        result = checker.check('https://example.com', response)
        
        protocol_findings = result.select { |f| f[:header] == 'protocol' && f[:issue].include?('HTTP/') }
        expect(protocol_findings).to be_empty
      end
    end
  end

  describe 'TLS version detection' do
    it 'handles connection failures gracefully' do
      result = checker.check('https://invalid-domain-that-does-not-exist-12345.com')
      
      # Should not raise error, may return empty or TLS findings
      expect(result).to be_an(Array)
    end
  end
end
