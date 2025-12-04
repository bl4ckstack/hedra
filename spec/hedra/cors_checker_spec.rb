# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Hedra::CorsChecker do
  let(:checker) { described_class.new }

  describe '#check' do
    context 'with wildcard origin' do
      let(:headers) do
        {
          'access-control-allow-origin' => '*'
        }
      end

      it 'flags wildcard origin as warning' do
        result = checker.check(headers)
        
        finding = result.find { |f| f[:header] == 'access-control-allow-origin' }
        expect(finding).not_to be_nil
        expect(finding[:severity]).to eq(:warning)
        expect(finding[:issue]).to include('all origins')
      end
    end

    context 'with wildcard origin and credentials' do
      let(:headers) do
        {
          'access-control-allow-origin' => '*',
          'access-control-allow-credentials' => 'true'
        }
      end

      it 'flags as critical security risk' do
        result = checker.check(headers)
        
        finding = result.find { |f| f[:severity] == :critical }
        expect(finding).not_to be_nil
        expect(finding[:issue]).to include('credentials')
      end
    end

    context 'with null origin' do
      let(:headers) do
        {
          'access-control-allow-origin' => 'null'
        }
      end

      it 'flags null origin as critical' do
        result = checker.check(headers)
        
        finding = result.find { |f| f[:header] == 'access-control-allow-origin' }
        expect(finding).not_to be_nil
        expect(finding[:severity]).to eq(:critical)
        expect(finding[:issue]).to include('null')
      end
    end

    context 'with multiple origins in single header' do
      let(:headers) do
        {
          'access-control-allow-origin' => 'https://example.com, https://test.com'
        }
      end

      it 'flags invalid syntax' do
        result = checker.check(headers)
        
        finding = result.find { |f| f[:issue].include?('Multiple origins') }
        expect(finding).not_to be_nil
        expect(finding[:severity]).to eq(:critical)
      end
    end

    context 'with HTTP origin' do
      let(:headers) do
        {
          'access-control-allow-origin' => 'http://example.com'
        }
      end

      it 'flags insecure HTTP origin' do
        result = checker.check(headers)
        
        finding = result.find { |f| f[:issue].include?('insecure HTTP') }
        expect(finding).not_to be_nil
        expect(finding[:severity]).to eq(:warning)
      end
    end

    context 'with dangerous HTTP methods' do
      let(:headers) do
        {
          'access-control-allow-origin' => 'https://example.com',
          'access-control-allow-methods' => 'GET, POST, TRACE, DELETE'
        }
      end

      it 'flags dangerous methods' do
        result = checker.check(headers)
        
        finding = result.find { |f| f[:issue].include?('Dangerous HTTP methods') }
        expect(finding).not_to be_nil
        expect(finding[:severity]).to eq(:critical)
      end
    end

    context 'with wildcard methods' do
      let(:headers) do
        {
          'access-control-allow-origin' => 'https://example.com',
          'access-control-allow-methods' => '*'
        }
      end

      it 'flags wildcard methods' do
        result = checker.check(headers)
        
        finding = result.find { |f| f[:issue].include?('all HTTP methods') }
        expect(finding).not_to be_nil
      end
    end

    context 'with wildcard headers' do
      let(:headers) do
        {
          'access-control-allow-origin' => 'https://example.com',
          'access-control-allow-headers' => '*'
        }
      end

      it 'flags wildcard headers' do
        result = checker.check(headers)
        
        finding = result.find { |f| f[:issue].include?('all headers') }
        expect(finding).not_to be_nil
      end
    end

    context 'with sensitive headers exposed' do
      let(:headers) do
        {
          'access-control-allow-origin' => 'https://example.com',
          'access-control-allow-headers' => 'authorization, x-api-key'
        }
      end

      it 'flags sensitive headers' do
        result = checker.check(headers)
        
        finding = result.find { |f| f[:issue].include?('Sensitive headers') }
        expect(finding).not_to be_nil
        expect(finding[:severity]).to eq(:info)
      end
    end

    context 'with invalid max-age' do
      let(:headers) do
        {
          'access-control-allow-origin' => 'https://example.com',
          'access-control-max-age' => '-1'
        }
      end

      it 'flags invalid max-age' do
        result = checker.check(headers)
        
        finding = result.find { |f| f[:header] == 'access-control-max-age' }
        expect(finding).not_to be_nil
      end
    end

    context 'with proper CORS configuration' do
      let(:headers) do
        {
          'access-control-allow-origin' => 'https://trusted.example.com',
          'access-control-allow-methods' => 'GET, POST',
          'access-control-allow-headers' => 'Content-Type',
          'access-control-max-age' => '3600'
        }
      end

      it 'does not flag properly configured CORS' do
        result = checker.check(headers)
        
        critical_findings = result.select { |f| f[:severity] == :critical }
        expect(critical_findings).to be_empty
      end
    end
  end
end
