# frozen_string_literal: true

require 'spec_helper'
require_relative '../../plugins/examples/comprehensive_security_plugin'

RSpec.describe Hedra::ComprehensiveSecurityPlugin do
  describe '.check' do
    context 'with information disclosure headers' do
      let(:headers) do
        {
          'server' => 'Apache/2.4.41 (Ubuntu)',
          'x-powered-by' => 'PHP/7.4.3'
        }
      end

      it 'detects server header disclosure' do
        findings = described_class.check(headers)
        server_finding = findings.find { |f| f[:header] == 'server' }

        expect(server_finding).not_to be_nil
        expect(server_finding[:severity]).to eq(:info)
      end

      it 'detects x-powered-by disclosure' do
        findings = described_class.check(headers)
        powered_by_finding = findings.find { |f| f[:header] == 'x-powered-by' }

        expect(powered_by_finding).not_to be_nil
        expect(powered_by_finding[:severity]).to eq(:warning)
      end
    end

    context 'with insecure cookies' do
      let(:headers) do
        {
          'set-cookie' => 'sessionid=abc123; Path=/'
        }
      end

      it 'detects missing Secure flag' do
        findings = described_class.check(headers)
        secure_finding = findings.find { |f| f[:issue].include?('Secure') }

        expect(secure_finding).not_to be_nil
        expect(secure_finding[:severity]).to eq(:warning)
      end

      it 'detects missing HttpOnly flag' do
        findings = described_class.check(headers)
        httponly_finding = findings.find { |f| f[:issue].include?('HttpOnly') }

        expect(httponly_finding).not_to be_nil
      end

      it 'detects missing SameSite attribute' do
        findings = described_class.check(headers)
        samesite_finding = findings.find { |f| f[:issue].include?('SameSite') }

        expect(samesite_finding).not_to be_nil
        expect(samesite_finding[:severity]).to eq(:info)
      end
    end

    context 'with secure cookies' do
      let(:headers) do
        {
          'set-cookie' => 'sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Strict'
        }
      end

      it 'does not flag secure cookies' do
        findings = described_class.check(headers)
        cookie_findings = findings.select { |f| f[:header] == 'set-cookie' }

        expect(cookie_findings).to be_empty
      end
    end

    context 'with weak HSTS' do
      let(:headers) do
        {
          'strict-transport-security' => 'max-age=31536000'
        }
      end

      it 'detects missing includeSubDomains' do
        findings = described_class.check(headers)
        subdomain_finding = findings.find { |f| f[:issue].include?('includeSubDomains') }

        expect(subdomain_finding).not_to be_nil
        expect(subdomain_finding[:severity]).to eq(:warning)
      end

      it 'detects missing preload' do
        findings = described_class.check(headers)
        preload_finding = findings.find { |f| f[:issue].include?('preload') }

        expect(preload_finding).not_to be_nil
        expect(preload_finding[:severity]).to eq(:info)
      end
    end

    context 'with public cache control' do
      let(:headers) do
        {
          'cache-control' => 'public, max-age=3600'
        }
      end

      it 'detects public caching risk' do
        findings = described_class.check(headers)
        cache_finding = findings.find { |f| f[:header] == 'cache-control' && f[:issue].include?('public') }

        expect(cache_finding).not_to be_nil
        expect(cache_finding[:severity]).to eq(:warning)
      end
    end

    context 'with no headers' do
      let(:headers) { {} }

      it 'returns findings for missing headers' do
        findings = described_class.check(headers)

        expect(findings).not_to be_empty
        expect(findings.any? { |f| f[:header] == 'cache-control' }).to be true
      end
    end
  end
end
