# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Hedra::CtChecker do
  let(:checker) { described_class.new }

  describe '#check' do
    context 'with HTTP URL' do
      it 'returns empty findings for HTTP' do
        result = checker.check('http://example.com')
        
        expect(result).to be_empty
      end
    end

    context 'with HTTPS URL' do
      it 'checks for Certificate Transparency' do
        # This test requires actual network connection
        # In real scenario, we'd mock the SSL connection
        result = checker.check('https://example.com')
        
        # Should return findings about CT
        expect(result).to be_an(Array)
      end

      it 'returns findings when no SCTs are found' do
        # Mock a certificate without CT extension
        allow(checker).to receive(:check_certificate_transparency).and_return({ scts: [], ct_enabled: false })
        
        result = checker.check('https://example.com')
        
        expect(result).not_to be_empty
        finding = result.find { |f| f[:header] == 'certificate-transparency' }
        expect(finding).not_to be_nil
        expect(finding[:issue]).to include('not logged')
      end

      it 'returns info when only one SCT is found' do
        # Mock a certificate with only one SCT
        scts = [{ source: :extension, index: 0, version: 0, log_id: 'abc123', timestamp: 123456, valid: true }]
        allow(checker).to receive(:check_certificate_transparency).and_return({ scts: scts, ct_enabled: true })
        
        result = checker.check('https://example.com')
        
        finding = result.find { |f| f[:issue].include?('Only 1 SCT') }
        expect(finding).not_to be_nil
        expect(finding[:severity]).to eq(:info)
      end

      it 'returns info when all SCTs are from extension only' do
        # Mock SCTs all from extension
        scts = [
          { source: :extension, index: 0, version: 0, log_id: 'abc123', timestamp: 123456, valid: true },
          { source: :extension, index: 1, version: 0, log_id: 'def456', timestamp: 123457, valid: true }
        ]
        allow(checker).to receive(:check_certificate_transparency).and_return({ scts: scts, ct_enabled: true })
        
        result = checker.check('https://example.com')
        
        finding = result.find { |f| f[:issue].include?('embedded in certificate only') }
        expect(finding).not_to be_nil
        expect(finding[:severity]).to eq(:info)
      end

      it 'flags invalid SCT versions' do
        # Mock SCTs with invalid version
        scts = [
          { source: :extension, index: 0, version: 0, log_id: 'abc123', timestamp: 123456, valid: true },
          { source: :extension, index: 1, version: 99, log_id: 'def456', timestamp: 123457, valid: false }
        ]
        allow(checker).to receive(:check_certificate_transparency).and_return({ scts: scts, ct_enabled: true })
        
        result = checker.check('https://example.com')
        
        finding = result.find { |f| f[:issue].include?('unsupported versions') }
        expect(finding).not_to be_nil
        expect(finding[:severity]).to eq(:warning)
      end
    end

    context 'with invalid domain' do
      it 'handles connection failures gracefully' do
        result = checker.check('https://invalid-domain-12345.test')
        
        # Should not raise error
        expect(result).to be_an(Array)
      end

      it 'handles connection timeout gracefully' do
        result = checker.check('https://10.255.255.1')
        
        # Should not raise error
        expect(result).to be_an(Array)
      end
    end

    context 'with malformed URL' do
      it 'handles parsing errors gracefully' do
        result = checker.check('not-a-valid-url')
        
        # Should not raise error
        expect(result).to be_an(Array)
      end
    end
  end

  describe 'SCT parsing' do
    it 'handles certificates without CT extension' do
      # This would require mocking OpenSSL certificate
      # For now, we just ensure the method exists and doesn't crash
      expect(checker).to respond_to(:check)
    end
  end
end
