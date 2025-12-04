# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Hedra::SriChecker do
  let(:checker) { described_class.new }

  describe '#check' do
    context 'with external scripts without SRI' do
      let(:html) do
        <<~HTML
          <html>
            <head>
              <script src="https://cdn.example.com/script.js"></script>
              <link rel="stylesheet" href="https://cdn.example.com/style.css">
            </head>
          </html>
        HTML
      end

      it 'identifies missing SRI on external script' do
        result = checker.check('https://example.com', html)
        
        script_finding = result.find { |f| f[:issue].include?('script') }
        expect(script_finding).not_to be_nil
        expect(script_finding[:severity]).to eq(:warning)
      end

      it 'identifies missing SRI on external stylesheet' do
        result = checker.check('https://example.com', html)
        
        link_finding = result.find { |f| f[:issue].include?('link') }
        expect(link_finding).not_to be_nil
      end
    end

    context 'with external scripts with SRI' do
      let(:html) do
        <<~HTML
          <html>
            <head>
              <script src="https://cdn.example.com/script.js" 
                      integrity="sha384-abc123" 
                      crossorigin="anonymous"></script>
            </head>
          </html>
        HTML
      end

      it 'does not flag scripts with proper SRI' do
        result = checker.check('https://example.com', html)
        
        expect(result).to be_empty
      end
    end

    context 'with SRI but missing crossorigin' do
      let(:html) do
        <<~HTML
          <html>
            <head>
              <script src="https://cdn.example.com/script.js" 
                      integrity="sha384-abc123"></script>
            </head>
          </html>
        HTML
      end

      it 'flags missing crossorigin attribute' do
        result = checker.check('https://example.com', html)
        
        crossorigin_finding = result.find { |f| f[:issue].include?('crossorigin') }
        expect(crossorigin_finding).not_to be_nil
        expect(crossorigin_finding[:severity]).to eq(:info)
      end
    end

    context 'with same-origin resources' do
      let(:html) do
        <<~HTML
          <html>
            <head>
              <script src="/js/script.js"></script>
              <script src="https://example.com/js/app.js"></script>
            </head>
          </html>
        HTML
      end

      it 'does not flag same-origin resources' do
        result = checker.check('https://example.com', html)
        
        expect(result).to be_empty
      end
    end

    context 'with data URIs and inline scripts' do
      let(:html) do
        <<~HTML
          <html>
            <head>
              <script src="data:text/javascript,alert('test')"></script>
              <script>console.log('inline');</script>
            </head>
          </html>
        HTML
      end

      it 'ignores data URIs and inline scripts' do
        result = checker.check('https://example.com', html)
        
        expect(result).to be_empty
      end
    end

    context 'with protocol-relative URLs' do
      let(:html) do
        <<~HTML
          <html>
            <head>
              <script src="//cdn.example.com/script.js"></script>
            </head>
          </html>
        HTML
      end

      it 'identifies missing SRI on protocol-relative URLs' do
        result = checker.check('https://example.com', html)
        
        expect(result).not_to be_empty
        expect(result.first[:issue]).to include('script')
      end
    end
  end
end
