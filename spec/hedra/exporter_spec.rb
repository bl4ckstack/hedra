# frozen_string_literal: true

require 'spec_helper'
require 'tempfile'
require 'json'
require 'csv'

RSpec.describe Hedra::Exporter do
  let(:exporter) { described_class.new }

  let(:results) do
    [
      {
        url: 'https://example.com',
        timestamp: '2025-11-12T10:00:00Z',
        score: 75,
        headers: { 'content-security-policy' => "default-src 'self'" },
        findings: [
          {
            header: 'x-frame-options',
            issue: 'Missing header',
            severity: :warning,
            recommended_fix: 'Add X-Frame-Options'
          }
        ]
      }
    ]
  end

  describe '#export' do
    context 'with JSON format' do
      it 'exports results as JSON' do
        Tempfile.create(['hedra', '.json']) do |f|
          exporter.export(results, 'json', f.path)

          output = JSON.parse(File.read(f.path))
          expect(output).to be_an(Array)
          expect(output.first['url']).to eq('https://example.com')
        end
      end
    end

    context 'with CSV format' do
      it 'exports results as CSV' do
        Tempfile.create(['hedra', '.csv']) do |f|
          exporter.export(results, 'csv', f.path)

          csv = CSV.read(f.path)
          expect(csv.first).to eq(%w[URL Timestamp Score Header Issue Severity Fix])
          expect(csv[1][0]).to eq('https://example.com')
        end
      end
    end

    context 'with unsupported format' do
      it 'raises error' do
        expect do
          exporter.export(results, 'xml', 'output.xml')
        end.to raise_error(Hedra::Error, /Unsupported format/)
      end
    end
  end
end
