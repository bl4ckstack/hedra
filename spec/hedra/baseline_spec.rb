# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe Hedra::Baseline do
  let(:baseline_dir) { Dir.mktmpdir }
  let(:baseline) { described_class.new }
  let(:sample_results) do
    [
      {
        url: 'https://example.com',
        score: 85,
        timestamp: Time.now.iso8601,
        findings: [
          { header: 'csp', issue: 'Missing CSP', severity: :warning }
        ]
      }
    ]
  end

  before do
    stub_const('Hedra::Baseline::BASELINE_DIR', baseline_dir)
  end

  after do
    FileUtils.rm_rf(baseline_dir)
  end

  describe '#save' do
    it 'saves baseline to file' do
      baseline.save('test-baseline', sample_results)
      expect(File.exist?(File.join(baseline_dir, 'test-baseline.json'))).to be true
    end

    it 'sanitizes baseline names' do
      baseline.save('test/baseline with spaces', sample_results)
      expect(File.exist?(File.join(baseline_dir, 'test_baseline_with_spaces.json'))).to be true
    end
  end

  describe '#load' do
    before do
      baseline.save('test-baseline', sample_results)
    end

    it 'loads saved baseline' do
      loaded = baseline.load('test-baseline')
      expect(loaded[:name]).to eq('test-baseline')
      expect(loaded[:results]).to be_an(Array)
    end

    it 'raises error for non-existent baseline' do
      expect { baseline.load('nonexistent') }.to raise_error(Hedra::Error)
    end
  end

  describe '#list' do
    it 'returns empty array when no baselines exist' do
      expect(baseline.list).to eq([])
    end

    it 'lists all saved baselines' do
      baseline.save('baseline1', sample_results)
      baseline.save('baseline2', sample_results)

      list = baseline.list
      expect(list.length).to eq(2)
      expect(list.map { |b| b[:name] }).to contain_exactly('baseline1', 'baseline2')
    end
  end

  describe '#delete' do
    before do
      baseline.save('test-baseline', sample_results)
    end

    it 'deletes existing baseline' do
      baseline.delete('test-baseline')
      expect(File.exist?(File.join(baseline_dir, 'test-baseline.json'))).to be false
    end

    it 'raises error for non-existent baseline' do
      expect { baseline.delete('nonexistent') }.to raise_error(Hedra::Error)
    end
  end

  describe '#compare' do
    let(:baseline_results) do
      [
        {
          url: 'https://example.com',
          score: 80,
          findings: [
            { header: 'csp', issue: 'Missing CSP', severity: :warning }
          ]
        }
      ]
    end

    let(:current_results) do
      [
        {
          url: 'https://example.com',
          score: 90,
          findings: []
        }
      ]
    end

    before do
      baseline.save('test-baseline', baseline_results)
    end

    it 'compares baseline with current results' do
      comparisons = baseline.compare('test-baseline', current_results)

      expect(comparisons.length).to eq(1)
      expect(comparisons[0][:score_change]).to eq(10)
      expect(comparisons[0][:resolved_findings].length).to eq(1)
    end

    it 'detects new findings' do
      current_with_new_findings = [
        {
          url: 'https://example.com',
          score: 75,
          findings: [
            { header: 'hsts', issue: 'Missing HSTS', severity: :critical }
          ]
        }
      ]

      comparisons = baseline.compare('test-baseline', current_with_new_findings)
      expect(comparisons[0][:new_findings].length).to eq(1)
      expect(comparisons[0][:new_findings][0][:header]).to eq('hsts')
    end
  end
end
