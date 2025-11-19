# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe Hedra::Cache do
  let(:cache_dir) { Dir.mktmpdir }
  let(:cache) { described_class.new(cache_dir: cache_dir, ttl: 2) }

  after do
    FileUtils.rm_rf(cache_dir)
  end

  describe '#set and #get' do
    it 'stores and retrieves values' do
      cache.set('key1', 'value1')
      expect(cache.get('key1')).to eq('value1')
    end

    it 'returns nil for non-existent keys' do
      expect(cache.get('nonexistent')).to be_nil
    end

    it 'handles complex data structures' do
      data = { 'url' => 'https://example.com', 'score' => 85, 'findings' => [] }
      cache.set('complex', data)
      expect(cache.get('complex')).to eq(data)
    end
  end

  describe 'TTL expiration' do
    it 'returns nil for expired entries' do
      cache.set('key1', 'value1')
      sleep 3
      expect(cache.get('key1')).to be_nil
    end

    it 'returns valid entries within TTL' do
      cache.set('key1', 'value1')
      sleep 1
      expect(cache.get('key1')).to eq('value1')
    end
  end

  describe '#clear' do
    it 'removes all cached entries' do
      cache.set('key1', 'value1')
      cache.set('key2', 'value2')
      cache.clear

      expect(cache.get('key1')).to be_nil
      expect(cache.get('key2')).to be_nil
    end
  end

  describe '#clear_expired' do
    it 'removes only expired entries' do
      cache.set('key1', 'value1')
      sleep 3
      cache.set('key2', 'value2')

      cache.clear_expired

      expect(cache.get('key1')).to be_nil
      expect(cache.get('key2')).to eq('value2')
    end
  end
end
