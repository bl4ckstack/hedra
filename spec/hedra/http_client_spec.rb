# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Hedra::HttpClient do
  let(:client) { described_class.new }

  describe '#get' do
    it 'fetches URL successfully' do
      stub_request(:get, 'https://example.com')
        .to_return(status: 200, headers: { 'Content-Type' => 'text/html' })

      response = client.get('https://example.com')
      expect(response.status.success?).to be true
    end

    it 'raises NetworkError on connection failure' do
      stub_request(:get, 'https://example.com').to_timeout

      expect { client.get('https://example.com') }.to raise_error(Hedra::NetworkError)
    end

    it 'retries on failure' do
      stub_request(:get, 'https://example.com')
        .to_timeout.times(2)
        .then.to_return(status: 200)

      response = client.get('https://example.com')
      expect(response.status.success?).to be true
    end

    it 'respects custom timeout' do
      client = described_class.new(timeout: 1)
      stub_request(:get, 'https://example.com').to_timeout

      expect { client.get('https://example.com') }.to raise_error(Hedra::NetworkError)
    end

    it 'uses custom user agent' do
      client = described_class.new(user_agent: 'CustomAgent/1.0')
      stub_request(:get, 'https://example.com')
        .with(headers: { 'User-Agent' => 'CustomAgent/1.0' })
        .to_return(status: 200)

      client.get('https://example.com')
    end

    context 'with redirects' do
      it 'follows redirects by default' do
        stub_request(:get, 'https://example.com')
          .to_return(status: 301, headers: { 'Location' => 'https://example.org' })

        stub_request(:get, 'https://example.org')
          .to_return(status: 200)

        response = client.get('https://example.com')
        expect(response.status.success?).to be true
      end

      it 'does not follow redirects when disabled' do
        client = described_class.new(follow_redirects: false)

        stub_request(:get, 'https://example.com')
          .to_return(status: 301, headers: { 'Location' => 'https://example.org' })

        expect { client.get('https://example.com') }.to raise_error(Hedra::NetworkError, /301/)
      end

      it 'follows redirects when explicitly enabled' do
        client = described_class.new(follow_redirects: true)

        stub_request(:get, 'https://example.com')
          .to_return(status: 301, headers: { 'Location' => 'https://example.org' })

        stub_request(:get, 'https://example.org')
          .to_return(status: 200)

        response = client.get('https://example.com')
        expect(response.status.success?).to be true
      end
    end
  end
end
