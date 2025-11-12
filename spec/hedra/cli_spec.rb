# frozen_string_literal: true

require 'spec_helper'
require 'json'
require 'tempfile'

RSpec.describe Hedra::CLI do
  describe 'audit command' do
    it 'performs audit and outputs JSON' do
      stub_request(:get, 'https://example.com')
        .to_return(
          status: 200,
          headers: {
            'Content-Security-Policy' => "default-src 'self'",
            'Strict-Transport-Security' => 'max-age=31536000'
          }
        )

      output = nil
      Tempfile.create(['hedra', '.json']) do |f|
        described_class.start(['audit', 'https://example.com', '--json', '--output', f.path, '--quiet'])
        output = JSON.parse(File.read(f.path))
      end

      expect(output).to have_key('url')
      expect(output).to have_key('findings')
      expect(output).to have_key('score')
      expect(output['url']).to eq('https://example.com')
    end
  end
end
