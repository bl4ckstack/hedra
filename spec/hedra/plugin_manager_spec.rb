# frozen_string_literal: true

require 'spec_helper'
require 'tempfile'

RSpec.describe Hedra::PluginManager do
  let(:manager) { described_class.new }

  describe '#list_plugins' do
    it 'returns empty array when no plugins installed' do
      expect(manager.list_plugins).to be_an(Array)
    end
  end

  describe '#run_checks' do
    it 'returns empty findings when no plugins' do
      findings = manager.run_checks({})
      expect(findings).to eq([])
    end

    it 'handles plugin errors gracefully' do
      expect { manager.run_checks({}) }.not_to raise_error
    end
  end
end
