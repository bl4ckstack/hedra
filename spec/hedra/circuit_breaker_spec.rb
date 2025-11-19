# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Hedra::CircuitBreaker do
  let(:circuit_breaker) { described_class.new(failure_threshold: 3, timeout: 1) }

  describe '#call' do
    context 'when circuit is closed' do
      it 'executes the block successfully' do
        result = circuit_breaker.call { 'success' }
        expect(result).to eq('success')
      end

      it 'remains closed after successful calls' do
        3.times { circuit_breaker.call { 'success' } }
        expect(circuit_breaker).to be_closed
      end
    end

    context 'when failures occur' do
      it 'counts failures' do
        2.times do
          circuit_breaker.call { raise StandardError, 'failure' }
        rescue StandardError
          # Expected
        end

        expect(circuit_breaker.failure_count).to eq(2)
      end

      it 'opens circuit after threshold failures' do
        3.times do
          circuit_breaker.call { raise StandardError, 'failure' }
        rescue StandardError
          # Expected
        end

        expect(circuit_breaker).to be_open
      end

      it 'raises CircuitOpenError when circuit is open' do
        3.times do
          circuit_breaker.call { raise StandardError, 'failure' }
        rescue StandardError
          # Expected
        end

        expect { circuit_breaker.call { 'test' } }.to raise_error(Hedra::CircuitOpenError)
      end
    end

    context 'when circuit is half-open' do
      before do
        # Open the circuit
        3.times do
          circuit_breaker.call { raise StandardError, 'failure' }
        rescue StandardError
          # Expected
        end

        # Wait for timeout
        sleep 1.1
      end

      it 'allows test requests' do
        result = circuit_breaker.call { 'success' }
        expect(result).to eq('success')
        expect(circuit_breaker).to be_half_open
      end

      it 'closes circuit after successful attempts' do
        3.times { circuit_breaker.call { 'success' } }
        expect(circuit_breaker).to be_closed
      end

      it 'reopens circuit on failure' do
        begin
          circuit_breaker.call { raise StandardError, 'failure' }
        rescue StandardError
          # Expected
        end

        expect(circuit_breaker).to be_open
      end
    end

    context 'with successful recovery' do
      it 'resets failure count after success' do
        # Cause some failures
        2.times do
          circuit_breaker.call { raise StandardError, 'failure' }
        rescue StandardError
          # Expected
        end

        expect(circuit_breaker.failure_count).to eq(2)

        # Successful call should reset
        circuit_breaker.call { 'success' }
        expect(circuit_breaker.failure_count).to eq(0)
      end
    end
  end

  describe '#state' do
    it 'starts in closed state' do
      expect(circuit_breaker.state).to eq(:closed)
    end

    it 'transitions to open after failures' do
      3.times do
        circuit_breaker.call { raise StandardError, 'failure' }
      rescue StandardError
        # Expected
      end

      expect(circuit_breaker.state).to eq(:open)
    end
  end
end
