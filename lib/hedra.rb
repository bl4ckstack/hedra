# frozen_string_literal: true

module Hedra
  class Error < StandardError; end
  class NetworkError < Error; end
  class ConfigError < Error; end
end

require_relative 'hedra/version'
require_relative 'hedra/config'
require_relative 'hedra/scorer'
require_relative 'hedra/circuit_breaker'
require_relative 'hedra/certificate_checker'
require_relative 'hedra/cache'
require_relative 'hedra/security_txt_checker'
require_relative 'hedra/progress_tracker'
require_relative 'hedra/baseline'
require_relative 'hedra/rate_limiter'
require_relative 'hedra/http_client'
require_relative 'hedra/plugin_manager'
require_relative 'hedra/exporter'
require_relative 'hedra/html_reporter'
require_relative 'hedra/analyzer'
require_relative 'hedra/cli'
