# frozen_string_literal: true

require_relative 'hedra/version'
require_relative 'hedra/cli'
require_relative 'hedra/analyzer'
require_relative 'hedra/http_client'
require_relative 'hedra/config'
require_relative 'hedra/plugin_manager'
require_relative 'hedra/exporter'
require_relative 'hedra/scorer'

module Hedra
  class Error < StandardError; end
  class NetworkError < Error; end
  class ConfigError < Error; end
end
