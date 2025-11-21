# frozen_string_literal: true

require_relative 'lib/hedra/version'

Gem::Specification.new do |spec|
  spec.name          = 'hedra'
  spec.version       = Hedra::VERSION
  spec.authors       = ['bl4ckstack']
  spec.email         = ['info@bl4ckstack.com']
  spec.summary       = 'Security header analyzer CLI'
  spec.description   = 'A comprehensive security header analyzer with scanning, auditing, and monitoring capabilities'
  spec.homepage      = 'https://github.com/bl4ckstack/hedra'
  spec.license       = 'MIT'
  spec.required_ruby_version = '>= 3.0.0'

  spec.files         = Dir['lib/**/*', 'bin/*', 'config/*', 'README.md', 'LICENSE']
  spec.bindir        = 'bin'
  spec.executables   = ['hedra']
  spec.require_paths = ['lib']

  spec.add_dependency 'concurrent-ruby', '~> 1.2'
  spec.add_dependency 'csv', '~> 3.2'
  spec.add_dependency 'http', '~> 5.1'
  spec.add_dependency 'openssl', '>= 3.1.2'
  spec.add_dependency 'pastel', '~> 0.8'
  spec.add_dependency 'thor', '~> 1.2'
  spec.add_dependency 'tty-table', '~> 0.12'
  spec.metadata['rubygems_mfa_required'] = 'true'
end
