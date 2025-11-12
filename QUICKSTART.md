# Hedra Quick Start

## Installation

```bash
# Install dependencies
bundle install

# Build the gem
rake build

# Install locally
gem install pkg/hedra-1.0.0.gem

# Or run directly from source
bin/hedra --help
```

## Basic Usage

### Scan a single URL
```bash
hedra scan https://example.com
```

### Audit with detailed output
```bash
hedra audit https://example.com
```

### Export as JSON
```bash
hedra audit https://example.com --json --output report.json
```

### Scan multiple URLs
```bash
# Create a file with URLs (one per line)
echo "https://example.com" > urls.txt
echo "https://github.com" >> urls.txt

# Scan all URLs
hedra scan -f urls.txt
```

### Advanced options
```bash
# Concurrent scanning with custom timeout
hedra scan -f urls.txt --concurrency 20 --timeout 15

# Through a proxy
hedra scan https://example.com --proxy http://127.0.0.1:8080

# Custom User-Agent
hedra scan https://example.com --user-agent "MyBot/1.0"
```

## Development

### Run tests
```bash
bundle exec rspec
```

### Run linter
```bash
bundle exec rubocop
```

### Run all checks
```bash
bundle exec rake
```

## Configuration

Create `~/.hedra/config.yml`:
```yaml
timeout: 10
concurrency: 10
follow_redirects: false
user_agent: "Hedra/1.0.0"
output_format: table
```

## Custom Rules

Create `~/.hedra/rules.yml`:
```yaml
rules:
  - header: "X-Custom-Security"
    type: missing
    severity: warning
    message: "Custom security header is missing"
    fix: "Add X-Custom-Security header"
```

## Plugin Development

Create a plugin in `~/.hedra/plugins/my_plugin.rb`:
```ruby
module Hedra
  class MyPlugin < Plugin
    def self.check(headers)
      findings = []
      
      unless headers.key?('x-my-header')
        findings << {
          header: 'x-my-header',
          issue: 'My custom header is missing',
          severity: :warning,
          recommended_fix: 'Add X-My-Header'
        }
      end
      
      findings
    end
  end
end
```

Then install it:
```bash
hedra plugin install ~/.hedra/plugins/my_plugin.rb
hedra plugin list
```
