# Hedra 🛡️

[![Ruby](https://img.shields.io/badge/Ruby-3.0%2B-CC342D?style=flat&logo=ruby)](https://www.ruby-lang.org/)
[![Gem Version](https://img.shields.io/gem/v/hedra?style=flat&logo=rubygems&color=E9573F)](https://rubygems.org/gems/hedra)
[![License](https://img.shields.io/badge/License-MIT-00A98F?style=flat)](LICENSE)
[![Downloads](https://img.shields.io/gem/dt/hedra?style=flat&color=blue)](https://rubygems.org/gems/hedra)
[![Maintainability](https://img.shields.io/codeclimate/maintainability/blackstack/hedra?style=flat&logo=codeclimate)](https://codeclimate.com/github/blackstack/hedra)

> Enterprise-grade security header analyzer with monitoring, plugins, and multi-format reporting.


## Installation

```bash
gem install hedra
```

## Usage

```bash
# Scan a URL
hedra scan https://example.com

# Detailed audit
hedra audit https://example.com

# Export as JSON
hedra audit https://example.com --json --output report.json

# Scan multiple URLs
hedra scan -f urls.txt --concurrency 20

# Monitor over time
hedra watch https://example.com --interval 3600

# Compare headers
hedra compare https://staging.example.com https://prod.example.com

# Through a proxy
hedra scan https://example.com --proxy http://127.0.0.1:8080

# Custom User-Agent
hedra scan https://example.com --user-agent "MyBot/1.0"

# Export as CSV
hedra scan -f urls.txt --output results.csv --format csv
```

## Security Headers Checked

- Content-Security-Policy (CSP)
- Strict-Transport-Security (HSTS)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- Cross-Origin-Opener-Policy (COOP)
- Cross-Origin-Embedder-Policy (COEP)
- Cross-Origin-Resource-Policy (CORP)

## Configuration

Create `~/.hedra/config.yml`:

```yaml
timeout: 10
concurrency: 10
user_agent: "Hedra/1.0.0"
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

## Plugins

```ruby
# ~/.hedra/plugins/my_plugin.rb
module Hedra
  class MyPlugin < Plugin
    def self.check(headers)
      findings = []
      unless headers.key?('x-my-header')
        findings << {
          header: 'x-my-header',
          issue: 'Custom header missing',
          severity: :warning,
          recommended_fix: 'Add X-My-Header'
        }
      end
      findings
    end
  end
end
```

```bash
hedra plugin install ~/.hedra/plugins/my_plugin.rb
hedra plugin list
```

## Development

```bash
git clone https://github.com/blackstack/hedra.git
cd hedra
bundle install
bundle exec rspec
bundle exec rubocop
rake build
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

**Built with ❤️ by [BlackStack](https://github.com/blackstack)**
