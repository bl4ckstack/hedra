# Hedra 🛡️

[![Ruby](https://img.shields.io/badge/ruby-%3E%3D%203.0-ruby.svg)](https://www.ruby-lang.org/)
[![CI](https://github.com/blackstack/hedra/workflows/CI/badge.svg)](https://github.com/blackstack/hedra/actions)
[![Gem Version](https://badge.fury.io/rb/hedra.svg)](https://badge.fury.io/rb/hedra)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive security header analyzer for modern web applications.

## Installation

```bash
gem install hedra
```

## Usage

### Scan a URL

```bash
hedra scan https://example.com
```

### Detailed Audit

```bash
hedra audit https://example.com
```

### Export as JSON

```bash
hedra audit https://example.com --json --output report.json
```

### Scan Multiple URLs

```bash
# Create urls.txt with one URL per line
hedra scan -f urls.txt --concurrency 20
```

### Monitor Over Time

```bash
hedra watch https://example.com --interval 3600
```

### Compare Headers

```bash
hedra compare https://staging.example.com https://prod.example.com
```

## Security Headers Checked

- **Content-Security-Policy (CSP)** - Prevents XSS attacks
- **Strict-Transport-Security (HSTS)** - Enforces HTTPS
- **X-Frame-Options** - Prevents clickjacking
- **X-Content-Type-Options** - Prevents MIME-sniffing
- **Referrer-Policy** - Controls referrer information
- **Permissions-Policy** - Controls browser features
- **Cross-Origin-Opener-Policy (COOP)**
- **Cross-Origin-Embedder-Policy (COEP)**
- **Cross-Origin-Resource-Policy (CORP)**

## Options

```bash
# Concurrent scanning
hedra scan -f urls.txt --concurrency 20 --timeout 15

# Through a proxy
hedra scan https://example.com --proxy http://127.0.0.1:8080

# Custom User-Agent
hedra scan https://example.com --user-agent "MyBot/1.0"

# Follow redirects
hedra scan https://example.com --follow-redirects

# Export as CSV
hedra scan -f urls.txt --output results.csv --format csv
```

## Configuration

Create `~/.hedra/config.yml`:

```yaml
timeout: 10
concurrency: 10
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

## Plugins

Create custom header checks:

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

Install plugin:

```bash
hedra plugin install ~/.hedra/plugins/my_plugin.rb
hedra plugin list
```

## Development

```bash
# Clone and install
git clone https://github.com/blackstack/hedra.git
cd hedra
bundle install

# Run tests
bundle exec rspec

# Run linter
bundle exec rubocop

# Build gem
rake build
```

## Output Examples

### Table Format

```
https://example.com
Score: 75/100
Timestamp: 2025-11-12T10:30:00Z

┌─────────────────────────────┬──────────────────────────────┬──────────────┐
│ Header                      │ Issue                        │ Severity     │
├─────────────────────────────┼──────────────────────────────┼──────────────┤
│ x-frame-options             │ Header is missing            │ ● WARNING    │
│ referrer-policy             │ Header is missing            │ ● INFO       │
└─────────────────────────────┴──────────────────────────────┴──────────────┘
```

### JSON Format

```json
{
  "url": "https://example.com",
  "timestamp": "2025-11-12T10:30:00Z",
  "score": 75,
  "headers": {
    "content-security-policy": "default-src 'self'",
    "strict-transport-security": "max-age=31536000"
  },
  "findings": [
    {
      "header": "x-frame-options",
      "issue": "X-Frame-Options header is missing",
      "severity": "warning",
      "recommended_fix": "Add X-Frame-Options: DENY or SAMEORIGIN"
    }
  ]
}
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests for your changes
4. Ensure tests pass (`bundle exec rspec`)
5. Ensure linting passes (`bundle exec rubocop`)
6. Commit your changes (`git commit -am 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

Built by [BlackStack](https://github.com/bl4ckstack)
