# Hedra

[![Ruby](https://img.shields.io/badge/ruby-%3E%3D%203.0-ruby.svg)](https://www.ruby-lang.org/)
[![Gem Version](https://badge.fury.io/rb/hedra.svg)](https://badge.fury.io/rb/hedra)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Security header analyzer for web applications. Scan, audit, and monitor HTTP security headers with support for SSL/TLS validation, baseline tracking, and CI/CD integration.

## Installation

```bash
gem install hedra
```

## Quick Start

```bash
# Scan a URL
hedra scan https://example.com

# Audit with full checks
hedra audit https://example.com

# Scan multiple URLs
hedra scan -f urls.txt

# Generate HTML report
hedra scan https://example.com --output report.html --format html
```

## Commands

### scan
Scan one or multiple URLs for security headers.

```bash
hedra scan https://example.com
hedra scan -f urls.txt --concurrency 20
hedra scan https://example.com --cache --rate 10/s
```

**Options:**
- `-f, --file` - Read URLs from file
- `-c, --concurrency N` - Concurrent requests (default: 10)
- `-t, --timeout N` - Request timeout in seconds (default: 10)
- `--rate RATE` - Rate limit (e.g., 10/s, 100/m, 1000/h)
- `--cache` - Enable response caching
- `--cache-ttl N` - Cache TTL in seconds (default: 3600)
- `-o, --output FILE` - Output file
- `--format FORMAT` - Output format: table, json, csv, html (default: table)
- `--proxy URL` - HTTP/SOCKS proxy
- `--user-agent STRING` - Custom User-Agent
- `--save-baseline NAME` - Save results as baseline
- `--[no-]progress` - Show/hide progress bar
- `--[no-]check-certificates` - Enable/disable SSL checks (default: enabled)
- `--[no-]check-security-txt` - Enable/disable security.txt checks

### audit
Deep security audit for a single URL.

```bash
hedra audit https://example.com
hedra audit https://example.com --json --output report.json
```

**Options:**
- `--json` - Output as JSON
- `-o, --output FILE` - Output file
- `--proxy URL` - HTTP/SOCKS proxy
- `--user-agent STRING` - Custom User-Agent
- `-t, --timeout N` - Request timeout
- `--[no-]check-certificates` - Enable/disable SSL checks
- `--[no-]check-security-txt` - Enable/disable security.txt checks

### watch
Monitor security headers periodically.

```bash
hedra watch https://example.com --interval 3600
```

**Options:**
- `--interval N` - Check interval in seconds (default: 3600)

### compare
Compare security headers between two URLs.

```bash
hedra compare https://staging.example.com https://prod.example.com
```

### ci_check
CI/CD friendly check with exit codes.

```bash
hedra ci_check https://example.com --threshold 80
hedra ci_check -f urls.txt --fail-on-critical
```

**Options:**
- `-f, --file` - Read URLs from file
- `--threshold N` - Minimum score threshold (default: 80)
- `--fail-on-critical` - Fail if critical issues found (default: true)

**Exit codes:**
- `0` - All checks passed
- `1` - Checks failed (score below threshold or critical issues)

### baseline
Manage security baselines.

```bash
# List baselines
hedra baseline list

# Compare against baseline
hedra baseline compare production-v1 -f urls.txt

# Delete baseline
hedra baseline delete production-v1
```

### cache
Manage response cache.

```bash
# Clear all cache
hedra cache clear

# Clear expired entries
hedra cache clear-expired
```

### plugin
Manage plugins.

```bash
# List plugins
hedra plugin list

# Install plugin
hedra plugin install path/to/plugin.rb

# Remove plugin
hedra plugin remove plugin_name
```

## Security Checks

### HTTP Headers
- Content-Security-Policy (CSP)
- Strict-Transport-Security (HSTS)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- Cross-Origin-Opener-Policy (COOP)
- Cross-Origin-Embedder-Policy (COEP)
- Cross-Origin-Resource-Policy (CORP)

### Additional Checks
- SSL/TLS certificate expiry and strength
- Certificate signature algorithms
- Certificate key size validation
- security.txt file (RFC 9116)

## Configuration

Create `~/.hedra/confiml`:

```yaml
# HTTP settings
timecurity Checks
concurrency: 10
user_agent: "Hedra/2.0.0"
follow_redirects: true
max_retries: 3

# Performance
cache_enabled: false
cache_ttl: 3600
rate_limit: "10/s"

# Security checks
check_certificates: true
check_security_txt: false

# Output
output_format: "table"
progress_bar: true

# Circuit breaker
circuit_breaker_threshold: 5
circuit_breaker_timeout: 60
```

## Custom Rules

Create `~/.hedra/rules.yml`:

```yaml
rules:
  - header: "X-Custom-Header"
    type: missing
    severity: warning
    message: "Custom header is missing"
    fix: "Add X-Custom-Header to responses"
```

**Rule types:**
- `missing` - Check if header is absent
- `pattern` - Match header value against regex pattern

**Severity levels:**
- `critical` - Critical security issue (-20 points)
- `warning` - Warning (-10 points)
- `info` - Informational (-5 points)

## Plugins

Create custom plugins in `~/.hedra/plugins/`:

```ruby
module Hedra
  class MyPlugin < Plugin
    def self.check(headers)
      findings = []
      
      unless headers.key?('x-custom-header')
        findings << {
          header: 'x-custom-header',
          issue: 'Custom header missing',
          severity: :warning,
          recommended_fix: 'Add X-Custom-Header'
        }
      end
      
      findings
    end
  end
end
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Headers

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Ruby
        uses: ruby/setup-ruby@v1
        with:
          ruby-version: '3.2'
      
      - name: Install Hedra
        run: gem install hedra
      
      - name: Security Check
        run: hedra ci_check ${{ secrets.APP_URL }} --threshold 85
      
      - name: Generate Report
        if: always()
        run: hedra scan ${{ secrets.APP_URL }} --output report.html --format html
      
      - name: Upload Report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: report.html
```

### GitLab CI

```yaml
security_headers:
  image: ruby:3.2
  script:
    - gem install hedra
    - hedra ci_check $APP_URL --threshold 85 --output report.json --format json
  artifacts:
    reports:
      junit: report.json
    paths:
      - report.json
```

## Export Formats

### JSON
```bash
hedra scan https://example.com --output report.json --format json
```

### CSV
```bash
hedra scan -f urls.txt --output report.csv --format csv
```

### HTML
```bash
hedra scan -f urls.txt --output report.html --format html
```

## Scoring

Headers are weighted by importance (total: 100 points):

| Header | Weight |
|--------|--------|
| Content-Security-Policy | 25 |
| Strict-Transport-Security | 25 |
| X-Frame-Options | 15 |
| X-Content-Type-Options | 10 |
| Referrer-Policy | 10 |
| Permissions-Policy | 5 |
| Cross-Origin-Opener-Policy | 5 |
| Cross-Origin-Embedder-Policy | 3 |
| Cross-Origin-Resource-Policy | 2 |

Penalties:
- Critical issue: -20 points
- Warning: -10 points
- Info: -5 points

## Examples

### Basic Usage
```bash
# Single URL
hedra scan https://example.com

# Multiple URLs with concurrency
hedra scan -f urls.txt --concurrency 20

# With caching
hedra scan -f urls.txt --cache --cache-ttl 7200
```

### Rate Limiting
```bash
# 10 requests per second
hedra scan -f urls.txt --rate 10/s

# 100 requests per minute
hedra scan -f urls.txt --rate 100/m
```

### Baseline Tracking
```bash
# Save baseline
hedra scan -f urls.txt --save-baseline prod-v1

# Compare later
hedra baseline compare prod-v1 -f urls.txt
```

### Proxy Usage
```bash
hedra scan https://example.com --proxy http://127.0.0.1:8080
```

### Custom User-Agent
```bash
hedra scan https://example.com --user-agent "MyScanner/1.0"
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

MIT License. See [LICENSE](LICENSE) for details.

## Links

- **GitHub**: https://github.com/blackstack/hedra
- **RubyGems**: https://rubygems.org/gems/hedra
- **Issues**: https://github.com/blackstack/hedra/issues

---

Built by [BlackStack](https://github.com/blackstack)
