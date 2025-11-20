# Hedra

[![Ruby](https://img.shields.io/badge/Ruby-3.0%2B-CC342D?style=flat&logo=ruby)](https://www.ruby-lang.org/)
[![Gem Version](https://img.shields.io/gem/v/hedra?style=flat&logo=rubygems&color=E9573F)](https://rubygems.org/gems/hedra)
[![License](https://img.shields.io/badge/License-MIT-00A98F?style=flat)](LICENSE)
[![Downloads](https://img.shields.io/gem/dt/hedra?style=flat&color=blue)](https://rubygems.org/gems/hedra)

> Security header analyzer with SSL/TLS validation, baseline tracking, and CI/CD integration.

<p align="center">
  <img src="logo.png" width="380" alt="Hedra Logo"/>
</p>

## Installation
```bash
gem install hedra
```

## Quick Start
```bash
hedra scan https://github.com
hedra audit https://stripe.com --json
hedra scan -f urls.txt --format html --output report.html
```

## Commands

### scan

Scan URLs for security headers with flexible output options.
```bash
hedra scan https://github.com
hedra scan -f urls.txt --concurrency 20
hedra scan https://stripe.com --cache --rate 10/s
```

**Key Options:**
- `-f, --file FILE` • Read URLs from file
- `-c, --concurrency N` • Concurrent requests (default: 10)
- `-t, --timeout N` • Request timeout in seconds (default: 10)
- `--rate RATE` • Rate limit: 10/s, 100/m, 1000/h
- `--cache` • Enable response caching
- `--cache-ttl N` • Cache TTL in seconds (default: 3600)
- `-o, --output FILE` • Output file
- `--format FORMAT` • table, json, csv, html (default: table)
- `--proxy URL` • HTTP/SOCKS proxy
- `--user-agent STRING` • Custom User-Agent
- `--save-baseline NAME` • Save results as baseline
- `--[no-]progress` • Show/hide progress bar
- `--[no-]check-certificates` • SSL checks (default: enabled)
- `--[no-]check-security-txt` • RFC 9116 checks

### audit

Deep security audit with detailed recommendations.
```bash
hedra audit https://github.com
hedra audit https://api.stripe.com --json --output report.json
```

**Options:**
- `--json` • JSON output format
- `-o, --output FILE` • Output file
- `--proxy URL` • HTTP/SOCKS proxy
- `--user-agent STRING` • Custom User-Agent
- `-t, --timeout N` • Request timeout
- `--[no-]check-certificates` • SSL/TLS validation
- `--[no-]check-security-txt` • security.txt checks

### watch

Monitor security headers periodically.
```bash
hedra watch https://myapp.com --interval 3600
```

**Options:**
- `--interval N` • Check interval in seconds (default: 3600)

### compare

Compare security headers between environments.
```bash
hedra compare https://staging.myapp.com https://myapp.com
```

### ci_check

CI/CD-friendly check with exit codes and thresholds.
```bash
hedra ci_check https://myapp.com --threshold 85
hedra ci_check -f urls.txt --fail-on-critical
```

**Options:**
- `-f, --file FILE` • Read URLs from file
- `--threshold N` • Minimum score threshold (default: 80)
- `--fail-on-critical` • Fail on critical issues (default: true)

**Exit Codes:**
- `0` • All checks passed
- `1` • Score below threshold or critical issues found

### baseline

Track security posture changes over time.
```bash
hedra baseline list
hedra baseline compare production-v1 -f urls.txt
hedra baseline delete production-v1
```

### cache

Manage response cache for faster repeated scans.
```bash
hedra cache clear
hedra cache clear-expired
```

### plugin

Extend functionality with custom security checks.
```bash
hedra plugin list
hedra plugin install path/to/plugin.rb
hedra plugin remove plugin_name
```

## Security Checks

### HTTP Headers Analyzed

| Header | Weight | Purpose |
|--------|--------|---------|
| Content-Security-Policy | 25 pts | Prevent XSS and injection attacks |
| Strict-Transport-Security | 25 pts | Enforce HTTPS connections |
| X-Frame-Options | 15 pts | Prevent clickjacking |
| X-Content-Type-Options | 10 pts | Stop MIME-type sniffing |
| Referrer-Policy | 10 pts | Control referrer information |
| Permissions-Policy | 5 pts | Manage browser features |
| Cross-Origin-Opener-Policy | 5 pts | Isolate browsing context |
| Cross-Origin-Embedder-Policy | 3 pts | Enable cross-origin isolation |
| Cross-Origin-Resource-Policy | 2 pts | Control resource loading |

### Additional Validations

**SSL/TLS Checks:**
- Certificate expiry dates
- Signature algorithm strength
- Key size validation
- Chain verification

**RFC 9116:**
- security.txt file presence and format

### Scoring System

**Base:** 100 points from header weights

**Penalties:**
- Critical issue: -20 points
- Warning: -10 points
- Info: -5 points

## Configuration

Create `~/.hedra/config.yml`:
```yaml
# HTTP settings
timeout: 10
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

Define organization-specific policies in `~/.hedra/rules.yml`:
```yaml
rules:
  - header: "X-Custom-Security"
    type: missing
    severity: warning
    message: "Custom security header is missing"
    fix: "Add X-Custom-Security: enabled"
    
  - header: "Server"
    type: pattern
    pattern: "^(Apache|nginx)"
    severity: info
    message: "Server header exposes software version"
    fix: "Remove or obfuscate Server header"
```

**Rule Types:**
- `missing` • Header should be present
- `pattern` • Header value must match regex

**Severity Levels:**
- `critical` • -20 points, immediate action required
- `warning` • -10 points, should be addressed
- `info` • -5 points, best practice

## Plugin System

Create custom checks in `~/.hedra/plugins/`:
```ruby
# ~/.hedra/plugins/corporate_policy.rb
module Hedra
  class CorporatePolicyPlugin < Plugin
    def self.check(headers)
      findings = []
      
      # Enforce corporate header
      unless headers.key?('x-corp-security')
        findings << {
          header: 'x-corp-security',
          issue: 'Corporate security header missing',
          severity: :critical,
          recommended_fix: 'Add X-Corp-Security: v2'
        }
      end
      
      # Check version disclosure
      if headers['server']&.match?(/\d+\.\d+/)
        findings << {
          header: 'server',
          issue: 'Server version exposed',
          severity: :warning,
          recommended_fix: 'Remove version from Server header'
        }
      end
      
      findings
    end
  end
end
```

**Management:**
```bash
hedra plugin install ~/.hedra/plugins/corporate_policy.rb
hedra plugin list
hedra plugin remove corporate_policy
```

## CI/CD Integration

### GitHub Actions
```yaml
name: Security Headers Check

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Ruby
        uses: ruby/setup-ruby@v1
        with:
          ruby-version: '3.2'
      
      - name: Install Hedra
        run: gem install hedra
      
      - name: Run Security Check
        run: hedra ci_check ${{ secrets.APP_URL }} --threshold 85
      
      - name: Generate HTML Report
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
    - hedra ci_check $APP_URL --threshold 85
    - hedra scan $APP_URL --output report.json --format json
  artifacts:
    reports:
      junit: report.json
    paths:
      - report.json
  only:
    - merge_requests
    - main
```

### Jenkins Pipeline
```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Headers') {
            steps {
                sh 'gem install hedra'
                sh 'hedra ci_check ${APP_URL} --threshold 85'
            }
        }
    }
    
    post {
        always {
            sh 'hedra scan ${APP_URL} --output report.html --format html'
            publishHTML([
                reportDir: '.',
                reportFiles: 'report.html',
                reportName: 'Security Report'
            ])
        }
    }
}
```

## Export Formats

### Table (Default)
```bash
hedra scan https://github.com
```

Clean, colored terminal output with scores and recommendations.

### JSON
```bash
hedra scan https://stripe.com --output report.json --format json
```

Structured data for automation and parsing.

### CSV
```bash
hedra scan -f urls.txt --output report.csv --format csv
```

Import into spreadsheets for analysis and tracking.

### HTML
```bash
hedra scan -f urls.txt --output report.html --format html
```

Interactive report with sorting, filtering, and charts.

## Real-World Examples

### Basic Security Audit
```bash
hedra scan https://myapp.com
```

### Production Deployment Check
```bash
# Save baseline after deployment
hedra scan -f production-urls.txt --save-baseline prod-v2.1.0

# Compare before next deployment
hedra baseline compare prod-v2.1.0 -f production-urls.txt
```

### High-Volume Scanning
```bash
# Scan 1000 URLs with rate limiting and caching
hedra scan -f large-list.txt \
  --concurrency 50 \
  --rate 20/s \
  --cache \
  --output results.json \
  --format json
```

### Continuous Monitoring
```bash
# Check every hour
hedra watch https://api.myapp.com --interval 3600
```

### Environment Comparison
```bash
hedra compare https://staging.myapp.com https://myapp.com
```

### Proxy-Based Testing
```bash
# Route through Burp Suite
hedra scan https://target.com --proxy http://127.0.0.1:8080
```

### Custom User-Agent
```bash
hedra scan https://myapp.com --user-agent "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0)"
```

## Performance Tuning

### Caching Strategy
```bash
# Enable caching for repeated scans
hedra scan -f urls.txt --cache --cache-ttl 7200

# Clear cache when needed
hedra cache clear
```

### Rate Limiting
```bash
# Conservative approach
hedra scan -f urls.txt --rate 10/s --concurrency 5

# Aggressive scanning
hedra scan -f urls.txt --rate 100/s --concurrency 50
```

### Timeout Configuration
```bash
# Fast scan for responsive servers
hedra scan -f urls.txt --timeout 5

# Patient scan for slow servers
hedra scan -f urls.txt --timeout 30
```

## Development
```bash
# Clone and setup
git clone https://github.com/blackstack/hedra.git
cd hedra
bundle install

# Run tests
bundle exec rspec

# Check code style
bundle exec rubocop

# Build gem
rake build
gem install pkg/hedra-*.gem
```

## Troubleshooting

### SSL Certificate Errors
```bash
# Skip certificate validation
hedra scan https://self-signed.badssl.com --no-check-certificates
```

### Rate Limiting Issues
```bash
# Reduce load on target server
hedra scan -f urls.txt --concurrency 1 --rate 1/s
```

### Timeout Problems
```bash
# Increase timeout for slow servers
hedra scan https://slow-server.com --timeout 60
```

## Resources

**GitHub:** https://github.com/blackstack/hedra  
**RubyGems:** https://rubygems.org/gems/hedra  
**Issues:** https://github.com/blackstack/hedra/issues  
**OWASP Headers:** https://owasp.org/www-project-secure-headers/

## License

MIT License - see [LICENSE](LICENSE) for details.

---

**Built by [BlackStack](https://github.com/bl4ckstack)** • Securing the web, one header at a time.
