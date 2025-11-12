# Hedra 🛡️

A comprehensive security header analyzer for modern web applications. Scan, audit, and monitor HTTP security headers with ease.

```
 _   _          _           
| | | | ___  __| |_ __ __ _ 
| |_| |/ _ \/ _` | '__/ _` |
|  _  |  __/ (_| | | | (_| |
|_| |_|\___|\__,_|_|  \__,_|
                             
Security Header Analyzer
```

## Features

- 🔍 **Comprehensive Scanning** - Analyze security headers for single or multiple URLs
- 🎯 **Deep Auditing** - Detailed security header analysis with recommendations
- 👁️ **Continuous Monitoring** - Watch URLs for header changes over time
- 📊 **Multiple Output Formats** - Table, JSON, and CSV export options
- 🔌 **Plugin Architecture** - Extend with custom header checks
- ⚡ **Concurrent Scanning** - Fast parallel URL scanning with configurable concurrency
- 🌐 **Proxy Support** - HTTP and SOCKS proxy compatibility
- 🎨 **Beautiful CLI** - Color-coded output with severity badges
- 📈 **Security Scoring** - 0-100 score based on header coverage

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/hedra/hedra.git
cd hedra

# Install dependencies
bundle install

# Build the gem
rake build

# Install the gem
gem install pkg/hedra-1.0.0.gem
```

### Quick Start

```bash
bundle install
chmod +x bin/hedra
bin/hedra --help
```

## Usage

### Basic Scanning

Scan a single URL:
```bash
hedra scan https://example.com
```

Scan multiple URLs from a file:
```bash
hedra scan -f urls.txt
```

### Deep Audit

Perform detailed security analysis:
```bash
hedra audit https://example.com
```

Export audit results as JSON:
```bash
hedra audit https://example.com --json --output result.json
```

### Advanced Scanning

Concurrent scanning with custom settings:
```bash
hedra scan -f urls.txt --concurrency 20 --timeout 15
```

Scan through a proxy:
```bash
hedra scan https://example.com --proxy http://127.0.0.1:8080
```

Custom User-Agent and follow redirects:
```bash
hedra scan https://example.com --user-agent "MyBot/1.0" --follow-redirects
```

### Continuous Monitoring

Watch a URL and check every hour:
```bash
hedra watch https://example.com --interval 3600
```

### Compare Headers

Compare security headers between two URLs:
```bash
hedra compare https://staging.example.com https://prod.example.com
```

### Export Results

Export scan results:
```bash
hedra scan -f urls.txt --output results.csv --format csv
```

### Plugin Management

List installed plugins:
```bash
hedra plugin list
```

Install a custom plugin:
```bash
hedra plugin install path/to/plugin.rb
```

Remove a plugin:
```bash
hedra plugin remove my_plugin
```

## Security Headers Checked

Hedra analyzes the following security headers:

### Critical Headers
- **Content-Security-Policy (CSP)** - Prevents XSS and injection attacks
- **Strict-Transport-Security (HSTS)** - Enforces HTTPS connections

### Important Headers
- **X-Frame-Options** - Prevents clickjacking attacks
- **X-Content-Type-Options** - Prevents MIME-sniffing attacks

### Recommended Headers
- **Referrer-Policy** - Controls referrer information
- **Permissions-Policy** - Controls browser features
- **Cross-Origin-Opener-Policy (COOP)** - Isolates browsing context
- **Cross-Origin-Embedder-Policy (COEP)** - Controls resource embedding
- **Cross-Origin-Resource-Policy (CORP)** - Controls resource sharing

## Configuration

Create a config file at `~/.hedra/config.yml`:

```yaml
timeout: 10
concurrency: 10
follow_redirects: false
user_agent: "Hedra/1.0.0"
output_format: table
```

### Custom Rules

Add custom header checks in `~/.hedra/rules.yml`:

```yaml
rules:
  - header: "X-Custom-Security"
    type: missing
    severity: warning
    message: "Custom security header is missing"
    fix: "Add X-Custom-Security header"
  
  - header: "Server"
    type: pattern
    pattern: "(Apache|nginx|IIS)"
    severity: info
    message: "Server header exposes server software"
    fix: "Remove or obfuscate Server header"
```

## Plugin Development

Create custom plugins to extend Hedra's functionality:

```ruby
# ~/.hedra/plugins/my_plugin.rb
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

## Output Examples

### Table Output
```
https://example.com
Score: 75/100
Timestamp: 2025-11-12T10:30:00Z

┌─────────────────────────────┬──────────────────────────────┬──────────┐
│ Header                      │ Issue                        │ Severity │
├─────────────────────────────┼──────────────────────────────┼──────────┤
│ permissions-policy          │ Header is missing            │ ● INFO   │
│ cross-origin-opener-policy  │ Header is missing            │ ● INFO   │
└─────────────────────────────┴──────────────────────────────┴──────────┘
```

### JSON Output
```json
{
  "url": "https://example.com",
  "timestamp": "2025-11-12T10:30:00Z",
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
  ],
  "score": 75
}
```

## Development

### Running Tests

```bash
# Run all tests
bundle exec rspec

# Run with coverage
bundle exec rspec --format documentation

# Run specific test file
bundle exec rspec spec/hedra/analyzer_spec.rb
```

### Linting

```bash
# Run RuboCop
bundle exec rubocop

# Auto-fix issues
bundle exec rubocop -a
```

### Building

```bash
# Build gem
rake build

# Install locally
gem install pkg/hedra-1.0.0.gem
```

## CI/CD

Hedra includes GitHub Actions CI configuration that:
- Runs tests on Ruby 3.0, 3.1, and 3.2
- Executes RuboCop linting
- Builds the gem package

## Architecture

### Core Components

- **CLI** - Thor-based command-line interface with subcommands
- **Analyzer** - Core logic for header analysis and validation
- **HttpClient** - HTTP wrapper with retry logic, proxy support, and TLS verification
- **Scorer** - Calculates security scores based on header coverage
- **PluginManager** - Discovers and executes custom plugins
- **Exporter** - Handles JSON and CSV output formats

### Design Decisions

1. **Modular Architecture** - Each header check is isolated, making it easy to add new checks
2. **Secure Defaults** - TLS verification on, no redirect following, conservative timeouts
3. **Thread-Safe Concurrency** - Uses Ruby's concurrent-ruby gem for safe parallel scanning
4. **Extensible Plugin System** - Simple base class for custom header checks
5. **Comprehensive Testing** - WebMock stubs prevent live network calls in tests

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

## Support

- 📖 Documentation: [GitHub Wiki](https://github.com/hedra/hedra/wiki)
- 🐛 Issues: [GitHub Issues](https://github.com/hedra/hedra/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/hedra/hedra/discussions)

## Acknowledgments

Built with:
- [Thor](https://github.com/rails/thor) - CLI framework
- [HTTP.rb](https://github.com/httprb/http) - HTTP client
- [TTY::Table](https://github.com/piotrmurach/tty-table) - Terminal tables
- [Pastel](https://github.com/piotrmurach/pastel) - Terminal colors
- [RSpec](https://rspec.info/) - Testing framework

---

Made with ❤️ by the Hedra Team
