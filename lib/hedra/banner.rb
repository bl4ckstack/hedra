# frozen_string_literal: true

module Hedra
  # Display banner and security quotes
  class Banner
    SECURITY_QUOTES = [
      "Security is not a product, but a process. - Bruce Schneier",
      "The only truly secure system is one that is powered off. - Gene Spafford",
      "HTTPS everywhere is not optional, it's essential. - Let's Encrypt",
      "A chain is only as strong as its weakest link. - Security Headers",
      "Defense in depth: Layer your security like an onion. - OWASP",
      "CSP is your first line of defense against XSS attacks.",
      "HSTS ensures your users always connect securely.",
      "Security headers are the low-hanging fruit of web security.",
      "TLS 1.3: Faster, stronger, more secure.",
      "X-Frame-Options: Because clickjacking is still a thing.",
      "Trust, but verify. Then verify again. - Security Principle",
      "Security is a journey, not a destination.",
      "Good security is invisible until it's needed.",
      "Headers don't lie, but they can tell you everything.",
      "CORS: Sharing is caring, but be careful who you trust.",
      "Every header matters. Every connection counts.",
      "Secure by default, not by accident.",
      "Your security posture is only as good as your weakest header.",
      "SSL/TLS: The foundation of web security.",
      "Content-Security-Policy: Your app's security bouncer."
    ].freeze

    ASCII_ART = <<~ART
       _   _          _           
      | | | | ___  __| |_ __ __ _ 
      | |_| |/ _ \\/ _` | '__/ _` |
      |  _  |  __/ (_| | | | (_| |
      |_| |_|\\___|\\__,_|_|  \\__,_|
    ART

    def self.show
      require 'pastel'
      pastel = Pastel.new

      puts "\n"
      puts pastel.cyan.bold(ASCII_ART)
      puts "  #{pastel.bold('Security Header Analyzer')} #{pastel.dim("v#{VERSION}")}"
      puts "  #{pastel.italic.dim(random_quote)}"
      puts "\n"
      puts "  Usage: #{pastel.yellow('hedra')} #{pastel.green('[command]')} #{pastel.dim('[options]')}"
      puts "  Run '#{pastel.yellow('hedra help')}' for more information"
      puts "\n"
    end

    def self.random_quote
      SECURITY_QUOTES.sample
    end
  end
end
