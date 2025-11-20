# frozen_string_literal: true

require 'erb'
require 'time'

module Hedra
  # Generate HTML reports
  class HtmlReporter
    TEMPLATE = <<~HTML.freeze
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Hedra Security Report</title>
        <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #fafafa; color: #1a1a1a; line-height: 1.6; }
          .container { max-width: 900px; margin: 40px auto; padding: 0 20px; }
          .header { margin-bottom: 48px; }
          .header h1 { font-size: 28px; font-weight: 600; margin-bottom: 8px; letter-spacing: -0.5px; }
          .header .meta { color: #666; font-size: 14px; }
          .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 48px; }
          .summary-card { background: white; border: 1px solid #e5e5e5; border-radius: 6px; padding: 20px; }
          .summary-card .label { color: #666; font-size: 13px; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }
          .summary-card .value { font-size: 32px; font-weight: 600; }
          .score-a { color: #16a34a; }
          .score-b { color: #ea580c; }
          .score-c { color: #dc2626; }
          .result-item { background: white; border: 1px solid #e5e5e5; border-radius: 6px; margin-bottom: 24px; overflow: hidden; }
          .result-header { padding: 24px; border-bottom: 1px solid #e5e5e5; }
          .result-header h2 { font-size: 16px; font-weight: 500; margin-bottom: 12px; word-break: break-all; color: #1a1a1a; }
          .result-meta { display: flex; align-items: center; gap: 16px; font-size: 14px; }
          .score-badge { display: inline-flex; align-items: center; padding: 4px 12px; border-radius: 4px; font-weight: 500; font-size: 14px; }
          .score-badge.score-a { background: #dcfce7; color: #166534; }
          .score-badge.score-b { background: #fed7aa; color: #9a3412; }
          .score-badge.score-c { background: #fee2e2; color: #991b1b; }
          .timestamp { color: #666; }
          .result-body { padding: 24px; }
          .finding { padding: 16px; margin-bottom: 12px; border-radius: 4px; border-left: 3px solid; }
          .finding.critical { border-color: #dc2626; background: #fef2f2; }
          .finding.warning { border-color: #ea580c; background: #fff7ed; }
          .finding.info { border-color: #2563eb; background: #eff6ff; }
          .finding-header { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
          .severity-badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
          .severity-badge.critical { background: #dc2626; color: white; }
          .severity-badge.warning { background: #ea580c; color: white; }
          .severity-badge.info { background: #2563eb; color: white; }
          .header-name { font-family: 'Courier New', monospace; font-size: 13px; color: #666; }
          .finding-issue { font-size: 14px; margin-bottom: 8px; color: #1a1a1a; }
          .finding-fix { font-size: 13px; color: #666; padding-left: 16px; border-left: 2px solid #e5e5e5; }
          .no-findings { text-align: center; padding: 32px; color: #16a34a; font-size: 15px; }
          .footer { text-align: center; padding: 32px 0; color: #999; font-size: 13px; border-top: 1px solid #e5e5e5; margin-top: 48px; }
          .footer a { color: #666; text-decoration: none; }
          .footer a:hover { color: #1a1a1a; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Security Report</h1>
            <div class="meta"><%= Time.now.strftime('%B %d, %Y at %H:%M %Z') %></div>
          </div>

          <div class="summary">
            <div class="summary-card">
              <div class="label">URLs</div>
              <div class="value"><%= results.length %></div>
            </div>
            <div class="summary-card">
              <div class="label">Avg Score</div>
              <div class="value <%= score_class(avg_score) %>"><%= avg_score.round %></div>
            </div>
            <div class="summary-card">
              <div class="label">Findings</div>
              <div class="value"><%= total_findings %></div>
            </div>
            <div class="summary-card">
              <div class="label">Critical</div>
              <div class="value score-c"><%= critical_count %></div>
            </div>
          </div>

          <% results.each do |result| %>
            <div class="result-item">
              <div class="result-header">
                <h2><%= result[:url] %></h2>
                <div class="result-meta">
                  <span class="score-badge <%= score_class(result[:score]) %>"><%= result[:score] %>/100</span>
                  <span class="timestamp"><%= result[:timestamp] %></span>
                </div>
              </div>
              <div class="result-body">
                <% if result[:findings].empty? %>
                  <div class="no-findings">✓ All security headers properly configured</div>
                <% else %>
                  <% result[:findings].each do |finding| %>
                    <div class="finding <%= finding[:severity] %>">
                      <div class="finding-header">
                        <span class="severity-badge <%= finding[:severity] %>"><%= finding[:severity] %></span>
                        <span class="header-name"><%= finding[:header] %></span>
                      </div>
                      <div class="finding-issue"><%= finding[:issue] %></div>
                      <% if finding[:recommended_fix] %>
                        <div class="finding-fix"><%= finding[:recommended_fix] %></div>
                      <% end %>
                    </div>
                  <% end %>
                <% end %>
              </div>
            </div>
          <% end %>

          <div class="footer">
            Generated by Hedra <%= Hedra::VERSION %> · <a href="https://github.com/bl4ckstack/hedra">GitHub</a>
          </div>
        </div>
      </body>
      </html>
    HTML

    def generate(results, output_file)
      avg_score = results.sum { |r| r[:score] }.to_f / results.length
      total_findings = results.sum { |r| r[:findings].length }
      critical_count = results.sum { |r| r[:findings].count { |f| f[:severity] == :critical } }

      html = ERB.new(TEMPLATE).result(binding)
      File.write(output_file, html)
    end

    private

    def score_class(score)
      if score >= 80
        'score-a'
      elsif score >= 60
        'score-b'
      else
        'score-c'
      end
    end
  end
end
