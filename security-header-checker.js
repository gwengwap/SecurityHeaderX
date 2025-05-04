// Web Security Header Checker
// A tool to analyze HTTP security headers of a website

const axios = require('axios');

// Import chalk using ESM syntax for v5+
const chalk = require('chalk');

class SecurityHeaderChecker {
  constructor(options = {}) {
    this.timeout = options.timeout || 10000; // 10 seconds default timeout
    this.userAgent = options.userAgent || 'SecurityHeaderChecker/1.0';
    this.verbose = options.verbose || false;
    
    // Define security headers to check with their descriptions and recommendations
    this.securityHeaders = {
      'strict-transport-security': {
        name: 'Strict-Transport-Security (HSTS)',
        description: 'Forces browsers to use HTTPS for the domain',
        recommendation: 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" header',
        criticalRating: 'high'
      },
      'content-security-policy': {
        name: 'Content-Security-Policy (CSP)',
        description: 'Controls resources the browser is allowed to load',
        recommendation: 'Implement a strict CSP policy to prevent XSS attacks',
        criticalRating: 'high'
      },
      'x-content-type-options': {
        name: 'X-Content-Type-Options',
        description: 'Prevents MIME-sniffing attacks',
        recommendation: 'Add "X-Content-Type-Options: nosniff" header',
        criticalRating: 'medium'
      },
      'x-frame-options': {
        name: 'X-Frame-Options',
        description: 'Prevents clickjacking attacks',
        recommendation: 'Add "X-Frame-Options: DENY" or "X-Frame-Options: SAMEORIGIN" header',
        criticalRating: 'medium'
      },
      'x-xss-protection': {
        name: 'X-XSS-Protection',
        description: 'Enables XSS filtering in browsers',
        recommendation: 'Add "X-XSS-Protection: 1; mode=block" header',
        criticalRating: 'low'
      },
      'referrer-policy': {
        name: 'Referrer-Policy',
        description: 'Controls how much referrer information should be included with requests',
        recommendation: 'Add "Referrer-Policy: strict-origin-when-cross-origin" header',
        criticalRating: 'low'
      },
      'permissions-policy': {
        name: 'Permissions-Policy',
        description: 'Controls which browser features can be used on the page',
        recommendation: 'Implement a Permissions-Policy to restrict unnecessary browser features',
        criticalRating: 'low'
      },
      'cache-control': {
        name: 'Cache-Control',
        description: 'Controls how pages are cached by browsers and proxies',
        recommendation: 'For sensitive pages, add "Cache-Control: no-store, max-age=0" header',
        criticalRating: 'low'
      },
      'clear-site-data': {
        name: 'Clear-Site-Data',
        description: 'Clears browsing data (cookies, storage, cache) associated with the site',
        recommendation: 'Consider using this header for logout pages',
        criticalRating: 'info'
      },
      'cross-origin-embedder-policy': {
        name: 'Cross-Origin-Embedder-Policy',
        description: 'Controls which cross-origin resources can be loaded',
        recommendation: 'Add "Cross-Origin-Embedder-Policy: require-corp" header for isolation',
        criticalRating: 'low'
      },
      'cross-origin-opener-policy': {
        name: 'Cross-Origin-Opener-Policy',
        description: 'Controls sharing browsing context with cross-origin documents',
        recommendation: 'Add "Cross-Origin-Opener-Policy: same-origin" header for isolation',
        criticalRating: 'low'
      },
      'cross-origin-resource-policy': {
        name: 'Cross-Origin-Resource-Policy',
        description: 'Controls which origins can load the resource',
        recommendation: 'Add "Cross-Origin-Resource-Policy: same-origin" header',
        criticalRating: 'low'
      }
    };
  }

  /**
   * Check security headers for a given URL
   * @param {string} url - The URL to check
   * @returns {Promise<Object>} - The scan results
   */
  async checkUrl(url) {
    if (!url.startsWith('http')) {
      url = 'https://' + url;
    }

    console.log(`\n🔍 Checking security headers for: ${url}`);
    
    try {
      const response = await axios({
        method: 'GET',
        url: url,
        timeout: this.timeout,
        headers: {
          'User-Agent': this.userAgent
        },
        maxRedirects: 5,
        validateStatus: function (status) {
          return status >= 200 && status < 600; // Accept all status codes to analyze headers
        }
      });

      return this.analyzeHeaders(url, response.headers, response.status);
    } catch (error) {
      console.error(`❌ Error accessing ${url}: ${error.message}`);
      return {
        url,
        status: 'error',
        errorMessage: error.message,
        timestamp: new Date().toISOString(),
        headers: {},
        findings: [],
        score: 0
      };
    }
  }

  /**
   * Analyze the security headers from the response
   * @param {string} url - The URL that was checked
   * @param {Object} headers - The response headers
   * @param {number} statusCode - The HTTP status code
   * @returns {Object} - The analysis results
   */
  analyzeHeaders(url, headers, statusCode) {
    // Convert header names to lowercase for case-insensitive comparison
    const normalizedHeaders = {};
    for (const [key, value] of Object.entries(headers)) {
      normalizedHeaders[key.toLowerCase()] = value;
    }

    const findings = [];
    let score = 100; // Start with perfect score and deduct

    // Check for presence and configuration of security headers
    for (const [header, info] of Object.entries(this.securityHeaders)) {
      if (!normalizedHeaders[header]) {
        // Header is missing
        findings.push({
          header: info.name,
          status: 'missing',
          description: info.description,
          recommendation: info.recommendation,
          criticalRating: info.criticalRating
        });

        // Deduct from score based on critical rating
        switch(info.criticalRating) {
          case 'high':
            score -= 15;
            break;
          case 'medium':
            score -= 10;
            break;
          case 'low':
            score -= 5;
            break;
          default:
            score -= 2;
        }
      } else {
        // Header is present, now check for proper configuration
        const configIssue = this.checkHeaderConfiguration(header, normalizedHeaders[header]);
        
        if (configIssue) {
          findings.push({
            header: info.name,
            status: 'misconfigured',
            value: normalizedHeaders[header],
            issue: configIssue.issue,
            recommendation: configIssue.recommendation,
            criticalRating: configIssue.criticalRating
          });
          
          // Deduct from score based on critical rating
          switch(configIssue.criticalRating) {
            case 'high':
              score -= 10;
              break;
            case 'medium':
              score -= 5;
              break;
            case 'low':
              score -= 2;
              break;
            default:
              score -= 1;
          }
        } else {
          findings.push({
            header: info.name,
            status: 'present',
            value: normalizedHeaders[header],
            criticalRating: info.criticalRating
          });
        }
      }
    }

    // Also check for potentially dangerous headers
    this.checkDangerousHeaders(normalizedHeaders, findings);

    // Ensure score is between 0 and 100
    score = Math.max(0, Math.min(100, score));

    return {
      url,
      statusCode,
      timestamp: new Date().toISOString(),
      headers: normalizedHeaders,
      findings,
      score: Math.round(score),
      grade: this.calculateGrade(score)
    };
  }

  /**
   * Check for specific header misconfiguration issues
   * @param {string} header - The header name
   * @param {string} value - The header value
   * @returns {Object|null} - Configuration issue or null if properly configured
   */
  checkHeaderConfiguration(header, value) {
    switch(header) {
      case 'strict-transport-security':
        if (!value.includes('max-age=')) {
          return {
            issue: 'HSTS header missing max-age directive',
            recommendation: 'Add max-age directive with a value of at least 31536000 (1 year)',
            criticalRating: 'high'
          };
        } else {
          const maxAgeMatch = value.match(/max-age=(\d+)/);
          if (maxAgeMatch && parseInt(maxAgeMatch[1]) < 31536000) {
            return {
              issue: 'HSTS max-age is less than 1 year',
              recommendation: 'Increase max-age to at least 31536000 (1 year)',
              criticalRating: 'medium'
            };
          }
          if (!value.includes('includeSubDomains')) {
            return {
              issue: 'HSTS missing includeSubDomains directive',
              recommendation: 'Add includeSubDomains directive to protect all subdomains',
              criticalRating: 'low'
            };
          }
        }
        break;
        
      case 'content-security-policy':
        if (value.includes("'unsafe-inline'") || value.includes("'unsafe-eval'")) {
          return {
            issue: 'CSP contains unsafe directives',
            recommendation: 'Remove unsafe-inline and unsafe-eval directives, use nonces or hashes instead',
            criticalRating: 'high'
          };
        }
        if (value.includes('*') && !value.includes('font-src') && !value.includes('img-src')) {
          return {
            issue: 'CSP contains wildcards',
            recommendation: 'Avoid using wildcards in CSP directives',
            criticalRating: 'medium'
          };
        }
        break;
        
      case 'x-frame-options':
        if (value.toUpperCase() !== 'DENY' && value.toUpperCase() !== 'SAMEORIGIN') {
          return {
            issue: 'X-Frame-Options has invalid value',
            recommendation: 'Use either DENY or SAMEORIGIN values',
            criticalRating: 'medium'
          };
        }
        break;
        
      case 'x-xss-protection':
        if (!value.includes('1')) {
          return {
            issue: 'XSS Protection is disabled',
            recommendation: 'Set value to "1; mode=block"',
            criticalRating: 'medium'
          };
        }
        if (!value.includes('mode=block')) {
          return {
            issue: 'XSS Protection is enabled but not in blocking mode',
            recommendation: 'Add mode=block directive',
            criticalRating: 'low'
          };
        }
        break;
        
      case 'referrer-policy':
        const weakReferrerPolicies = [
          'unsafe-url', 
          'no-referrer-when-downgrade'
        ];
        
        for (const weakPolicy of weakReferrerPolicies) {
          if (value.includes(weakPolicy)) {
            return {
              issue: `Referrer-Policy contains weak policy: ${weakPolicy}`,
              recommendation: 'Use stricter policies like strict-origin-when-cross-origin',
              criticalRating: 'low'
            };
          }
        }
        break;
    }
    
    return null; // No issues found
  }

  /**
   * Check for headers that could expose sensitive information
   * @param {Object} headers - The normalized headers
   * @param {Array} findings - The findings array to add results to
   */
  checkDangerousHeaders(headers, findings) {
    const dangerousHeaders = {
      'server': {
        name: 'Server',
        description: 'Reveals server software version',
        recommendation: 'Remove or sanitize the Server header to hide implementation details',
        criticalRating: 'low'
      },
      'x-powered-by': {
        name: 'X-Powered-By',
        description: 'Reveals technology stack information',
        recommendation: 'Remove the X-Powered-By header to hide implementation details',
        criticalRating: 'low'
      },
      'x-aspnet-version': {
        name: 'X-AspNet-Version',
        description: 'Reveals ASP.NET version',
        recommendation: 'Remove the X-AspNet-Version header',
        criticalRating: 'medium'
      },
      'x-aspnetmvc-version': {
        name: 'X-AspNetMvc-Version',
        description: 'Reveals ASP.NET MVC version',
        recommendation: 'Remove the X-AspNetMvc-Version header',
        criticalRating: 'medium'
      }
    };

    for (const [header, info] of Object.entries(dangerousHeaders)) {
      if (headers[header]) {
        findings.push({
          header: info.name,
          status: 'dangerous',
          value: headers[header],
          description: info.description,
          recommendation: info.recommendation,
          criticalRating: info.criticalRating
        });
      }
    }
  }

  /**
   * Calculate a letter grade based on the score
   * @param {number} score - The security score
   * @returns {string} - The letter grade
   */
  calculateGrade(score) {
    if (score >= 90) return 'A';
    if (score >= 80) return 'B';
    if (score >= 70) return 'C';
    if (score >= 60) return 'D';
    if (score >= 50) return 'E';
    return 'F';
  }

  /**
   * Print the scan results to the console in a readable format
   * @param {Object} results - The scan results
   */
  printResults(results) {
    console.log('\n📊 SECURITY HEADER SCAN RESULTS');
    console.log('-'.repeat(50));
    console.log(`URL: ${results.url}`);
    console.log(`Status: ${results.statusCode}`);
    console.log(`Score: ${results.score}/100 (Grade ${results.grade})`);
    console.log(`Scan Time: ${new Date(results.timestamp).toLocaleString()}`);
    console.log('-'.repeat(50));
    
    console.log('\n📋 FINDINGS SUMMARY');
    
    // Group findings by status
    const missing = results.findings.filter(f => f.status === 'missing');
    const misconfigured = results.findings.filter(f => f.status === 'misconfigured');
    const dangerous = results.findings.filter(f => f.status === 'dangerous');
    const present = results.findings.filter(f => f.status === 'present');
    
    // Print missing headers
    if (missing.length > 0) {
      console.log('\n❌ MISSING HEADERS');
      missing.forEach(finding => {
        console.log(`  ${finding.header}`);
        console.log(`    Description: ${finding.description}`);
        console.log(`    Recommendation: ${finding.recommendation}`);
        console.log(`    Critical Rating: ${finding.criticalRating.toUpperCase()}`);
      });
    }
    
    // Print misconfigured headers
    if (misconfigured.length > 0) {
      console.log('\n⚠️ MISCONFIGURED HEADERS');
      misconfigured.forEach(finding => {
        console.log(`  ${finding.header}`);
        console.log(`    Current Value: ${finding.value}`);
        console.log(`    Issue: ${finding.issue}`);
        console.log(`    Recommendation: ${finding.recommendation}`);
        console.log(`    Critical Rating: ${finding.criticalRating.toUpperCase()}`);
      });
    }
    
    // Print dangerous headers
    if (dangerous.length > 0) {
      console.log('\n🚨 INFORMATION DISCLOSURE HEADERS');
      dangerous.forEach(finding => {
        console.log(`  ${finding.header}`);
        console.log(`    Current Value: ${finding.value}`);
        console.log(`    Description: ${finding.description}`);
        console.log(`    Recommendation: ${finding.recommendation}`);
        console.log(`    Critical Rating: ${finding.criticalRating.toUpperCase()}`);
      });
    }
    
    // Print properly configured headers
    if (present.length > 0) {
      console.log('\n✅ PROPERLY CONFIGURED HEADERS');
      present.forEach(finding => {
        console.log(`  ${finding.header}`);
        console.log(`    Value: ${finding.value}`);
      });
    }
    
    // Print overall recommendation
    console.log('\n📝 OVERALL RECOMMENDATION');
    if (results.score >= 90) {
      console.log('Excellent security header implementation! Make sure to keep them updated with industry best practices.');
    } else if (results.score >= 70) {
      console.log('Good foundation, but there are some important headers missing or misconfigured. Address the high and medium priority findings.');
    } else {
      console.log('Significant security header issues detected. Implement the missing headers and fix the misconfigured ones to improve your security posture.');
    }
  }

  /**
   * Generate a JSON report of the scan results
   * @param {Object} results - The scan results
   * @returns {string} - JSON string of the report
   */
  generateJSONReport(results) {
    return JSON.stringify(results, null, 2);
  }

  /**
   * Generate an HTML report of the scan results
   * @param {Object} results - The scan results
   * @returns {string} - HTML report
   */
  generateHTMLReport(results) {
    let scoreColor;
    if (results.score >= 80) scoreColor = 'green';
    else if (results.score >= 60) scoreColor = 'orange';
    else scoreColor = 'red';

    let html = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Header Scan Results - ${results.url}</title>
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1100px;
            margin: 0 auto;
            padding: 20px;
          }
          h1, h2, h3 {
            color: #2c3e50;
          }
          .summary {
            background-color: #f8f9fa;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
          }
          .score {
            font-size: 24px;
            font-weight: bold;
            color: ${scoreColor};
          }
          .grade {
            font-size: 36px;
            font-weight: bold;
            color: ${scoreColor};
          }
          table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
          }
          th, td {
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid #ddd;
          }
          th {
            background-color: #f2f2f2;
          }
          .missing {
            background-color: #ffebee;
          }
          .misconfigured {
            background-color: #fff8e1;
          }
          .dangerous {
            background-color: #fff8e1;
          }
          .present {
            background-color: #e8f5e9;
          }
          .high {
            color: #d32f2f;
            font-weight: bold;
          }
          .medium {
            color: #f57c00;
            font-weight: bold;
          }
          .low {
            color: #388e3c;
          }
        </style>
      </head>
      <body>
        <h1>Security Header Scan Results</h1>
        
        <div class="summary">
          <p><strong>URL:</strong> ${results.url}</p>
          <p><strong>Status Code:</strong> ${results.statusCode}</p>
          <p><strong>Scan Time:</strong> ${new Date(results.timestamp).toLocaleString()}</p>
          <p><strong>Score:</strong> <span class="score">${results.score}/100</span></p>
          <p><strong>Grade:</strong> <span class="grade">${results.grade}</span></p>
        </div>
        
        <h2>Findings</h2>
    `;

    // Missing headers
    const missing = results.findings.filter(f => f.status === 'missing');
    if (missing.length > 0) {
      html += `
        <h3>Missing Headers (${missing.length})</h3>
        <table>
          <tr>
            <th>Header</th>
            <th>Description</th>
            <th>Recommendation</th>
            <th>Severity</th>
          </tr>
      `;
      
      missing.forEach(finding => {
        html += `
          <tr class="missing">
            <td><strong>${finding.header}</strong></td>
            <td>${finding.description}</td>
            <td>${finding.recommendation}</td>
            <td class="${finding.criticalRating}">${finding.criticalRating.toUpperCase()}</td>
          </tr>
        `;
      });
      
      html += '</table>';
    }

    // Misconfigured headers
    const misconfigured = results.findings.filter(f => f.status === 'misconfigured');
    if (misconfigured.length > 0) {
      html += `
        <h3>Misconfigured Headers (${misconfigured.length})</h3>
        <table>
          <tr>
            <th>Header</th>
            <th>Current Value</th>
            <th>Issue</th>
            <th>Recommendation</th>
            <th>Severity</th>
          </tr>
      `;
      
      misconfigured.forEach(finding => {
        html += `
          <tr class="misconfigured">
            <td><strong>${finding.header}</strong></td>
            <td><code>${finding.value}</code></td>
            <td>${finding.issue}</td>
            <td>${finding.recommendation}</td>
            <td class="${finding.criticalRating}">${finding.criticalRating.toUpperCase()}</td>
          </tr>
        `;
      });
      
      html += '</table>';
    }

    // Dangerous headers
    const dangerous = results.findings.filter(f => f.status === 'dangerous');
    if (dangerous.length > 0) {
      html += `
        <h3>Information Disclosure Headers (${dangerous.length})</h3>
        <table>
          <tr>
            <th>Header</th>
            <th>Current Value</th>
            <th>Description</th>
            <th>Recommendation</th>
            <th>Severity</th>
          </tr>
      `;
      
      dangerous.forEach(finding => {
        html += `
          <tr class="dangerous">
            <td><strong>${finding.header}</strong></td>
            <td><code>${finding.value}</code></td>
            <td>${finding.description}</td>
            <td>${finding.recommendation}</td>
            <td class="${finding.criticalRating}">${finding.criticalRating.toUpperCase()}</td>
          </tr>
        `;
      });
      
      html += '</table>';
    }

    // Properly configured headers
    const present = results.findings.filter(f => f.status === 'present');
    if (present.length > 0) {
      html += `
        <h3>Properly Configured Headers (${present.length})</h3>
        <table>
          <tr>
            <th>Header</th>
            <th>Value</th>
          </tr>
      `;
      
      present.forEach(finding => {
        html += `
          <tr class="present">
            <td><strong>${finding.header}</strong></td>
            <td><code>${finding.value}</code></td>
          </tr>
        `;
      });
      
      html += '</table>';
    }

    // Overall recommendation
    html += '<h2>Overall Recommendation</h2>';
    if (results.score >= 90) {
      html += '<p>Excellent security header implementation! Make sure to keep them updated with industry best practices.</p>';
    } else if (results.score >= 70) {
      html += '<p>Good foundation, but there are some important headers missing or misconfigured. Address the high and medium priority findings.</p>';
    } else {
      html += '<p>Significant security header issues detected. Implement the missing headers and fix the misconfigured ones to improve your security posture.</p>';
    }

    // Raw headers
    html += `
        <h2>All Response Headers</h2>
        <table>
          <tr>
            <th>Header</th>
            <th>Value</th>
          </tr>
    `;
    
    for (const [header, value] of Object.entries(results.headers)) {
      html += `
        <tr>
          <td><strong>${header}</strong></td>
          <td><code>${value}</code></td>
        </tr>
      `;
    }
    
    html += `
        </table>
        
        <footer>
          <p>Generated by Security Header Checker on ${new Date().toLocaleString()}</p>
        </footer>
      </body>
      </html>
    `;

    return html;
  }
}

// Example usage
async function main() {
  // URL to scan
  const url = process.argv[2] || 'https://example.com';
  
  // Create scanner instance
  const checker = new SecurityHeaderChecker({
    verbose: true
  });
  
  // Run the scan
  const results = await checker.checkUrl(url);
  
  // Print results to console
  checker.printResults(results);
  
  // Save HTML report
  const fs = require('fs');
  const htmlReport = checker.generateHTMLReport(results);
  const reportFileName = `header_scan_${new Date().toISOString().replace(/:/g, '-')}.html`;
  
  fs.writeFileSync(reportFileName, htmlReport);
  console.log(`\n📄 HTML report saved to ${reportFileName}`);
  
  // Save JSON report
  const jsonReport = checker.generateJSONReport(results);
  const jsonFileName = `header_scan_${new Date().toISOString().replace(/:/g, '-')}.json`;
  
  fs.writeFileSync(jsonFileName, jsonReport);
  console.log(`📄 JSON report saved to ${jsonFileName}`);
}

// Run the scanner if this script is executed directly
if (require.main === module) {
  if (process.argv.length < 3) {
    console.log('Usage: node security-header-checker.js <url>');
    console.log('Example: node security-header-checker.js https://example.com');
  } else {
    main().catch(error => {
      console.error('Error running scanner:', error);
    });
  }
}

module.exports = SecurityHeaderChecker;