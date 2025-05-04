/**
 * HTML Report Generator
 * Creates an HTML report for security header scan results
 */

/**
 * Generate an HTML report from scan results
 * @param {Object} results - The scan results
 * @returns {string} - HTML report content
 */
function generateReport(results) {
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
        .info {
          color: #1976d2;
        }
        code {
          background-color: #f5f5f5;
          padding: 2px 4px;
          border-radius: 3px;
          font-family: monospace;
          word-break: break-all;
          white-space: pre-wrap;
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
      
      <h2>Summary of Findings</h2>
  `;

  // Create a summary chart or diagram if desired
  // e.g., add a list of the most critical issues

  // Group findings by status
  const missing = results.findings.filter(f => f.status === 'missing');
  const misconfigured = results.findings.filter(f => f.status === 'misconfigured');
  const dangerous = results.findings.filter(f => f.status === 'dangerous');
  const present = results.findings.filter(f => f.status === 'present');
  
  // Define criticality order for sorting (high to low)
  const criticalityOrder = {
    'high': 1,
    'medium': 2,
    'low': 3,
    'info': 4,
    undefined: 5
  };
  
  // Sort function for findings by criticality (high to low)
  const sortByCriticality = (a, b) => {
    const aValue = criticalityOrder[a.criticalRating] || 4;
    const bValue = criticalityOrder[b.criticalRating] || 4;
    return aValue - bValue;
  };

  // Missing headers section - sorted by criticality
  if (missing.length > 0) {
    // Sort missing headers by criticality (high to low)
    const sortedMissing = [...missing].sort(sortByCriticality);
    
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
    
    sortedMissing.forEach(finding => {
      html += `
        <tr class="missing">
          <td><strong>${escape(finding.header)}</strong></td>
          <td>${escape(finding.description)}</td>
          <td>${escape(finding.recommendation)}</td>
          <td class="${finding.criticalRating || 'unknown'}">${(finding.criticalRating || 'unknown').toUpperCase()}</td>
        </tr>
      `;
    });
    
    html += '</table>';
  }

  // Misconfigured headers section - sorted by criticality
  if (misconfigured.length > 0) {
    // Sort misconfigured headers by criticality (high to low)
    const sortedMisconfigured = [...misconfigured].sort(sortByCriticality);
    
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
    
    sortedMisconfigured.forEach(finding => {
      html += `
        <tr class="misconfigured">
          <td><strong>${escape(finding.header)}</strong></td>
          <td><code>${escape(finding.value)}</code></td>
          <td>${escape(finding.issue)}</td>
          <td>${escape(finding.recommendation)}</td>
          <td class="${finding.criticalRating}">${finding.criticalRating.toUpperCase()}</td>
        </tr>
      `;
    });
    
    html += '</table>';
  }

  // Dangerous headers section - sorted by criticality
  if (dangerous.length > 0) {
    // Sort dangerous headers by criticality (high to low)
    const sortedDangerous = [...dangerous].sort(sortByCriticality);
    
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
    
    sortedDangerous.forEach(finding => {
      html += `
        <tr class="dangerous">
          <td><strong>${escape(finding.header)}</strong></td>
          <td><code>${escape(finding.value)}</code></td>
          <td>${escape(finding.description)}</td>
          <td>${escape(finding.recommendation)}</td>
          <td class="${finding.criticalRating}">${finding.criticalRating.toUpperCase()}</td>
        </tr>
      `;
    });
    
    html += '</table>';
  }

  // Properly configured headers section
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
          <td><strong>${escape(finding.header)}</strong></td>
          <td><code>${escape(finding.value)}</code></td>
        </tr>
      `;
    });
    
    html += '</table>';
  }

  // Overall recommendation section
  html += '<h2>Overall Recommendation</h2>';
  if (results.score >= 90) {
    html += '<p>Excellent security header implementation! Make sure to keep them updated with industry best practices.</p>';
  } else if (results.score >= 70) {
    html += '<p>Good foundation, but there are some important headers missing or misconfigured. Address the high and medium priority findings.</p>';
  } else {
    html += '<p>Significant security header issues detected. Implement the missing headers and fix the misconfigured ones to improve your security posture.</p>';
  }

  // Add security best practices section
  html += `
    <h2>Security Headers Best Practices</h2>
    <table>
      <tr>
        <th>Header</th>
        <th>Recommended Value</th>
        <th>Purpose</th>
      </tr>
      <tr>
        <td>Strict-Transport-Security</td>
        <td><code>max-age=31536000; includeSubDomains; preload</code></td>
        <td>Enforces HTTPS connections and prevents downgrade attacks</td>
      </tr>
      <tr>
        <td>Content-Security-Policy</td>
        <td><code>default-src 'self'; script-src 'self';</code> (and more directives)</td>
        <td>Prevents XSS attacks by controlling resource loading</td>
      </tr>
      <tr>
        <td>X-Content-Type-Options</td>
        <td><code>nosniff</code></td>
        <td>Prevents MIME type sniffing attacks</td>
      </tr>
      <tr>
        <td>X-Frame-Options</td>
        <td><code>DENY</code> or <code>SAMEORIGIN</code></td>
        <td>Prevents clickjacking attacks</td>
      </tr>
      <tr>
        <td>Referrer-Policy</td>
        <td><code>strict-origin-when-cross-origin</code></td>
        <td>Controls how much referrer information is included with requests</td>
      </tr>
      <tr>
        <td>Permissions-Policy</td>
        <td><code>camera=(), microphone=(), geolocation=()</code></td>
        <td>Restricts which browser features can be used on the page</td>
      </tr>
    </table>
  `;

  // Raw headers section
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
        <td><strong>${escape(header)}</strong></td>
        <td><code>${escape(value)}</code></td>
      </tr>
    `;
  }
  
  // Close the table and add footer
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

/**
 * Escape HTML special characters to prevent XSS
 * @param {string} text - The text to escape
 * @returns {string} - Escaped text
 */
function escape(text) {
  if (!text) return '';
  
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

module.exports = {
  generateReport
};