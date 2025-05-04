/**
 * JSON Report Generator
 * Creates a JSON report for security header scan results
 */

/**
 * Generate a JSON report from scan results
 * @param {Object} results - The scan results
 * @returns {string} - JSON string of the report
 */
function generateReport(results) {
  // Create a copy of results to avoid modifying the original
  const reportData = JSON.parse(JSON.stringify(results));
  
  // Add a metadata section
  reportData.metadata = {
    reportVersion: '1.0',
    generatedAt: new Date().toISOString(),
    scannerVersion: '1.0.0'
  };
  
  // Add a summary section
  reportData.summary = {
    totalHeaders: Object.keys(reportData.headers).length,
    missingHeaders: reportData.findings.filter(f => f.status === 'missing').length,
    misconfiguredHeaders: reportData.findings.filter(f => f.status === 'misconfigured').length,
    dangerousHeaders: reportData.findings.filter(f => f.status === 'dangerous').length,
    presentHeaders: reportData.findings.filter(f => f.status === 'present').length
  };
  
  // Define criticality order for sorting
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
  
  // Group findings by criticality
  reportData.criticalFindings = {
    high: reportData.findings.filter(f => f.criticalRating === 'high').sort(sortByCriticality),
    medium: reportData.findings.filter(f => f.criticalRating === 'medium').sort(sortByCriticality),
    low: reportData.findings.filter(f => f.criticalRating === 'low').sort(sortByCriticality),
    info: reportData.findings.filter(f => f.criticalRating === 'info').sort(sortByCriticality)
  };
  
  // Sort findings lists by criticality
  if (reportData.findings) {
    // First sort the main findings array
    reportData.findings.sort(sortByCriticality);
    
    // Also sort any filtered findings arrays
    const findingTypes = ['missing', 'misconfigured', 'dangerous', 'present'];
    findingTypes.forEach(type => {
      const typeFindings = reportData.findings.filter(f => f.status === type);
      if (typeFindings.length > 0) {
        reportData[`${type}Findings`] = typeFindings.sort(sortByCriticality);
      }
    });
  }
  
  // Add recommendations section
  reportData.recommendations = generateRecommendations(reportData);
  
  // Return pretty-printed JSON
  return JSON.stringify(reportData, null, 2);
}

/**
 * Generate recommendations based on scan results
 * @param {Object} results - The scan results
 * @returns {Object} - Recommendations object
 */
function generateRecommendations(results) {
  const recommendations = {
    critical: [],
    important: [],
    recommended: [],
    optional: []
  };
  
  // Extract recommendations from findings
  results.findings.forEach(finding => {
    if (finding.status === 'missing' || finding.status === 'misconfigured' || finding.status === 'dangerous') {
      let recommendation = {
        header: finding.header,
        description: finding.description || '',
        action: finding.recommendation || '',
        implementation: getImplementationExample(finding.header)
      };
      
      // Add to appropriate priority list based on critical rating
      switch (finding.criticalRating) {
        case 'high':
          recommendations.critical.push(recommendation);
          break;
        case 'medium':
          recommendations.important.push(recommendation);
          break;
        case 'low':
          recommendations.recommended.push(recommendation);
          break;
        default:
          recommendations.optional.push(recommendation);
      }
    }
  });
  
  return recommendations;
}

/**
 * Get implementation example for a given header
 * @param {string} header - The header name
 * @returns {string} - Example implementation
 */
function getImplementationExample(header) {
  const headerName = header.toLowerCase();
  
  // Examples for common headers
  const examples = {
    'strict-transport-security (hsts)': 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    'content-security-policy (csp)': "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'self'",
    'x-content-type-options': 'X-Content-Type-Options: nosniff',
    'x-frame-options': 'X-Frame-Options: DENY',
    'x-xss-protection': 'X-XSS-Protection: 1; mode=block',
    'referrer-policy': 'Referrer-Policy: strict-origin-when-cross-origin',
    'permissions-policy': 'Permissions-Policy: camera=(), microphone=(), geolocation=()',
    'cache-control': 'Cache-Control: no-store, max-age=0, must-revalidate',
    'clear-site-data': 'Clear-Site-Data: "cache", "cookies", "storage"',
    'cross-origin-embedder-policy': 'Cross-Origin-Embedder-Policy: require-corp',
    'cross-origin-opener-policy': 'Cross-Origin-Opener-Policy: same-origin',
    'cross-origin-resource-policy': 'Cross-Origin-Resource-Policy: same-origin',
    'expect-ct': 'Expect-CT: max-age=86400, enforce',
    'nel': '{"report_to": "default", "max_age": 31536000, "include_subdomains": true}',
    'report-to': '{"group": "default", "max_age": 31536000, "endpoints": [{"url": "https://example.com/reports"}]}'
  };
  
  // Normalize header name to match examples
  const normalizedHeader = headerName.toLowerCase();
  
  // Return example or generic message
  for (const [exampleHeader, example] of Object.entries(examples)) {
    if (normalizedHeader.includes(exampleHeader.toLowerCase())) {
      return example;
    }
  }
  
  return 'Implementation depends on specific requirements';
}

module.exports = {
  generateReport
};