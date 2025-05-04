/**
 * Updated central configuration for the Security Header Checker
 */

const config = {
  // HTTP client defaults
  defaultUserAgent: 'SecurityHeaderChecker/1.0',
  defaultTimeout: 10000, 
  defaultMaxRedirects: 5,
  
  // Essential header weights (out of 100 total points)
  essentialHeaderWeights: {
    'strict-transport-security': 15,     // HSTS is critical
    'content-security-policy': 15,       // CSP is critical
    'x-content-type-options': 10,        // Prevents MIME-sniffing
    'x-frame-options': 10,               // Prevents clickjacking
    'referrer-policy': 8,                // Controls referrer leakage
    'permissions-policy': 7,             // Restricts browser features
    'x-xss-protection': 5,               // Basic XSS protection
    'cache-control': 5,                  // Prevents sensitive data caching
  },
  
  // Advanced headers (out of 25 total points)
  advancedHeaderWeights: {
    'expect-ct': 5,                      // Certificate Transparency
    'cross-origin-embedder-policy': 4,   // Resource isolation
    'cross-origin-opener-policy': 4,     // Context isolation
    'cross-origin-resource-policy': 4,   // Resource access control
    'report-to': 2,                      // Error reporting
    'nel': 2,                            // Network error logging
    'clear-site-data': 2,                // Data clearing
    'server-timing': 2,                  // Performance metrics
  },
  
  // CORS headers (out of 15 total points)
  corsHeaderWeights: {
    'access-control-allow-origin': 5,      // Core CORS mechanism
    'access-control-allow-credentials': 4, // Authentication handling
    'access-control-allow-methods': 2,     // HTTP method control
    'access-control-allow-headers': 2,     // Header control
    'access-control-expose-headers': 1,    // Header exposure
    'access-control-max-age': 1,           // Preflight caching
  },
  
  // Misconfiguration penalty multipliers (applied to the above weights)
  misconfigurationPenalties: {
    high: 0.8,    // Lose 80% of the points for high-severity issues
    medium: 0.6,  // Lose 60% of the points for medium-severity issues
    low: 0.3,     // Lose 30% of the points for low-severity issues
    info: 0.1,    // Lose 10% of the points for informational issues
  },
  
  // Dangerous header penalties (total possible deduction: 10 points)
  dangerousHeaderPenalties: {
    high: 4,
    medium: 2,
    low: 1,
    info: 0.5,
  },
  
  // Cookie security penalties (total possible deduction: 10 points)
  cookieSecurityPenalties: {
    high: 4,
    medium: 2,
    low: 1,
    info: 0.5,
  },
  
  // Maximum penalty caps
  maxDangerousHeadersPenalty: 10,
  maxCookieSecurityPenalty: 10,

  // Scoring thresholds (unchanged)
  scoringThresholds: {
    A: 90,
    B: 80,
    C: 70,
    D: 60,
    E: 50,
    F: 0
  },
  
  // Application version
  version: '1.0.0'
};

module.exports = config;