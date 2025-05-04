/**
 * Essential Security Headers Module
 * Contains the most critical security headers that should be implemented on all websites
 */

/**
 * Check Strict-Transport-Security configuration
 * @param {string} value - The header value
 * @returns {Object|null} - Configuration issue or null if properly configured
 */
function checkHstsConfiguration(value) {
    if (!value) {
      return {
        issue: 'HSTS header missing',
        recommendation: 'Add Strict-Transport-Security header with appropriate directives',
        criticalRating: 'high'
      };
    }
    
    if (!value.includes('max-age=')) {
      return {
        issue: 'HSTS header missing max-age directive',
        recommendation: 'Add max-age directive with a value of at least 31536000 (1 year)',
        criticalRating: 'high'
      };
    }
    
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
    if (!value.includes('preload')) {
      return {
        issue: 'HSTS missing preload directive',
        recommendation: 'Consider adding preload directive to be eligible for browser preload lists',
        criticalRating: 'info'
      };
    }
    return null;
}
  
/**
 * Check Content-Security-Policy configuration
 * @param {string} value - The header value
 * @returns {Object|null} - Configuration issue or null if properly configured
 */
function checkCspConfiguration(value) {
    if (!value) {
      return {
        issue: 'CSP header missing',
        recommendation: 'Add Content-Security-Policy header with appropriate directives',
        criticalRating: 'high'
      };
    }

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
    
    // Check for common recommended directives
    const recommendedDirectives = ['default-src', 'script-src', 'style-src'];
    const missingDirectives = recommendedDirectives.filter(directive => !value.includes(directive));
    
    if (missingDirectives.length > 0) {
      return {
        issue: `CSP missing recommended directives: ${missingDirectives.join(', ')}`,
        recommendation: 'Include all recommended directives in your CSP',
        criticalRating: 'medium'
      };
    }
    
    return null;
}
  
/**
 * Check X-Frame-Options configuration
 * @param {string} value - The header value
 * @returns {Object|null} - Configuration issue or null if properly configured
 */
function checkXFrameOptionsConfiguration(value) {
    if (value.toUpperCase() !== 'DENY' && value.toUpperCase() !== 'SAMEORIGIN') {
      return {
        issue: 'X-Frame-Options has invalid value',
        recommendation: 'Use either DENY or SAMEORIGIN values',
        criticalRating: 'medium'
      };
    }
    return null;
}
  
/**
 * Check X-XSS-Protection configuration
 * @param {string} value - The header value
 * @returns {Object|null} - Configuration issue or null if properly configured
 */
function checkXssProtectionConfiguration(value) {
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
    return null;
}
  
/**
 * Check Referrer-Policy configuration
 * @param {string} value - The header value
 * @returns {Object|null} - Configuration issue or null if properly configured
 */
function checkReferrerPolicyConfiguration(value) {
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
    return null;
}
  
// Essential security headers definitions
const essentialHeaders = {
  'strict-transport-security': {
    name: 'Strict-Transport-Security (HSTS)',
    description: 'Forces browsers to use HTTPS for the domain',
    recommendation: 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" header',
    criticalRating: 'high',
    checkConfiguration: checkHstsConfiguration
  },
  'content-security-policy': {
    name: 'Content-Security-Policy (CSP)',
    description: 'Controls resources the browser is allowed to load',
    recommendation: 'Implement a strict CSP policy to prevent XSS attacks',
    criticalRating: 'high',
    checkConfiguration: checkCspConfiguration
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
    criticalRating: 'medium',
    checkConfiguration: checkXFrameOptionsConfiguration
  },
  'x-xss-protection': {
    name: 'X-XSS-Protection',
    description: 'Enables XSS filtering in browsers',
    recommendation: 'Add "X-XSS-Protection: 1; mode=block" header',
    criticalRating: 'low',
    checkConfiguration: checkXssProtectionConfiguration
  },
  'referrer-policy': {
    name: 'Referrer-Policy',
    description: 'Controls how much referrer information should be included with requests',
    recommendation: 'Add "Referrer-Policy: strict-origin-when-cross-origin" header',
    criticalRating: 'low',
    checkConfiguration: checkReferrerPolicyConfiguration
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
  }
};
  
module.exports = essentialHeaders;