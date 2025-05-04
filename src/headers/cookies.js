/**
 * Cookie Security Headers Module
 * Analyzes cookie security attributes and provides recommendations
 */

/**
 * Check Set-Cookie configuration
 * @param {string} value - The header value (may be an array if multiple cookies)
 * @returns {Object|null} - Configuration issues or null if properly configured
 */
function checkSetCookieConfiguration(value) {
  // Handle multiple cookies
  const cookies = Array.isArray(value) ? value : [value];
  const issues = [];
  
  for (const cookie of cookies) {
    // Extract cookie name
    const cookieName = cookie.split('=')[0].trim();
    
    // Check for Secure attribute
    if (!cookie.includes('Secure')) {
      issues.push({
        issue: `Cookie "${cookieName}" missing Secure attribute`,
        recommendation: 'Add Secure attribute to ensure cookie is only sent over HTTPS',
        criticalRating: 'high'
      });
    }
    
    // Check for HttpOnly attribute
    if (!cookie.includes('HttpOnly')) {
      issues.push({
        issue: `Cookie "${cookieName}" missing HttpOnly attribute`,
        recommendation: 'Add HttpOnly attribute to prevent JavaScript access to cookie',
        criticalRating: 'high'
      });
    }
    
    // Check for SameSite attribute
    if (!cookie.includes('SameSite')) {
      issues.push({
        issue: `Cookie "${cookieName}" missing SameSite attribute`,
        recommendation: 'Add SameSite=Strict or SameSite=Lax attribute to prevent CSRF attacks',
        criticalRating: 'medium'
      });
    } else if (cookie.includes('SameSite=None')) {
      // If SameSite=None, check if Secure is set
      if (!cookie.includes('Secure')) {
        issues.push({
          issue: `Cookie "${cookieName}" has SameSite=None without Secure attribute`,
          recommendation: 'When using SameSite=None, the Secure attribute is required',
          criticalRating: 'high'
        });
      }
    }
    
    // Check for Max-Age or Expires
    if (!cookie.includes('Max-Age') && !cookie.includes('Expires')) {
      issues.push({
        issue: `Cookie "${cookieName}" missing expiration (Max-Age or Expires)`,
        recommendation: 'Add Max-Age or Expires to prevent indefinite persistence',
        criticalRating: 'low'
      });
    }
    
    // Check for Path attribute
    if (!cookie.includes('Path=')) {
      issues.push({
        issue: `Cookie "${cookieName}" missing Path attribute`,
        recommendation: 'Add a specific Path attribute to limit cookie scope',
        criticalRating: 'low'
      });
    } else if (cookie.includes('Path=/')) {
      // Path=/ is too broad for some cookies
      issues.push({
        issue: `Cookie "${cookieName}" uses broad Path=/ scope`,
        recommendation: 'Consider restricting Path to specific application paths if possible',
        criticalRating: 'info'
      });
    }
    
    // Check for potentially sensitive data in cookie names
    const sensitiveKeywords = ['auth', 'session', 'token', 'key', 'secret', 'password', 'credential'];
    
    for (const keyword of sensitiveKeywords) {
      if (cookieName.toLowerCase().includes(keyword)) {
        // Ensure critical security attributes for sensitive cookies
        const missingAttributes = [];
        
        if (!cookie.includes('Secure')) missingAttributes.push('Secure');
        if (!cookie.includes('HttpOnly')) missingAttributes.push('HttpOnly');
        if (!cookie.includes('SameSite')) missingAttributes.push('SameSite');
        
        if (missingAttributes.length > 0) {
          issues.push({
            issue: `Potentially sensitive cookie "${cookieName}" missing critical attributes: ${missingAttributes.join(', ')}`,
            recommendation: 'Ensure all security attributes are set for sensitive cookies',
            criticalRating: 'high'
          });
        }
        
        break; // Only add this issue once per cookie
      }
    }
  }
  
  return issues.length > 0 ? issues[0] : null; // Return first issue or null
}

/**
 * Advanced cookie analyzer that can handle multiple cookies
 * @param {string|string[]} setCookieValues - The Set-Cookie header values
 * @returns {Object} - Findings and score adjustment
 */
function cookieAnalyzer(setCookieValues) {
  // Handle both array and string cases
  const cookies = Array.isArray(setCookieValues) ? setCookieValues : [setCookieValues];
  const findings = [];
  let scoreAdjustment = 0;
  
  for (const cookie of cookies) {
    // Extract cookie name
    const cookieName = cookie.split('=')[0].trim();
    
    // Initialize secure attributes tracking
    const secureAttributes = {
      secure: cookie.includes('Secure'),
      httpOnly: cookie.includes('HttpOnly'),
      sameSite: /SameSite=(Strict|Lax|None)/i.test(cookie),
      sameSiteValue: /SameSite=(Strict|Lax|None)/i.exec(cookie)?.[1]?.toLowerCase() || 'none'
    };
    
    // Build finding for this cookie
    const cookieIssues = [];
    
    // Check for Secure attribute
    if (!secureAttributes.secure) {
      cookieIssues.push({
        type: 'missing_secure',
        description: 'Missing Secure attribute',
        recommendation: 'Add Secure attribute to ensure cookie is only sent over HTTPS',
        criticalRating: 'high'
      });
      scoreAdjustment -= 2; // Reduced from 10
    }
    
    // Check for HttpOnly attribute
    if (!secureAttributes.httpOnly) {
      cookieIssues.push({
        type: 'missing_httponly',
        description: 'Missing HttpOnly attribute',
        recommendation: 'Add HttpOnly attribute to prevent JavaScript access to cookie',
        criticalRating: 'high'
      });
      scoreAdjustment -= 2; // Reduced from 10
    }
    
    // Check for SameSite attribute
    if (!secureAttributes.sameSite) {
      cookieIssues.push({
        type: 'missing_samesite',
        description: 'Missing SameSite attribute',
        recommendation: 'Add SameSite=Strict or SameSite=Lax attribute to prevent CSRF attacks',
        criticalRating: 'medium'
      });
      scoreAdjustment -= 1; // Reduced from 5
    } else if (secureAttributes.sameSiteValue === 'none' && !secureAttributes.secure) {
      cookieIssues.push({
        type: 'samesite_none_without_secure',
        description: 'Using SameSite=None without Secure attribute',
        recommendation: 'When using SameSite=None, the Secure attribute is required',
        criticalRating: 'high'
      });
      scoreAdjustment -= 2; // Reduced from 10
    }
    
    // Only add the finding if there are issues
    if (cookieIssues.length > 0) {
      findings.push({
        header: 'Cookie Security',
        status: 'misconfigured',
        cookie: cookieName,
        value: cookie,
        issues: cookieIssues,
        recommendation: 'Set appropriate security attributes for cookies',
        criticalRating: 'high'
      });
    }
  }
  
  // Print for debugging
  if (findings.length > 0) {
    console.log(`[DEBUG] Cookie issues found: ${findings.length}, score adjustment: ${scoreAdjustment}`);
  }

  return {
    findings,
    scoreAdjustment
  };
}

// Cookie headers definition with just the header, not the analyzer
const setCookieHeader = {
  'set-cookie': {
    name: 'Set-Cookie',
    description: 'Sets a cookie with security attributes',
    recommendation: 'Ensure cookies use Secure, HttpOnly, and SameSite attributes',
    criticalRating: 'high',
    checkConfiguration: checkSetCookieConfiguration
  }
};

// Export the cookie header and the analyzer separately
module.exports = {
  ...setCookieHeader,
  cookieAnalyzer
};