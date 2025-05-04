/**
 * CORS Headers Module
 * Contains headers related to Cross-Origin Resource Sharing
 */

/**
 * Check Access-Control-Allow-Origin configuration
 * @param {string} value - The header value
 * @returns {Object|null} - Configuration issue or null if properly configured
 */
function checkAccessControlAllowOriginConfiguration(value) {
    // Using * is generally not recommended for sensitive endpoints
    if (value === '*') {
      return {
        issue: 'Access-Control-Allow-Origin uses wildcard (*)',
        recommendation: 'Restrict CORS to specific origins instead of using a wildcard',
        criticalRating: 'medium'
      };
    }
    return null;
  }
  
  /**
   * Check Access-Control-Allow-Credentials configuration
   * @param {string} value - The header value
   * @param {Object} headers - All response headers
   * @returns {Object|null} - Configuration issue or null if properly configured
   */
  function checkAccessControlAllowCredentialsConfiguration(value, headers) {
    // If credentials are allowed, origin should not be a wildcard
    if (value.toLowerCase() === 'true') {
      const allowOrigin = headers['access-control-allow-origin'];
      if (allowOrigin === '*') {
        return {
          issue: 'Access-Control-Allow-Credentials is true while Allow-Origin is wildcard',
          recommendation: 'When allowing credentials, specify explicit origins instead of using a wildcard',
          criticalRating: 'high'
        };
      }
    }
    return null;
  }
  
  /**
   * Check Access-Control-Allow-Methods configuration
   * @param {string} value - The header value
   * @returns {Object|null} - Configuration issue or null if properly configured
   */
  function checkAccessControlAllowMethodsConfiguration(value) {
    // Check if dangerous methods are allowed unnecessarily
    const sensitiveHttpMethods = ['PUT', 'DELETE', 'PATCH'];
    const allowedMethods = value.split(',').map(method => method.trim().toUpperCase());
    
    const allowedSensitiveMethods = sensitiveHttpMethods.filter(method => 
      allowedMethods.includes(method)
    );
    
    if (allowedSensitiveMethods.length > 0) {
      return {
        issue: `CORS allows potentially dangerous methods: ${allowedSensitiveMethods.join(', ')}`,
        recommendation: 'Only allow necessary HTTP methods in Access-Control-Allow-Methods',
        criticalRating: 'low'
      };
    }
    return null;
  }
  
  /**
   * Check Access-Control-Allow-Headers configuration
   * @param {string} value - The header value
   * @returns {Object|null} - Configuration issue or null if properly configured
   */
  function checkAccessControlAllowHeadersConfiguration(value) {
    // Using * is generally not recommended
    if (value === '*') {
      return {
        issue: 'Access-Control-Allow-Headers uses wildcard (*)',
        recommendation: 'Explicitly list allowed headers instead of using a wildcard',
        criticalRating: 'low'
      };
    }
    return null;
  }
  
  /**
   * Check Access-Control-Expose-Headers configuration
   * @param {string} value - The header value
   * @returns {Object|null} - Configuration issue or null if properly configured
   */
  function checkAccessControlExposeHeadersConfiguration(value) {
    // Check if sensitive headers are being exposed
    const potentiallySensitiveHeaders = [
      'Authorization', 'X-API-Key', 'X-Auth-Token', 'Set-Cookie'
    ];
    
    const exposedHeaders = value.split(',').map(header => header.trim().toLowerCase());
    
    const exposedSensitiveHeaders = potentiallySensitiveHeaders.filter(header => 
      exposedHeaders.includes(header.toLowerCase())
    );
    
    if (exposedSensitiveHeaders.length > 0) {
      return {
        issue: `Exposing potentially sensitive headers: ${exposedSensitiveHeaders.join(', ')}`,
        recommendation: 'Avoid exposing sensitive headers to cross-origin requests',
        criticalRating: 'medium'
      };
    }
    return null;
  }
  
  /**
   * Check Access-Control-Max-Age configuration
   * @param {string} value - The header value
   * @returns {Object|null} - Configuration issue or null if properly configured
   */
  function checkAccessControlMaxAgeConfiguration(value) {
    const maxAge = parseInt(value);
    
    // Check if max age is excessively long
    if (maxAge > 86400) {
      return {
        issue: 'Access-Control-Max-Age is excessively long',
        recommendation: 'Consider using a shorter max-age value (e.g., 7200 seconds / 2 hours)',
        criticalRating: 'info'
      };
    }
    return null;
  }
  
  // CORS headers definitions
  const corsHeaders = {
    'access-control-allow-origin': {
      name: 'Access-Control-Allow-Origin',
      description: 'Specifies which origins can access the resource',
      recommendation: 'Restrict to specific trusted origins instead of using a wildcard (*)',
      criticalRating: 'medium',
      checkConfiguration: checkAccessControlAllowOriginConfiguration
    },
    'access-control-allow-credentials': {
      name: 'Access-Control-Allow-Credentials',
      description: 'Indicates whether the response can be shared with requesting code from the given origin when credentials are provided',
      recommendation: 'Only set to true if necessary, and ensure origins are restricted',
      criticalRating: 'medium',
      checkConfiguration: checkAccessControlAllowCredentialsConfiguration
    },
    'access-control-allow-methods': {
      name: 'Access-Control-Allow-Methods',
      description: 'Specifies which HTTP methods are allowed when accessing the resource',
      recommendation: 'Only allow necessary HTTP methods',
      criticalRating: 'low',
      checkConfiguration: checkAccessControlAllowMethodsConfiguration
    },
    'access-control-allow-headers': {
      name: 'Access-Control-Allow-Headers',
      description: 'Specifies which HTTP headers can be used when making the actual request',
      recommendation: 'Explicitly list allowed headers instead of using a wildcard',
      criticalRating: 'low',
      checkConfiguration: checkAccessControlAllowHeadersConfiguration
    },
    'access-control-expose-headers': {
      name: 'Access-Control-Expose-Headers',
      description: 'Indicates which headers can be exposed as part of the response',
      recommendation: 'Only expose necessary non-sensitive headers',
      criticalRating: 'low',
      checkConfiguration: checkAccessControlExposeHeadersConfiguration
    },
    'access-control-max-age': {
      name: 'Access-Control-Max-Age',
      description: 'Indicates how long the results of a preflight request can be cached',
      recommendation: 'Set a reasonable max age (e.g., 7200 seconds / 2 hours)',
      criticalRating: 'info',
      checkConfiguration: checkAccessControlMaxAgeConfiguration
    }
  };
  
  // Export a function to check CORS headers as a group
  module.exports = corsHeaders;