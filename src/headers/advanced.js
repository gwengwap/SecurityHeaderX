/**
 * Advanced Security Headers Module
 * Contains newer and more advanced security headers
 */

/**
 * Check Expect-CT configuration
 * @param {string} value - The header value
 * @returns {Object|null} - Configuration issue or null if properly configured
 */
function checkExpectCtConfiguration(value) {
    if (!value.includes('max-age=')) {
      return {
        issue: 'Expect-CT header missing max-age directive',
        recommendation: 'Add max-age directive with an appropriate value',
        criticalRating: 'medium'
      };
    }
    
    if (!value.includes('enforce')) {
      return {
        issue: 'Expect-CT header missing enforce directive',
        recommendation: 'Add enforce directive to require Certificate Transparency compliance',
        criticalRating: 'low'
      };
    }
    
    return null;
  }
  
  /**
   * Check Report-To configuration
   * @param {string} value - The header value
   * @returns {Object|null} - Configuration issue or null if properly configured
   */
  function checkReportToConfiguration(value) {
    try {
      // Report-To header should be valid JSON
      const reportConfig = JSON.parse(value);
      
      // Check if it contains the required fields
      if (!reportConfig.endpoints || !Array.isArray(reportConfig.endpoints) || reportConfig.endpoints.length === 0) {
        return {
          issue: 'Report-To header has invalid or missing endpoints',
          recommendation: 'Include at least one valid endpoint in the Report-To configuration',
          criticalRating: 'low'
        };
      }
      
      // Check if the max_age is reasonable
      if (!reportConfig.max_age || reportConfig.max_age < 86400) {
        return {
          issue: 'Report-To header has short max_age or missing max_age',
          recommendation: 'Set max_age to at least 86400 (1 day)',
          criticalRating: 'info'
        };
      }
      
      return null;
    } catch (error) {
      return {
        issue: 'Report-To header contains invalid JSON',
        recommendation: 'Ensure the Report-To header contains valid JSON',
        criticalRating: 'low'
      };
    }
  }
  
  /**
   * Check NEL configuration
   * @param {string} value - The header value
   * @returns {Object|null} - Configuration issue or null if properly configured
   */
  function checkNelConfiguration(value) {
    try {
      // NEL header should be valid JSON
      const nelConfig = JSON.parse(value);
      
      // Check if it contains the required fields
      if (!nelConfig.report_to) {
        return {
          issue: 'NEL header missing report_to field',
          recommendation: 'Include report_to field to specify the reporting group',
          criticalRating: 'low'
        };
      }
      
      // Check if max_age is reasonable
      if (!nelConfig.max_age || nelConfig.max_age < 86400) {
        return {
          issue: 'NEL header has short max_age or missing max_age',
          recommendation: 'Set max_age to at least 86400 (1 day)',
          criticalRating: 'info'
        };
      }
      
      return null;
    } catch (error) {
      return {
        issue: 'NEL header contains invalid JSON',
        recommendation: 'Ensure the NEL header contains valid JSON',
        criticalRating: 'low'
      };
    }
  }
  
  /**
   * Check Clear-Site-Data configuration
   * @param {string} value - The header value
   * @returns {Object|null} - Configuration issue or null if properly configured
   */
  function checkClearSiteDataConfiguration(value) {
    // The header should contain valid JSON
    try {
      JSON.parse(value);
      return null;
    } catch (error) {
      return {
        issue: 'Clear-Site-Data header contains invalid JSON',
        recommendation: 'Ensure the Clear-Site-Data header contains valid JSON',
        criticalRating: 'low'
      };
    }
  }
  
  /**
   * Check Feature-Policy/Permissions-Policy configuration
   * @param {string} value - The header value
   * @returns {Object|null} - Configuration issue or null if properly configured
   */
  function checkPermissionsPolicyConfiguration(value) {
    // Check for common patterns that suggest a misconfiguration
    if (value.includes('*')) {
      return {
        issue: 'Permissions-Policy contains wildcards for feature policies',
        recommendation: 'Be explicit about allowed origins for each feature',
        criticalRating: 'low'
      };
    }
    
    // Check if key security features are restricted
    const criticalFeatures = ['camera', 'microphone', 'geolocation', 'payment'];
    const missingRestrictions = [];
    
    for (const feature of criticalFeatures) {
      if (!value.includes(feature)) {
        missingRestrictions.push(feature);
      }
    }
    
    if (missingRestrictions.length > 0) {
      return {
        issue: `Permissions-Policy missing restrictions for: ${missingRestrictions.join(', ')}`,
        recommendation: 'Consider restricting these features if not needed by your application',
        criticalRating: 'low'
      };
    }
    
    return null;
  }
  
  /**
   * Check Cross-Origin-Embedder-Policy configuration
   * @param {string} value - The header value
   * @returns {Object|null} - Configuration issue or null if properly configured
   */
  function checkCoepConfiguration(value) {
    if (value !== 'require-corp' && value !== 'credentialless') {
      return {
        issue: 'Cross-Origin-Embedder-Policy has invalid value',
        recommendation: 'Use either "require-corp" or "credentialless" values',
        criticalRating: 'low'
      };
    }
    return null;
  }
  
  /**
   * Check Cross-Origin-Opener-Policy configuration
   * @param {string} value - The header value
   * @returns {Object|null} - Configuration issue or null if properly configured
   */
  function checkCoopConfiguration(value) {
    if (value !== 'same-origin' && value !== 'same-origin-allow-popups' && value !== 'unsafe-none') {
      return {
        issue: 'Cross-Origin-Opener-Policy has invalid value',
        recommendation: 'Use "same-origin", "same-origin-allow-popups", or "unsafe-none" values',
        criticalRating: 'low'
      };
    }
    return null;
  }
  
  /**
   * Check Cross-Origin-Resource-Policy configuration
   * @param {string} value - The header value
   * @returns {Object|null} - Configuration issue or null if properly configured
   */
  function checkCorpConfiguration(value) {
    if (value !== 'same-site' && value !== 'same-origin' && value !== 'cross-origin') {
      return {
        issue: 'Cross-Origin-Resource-Policy has invalid value',
        recommendation: 'Use "same-site", "same-origin", or "cross-origin" values',
        criticalRating: 'low'
      };
    }
    return null;
  }
  
  // Advanced security headers definitions
  const advancedHeaders = {
    'expect-ct': {
      name: 'Expect-CT',
      description: 'Allows sites to opt-in to Certificate Transparency reporting',
      recommendation: 'Add "Expect-CT: max-age=86400, enforce" header',
      criticalRating: 'medium',
      checkConfiguration: checkExpectCtConfiguration
    },
    'report-to': {
      name: 'Report-To',
      description: 'Specifies a server for browsers to send security reports to',
      recommendation: 'Implement a Report-To header with valid JSON configuration',
      criticalRating: 'low',
      checkConfiguration: checkReportToConfiguration
    },
    'nel': {
      name: 'NEL (Network Error Logging)',
      description: 'Enables reporting of network errors to help identify connectivity issues',
      recommendation: 'Configure NEL header with appropriate report-to group',
      criticalRating: 'low',
      checkConfiguration: checkNelConfiguration
    },
    'clear-site-data': {
      name: 'Clear-Site-Data',
      description: 'Clears browsing data (cookies, storage, cache) associated with the site',
      recommendation: 'Consider using this header for logout pages',
      criticalRating: 'info',
      checkConfiguration: checkClearSiteDataConfiguration
    },
    'cross-origin-embedder-policy': {
      name: 'Cross-Origin-Embedder-Policy',
      description: 'Controls which cross-origin resources can be loaded',
      recommendation: 'Add "Cross-Origin-Embedder-Policy: require-corp" header for isolation',
      criticalRating: 'low',
      checkConfiguration: checkCoepConfiguration
    },
    'cross-origin-opener-policy': {
      name: 'Cross-Origin-Opener-Policy',
      description: 'Controls sharing browsing context with cross-origin documents',
      recommendation: 'Add "Cross-Origin-Opener-Policy: same-origin" header for isolation',
      criticalRating: 'low',
      checkConfiguration: checkCoopConfiguration
    },
    'cross-origin-resource-policy': {
      name: 'Cross-Origin-Resource-Policy',
      description: 'Controls which origins can load the resource',
      recommendation: 'Add "Cross-Origin-Resource-Policy: same-origin" header',
      criticalRating: 'low',
      checkConfiguration: checkCorpConfiguration
    },
    'server-timing': {
      name: 'Server-Timing',
      description: 'Provides performance metrics to help diagnose site performance',
      recommendation: 'Use Server-Timing to expose appropriate performance metrics',
      criticalRating: 'info'
    }
  };
  
  module.exports = advancedHeaders;