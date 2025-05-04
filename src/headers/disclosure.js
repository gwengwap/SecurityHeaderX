/**
 * Information Disclosure Headers Module
 * Checks for headers that could leak sensitive information
 */

/**
 * Check for headers that could expose sensitive information
 * @param {Object} headers - The normalized headers
 * @returns {Object} - Findings and score adjustment
 */
function checkDangerousHeaders(headers) {
  const findings = [];
  let scoreAdjustment = 0; // Start with zero adjustment
  
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
    },
    'x-generator': {
      name: 'X-Generator',
      description: 'Reveals the platform or CMS used',
      recommendation: 'Remove the X-Generator header',
      criticalRating: 'low'
    },
    'x-drupal-cache': {
      name: 'X-Drupal-Cache',
      description: 'Reveals Drupal as the CMS',
      recommendation: 'Remove the X-Drupal-Cache header',
      criticalRating: 'low'
    },
    'x-drupal-dynamic-cache': {
      name: 'X-Drupal-Dynamic-Cache',
      description: 'Reveals Drupal as the CMS',
      recommendation: 'Remove the X-Drupal-Dynamic-Cache header',
      criticalRating: 'low'
    },
    'x-wordpress-cache': {
      name: 'X-WordPress-Cache',
      description: 'Reveals WordPress as the CMS',
      recommendation: 'Remove the X-WordPress-Cache header',
      criticalRating: 'low'
    },
    'x-wp-nonce': {
      name: 'X-WP-Nonce',
      description: 'Reveals WordPress as the CMS',
      recommendation: 'Consider whether this header should be exposed',
      criticalRating: 'low'
    },
    'x-pingback': {
      name: 'X-Pingback',
      description: 'Often indicates WordPress and provides an XML-RPC endpoint',
      recommendation: 'Remove the X-Pingback header if not needed',
      criticalRating: 'low'
    },
    'laravel_session': {
      name: 'laravel_session',
      description: 'Reveals Laravel as the framework',
      recommendation: 'Rename the session cookie to hide framework information',
      criticalRating: 'low'
    },
    'phpbb-data': {
      name: 'phpbb-data',
      description: 'Reveals phpBB as the forum software',
      recommendation: 'Rename the cookie to hide implementation details',
      criticalRating: 'low'
    },
    'joomla_user_state': {
      name: 'joomla_user_state',
      description: 'Reveals Joomla as the CMS',
      recommendation: 'Rename the cookie to hide implementation details',
      criticalRating: 'low'
    },
    'x-varnish': {
      name: 'X-Varnish',
      description: 'Reveals Varnish Cache is in use',
      recommendation: 'Consider removing the X-Varnish header',
      criticalRating: 'info'
    },
    'via': {
      name: 'Via',
      description: 'May reveal proxy information',
      recommendation: 'Consider customizing or removing the Via header',
      criticalRating: 'info'
    },
    'x-cache': {
      name: 'X-Cache',
      description: 'Reveals caching infrastructure details',
      recommendation: 'Consider removing the X-Cache header',
      criticalRating: 'info'
    },
    'x-runtime': {
      name: 'X-Runtime',
      description: 'Reveals application runtime information',
      recommendation: 'Remove the X-Runtime header to hide implementation details',
      criticalRating: 'low'
    },
    'x-debug-token': {
      name: 'X-Debug-Token',
      description: 'Debug information from Symfony framework',
      recommendation: 'Remove debug headers in production',
      criticalRating: 'medium'
    },
    'x-debug-token-link': {
      name: 'X-Debug-Token-Link',
      description: 'Debug information from Symfony framework',
      recommendation: 'Remove debug headers in production',
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
      
      // Adjust score based on criticality
      // IMPORTANT: Using smaller deductions to avoid double-counting
      switch(info.criticalRating) {
        case 'high':
          scoreAdjustment -= 3;
          break;
        case 'medium':
          scoreAdjustment -= 2;
          break;
        case 'low':
          scoreAdjustment -= 1;
          break;
        default:
          scoreAdjustment -= 0;
      }
    }
  }

  // Check for version information in Server or X-Powered-By headers
  const versionHeaderRegex = /[0-9]+\.[0-9]+(\.[0-9]+)?/;
  
  if (headers['server'] && versionHeaderRegex.test(headers['server'])) {
    findings.push({
      header: 'Server',
      status: 'dangerous',
      value: headers['server'],
      description: 'Server header contains version information',
      recommendation: 'Remove version information from Server header',
      criticalRating: 'medium'
    });
    scoreAdjustment -= 2; // Reduced from 5
  }
  
  if (headers['x-powered-by'] && versionHeaderRegex.test(headers['x-powered-by'])) {
    findings.push({
      header: 'X-Powered-By',
      status: 'dangerous',
      value: headers['x-powered-by'],
      description: 'X-Powered-By header contains version information',
      recommendation: 'Remove version information from X-Powered-By header',
      criticalRating: 'medium'
    });
    scoreAdjustment -= 2; // Reduced from 5
  }

  // Print for debugging
  if (findings.length > 0) {
    console.log(`[DEBUG] Dangerous headers found: ${findings.length}, score adjustment: ${scoreAdjustment}`);
  }

  return {
    findings,
    scoreAdjustment
  };
}

// Export only the dangerousHeaders analyzer
module.exports = {
  dangerousHeaders: checkDangerousHeaders
};