/**
 * Web Security Tool - Main Entry Point
 * A comprehensive tool for analyzing web security
 */

// Import core modules
const { SecurityHeaderChecker } = require('./src/core/scanner');
const { HttpClient } = require('./src/core/http-client');
const config = require('./config/default');

// Import header modules
const headerChecks = {
  essential: require('./src/headers/essential'),
  advanced: require('./src/headers/advanced'),
  cors: require('./src/headers/cors'),
  cookies: require('./src/headers/cookies'),
  disclosure: require('./src/headers/disclosure')
};

// Import reports
const reports = {
  console: require('./src/reports/console-report'),
  html: require('./src/reports/html-report'),
  json: require('./src/reports/json-report')
};

// Import CLI - Comment this for now to avoid the circular dependency error
// const cli = require('./cli/index');

/**
 * Creates a security header checker with all available header modules
 * @param {Object} options - Configuration options
 * @returns {SecurityHeaderChecker} - Configured security header checker instance
 */
function createDefaultChecker(options = {}) {
  // We need to separate header definitions from analyzer functions
  const allHeaders = {};
  
  // Essential headers are core security headers
  Object.keys(headerChecks.essential).forEach(key => {
    allHeaders[key] = headerChecks.essential[key];
  });
  
  // Advanced headers are newer security headers
  Object.keys(headerChecks.advanced).forEach(key => {
    allHeaders[key] = headerChecks.advanced[key];
  });
  
  // CORS headers
  Object.keys(headerChecks.cors).forEach(key => {
    allHeaders[key] = headerChecks.cors[key];
  });
  
  // Add cookie headers but not the analyzer
  Object.keys(headerChecks.cookies).forEach(key => {
    if (key !== 'cookieAnalyzer') {
      allHeaders[key] = headerChecks.cookies[key];
    }
  });
  
  // Set up analyzers properly
  const analyzers = {};
  
  // Add the cookie analyzer if it exists
  if (headerChecks.cookies.cookieAnalyzer) {
    analyzers.cookieAnalyzer = headerChecks.cookies.cookieAnalyzer;
  }
  
  // Add the dangerous headers analyzer if it exists
  if (headerChecks.disclosure.dangerousHeaders) {
    analyzers.dangerousHeaders = headerChecks.disclosure.dangerousHeaders;
  }
  
  // Create HTTP client if not provided
  const httpClient = options.httpClient || new HttpClient(options);

  // Create and return a fully configured checker
  return new SecurityHeaderChecker({
    httpClient: httpClient,
    securityHeaders: allHeaders,
    analyzers: analyzers,
    ...options
  });
}

/**
 * Scans a URL for security headers and returns the results
 * @param {string} url - The URL to scan
 * @param {Object} options - Configuration options
 * @returns {Promise<Object>} - Scan results
 */
async function scanUrl(url, options = {}) {
  if (!url) {
    throw new Error('URL is required');
  }
  
  try {
    const checker = createDefaultChecker(options);
    return await checker.checkUrl(url);
  } catch (error) {
    console.error(`Failed to scan ${url}:`, error.message);
    // Return a graceful error result object
    return {
      url,
      status: 'error',
      errorMessage: error.message,
      timestamp: new Date().toISOString(),
      headers: {},
      findings: [],
      score: 0,
      grade: 'F'
    };
  }
}

/**
 * Scans a URL and outputs the results to console
 * @param {string} url - The URL to scan
 * @param {Object} options - Configuration options
 * @returns {Promise<Object>} - Scan results
 */
async function scanAndPrintResults(url, options = {}) {
  try {
    const results = await scanUrl(url, options);
    reports.console.printResults(results);
    return results;
  } catch (error) {
    console.error(`Error during scan of ${url}:`, error.message);
    return {
      url,
      status: 'error',
      errorMessage: error.message,
      timestamp: new Date().toISOString(),
      headers: {},
      findings: [],
      score: 0,
      grade: 'F'
    };
  }
}

/**
 * Scans a URL and generates HTML and JSON reports
 * @param {string} url - The URL to scan
 * @param {Object} options - Configuration options
 * @returns {Promise<Object>} - Object containing results and report paths
 */
async function scanAndGenerateReports(url, options = {}) {
  try {
    const results = await scanUrl(url, options);
    
    // Generate reports
    const htmlReport = reports.html.generateReport(results);
    const jsonReport = reports.json.generateReport(results);
    
    // Save reports to files
    const fs = require('fs');
    const timestamp = new Date().toISOString().replace(/:/g, '-');
    
    // Extract domain for filename
    let domain = url.replace(/^https?:\/\//, '').replace(/[^\w.-]/g, '_');
    if (domain.length > 30) domain = domain.substring(0, 30);
    
    const htmlFileName = `header_scan_${domain}_${timestamp}.html`;
    const jsonFileName = `header_scan_${domain}_${timestamp}.json`;
    
    try {
      fs.writeFileSync(htmlFileName, htmlReport);
      fs.writeFileSync(jsonFileName, jsonReport);
      
      console.log(`\n📄 HTML report saved to ${htmlFileName}`);
      console.log(`📄 JSON report saved to ${jsonFileName}`);
    } catch (fileError) {
      console.error('Error saving report files:', fileError.message);
    }
    
    return {
      results,
      reports: {
        html: htmlFileName,
        json: jsonFileName
      }
    };
  } catch (error) {
    console.error(`Error generating reports for ${url}:`, error.message);
    return {
      results: {
        url,
        status: 'error',
        errorMessage: error.message
      },
      reports: null
    };
  }
}

/**
 * Runs a comprehensive security scan on the provided URL
 * @param {string} url - Target URL to scan
 * @param {Object} options - Scan options
 * @returns {Promise<Object>} - Scan results
 */
async function runScan(url, options = {}) {
  if (!url) {
    throw new Error('URL is required');
  }
  
  console.log(`Starting comprehensive security scan for ${url}`);
  
  try {
    // Start with basic security header scan
    const headerResults = await scanUrl(url, options);
    
    // Initialize result object with header findings
    const results = {
      url,
      timestamp: new Date().toISOString(),
      headerScan: headerResults,
      tlsScan: null,
      apiScan: null,
      complianceMapping: null,
      remediation: null
    };
    
    // Here you would add additional scan types as they get implemented
    // For example:
    // if (options.includeTLS) {
    //   results.tlsScan = await tlsScanner.scan(url, options);
    // }
    
    // Generate unified report if requested
    if (options.generateReports) {
      await scanAndGenerateReports(url, options);
    }
    
    return results;
  } catch (error) {
    console.error(`Error during comprehensive scan of ${url}:`, error.message);
    return { 
      url, 
      status: 'error', 
      errorMessage: error.message,
      timestamp: new Date().toISOString()
    };
  }
}

// CLI functionality
function runCli() {
  const url = process.argv[2];
  
  if (!url) {
    console.log('Usage: node index.js <url>');
    console.log('Example: node index.js https://example.com');
    process.exit(1);
  }
  
  console.log(`🔍 Web Security Tool v${config.version}`);
  console.log(`Starting scan for ${url}...`);
  
  scanAndPrintResults(url, { verbose: true })
    .then(results => {
      if (results.status === 'error') {
        console.log('Skipping report generation due to scan errors.');
        return null;
      }
      return scanAndGenerateReports(url);
    })
    .catch(error => {
      console.error('Error running scanner:', error);
      process.exit(1);
    });
}

// Export public API
module.exports = {
  runScan,
  scanUrl,
  scanAndPrintResults,
  scanAndGenerateReports,
  createDefaultChecker,
  SecurityHeaderChecker,
  HttpClient,
  headerChecks,
  reports
};

// Run CLI if executed directly
if (require.main === module) {
  runCli();
}