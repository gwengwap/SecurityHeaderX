/**
 * Web Security Tool - Core API
 * Provides the main functionality and public interface
 */

// Import core modules
const { SecurityHeaderChecker } = require('./scanner');
const { HttpClient } = require('./http-client');
const config = require('../../config/default');

// Import analyzers
const headerModules = {
  essential: require('../headers/essential'),
  advanced: require('../headers/advanced'),
  cors: require('../headers/cors'),
  cookies: require('../headers/cookies'),
  disclosure: require('../headers/disclosure')
};

// Import reports
const reporters = {
  console: require('../reports/console-report'),
  html: require('../reports/html-report'),
  json: require('../reports/json-report')
};

/**
 * Creates a security header checker with all available header modules
 * @param {Object} options - Configuration options
 * @returns {SecurityHeaderChecker} - Configured security header checker instance
 */
function createDefaultChecker(options = {}) {
  // We need to separate header definitions from analyzer functions
  const allHeaders = {};
  
  // Essential headers are core security headers
  Object.keys(headerModules.essential).forEach(key => {
    allHeaders[key] = headerModules.essential[key];
  });
  
  // Advanced headers are newer security headers
  Object.keys(headerModules.advanced).forEach(key => {
    allHeaders[key] = headerModules.advanced[key];
  });
  
  // CORS headers
  Object.keys(headerModules.cors).forEach(key => {
    allHeaders[key] = headerModules.cors[key];
  });
  
  // Add cookie headers but not the analyzer
  Object.keys(headerModules.cookies).forEach(key => {
    if (key !== 'cookieAnalyzer') {
      allHeaders[key] = headerModules.cookies[key];
    }
  });
  
  // Set up analyzers properly
  const analyzers = {};
  
  // Add the cookie analyzer if it exists
  if (headerModules.cookies.cookieAnalyzer) {
    analyzers.cookieAnalyzer = headerModules.cookies.cookieAnalyzer;
  }
  
  // Add the dangerous headers analyzer if it exists
  if (headerModules.disclosure.dangerousHeaders) {
    analyzers.dangerousHeaders = headerModules.disclosure.dangerousHeaders;
  }
  
  if (options.verbose) {
    console.log(`[DEBUG] Total headers to check: ${Object.keys(allHeaders).length}`);
    console.log(`[DEBUG] Analyzers set up: ${Object.keys(analyzers).length}`);
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
    reporters.console.printResults(results);
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
    const htmlReport = reporters.html.generateReport(results);
    const jsonReport = reporters.json.generateReport(results);
    
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
 * Print comprehensive scan results
 * @param {Object} results - The scan results
 */
async function printScanResults(results) {
  if (results.headerScan) {
    reporters.console.printResults(results.headerScan);
  }
  
  // Print TLS results if available
  if (results.tlsScan) {
    console.log('\n--- TLS/SSL Scan Results ---');
    // Implement TLS result printing when available
    console.log('TLS scan results not implemented yet');
  }
  
  // Print API results if available
  if (results.apiScan) {
    console.log('\n--- API Security Scan Results ---');
    // Implement API result printing when available
    console.log('API scan results not implemented yet');
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
    if (options.scanTypes && options.scanTypes.includes('tls')) {
      // This is a placeholder for future TLS scanning implementation
      console.log('TLS scanning not implemented yet');
      results.tlsScan = { status: 'not_implemented' };
    }
    
    if (options.scanTypes && options.scanTypes.includes('api')) {
      // This is a placeholder for future API scanning implementation
      console.log('API scanning not implemented yet');
      results.apiScan = { status: 'not_implemented' };
    }
    
    // Generate unified report if requested
    if (options.generateReports) {
      const reportOptions = {
        ...options,
        includeTLS: !!results.tlsScan,
        includeAPI: !!results.apiScan
      };
      
      // For now, just generate header scan reports
      await scanAndGenerateReports(url, reportOptions);
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

// Export the public API
module.exports = {
  // Core functionality
  createDefaultChecker,
  SecurityHeaderChecker,
  HttpClient,
  
  // Scanning functions
  scanUrl,
  scanAndPrintResults,
  scanAndGenerateReports,
  runScan,
  printScanResults,
  
  // Modules
  headers: headerModules,
  reporters
};