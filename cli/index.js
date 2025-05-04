/**
 * Web Security Tool - CLI Module
 * Handles command-line interface functionality
 */

const api = require('../src/core/api');
const pkg = require('../package.json');

/**
 * Parse command line arguments
 * @returns {Object} Parsed options
 */
function parseArgs() {
  const args = process.argv.slice(2);
  const options = {
    url: null,
    verbose: false,
    generateReports: false,
    reportFormat: ['console'],
    scanTypes: ['headers'],
  };

  // Simple argument parsing
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    
    if (arg === '--verbose' || arg === '-v') {
      options.verbose = true;
    } else if (arg === '--reports' || arg === '-r') {
      options.generateReports = true;
      options.reportFormat.push('html', 'json');
    } else if (arg === '--full' || arg === '-f') {
      options.scanTypes.push('tls', 'api');
    } else if (!arg.startsWith('-') && !options.url) {
      options.url = arg;
    }
  }

  return options;
}

/**
 * Print usage information
 */
function printUsage() {
  console.log(`Web Security Tool v${pkg.version}`);
  console.log('\nUsage: node index.js <url> [options]');
  console.log('\nOptions:');
  console.log('  --verbose, -v     Enable verbose output');
  console.log('  --reports, -r     Generate HTML and JSON reports');
  console.log('  --full, -f        Perform a comprehensive scan (headers, TLS, API)');
  console.log('\nExamples:');
  console.log('  node index.js https://example.com');
  console.log('  node index.js https://example.com --reports --verbose');
}

/**
 * Run the CLI
 */
async function run() {
  const options = parseArgs();
  
  if (!options.url) {
    printUsage();
    process.exit(1);
  }
  
  console.log(`🔍 Web Security Tool v${pkg.version}`);
  console.log(`Starting scan for ${options.url}...`);
  
  try {
    // Check if full scan was requested
    if (options.scanTypes.length > 1) {
      const results = await api.runScan(options.url, options);
      if (options.reportFormat.includes('console')) {
        await api.printScanResults(results);
      }
    } else {
      // Default to header scan with console output
      const results = await api.scanAndPrintResults(options.url, { verbose: options.verbose });
      
      // Generate additional reports if requested
      if (options.generateReports && results.status !== 'error') {
        await api.scanAndGenerateReports(options.url);
      }
    }
  } catch (error) {
    console.error('Error running scanner:', error);
    process.exit(1);
  }
}

module.exports = { run, parseArgs };