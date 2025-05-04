/**
 * Web Security Tool - Main Entry Point
 * A comprehensive tool for analyzing web security
 */

// Export the public API
module.exports = require('./src/core/api');

// Run CLI if executed directly
if (require.main === module) {
  require('./cli').run();
}