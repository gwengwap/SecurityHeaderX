/**
 * Web Security Tool - REST API Server
 * Provides HTTP endpoints for the web security tool
 */

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const api = require('../src/core/api');
const pkg = require('../package.json');

// Create Express app
const app = express();

// Apply middleware
app.use(cors());
app.use(bodyParser.json());

// Get package info
app.get('/api', (req, res) => {
  res.json({
    name: pkg.name,
    version: pkg.version,
    description: pkg.description
  });
});

// Scan endpoint
app.post('/api/scan', async (req, res) => {
  try {
    const { url, options = {} } = req.body;
    
    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }
    
    // Start the scan
    console.log(`API: Starting scan for ${url}`);
    const results = await api.scanUrl(url, options);
    
    res.json(results);
  } catch (error) {
    console.error('API error:', error);
    res.status(500).json({ 
      error: error.message,
      status: 'error'
    });
  }
});

// Comprehensive scan endpoint
app.post('/api/scan/full', async (req, res) => {
  try {
    const { url, options = {} } = req.body;
    
    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }
    
    // Set scan types to include all available
    const scanOptions = {
      ...options,
      scanTypes: ['headers', 'tls', 'api']
    };
    
    // Start the comprehensive scan
    console.log(`API: Starting comprehensive scan for ${url}`);
    const results = await api.runScan(url, scanOptions);
    
    res.json(results);
  } catch (error) {
    console.error('API error:', error);
    res.status(500).json({ 
      error: error.message,
      status: 'error'
    });
  }
});

// Generate reports
app.post('/api/reports', async (req, res) => {
  try {
    const { url, options = {} } = req.body;
    
    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }
    
    // Generate reports
    console.log(`API: Generating reports for ${url}`);
    const result = await api.scanAndGenerateReports(url, options);
    
    res.json(result);
  } catch (error) {
    console.error('API error:', error);
    res.status(500).json({ 
      error: error.message,
      status: 'error'
    });
  }
});

/**
 * Start the API server
 * @param {Object} options - Server options
 * @returns {Object} - Server instance
 */
function startServer(options = {}) {
  const port = options.port || process.env.PORT || 3000;
  
  return app.listen(port, () => {
    console.log(`🚀 Web Security Tool API server running on port ${port}`);
  });
}

// Export the Express app and server starter
module.exports = {
  app,
  startServer
};

// Start server if executed directly
if (require.main === module) {
  startServer();
}