# Web Security Tool

A comprehensive web security analysis tool that evolved from a security header checker. This tool scans websites for security vulnerabilities, starting with HTTP security headers and expanding to include TLS/SSL configuration and API security.

## Features

- Security header analysis
- TLS/SSL verification (coming soon)
- API security assessment (coming soon)
- Compliance mapping
- Remediation suggestions
- Multiple reporting formats (Console, HTML, JSON)
- REST API server

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/web-security-tool.git
cd web-security-tool

# Install dependencies
npm install
```

## Usage

### Command Line Interface

Scan a website for security headers:

```bash
node index.js https://example.com
```

With additional options:

```bash
# Generate HTML and JSON reports
node index.js https://example.com --reports

# Enable verbose output
node index.js https://example.com --verbose

# Perform a comprehensive scan (when implemented)
node index.js https://example.com --full
```

### Programmatic Usage

```javascript
const securityTool = require('./path/to/web-security-tool');

// Scan a URL and get results
async function scanWebsite() {
  const results = await securityTool.scanUrl('https://example.com');
  console.log(results);
}

// Generate reports
async function generateReports() {
  const reportResult = await securityTool.scanAndGenerateReports('https://example.com');
  console.log(`Reports saved to: ${reportResult.reports.html}`);
}

scanWebsite();
```

### REST API

Start the API server:

```bash
npm run start:api
```

The API server provides the following endpoints:

- `POST /api/scan` - Scan a URL for security headers
- `POST /api/scan/full` - Perform a comprehensive security scan
- `POST /api/reports` - Generate security reports

Example API request:

```bash
curl -X POST http://localhost:3000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

## Project Structure

```
web-security-tool/
├── api/                 # REST API server
│   └── index.js
├── cli/                 # Command line interface
│   └── index.js
├── config/              # Configuration files
│   ├── compliance/      # Security standards (NIST, OWASP, etc)
│   ├── default.js       # Default configuration
│   └── scan-profiles/   # Scanning profiles
├── docs/                # Documentation
├── src/                 # Source code
│   ├── analyzers/       # Specialized analyzers
│   ├── core/            # Core functionality
│   │   ├── api.js       # Main API module
│   │   ├── http-client.js # HTTP client
│   │   └── scanner.js   # Scanner engine
│   ├── headers/         # Header modules
│   ├── integrations/    # Third-party integrations
│   ├── remediation/     # Remediation suggestions
│   ├── reports/         # Report generators
│   ├── tls/             # TLS/SSL verification
│   └── utils/           # Utility functions
├── tests/               # Test files
├── index.js             # Main entry point
└── package.json         # Project metadata
```

## Development

Run tests:

```bash
npm test
```

Run tests with coverage:

```bash
npm run test:coverage
```

## Roadmap

- [x] HTTP security header analysis
- [ ] TLS/SSL verification
- [ ] API security assessment
- [ ] Web UI
- [ ] CI/CD integration
- [ ] Custom scan profiles