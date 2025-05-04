# SecurityHeaderX

<div align="center">
  
![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Node](https://img.shields.io/badge/node-%3E%3D14.16-brightgreen.svg)

</div>

A comprehensive web security analysis tool focused on detecting HTTP security header vulnerabilities and providing actionable remediation steps. SecurityHeaderX helps developers and security professionals identify and fix security misconfigurations in web applications.

## ✨ Features

- 🔍 **Security Header Analysis**: Thorough scanning of HTTP security headers with detailed findings
- 📊 **Risk Scoring**: Security grade assessment based on OWASP recommendations
- 🔐 **TLS/SSL Verification**: (Coming Soon) Analyze TLS configurations for vulnerabilities
- 🚨 **Remediation Guidance**: Clear instructions for fixing identified issues
- 📝 **Multiple Report Formats**: Console, HTML, and JSON reports
- 🔧 **Customizable**: Configurable scanning profiles for different security requirements
- 🔄 **API Support**: (Coming Soon) REST API for integration with CI/CD pipelines

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/911Abaddon/SecurityHeaderX.git

# Navigate to the project directory
cd SecurityHeaderX

# Install dependencies
npm install
```

## 📋 Usage

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
```

### Programmatic Usage

```javascript
const securityHeaderX = require('./index');

// Scan a URL and get results
async function scanWebsite() {
  const results = await securityHeaderX.scanUrl('https://example.com');
  console.log(results);
}

// Generate reports
async function generateReports() {
  const reportResult = await securityHeaderX.scanAndGenerateReports('https://example.com');
  console.log(`Reports saved to: ${reportResult.reports.html}`);
}

scanWebsite();
```

## 📊 Security Headers Analyzed

SecurityHeaderX thoroughly analyzes the following HTTP security headers:

| Header | Description | Security Impact |
|--------|-------------|----------------|
| Content-Security-Policy | Controls resources the browser can load | Critical - Prevents XSS |
| Strict-Transport-Security | Forces HTTPS connections | Critical - Prevents MITM attacks |
| X-Content-Type-Options | Prevents MIME-sniffing | High - Prevents content-type attacks |
| X-Frame-Options | Controls framing of the page | High - Prevents clickjacking |
| Referrer-Policy | Controls referrer information | Medium - Prevents information leakage |
| Permissions-Policy | Restricts browser features | Medium - Reduces attack surface |
| X-XSS-Protection | Enables browser XSS filtering | Medium - Additional XSS protection |
| Cache-Control | Controls browser caching | Medium - Prevents sensitive data exposure |

## 🛠️ Project Structure

```
SecurityHeaderX/
├── api/                # REST API server
│   └── routes/         # API endpoints
├── cli/                # Command line interface
├── config/             # Configuration files
│   ├── compliance/     # Security standards (NIST, OWASP, PCI)
│   └── default.js      # Default configuration
├── docs/               # Documentation
├── src/
│   ├── analyzers/      # Specialized analyzers
│   ├── core/           # Core functionality
│   ├── headers/        # Header modules
│   ├── remediation/    # Remediation suggestions
│   ├── reports/        # Report generators
│   └── utils/          # Utility functions
├── tests/              # Test files
├── index.js            # Main entry point
└── package.json        # Project metadata
```

## 🧪 Development

Run tests:

```bash
npm test
```

Run tests with coverage:

```bash
npm run test:coverage
```

## 📝 Sample Report

SecurityHeaderX generates comprehensive reports with findings categorized by severity:

```
📊 SECURITY HEADER SCAN RESULTS
--------------------------------------------------
URL: https://example.com
Status: 200
Score: 65/100 (Grade C)
Scan Time: May 4, 2025, 10:15:00 AM
--------------------------------------------------

❌ MISSING HEADERS (3)
  HIGH SEVERITY ISSUES (1):
    Content-Security-Policy (CSP)
      Description: Controls resources the browser is allowed to load
      Recommendation: Add Content-Security-Policy header with appropriate directives

  MEDIUM SEVERITY ISSUES (2):
    Referrer-Policy
      Description: Controls how much referrer information should be included with requests
      Recommendation: Add "Referrer-Policy: strict-origin-when-cross-origin" header
    
    Permissions-Policy
      Description: Controls which browser features can be used on the page
      Recommendation: Implement a Permissions-Policy to restrict unnecessary features

⚠️ MISCONFIGURED HEADERS (1)
  HIGH SEVERITY ISSUES (1):
    Strict-Transport-Security (HSTS)
      Current Value: max-age=15768000
      Issue: HSTS max-age is less than 1 year
      Recommendation: Increase max-age to at least 31536000 (1 year)
```

## 🗺️ Roadmap

- [x] HTTP security header analysis
- [x] Multiple report formats (Console, HTML, JSON)
- [ ] TLS/SSL verification
- [ ] API security assessment
- [ ] Web UI for interactive scanning
- [ ] CI/CD integration
- [ ] Custom scan profiles
- [ ] Docker containerization

## 🤝 Contributing

Contributions are welcome! Feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgements

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Mozilla Observatory](https://observatory.mozilla.org/)
- [SecurityHeaders.com](https://securityheaders.com/)