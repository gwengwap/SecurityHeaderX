/**
 * Core Security Header Checker class
 * Responsible for orchestrating the header checks and analyzing results
 */

// Import config from the same location as http-client.js
const config = require('../../config');

class SecurityHeaderChecker {
  /**
   * Create a new SecurityHeaderChecker instance
   * @param {Object} options - Configuration options
   * @param {Object} options.httpClient - HTTP client for making requests
   * @param {Object} options.securityHeaders - Security headers to check
   * @param {Object} options.analyzers - Specialized analyzers for headers
   * @param {boolean} options.verbose - Whether to log verbose output
   */
  constructor(options = {}) {
    this.httpClient = options.httpClient;
    this.securityHeaders = options.securityHeaders || {};
    this.verbose = options.verbose || false;
    
    // Properly initialize analyzers
    this.analyzers = options.analyzers || {};
  }

  /**
   * Check security headers for a given URL
   * @param {string} url - The URL to check
   * @returns {Promise<Object>} - The scan results
   */
  async checkUrl(url) {
    if (!url.startsWith('http')) {
      url = 'https://' + url;
    }

    console.log(`\n🔍 Checking security headers for: ${url}`);
    
    try {
      // Make the HTTP request
      const response = await this.httpClient.fetch(url);
      
      // Analyze the headers
      return this.analyzeHeaders(url, response.headers, response.status);
    } catch (error) {
      console.error(`❌ Error accessing ${url}: ${error.message}`);
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
   * Analyze the security headers from the response
   * @param {string} url - The URL that was checked
   * @param {Object} headers - The response headers
   * @param {number} statusCode - The HTTP status code
   * @returns {Object} - The analysis results
   */
  analyzeHeaders(url, headers, statusCode) {
    const normalizedHeaders = {};
    for (const [key, value] of Object.entries(headers)) {
      normalizedHeaders[key.toLowerCase()] = value;
    }

    const findings = [];
    
    // Initialize score tracking variables
    let score = 100;
    let scoreLog = [];

    // Track available points for each category
    const totalEssentialPoints = Object.values(config.essentialHeaderWeights || {}).reduce((a, b) => a + b, 0) || 60;
    const totalAdvancedPoints = Object.values(config.advancedHeaderWeights || {}).reduce((a, b) => a + b, 0) || 25;
    const totalCorsPoints = Object.values(config.corsHeaderWeights || {}).reduce((a, b) => a + b, 0) || 15;
    
    // Track earned points
    let earnedEssentialPoints = 0;
    let earnedAdvancedPoints = 0;
    let earnedCorsPoints = 0;
    
    // Check all security headers
    for (const [header, info] of Object.entries(this.securityHeaders)) {
      // Skip headers that are part of analyzer functions
      if (header === 'cookieAnalyzer' || header === 'dangerousHeaders') {
        continue;
      }
      
      // Determine header category and weight
      let headerWeight = 0;
      let category = '';
      
      // Assign weights and categories based on config
      if (config.essentialHeaderWeights && header in config.essentialHeaderWeights) {
        headerWeight = config.essentialHeaderWeights[header];
        category = 'essential';
      } else if (config.advancedHeaderWeights && header in config.advancedHeaderWeights) {
        headerWeight = config.advancedHeaderWeights[header];
        category = 'advanced';
      } else if (config.corsHeaderWeights && header in config.corsHeaderWeights) {
        headerWeight = config.corsHeaderWeights[header];
        category = 'cors';
      } else {
        // Fallback for headers not explicitly defined in config
        headerWeight = 5; // Default weight
        category = 'other';
      }
      
      if (!normalizedHeaders[header]) {
        // Header is missing - add finding but don't award points
        findings.push({
          header: info.name,
          status: 'missing',
          description: info.description,
          recommendation: info.recommendation,
          criticalRating: info.criticalRating,
          category: category,
          weight: headerWeight
        });
        
        scoreLog.push(`${info.name}: Missing (-${headerWeight} points)`);
      } else {
        // Header is present, check configuration
        let configIssue = null;
        if (info.checkConfiguration) {
          configIssue = info.checkConfiguration(normalizedHeaders[header], normalizedHeaders);
        }
        
        if (configIssue) {
          // Header is misconfigured - award partial points based on severity
          const penaltyMultiplier = config.misconfigurationPenalties?.[configIssue.criticalRating || info.criticalRating] || 0.5;
          const pointsLost = headerWeight * penaltyMultiplier;
          const pointsEarned = headerWeight - pointsLost;
          
          findings.push({
            header: info.name,
            status: 'misconfigured',
            value: normalizedHeaders[header],
            issue: configIssue.issue,
            recommendation: configIssue.recommendation,
            criticalRating: configIssue.criticalRating || info.criticalRating,
            category: category,
            weight: headerWeight,
            pointsEarned: pointsEarned
          });
          
          // Add points to the correct category
          if (category === 'essential') earnedEssentialPoints += pointsEarned;
          else if (category === 'advanced') earnedAdvancedPoints += pointsEarned;
          else if (category === 'cors') earnedCorsPoints += pointsEarned;
          
          scoreLog.push(`${info.name}: Misconfigured (earned ${pointsEarned.toFixed(1)} out of ${headerWeight} points)`);
        } else {
          // Header is properly configured - award full points
          findings.push({
            header: info.name,
            status: 'present',
            value: normalizedHeaders[header],
            criticalRating: info.criticalRating,
            category: category,
            weight: headerWeight,
            pointsEarned: headerWeight
          });
          
          // Add points to the correct category
          if (category === 'essential') earnedEssentialPoints += headerWeight;
          else if (category === 'advanced') earnedAdvancedPoints += headerWeight;
          else if (category === 'cors') earnedCorsPoints += headerWeight;
          
          scoreLog.push(`${info.name}: Present (earned ${headerWeight} points)`);
        }
      }
    }
    
    // Special handling for analyzer functions
    let dangerousPenalty = 0;
    let cookiePenalty = 0;
    
    // Check for dangerous headers
    if (this.analyzers.dangerousHeaders) {
      const dangerousResults = this.analyzers.dangerousHeaders(normalizedHeaders);
      if (dangerousResults && dangerousResults.findings && dangerousResults.findings.length > 0) {
        findings.push(...dangerousResults.findings);
        
        // Calculate penalty for dangerous headers
        dangerousResults.findings.forEach(finding => {
          if (finding.criticalRating && config.dangerousHeaderPenalties?.[finding.criticalRating]) {
            dangerousPenalty += config.dangerousHeaderPenalties[finding.criticalRating];
          } else {
            // Fallback for when config doesn't have dangerousHeaderPenalties
            const defaultPenalties = { high: 4, medium: 2, low: 1, info: 0.5 };
            dangerousPenalty += defaultPenalties[finding.criticalRating] || 1;
          }
        });
        
        // Cap the dangerous header penalty
        const maxPenalty = config.maxDangerousHeadersPenalty || 10;
        dangerousPenalty = Math.min(dangerousPenalty, maxPenalty);
        scoreLog.push(`Dangerous Headers: -${dangerousPenalty.toFixed(1)} points`);
      }
    }
    
    // Check for cookie security issues
    if (this.analyzers.cookieAnalyzer && normalizedHeaders['set-cookie']) {
      const cookieResults = this.analyzers.cookieAnalyzer(normalizedHeaders['set-cookie']);
      if (cookieResults && cookieResults.findings && cookieResults.findings.length > 0) {
        findings.push(...cookieResults.findings);
        
        // Calculate penalty for cookie issues
        cookieResults.findings.forEach(finding => {
          if (finding.issues) {
            finding.issues.forEach(issue => {
              if (issue.criticalRating && config.cookieSecurityPenalties?.[issue.criticalRating]) {
                cookiePenalty += config.cookieSecurityPenalties[issue.criticalRating];
              } else {
                // Fallback for when config doesn't have cookieSecurityPenalties
                const defaultPenalties = { high: 4, medium: 2, low: 1, info: 0.5 };
                cookiePenalty += defaultPenalties[issue.criticalRating] || 1;
              }
            });
          } else if (finding.criticalRating) {
            // Direct criticalRating on the finding
            const defaultPenalties = { high: 4, medium: 2, low: 1, info: 0.5 };
            cookiePenalty += config.cookieSecurityPenalties?.[finding.criticalRating] || 
                           defaultPenalties[finding.criticalRating] || 1;
          }
        });
        
        // Cap the cookie security penalty
        const maxPenalty = config.maxCookieSecurityPenalty || 10;
        cookiePenalty = Math.min(cookiePenalty, maxPenalty);
        scoreLog.push(`Cookie Security Issues: -${cookiePenalty.toFixed(1)} points`);
      }
    }
    
    // Calculate category percentages
    // Use standard distributions if config weights are not properly defined
    const essentialPercent = totalEssentialPoints > 0 ? (earnedEssentialPoints / totalEssentialPoints) : 0;
    const advancedPercent = totalAdvancedPoints > 0 ? (earnedAdvancedPoints / totalAdvancedPoints) : 0;
    const corsPercent = totalCorsPoints > 0 ? (earnedCorsPoints / totalCorsPoints) : 0;
    
    // Calculate weighted scores
    // We weight the categories differently to emphasize essential headers
    const essentialContribution = 60; // 60% of total
    const advancedContribution = 25; // 25% of total
    const corsContribution = 15;     // 15% of total
    
    const essentialScore = essentialPercent * essentialContribution;
    const advancedScore = advancedPercent * advancedContribution;
    const corsScore = corsPercent * corsContribution;
    
    // Combine scores and apply penalties
    score = essentialScore + advancedScore + corsScore - dangerousPenalty - cookiePenalty;
    
    // Ensure final score is between 0 and 100
    score = Math.max(0, Math.min(100, Math.round(score)));
    
    // Log detailed score breakdown if verbose mode is enabled
    if (this.verbose) {
      console.log('\n--- Score Breakdown ---');
      console.log(`Essential Headers: ${earnedEssentialPoints.toFixed(1)}/${totalEssentialPoints} (${essentialScore.toFixed(1)} points)`);
      console.log(`Advanced Headers: ${earnedAdvancedPoints.toFixed(1)}/${totalAdvancedPoints} (${advancedScore.toFixed(1)} points)`);
      console.log(`CORS Headers: ${earnedCorsPoints.toFixed(1)}/${totalCorsPoints} (${corsScore.toFixed(1)} points)`);
      console.log(`Dangerous Headers Penalty: -${dangerousPenalty.toFixed(1)}`);
      console.log(`Cookie Security Penalty: -${cookiePenalty.toFixed(1)}`);
      console.log('Detailed Point Allocation:');
      scoreLog.forEach(entry => console.log(`  ${entry}`));
      console.log(`Final Score: ${score}`);
    }

    return {
      url,
      statusCode,
      timestamp: new Date().toISOString(),
      headers: normalizedHeaders,
      findings,
      score: score,
      grade: this.calculateGrade(score),
      scoreBreakdown: {
        essential: { 
          earned: earnedEssentialPoints, 
          total: totalEssentialPoints, 
          weighted: essentialScore 
        },
        advanced: { 
          earned: earnedAdvancedPoints, 
          total: totalAdvancedPoints, 
          weighted: advancedScore 
        },
        cors: { 
          earned: earnedCorsPoints, 
          total: totalCorsPoints, 
          weighted: corsScore 
        },
        penalties: { 
          dangerous: dangerousPenalty, 
          cookies: cookiePenalty 
        }
      }
    };
  }

  /**
   * Calculate a letter grade based on the score
   * @param {number} score - The security score
   * @returns {string} - The letter grade
   */
  calculateGrade(score) {
    // Use config thresholds for consistent grading
    if (score >= config.scoringThresholds.A) return 'A';
    if (score >= config.scoringThresholds.B) return 'B';
    if (score >= config.scoringThresholds.C) return 'C';
    if (score >= config.scoringThresholds.D) return 'D';
    if (score >= config.scoringThresholds.E) return 'E';
    return 'F';
  }
}

module.exports = { SecurityHeaderChecker };