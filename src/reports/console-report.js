/**
 * Console Report Generator
 * Formats and prints security header scan results to the console
 */

// Handle Chalk v5 (ESM) compatibility
let chalk;

// Create a minimal chalk-like interface as fallback
const defaultChalk = {
  green: (text) => text,
  yellow: (text) => text,
  red: (text) => text,
  blue: (text) => text,
  gray: (text) => text,
  bold: (text) => text,
  white: (text) => text
};

// Try to import chalk either via require (v4) or dynamic import (v5)
try {
  // First try to require chalk (works for v4 and earlier)
  try {
    chalk = require('chalk');
  } catch (requireError) {
    // If require fails, set the fallback
    chalk = defaultChalk;
    
    // Attempt dynamic import for ESM version (v5+)
    // Note: This is an async operation, but we're setting up fallback first
    (async () => {
      try {
        const chalkModule = await import('chalk');
        chalk = chalkModule.default;
      } catch (importError) {
        // Keep using the fallback if import also fails
        console.warn('Warning: Chalk library not available, using plain text output');
      }
    })();
  }
} catch (error) {
  chalk = defaultChalk;
  console.warn('Warning: Chalk library not available, using plain text output');
}

/**
 * Print the scan results to the console in a readable format
 * @param {Object} results - The scan results
 */
function printResults(results) {
  if (!results) {
    console.error('Error: No results to print');
    return;
  }

  try {
    // Use a safer way to check properties that might not exist
    const url = results.url || 'Unknown URL';
    const statusCode = results.statusCode || 'Unknown';
    const score = typeof results.score === 'number' ? results.score : 0;
    const grade = results.grade || 'F';
    const timestamp = results.timestamp || new Date().toISOString();
    
    console.log('\n' + makeBold('📊 SECURITY HEADER SCAN RESULTS'));
    console.log(makeGray('-'.repeat(50)));
    console.log(`${makeBold('URL:')} ${url}`);
    console.log(`${makeBold('Status:')} ${statusCode}`);
    
    // Print score with color based on grade
    let scoreColor;
    if (score >= 80) scoreColor = makeGreen;
    else if (score >= 60) scoreColor = makeYellow;
    else scoreColor = makeRed;
    
    console.log(`${makeBold('Score:')} ${scoreColor(`${score}/100 (Grade ${grade})`)}`);
    console.log(`${makeBold('Scan Time:')} ${new Date(timestamp).toLocaleString()}`);
    console.log(makeGray('-'.repeat(50)));
    
    if (!results.findings || !Array.isArray(results.findings)) {
      console.error('No findings available in the results');
      return;
    }
    
    console.log('\n' + makeBold('📋 FINDINGS SUMMARY'));
    
    // Group findings by status
    const missing = results.findings.filter(f => f.status === 'missing');
    const misconfigured = results.findings.filter(f => f.status === 'misconfigured');
    const dangerous = results.findings.filter(f => f.status === 'dangerous');
    const present = results.findings.filter(f => f.status === 'present');
    
    // Severity order: high, medium, low, info, undefined
    const criticalityOrder = ['high', 'medium', 'low', 'info', undefined];
    
    // Sort function for findings by criticality
    const sortByCriticality = (a, b) => {
      const aIndex = criticalityOrder.indexOf(a.criticalRating);
      const bIndex = criticalityOrder.indexOf(b.criticalRating);
      return aIndex - bIndex;
    };
    
    // Print missing headers - sorted by criticality (high to low)
    if (missing.length > 0) {
      const sortedMissing = [...missing].sort(sortByCriticality);
      
      // Group by criticality
      const missingSeverityGroups = criticalityOrder.map(severity => 
        sortedMissing.filter(f => f.criticalRating === severity)
      ).filter(group => group.length > 0);
      
      console.log('\n' + makeRed(`❌ MISSING HEADERS (${missing.length})`));
      
      missingSeverityGroups.forEach(group => {
        const severity = group[0].criticalRating || 'unknown';
        const severityColor = getSeverityColor(severity);
        
        console.log(`\n  ${severityColor(severity.toUpperCase())} SEVERITY ISSUES (${group.length}):`);
        
        group.forEach(finding => {
          printFinding(finding);
        });
      });
    }
    
    // Print misconfigured headers - sorted by criticality (high to low)
    if (misconfigured.length > 0) {
      const sortedMisconfigured = [...misconfigured].sort(sortByCriticality);
      
      // Group by criticality
      const misconfiguredSeverityGroups = criticalityOrder.map(severity => 
        sortedMisconfigured.filter(f => f.criticalRating === severity)
      ).filter(group => group.length > 0);
      
      console.log('\n' + makeYellow(`⚠️ MISCONFIGURED HEADERS (${misconfigured.length})`));
      
      misconfiguredSeverityGroups.forEach(group => {
        const severity = group[0].criticalRating || 'unknown';
        const severityColor = getSeverityColor(severity);
        
        console.log(`\n  ${severityColor(severity.toUpperCase())} SEVERITY ISSUES (${group.length}):`);
        
        group.forEach(finding => {
          printFinding(finding);
        });
      });
    }
    
    // Print dangerous headers - sorted by criticality (high to low)
    if (dangerous.length > 0) {
      const sortedDangerous = [...dangerous].sort(sortByCriticality);
      
      // Group by criticality
      const dangerousSeverityGroups = criticalityOrder.map(severity => 
        sortedDangerous.filter(f => f.criticalRating === severity)
      ).filter(group => group.length > 0);
      
      console.log('\n' + makeYellow(`🚨 INFORMATION DISCLOSURE HEADERS (${dangerous.length})`));
      
      dangerousSeverityGroups.forEach(group => {
        const severity = group[0].criticalRating || 'unknown';
        const severityColor = getSeverityColor(severity);
        
        console.log(`\n  ${severityColor(severity.toUpperCase())} SEVERITY ISSUES (${group.length}):`);
        
        group.forEach(finding => {
          printFinding(finding);
        });
      });
    }
    
    // Print properly configured headers
    if (present.length > 0) {
      console.log('\n' + makeGreen(`✅ PROPERLY CONFIGURED HEADERS (${present.length})`));
      present.forEach(finding => {
        console.log(`  ${makeBold(finding.header)}`);
        console.log(`    ${makeGray('Value:')} ${finding.value}`);
      });
    }
    
    // Print overall recommendation
    console.log('\n' + makeBold('📝 OVERALL RECOMMENDATION'));
    if (score >= 90) {
      console.log(makeGreen('Excellent security header implementation! Make sure to keep them updated with industry best practices.'));
    } else if (score >= 70) {
      console.log(makeYellow('Good foundation, but there are some important headers missing or misconfigured. Address the high and medium priority findings.'));
    } else {
      console.log(makeRed('Significant security header issues detected. Implement the missing headers and fix the misconfigured ones to improve your security posture.'));
    }
  } catch (error) {
    console.error('Error printing results:', error.message);
    // Simplified fallback output
    console.log(`URL: ${results.url || 'Unknown'}`);
    console.log(`Score: ${results.score || 0}/100`);
    console.log(`Findings: ${results.findings ? results.findings.length : 0}`);
  }
}

/**
 * Print a single finding with formatting
 * @param {Object} finding - The finding to print
 */
function printFinding(finding) {
  if (!finding || typeof finding !== 'object') {
    console.error('Invalid finding object');
    return;
  }
  
  try {
    console.log(`    ${makeBold(finding.header || 'Unknown Header')}`);
    
    // Print different fields based on finding status
    if (finding.status === 'missing') {
      console.log(`      ${makeGray('Description:')} ${finding.description || 'No description'}`);
      console.log(`      ${makeGray('Recommendation:')} ${finding.recommendation || 'No recommendation'}`);
    } else if (finding.status === 'misconfigured') {
      console.log(`      ${makeGray('Current Value:')} ${finding.value || 'No value'}`);
      console.log(`      ${makeGray('Issue:')} ${finding.issue || 'Unspecified issue'}`);
      console.log(`      ${makeGray('Recommendation:')} ${finding.recommendation || 'No recommendation'}`);
    } else if (finding.status === 'dangerous') {
      console.log(`      ${makeGray('Current Value:')} ${finding.value || 'No value'}`);
      console.log(`      ${makeGray('Description:')} ${finding.description || 'No description'}`);
      console.log(`      ${makeGray('Recommendation:')} ${finding.recommendation || 'No recommendation'}`);
    }
    
    // Print critical rating with appropriate color
    const criticalRating = finding.criticalRating || 'unknown';
    const criticalColor = getSeverityColor(criticalRating);
    
    console.log(`      ${makeGray('Critical Rating:')} ${criticalColor(criticalRating.toUpperCase())}`);
  } catch (error) {
    console.error('Error printing finding:', error.message);
  }
}

/**
 * Get appropriate color function for a severity level
 * @param {string} severity - The severity level
 * @returns {Function} - The color function
 */
function getSeverityColor(severity) {
  switch(severity.toLowerCase()) {
    case 'high':
      return makeRed;
    case 'medium':
      return makeYellow;
    case 'low':
      return makeGreen;
    default:
      return makeBlue;
  }
}

// Helper functions that safely use chalk if available
function makeGreen(text) {
  try {
    return chalk.green(text);
  } catch (e) {
    return text;
  }
}

function makeYellow(text) {
  try {
    return chalk.yellow(text);
  } catch (e) {
    return text;
  }
}

function makeRed(text) {
  try {
    return chalk.red(text);
  } catch (e) {
    return text;
  }
}

function makeBlue(text) {
  try {
    return chalk.blue(text);
  } catch (e) {
    return text;
  }
}

function makeGray(text) {
  try {
    return chalk.gray(text);
  } catch (e) {
    return text;
  }
}

function makeBold(text) {
  try {
    return chalk.bold(text);
  } catch (e) {
    return text;
  }
}

module.exports = {
  printResults
};