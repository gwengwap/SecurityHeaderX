const essentialHeaders = require('../../../lib/headers/essential');

describe('Essential Headers Analysis', () => {
  test('should detect missing HSTS header', () => {
    const headers = {
      'content-type': 'text/html',
      'server': 'nginx'
    };
    
    const result = essentialHeaders['strict-transport-security'].checkConfiguration(headers['strict-transport-security']);
    expect(result).toBeDefined();
    expect(result.issue).toContain('HSTS header missing');
  });

  test('should properly analyze present HSTS header', () => {
    const headers = {
      'strict-transport-security': 'max-age=31536000; includeSubDomains; preload'
    };
    
    const result = essentialHeaders['strict-transport-security'].checkConfiguration(headers['strict-transport-security']);
    expect(result).toBeNull();
  });

  test('should detect missing CSP header', () => {
    const headers = {
      'content-type': 'text/html'
    };
    
    const result = essentialHeaders['content-security-policy'].checkConfiguration(headers['content-security-policy']);
    expect(result).toBeDefined();
    expect(result.issue).toContain('CSP');
  });

  test('should properly analyze present CSP header', () => {
    const headers = {
      'content-security-policy': "default-src 'self'; script-src 'self'; style-src 'self'"
    };
    
    const result = essentialHeaders['content-security-policy'].checkConfiguration(headers['content-security-policy']);
    expect(result).toBeNull();
  });
}); 