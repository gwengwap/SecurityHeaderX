const nock = require('nock');
const { HttpClient } = require('../../../lib/core/http-client');

describe('HTTP Client', () => {
  let httpClient;

  beforeEach(() => {
    nock.cleanAll();
    httpClient = new HttpClient({ timeout: 1000 });
  });

  test('should successfully fetch headers from a valid URL', async () => {
    const mockHeaders = {
      'strict-transport-security': 'max-age=31536000',
      'content-security-policy': "default-src 'self'"
    };

    nock('https://example.com')
      .head('/')
      .reply(200, '', mockHeaders);

    const result = await httpClient.fetchHeaders('https://example.com');
    expect(result.headers).toMatchObject(mockHeaders);
  });

  test('should handle non-existent domains', async () => {
    nock('https://nonexistent.example.com')
      .head('/')
      .replyWithError('getaddrinfo ENOTFOUND');

    await expect(httpClient.fetchHeaders('https://nonexistent.example.com'))
      .rejects
      .toThrow(/Network error accessing.*ENOTFOUND/);
  });

  test('should handle timeouts', async () => {
    nock('https://example.com')
      .head('/')
      .delay(10000)
      .reply(200);

    await expect(httpClient.fetchHeaders('https://example.com'))
      .rejects
      .toThrow(/timeout/);
  });

  test('should handle redirects', async () => {
    const mockHeaders = {
      'strict-transport-security': 'max-age=31536000'
    };

    nock('https://example.com')
      .head('/')
      .reply(301, '', { 'location': 'https://www.example.com' });

    nock('https://www.example.com')
      .head('/')
      .reply(200, '', mockHeaders);

    const result = await httpClient.fetchHeaders('https://example.com');
    expect(result.headers).toMatchObject(mockHeaders);
  });
}); 