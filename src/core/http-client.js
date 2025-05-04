/**
 * HTTP Client for making requests to websites for security header analysis
 */

const axios = require('axios');
const config = require('../../config');

class HttpClient {
  /**
   * Create a new HttpClient instance
   * @param {Object} options - Configuration options
   * @param {number} options.timeout - Timeout in milliseconds
   * @param {string} options.userAgent - User agent string
   * @param {number} options.maxRedirects - Maximum number of redirects to follow
   */
  constructor(options = {}) {
    this.timeout = options.timeout || config.defaultTimeout;
    this.userAgent = options.userAgent || config.defaultUserAgent;
    this.maxRedirects = options.maxRedirects || config.defaultMaxRedirects;
    
    // Create an axios instance with defaults
    this.axiosInstance = axios.create({
      timeout: this.timeout,
      headers: {
        'User-Agent': this.userAgent
      },
      maxRedirects: this.maxRedirects,
      validateStatus: function (status) {
        return status >= 200 && status < 600; // Accept all status codes to analyze headers
      }
    });
    
    // Add response interceptor for consistent error handling
    this.axiosInstance.interceptors.response.use(
      response => response,
      error => {
        // Enhance error with context
        if (error.response) {
          error.status = error.response.status;
          error.headers = error.response.headers;
        }
        return Promise.reject(error);
      }
    );
  }

  /**
   * Validate and normalize URL
   * @param {string} url - The URL to validate
   * @returns {string} - Normalized URL
   */
  validateUrl(url) {
    if (!url || typeof url !== 'string') {
      throw new Error('URL is required and must be a string');
    }
    
    try {
      // Normalize the URL
      const parsedUrl = new URL(url.startsWith('http') ? url : `https://${url}`);
      return parsedUrl.toString();
    } catch (error) {
      throw new Error(`Invalid URL: ${url}`);
    }
  }

  /**
   * Fetch a URL and return the response
   * @param {string} url - The URL to fetch
   * @returns {Promise<Object>} - The HTTP response
   */
  async fetch(url) {
    const normalizedUrl = this.validateUrl(url);
    
    try {
      const response = await this.axiosInstance.get(normalizedUrl);
      
      return {
        status: response.status,
        headers: response.headers,
        data: response.data
      };
    } catch (error) {
      // Enhanced error handling
      if (error.code === 'ENOTFOUND') {
        throw new Error(`Domain not found: ${url}`);
      } else if (error.code === 'ETIMEDOUT') {
        throw new Error(`Connection timed out for: ${url} (after ${this.timeout}ms)`);
      } else if (error.response) {
        return {
          status: error.response.status,
          headers: error.response.headers || {},
          error: error.message
        };
      } else {
        throw new Error(`Network error accessing ${url}: ${error.message}`);
      }
    }
  }

  /**
   * Fetch multiple URLs in parallel
   * @param {string[]} urls - The URLs to fetch
   * @returns {Promise<Object[]>} - Array of HTTP responses
   */
  async fetchMultiple(urls) {
    const validUrls = urls.map(url => this.validateUrl(url));
    const promises = validUrls.map(url => this.fetch(url));
    return Promise.all(promises);
  }

  /**
   * Make a HEAD request to get headers only
   * @param {string} url - The URL to check
   * @returns {Promise<Object>} - The HTTP headers
   */
  async fetchHeaders(url) {
    const normalizedUrl = this.validateUrl(url);
    
    try {
      const response = await this.axiosInstance({
        method: 'HEAD',
        url: normalizedUrl
      });

      return {
        status: response.status,
        headers: response.headers
      };
    } catch (error) {
      // Enhanced error handling similar to fetch
      if (error.code === 'ENOTFOUND') {
        throw new Error(`Domain not found: ${url}`);
      } else if (error.code === 'ETIMEDOUT') {
        throw new Error(`Connection timed out for: ${url} (after ${this.timeout}ms)`);
      } else if (error.response) {
        return {
          status: error.response.status,
          headers: error.response.headers || {},
          error: error.message
        };
      } else {
        throw new Error(`Network error accessing ${url}: ${error.message}`);
      }
    }
  }
}

module.exports = { HttpClient };