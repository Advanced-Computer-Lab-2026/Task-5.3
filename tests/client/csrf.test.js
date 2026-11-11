import axios from 'axios';
import { api, fetchCsrfToken } from '../../client/src/api.js';

describe('Client-side CSRF Protection', () => {
  beforeEach(() => {
    jest.restoreAllMocks();
  });

  test('fetches a CSRF token from the server and stores it', async () => {
    const mockGet = jest.spyOn(axios, 'get').mockResolvedValue({ 
      data: { csrfToken: 'mock-csrf-token-123' } 
    });
    
    await fetchCsrfToken();
    
    expect(mockGet).toHaveBeenCalledWith(
      'http://localhost:4000/api/csrf-token', 
      expect.any(Object)
    );
  });

  test('automatically attaches the CSRF token to unsafe requests (POST/PUT/DELETE)', async () => {
    // 1. Populate the token in memory
    jest.spyOn(axios, 'get').mockResolvedValue({ 
      data: { csrfToken: 'mock-csrf-token-123' } 
    });
    await fetchCsrfToken();

    // 2. Access the Axios interceptor we wrote in client/src/api.js
    const interceptor = api.interceptors.request.handlers[0].fulfilled;
    
    // 3. Simulate a POST request configuration
    const config = { method: 'post', headers: {} };
    
    // 4. Run the interceptor
    const updatedConfig = await interceptor(config);
    
    // 5. Verify the token was attached to the headers
    expect(updatedConfig.headers['x-csrf-token']).toBe('mock-csrf-token-123');
  });
});