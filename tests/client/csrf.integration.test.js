import { api, clearCsrfToken } from '../../client/src/api.js';

describe('focused client CSRF behavior', () => {
  let requests;

  beforeEach(() => {
    clearCsrfToken();
    requests = [];
    api.defaults.adapter = async (config) => {
      requests.push(config);
      const data = (config.url || '').includes('/csrf-token') ? { csrfToken: 'focused-token' } : {};
      return { data, status: 200, statusText: 'OK', headers: {}, config };
    };
  });

  test('safe GET requests do not fetch or attach CSRF tokens', async () => {
    await api.get('/items');
    expect(requests.map((request) => request.url)).toEqual(['/items']);
    expect(requests[0].headers.get('x-csrf-token')).toBeUndefined();
  });

  test.each(['/auth/login', '/auth/register'])('%s remains a pre-auth mutation', async (url) => {
    await api.post(url, {});
    expect(requests.map((request) => request.url)).toEqual([url]);
    expect(requests[0].headers.get('x-csrf-token')).toBeUndefined();
  });

  test('authenticated mutations reuse an in-memory token', async () => {
    await api.post('/items', {});
    await api.patch('/items/123', {});
    const tokenRequests = requests.filter((request) => request.url === '/csrf-token');
    expect(tokenRequests).toHaveLength(1);
    for (const request of requests.filter((entry) => entry.url !== '/csrf-token')) {
      expect(request.headers.get('x-csrf-token')).toBe('focused-token');
    }
  });
});
