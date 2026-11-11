import { api, clearCsrfToken } from '../../client/src/api.js';

// Read a header value whether axios stored it as a plain object or an AxiosHeaders.
function getHeader(headers, name) {
  if (!headers) return undefined;
  if (typeof headers.get === 'function') return headers.get(name);
  return headers[name] ?? headers[name.toLowerCase()];
}

describe('client api CSRF behavior', () => {
  let captured;
  let issued;

  beforeEach(() => {
    captured = [];
    issued = 0;
    clearCsrfToken();
    // Stub the network layer. Answer the CSRF-token request with a known token
    // and record every other outgoing request so we can inspect its headers.
    api.defaults.adapter = async (config) => {
      if ((config.url || '').includes('/csrf-token')) {
        issued += 1;
        return { data: { csrfToken: 'test-token' }, status: 200, statusText: 'OK', headers: {}, config };
      }
      captured.push(config);
      return { data: {}, status: 200, statusText: 'OK', headers: {}, config };
    };
  });

  test('requests are sent with credentials so the auth cookie rides along', () => {
    expect(api.defaults.withCredentials).toBe(true);
  });

  test('concurrent writes share token issuance', async () => {
    await Promise.all([api.post('/settings/recovery-email', {}), api.patch('/items/123', {})]);
    expect(issued).toBe(1);
    expect(captured.every((c) => getHeader(c.headers, 'x-csrf-token') === 'test-token')).toBe(true);
  });

  test('safe reads and pre-auth writes do not fetch a token', async () => {
    await api.get('/settings');
    await api.post('/auth/login', {});
    await api.post('/auth/register', {});
    expect(issued).toBe(0);
  });

  test.each(['post', 'put', 'patch', 'delete'])('%s attaches the token', async (method) => {
    await api[method]('/items/123');
    expect(getHeader(captured[0].headers, 'x-csrf-token')).toBe('test-token');
  });

  test('logout is protected and clearing the cache fetches a new token', async () => {
    await api.post('/auth/logout');
    expect(getHeader(captured[0].headers, 'x-csrf-token')).toBe('test-token');
    clearCsrfToken();
    await api.post('/settings/recovery-email', {});
    expect(issued).toBe(2);
  });

  // A state-changing request must carry an anti-CSRF token in a header. The
  // attacker's forged request cannot set this header (and cannot read the token),
  // so this is what defeats CSRF. The vulnerable client never attaches it.
  test('a mutating request carries the x-csrf-token header', async () => {
    await api.post('/settings/recovery-email', { recoveryEmail: 'legit@user.com' });

    const sent = captured.find((c) => (c.url || '').includes('/settings/recovery-email'));
    expect(sent).toBeDefined();
    expect(getHeader(sent.headers, 'x-csrf-token')).toBe('test-token');
  });
});
