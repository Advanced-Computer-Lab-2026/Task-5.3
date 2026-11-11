import { api } from '../../client/src/api.js';

// Read a header value whether axios stored it as a plain object or an AxiosHeaders.
function getHeader(headers, name) {
  if (!headers) return undefined;
  if (typeof headers.get === 'function') return headers.get(name);
  return headers[name] ?? headers[name.toLowerCase()];
}

describe('client api CSRF behavior', () => {
  let captured;

  beforeEach(() => {
    captured = [];
    // Stub the network layer. Answer the CSRF-token request with a known token
    // and record every other outgoing request so we can inspect its headers.
    api.defaults.adapter = async (config) => {
      if ((config.url || '').includes('/csrf-token')) {
        return { data: { csrfToken: 'test-token' }, status: 200, statusText: 'OK', headers: {}, config };
      }
      captured.push(config);
      return { data: {}, status: 200, statusText: 'OK', headers: {}, config };
    };
  });

  test('requests are sent with credentials so the auth cookie rides along', () => {
    expect(api.defaults.withCredentials).toBe(true);
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

describe('CSRF client request boundaries', () => {
  let calls;
  let token;
  beforeEach(() => {
    calls = [];
    token = 'current-session';
    api.defaults.adapter = async config => {
      calls.push(config);
      return {
        data: config.url === '/csrf-token' ? { csrfToken: token } : {},
        status: 200, statusText: 'OK', headers: {}, config
      };
    };
  });

  test.each(['get', 'head', 'options'])('%s does not fetch or attach a CSRF token', async method => {
    await api.request({ method, url: '/items' });
    expect(calls).toHaveLength(1);
    expect(getHeader(calls[0].headers, 'x-csrf-token')).toBeUndefined();
  });

  test.each(['/auth/login', '/auth/register'])('%s works before a session exists', async url => {
    await api.post(url, {});
    expect(calls).toHaveLength(1);
    expect(getHeader(calls[0].headers, 'x-csrf-token')).toBeUndefined();
  });

  test.each(['post', 'put', 'patch', 'delete'])('%s sends the current token', async method => {
    await api.request({ method, url: '/items' });
    expect(calls.map(c => c.url)).toEqual(['/csrf-token', '/items']);
    expect(getHeader(calls[1].headers, 'x-csrf-token')).toBe(token);
  });

  test('writes use the new session token after login', async () => {
    await api.post('/settings/recovery-email', {});
    await api.post('/auth/login', {});
    token = 'new-session';
    await api.post('/settings/recovery-email', {});
    expect(getHeader(calls[calls.length - 1].headers, 'x-csrf-token')).toBe('new-session');
  });

  test('a failed token fetch prevents the write', async () => {
    api.defaults.adapter = async config => {
      calls.push(config);
      throw new Error('Token endpoint unavailable');
    };
    await expect(api.post('/settings/recovery-email', {})).rejects.toThrow('Token endpoint unavailable');
    expect(calls.map(c => c.url)).toEqual(['/csrf-token']);
  });

  test('concurrent writes share token issuance', async () => {
    await Promise.all([api.post('/items', {}), api.post('/settings/recovery-email', {})]);
    expect(calls.filter(c => c.url === '/csrf-token')).toHaveLength(1);
    for (const config of calls.filter(c => c.url !== '/csrf-token')) {
      expect(getHeader(config.headers, 'x-csrf-token')).toBe(token);
    }
  });
});
