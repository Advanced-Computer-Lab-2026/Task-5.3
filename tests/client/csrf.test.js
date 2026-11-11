import { api } from '../../client/src/api.js';

function getHeader(headers, name) {
  if (!headers) return undefined;
  if (typeof headers.get === 'function') return headers.get(name);
  return headers[name] ?? headers[name.toLowerCase()];
}

describe('client API CSRF behavior', () => {
  let captured;

  beforeEach(() => {
    captured = [];
    api.defaults.adapter = async config => {
      if ((config.url || '').includes('/csrf-token')) {
        return {
          data: { csrfToken: 'test-token' },
          status: 200,
          statusText: 'OK',
          headers: {},
          config
        };
      }
      captured.push(config);
      return { data: {}, status: 200, statusText: 'OK', headers: {}, config };
    };
  });

  test('requests include credentials so the auth cookie is sent', () => {
    expect(api.defaults.withCredentials).toBe(true);
  });

  test('mutating requests include the CSRF token header', async () => {
    await api.post('/settings/recovery-email', { recoveryEmail: 'legit@user.com' });

    const sent = captured.find(config => (config.url || '').includes('/settings/recovery-email'));
    expect(sent).toBeDefined();
    expect(getHeader(sent.headers, 'x-csrf-token')).toBe('test-token');
  });
});
