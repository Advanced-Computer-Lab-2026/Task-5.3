import request from 'supertest';
jest.mock('../../server/src/models/User.js', () => {
  const users = globalThis.__csrfTestUsers || (globalThis.__csrfTestUsers = new Map());
  return {
    User: {
      findOne: jest.fn(({ email }) => Promise.resolve(users.get(email) || null)),
      create: jest.fn(async (fields) => {
        const id = `user-${users.size + 1}`;
        const user = {
          ...fields,
          _id: { toString: () => id },
          comparePassword: async (password) => password === fields.password
        };
        users.set(fields.email, user);
        return user;
      }),
      findById: jest.fn((id) => ({
        lean: async () => Array.from(users.values()).find((user) => user._id.toString() === id) || null
      }))
    }
  };
});

jest.mock('../../server/src/models/Setting.js', () => {
  const settings = globalThis.__csrfTestSettings || (globalThis.__csrfTestSettings = new Map());
  return {
    Setting: {
      findOne: jest.fn(({ user }) => ({
        lean: async () => settings.get(user) || null
      })),
      findOneAndUpdate: jest.fn(async ({ user }, update) => {
        const doc = { user, ...update.$set, notifications: true };
        settings.set(user, doc);
        return doc;
      })
    }
  };
});

import app from '../../server/src/app.js';

beforeAll(() => {
  process.env.JWT_SECRET = 'test-secret';
  process.env.JWT_EXPIRES_IN = '1h';
  process.env.CSRF_SECRET = 'test-csrf-secret';
});

beforeEach(() => {
  globalThis.__csrfTestUsers.clear();
  globalThis.__csrfTestSettings.clear();
});

// Turn a response's Set-Cookie header into the "name=value" pairs a browser
// would echo back in the Cookie header on the next request.
function cookiePairs(setCookie) {
  return (setCookie || []).map((c) => c.split(';')[0]);
}

let counter = 0;
async function registerUser() {
  counter += 1;
  const email = `victim${Date.now()}_${counter}@test.dev`;
  const res = await request(app)
    .post('/api/auth/register')
    .send({ name: 'Victim', email, password: 'secret123' });
  expect(res.status).toBe(201);
  // The auth cookie the browser will now send automatically on every request.
  return cookiePairs(res.headers['set-cookie']);
}

describe('Account settings — recovery email', () => {
  test('a logged-in user can update their own recovery email (the happy path)', async () => {
    const authCookies = await registerUser();

    let cookies = [...authCookies];
    const headers = {};
    const tokenRes = await request(app).get('/api/csrf-token').set('Cookie', cookies.join('; '));
    expect(tokenRes.status).toBe(200);
    headers['x-csrf-token'] = tokenRes.body.csrfToken;
    cookies = [...cookies, ...cookiePairs(tokenRes.headers['set-cookie'])];

    const res = await request(app)
      .post('/api/settings/recovery-email')
      .set('Cookie', cookies.join('; '))
      .set(headers)
      .send({ recoveryEmail: 'legit@user.com' });
    expect(res.status).toBe(200);

    const check = await request(app).get('/api/settings').set('Cookie', authCookies.join('; '));
    expect(check.status).toBe(200);
    expect(check.body.settings.recoveryEmail).toBe('legit@user.com');
  });

  // The core CSRF test. A forged cross-site request carries the victim's auth
  // cookie (the browser sends it automatically) but NO anti-CSRF token. A secure
  // server must reject it; a vulnerable one performs the state change.
  test('a forged cross-site request with no CSRF token is rejected', async () => {
    const authCookies = await registerUser();

    const forged = await request(app)
      .post('/api/settings/recovery-email')
      .set('Cookie', authCookies.join('; ')) // only the auth cookie — as in a real CSRF
      .set('Origin', 'http://attacker.evil') // request originates off-site
      .send({ recoveryEmail: 'attacker@evil.com' });

    // Secure behavior: refuse the request for lack of a valid CSRF token.
    expect(forged.status).toBe(403);

    // And the victim's recovery email must be untouched.
    const check = await request(app).get('/api/settings').set('Cookie', authCookies.join('; '));
    expect(check.status).toBe(200);
    expect(check.body.settings.recoveryEmail).not.toBe('attacker@evil.com');
  });

});
