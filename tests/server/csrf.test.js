import request from 'supertest';
import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import app from '../../server/src/app.js';
import jwt from 'jsonwebtoken';
import { assertCsrfSecret } from '../../server/src/middleware/csrf.js';

let mongo;

beforeAll(async () => {
  process.env.JWT_SECRET = 'test-secret';
  process.env.JWT_EXPIRES_IN = '1h';
  process.env.CSRF_SECRET = 'test-csrf-secret';
  mongo = await MongoMemoryServer.create();
  await mongoose.connect(mongo.getUri());
}, 60000);

afterAll(async () => {
  await mongoose.disconnect();
  if (mongo) await mongo.stop();
});

describe('Session-bound CSRF protection', () => {
  async function session() {
    const authCookies = await registerUser();
    const response = await request(app).get('/api/csrf-token').set('Cookie', authCookies.join('; '));
    expect(response.status).toBe(200);
    return {
      authCookies,
      csrfCookies: cookiePairs(response.headers['set-cookie']),
      token: response.body.csrfToken,
      response
    };
  }

  async function save(cookies, token, email = 'original@test.dev') {
    return request(app).post('/api/settings/recovery-email')
      .set('Cookie', cookies.join('; ')).set('x-csrf-token', token)
      .send({ recoveryEmail: email });
  }

  test('token issuance requires authentication and sets a private, reusable cookie', async () => {
    expect((await request(app).get('/api/csrf-token')).status).toBe(401);
    const s = await session();
    expect(s.response.headers['cache-control']).toBe('no-store');
    expect(s.response.headers['set-cookie'][0]).toMatch(/HttpOnly/);
    expect(s.response.headers['set-cookie'][0]).toMatch(/SameSite=Lax/);
    expect(s.response.headers['set-cookie'][0]).toMatch(/Path=\//);
    expect(s.response.headers['set-cookie'][0]).not.toMatch(/; Domain=/);
    const reused = await request(app).get('/api/csrf-token')
      .set('Cookie', [...s.authCookies, ...s.csrfCookies].join('; '));
    expect(reused.status).toBe(200);
    expect(reused.body.csrfToken).toBe(s.token);
  });

  test.each(['form', 'incorrect header', 'missing cookie', 'body token only', 'other session'])(
    '%s cannot change an existing recovery email', async (attack) => {
      const s = await session();
      const cookies = [...s.authCookies, ...s.csrfCookies];
      expect((await save(cookies, s.token)).status).toBe(200);
      let attackCookies = cookies;
      let header;
      if (attack === 'incorrect header') header = 'incorrect-token';
      if (attack === 'missing cookie') {
        attackCookies = s.authCookies;
        header = s.token;
      }
      if (attack === 'other session') {
        const other = await session();
        attackCookies = [...s.authCookies, ...other.csrfCookies];
        header = other.token;
      }
      let forged = request(app).post('/api/settings/recovery-email')
        .set('Cookie', attackCookies.join('; ')).set('Origin', 'http://localhost:1337');
      if (header) forged = forged.set('x-csrf-token', header);
      if (attack === 'form') forged = forged.type('form');
      const response = await forged.send({
        recoveryEmail: 'attacker@evil.com',
        ...(attack === 'body token only' ? { csrfToken: s.token } : {})
      });
      expect(response.status).toBe(403);
      expect(response.body.message).toBe('invalid csrf token');
      const check = await request(app).get('/api/settings').set('Cookie', s.authCookies.join('; '));
      expect(check.body.settings.recoveryEmail).toBe('original@test.dev');
    }
  );

  test.each([
    ['post', '/api/items'], ['patch', '/api/items/123'], ['delete', '/api/items/123'],
    ['patch', '/api/users/123'], ['delete', '/api/users/123'], ['post', '/api/auth/logout']
  ])('%s %s rejects writes without tokens', async (method, path) => {
    const authCookies = await registerUser();
    const response = await request(app)[method](path).set('Cookie', authCookies.join('; ')).send({});
    expect(response.status).toBe(403);
  });

  test('safe requests do not need CSRF tokens', async () => {
    const authCookies = await registerUser();
    expect((await request(app).get('/api/settings').set('Cookie', authCookies.join('; '))).status).toBe(200);
    expect((await request(app).head('/api/settings').set('Cookie', authCookies.join('; '))).status).toBe(200);
    expect((await request(app).options('/api/settings/recovery-email')).status).toBe(204);
  });

  test('login rotates the session, clears its CSRF cookie, and rejects the previous token', async () => {
    const email = `rotate${Date.now()}@test.dev`;
    const registered = await request(app).post('/api/auth/register')
      .send({ name: 'Victim', email, password: 'secret123' });
    expect(registered.status).toBe(201);
    const initialCookies = cookiePairs(registered.headers['set-cookie']);
    const tokenRes = await request(app).get('/api/csrf-token').set('Cookie', initialCookies.join('; '));
    const oldCsrfCookies = cookiePairs(tokenRes.headers['set-cookie']);
    const login = await request(app).post('/api/auth/login')
      .set('Cookie', [...initialCookies, ...oldCsrfCookies].join('; '))
      .send({ email, password: 'secret123' });
    expect(login.status).toBe(200);
    const newAuth = cookiePairs(login.headers['set-cookie']).filter((c) => c.startsWith('token='));
    const oldJwt = jwt.decode(initialCookies.find((c) => c.startsWith('token=')).slice(6));
    const newJwt = jwt.decode(newAuth[0].slice(6));
    expect(newJwt.jti).toBeTruthy();
    expect(newJwt.jti).not.toBe(oldJwt.jti);
    expect(login.headers['set-cookie'].some((c) => c.startsWith('csrf-token=;'))).toBe(true);
    expect((await save([...newAuth, ...oldCsrfCookies], tokenRes.body.csrfToken)).status).toBe(403);
    const refreshed = await request(app).get('/api/csrf-token')
      .set('Cookie', [...newAuth, ...oldCsrfCookies].join('; '));
    expect(refreshed.status).toBe(200);
    expect(refreshed.body.csrfToken).not.toBe(tokenRes.body.csrfToken);
    const cookies = [...newAuth, ...cookiePairs(refreshed.headers['set-cookie'])];
    expect((await save(cookies, refreshed.body.csrfToken)).status).toBe(200);
    const logout = await request(app).post('/api/auth/logout').set('Cookie', cookies.join('; '))
      .set('x-csrf-token', refreshed.body.csrfToken);
    expect(logout.status).toBe(200);
    expect(logout.headers['set-cookie'].some((c) => c.startsWith('token=;'))).toBe(true);
    expect(logout.headers['set-cookie'].some((c) => c.startsWith('csrf-token=;'))).toBe(true);
  });

  test('missing CSRF_SECRET fails configuration validation', () => {
    const original = process.env.CSRF_SECRET;
    try {
      delete process.env.CSRF_SECRET;
      expect(assertCsrfSecret).toThrow('CSRF_SECRET');
    } finally {
      process.env.CSRF_SECRET = original;
    }
  });
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

    // The real client fetches a CSRF token first. The vulnerable app has no such
    // endpoint (404) — tolerate that so this control test passes in both projects.
    let cookies = [...authCookies];
    const headers = {};
    const tokenRes = await request(app).get('/api/csrf-token').set('Cookie', cookies.join('; '));
    if (tokenRes.status === 200) {
      headers['x-csrf-token'] = tokenRes.body.csrfToken;
      cookies = [...cookies, ...cookiePairs(tokenRes.headers['set-cookie'])];
    }

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
