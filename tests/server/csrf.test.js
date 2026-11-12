import request from 'supertest';
import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import app from '../../server/src/app.js';

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

function cookiePairs(setCookie) {
  return (setCookie || []).map((cookie) => cookie.split(';')[0]);
}

let counter = 0;
async function registerUser() {
  counter += 1;
  const email = `victim${Date.now()}_${counter}@test.dev`;
  const res = await request(app)
    .post('/api/auth/register')
    .send({ name: 'Victim', email, password: 'secret123' });
  expect(res.status).toBe(201);
  return cookiePairs(res.headers['set-cookie']);
}

describe('Account settings — recovery email', () => {
  test('a logged-in user can update their own recovery email', async () => {
    const authCookies = await registerUser();
    const tokenRes = await request(app)
      .get('/api/csrf-token')
      .set('Cookie', authCookies.join('; '));
    expect(tokenRes.status).toBe(200);

    const cookies = [...authCookies, ...cookiePairs(tokenRes.headers['set-cookie'])];
    const res = await request(app)
      .post('/api/settings/recovery-email')
      .set('Cookie', cookies.join('; '))
      .set('x-csrf-token', tokenRes.body.csrfToken)
      .send({ recoveryEmail: 'legit@user.com' });
    expect(res.status).toBe(200);

    const check = await request(app).get('/api/settings').set('Cookie', authCookies.join('; '));
    expect(check.status).toBe(200);
    expect(check.body.settings.recoveryEmail).toBe('legit@user.com');
  });

  test('a forged cross-site request without a CSRF token is rejected', async () => {
    const authCookies = await registerUser();
    const tokenRes = await request(app)
      .get('/api/csrf-token')
      .set('Cookie', authCookies.join('; '));
    expect(tokenRes.status).toBe(200);
    const cookies = [...authCookies, ...cookiePairs(tokenRes.headers['set-cookie'])];

    const baseline = 'victim@user.com';
    const legitimate = await request(app)
      .post('/api/settings/recovery-email')
      .set('Cookie', cookies.join('; '))
      .set('x-csrf-token', tokenRes.body.csrfToken)
      .send({ recoveryEmail: baseline });
    expect(legitimate.status).toBe(200);

    const forged = await request(app)
      .post('/api/settings/recovery-email')
      .set('Cookie', cookies.join('; '))
      .set('Origin', 'http://localhost:1337')
      .type('form')
      .send({ recoveryEmail: 'attacker@evil.com' });
    expect(forged.status).toBe(403);
    expect(forged.headers['set-cookie']).toBeUndefined();

    // The auth cookie was accepted, and the failed CSRF check did not log the
    // victim out or clear the cookie.
    const session = await request(app).get('/api/auth/me').set('Cookie', cookies.join('; '));
    expect(session.status).toBe(200);

    const check = await request(app).get('/api/settings').set('Cookie', cookies.join('; '));
    expect(check.status).toBe(200);
    expect(check.body.settings.recoveryEmail).toBe(baseline);
  });

  test('an invalid CSRF token is rejected without changing the recovery email', async () => {
    const authCookies = await registerUser();
    const forged = await request(app)
      .post('/api/settings/recovery-email')
      .set('Cookie', authCookies.join('; '))
      .set('x-csrf-token', 'forged-token')
      .send({ recoveryEmail: 'attacker@evil.com' });
    expect(forged.status).toBe(403);

    const check = await request(app).get('/api/settings').set('Cookie', authCookies.join('; '));
    expect(check.status).toBe(200);
    expect(check.body.settings.recoveryEmail).not.toBe('attacker@evil.com');
  });

  test('registration and login still establish an authenticated session', async () => {
    const email = `login${Date.now()}@test.dev`;
    const registration = await request(app)
      .post('/api/auth/register')
      .send({ name: 'Login Test', email, password: 'secret123' });
    expect(registration.status).toBe(201);

    const login = await request(app)
      .post('/api/auth/login')
      .send({ email, password: 'secret123' });
    expect(login.status).toBe(200);
    const cookies = cookiePairs(login.headers['set-cookie']);
    expect(cookies.some((cookie) => cookie.startsWith('token='))).toBe(true);

    const session = await request(app).get('/api/auth/me').set('Cookie', cookies.join('; '));
    expect(session.status).toBe(200);
    expect(session.body.user.email).toBe(email);
  });

  test('logout requires a valid CSRF token and clears both cookies', async () => {
    const authCookies = await registerUser();
    const tokenRes = await request(app)
      .get('/api/csrf-token')
      .set('Cookie', authCookies.join('; '));
    expect(tokenRes.status).toBe(200);
    const cookies = [...authCookies, ...cookiePairs(tokenRes.headers['set-cookie'])];

    const logout = await request(app)
      .post('/api/auth/logout')
      .set('Cookie', cookies.join('; '))
      .set('x-csrf-token', tokenRes.body.csrfToken);
    expect(logout.status).toBe(200);
    expect(logout.headers['set-cookie'].some((cookie) => cookie.startsWith('token=;'))).toBe(true);
    expect(logout.headers['set-cookie'].some((cookie) => cookie.startsWith('csrf-token=;'))).toBe(true);

    const session = await request(app).get('/api/auth/me');
    expect(session.status).toBe(401);
  });
});
