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
  test('a new login cannot reuse the previous session CSRF token', async () => {
    const email = `session${Date.now()}@test.dev`;
    const registration = await request(app).post('/api/auth/register')
      .send({ name: 'Victim', email, password: 'secret123' });
    expect(registration.status).toBe(201);
    const oldAuth = cookiePairs(registration.headers['set-cookie']);
    const oldToken = await request(app).get('/api/csrf-token').set('Cookie', oldAuth.join('; '));
    expect(oldToken.status).toBe(200);

    const login = await request(app).post('/api/auth/login').send({ email, password: 'secret123' });
    expect(login.status).toBe(200);
    const newAuth = cookiePairs(login.headers['set-cookie']);
    expect(newAuth).not.toEqual(oldAuth);
    const staleCookies = [...newAuth, ...cookiePairs(oldToken.headers['set-cookie'])];
    const rejected = await request(app).post('/api/settings/recovery-email')
      .set('Cookie', staleCookies.join('; '))
      .set('x-csrf-token', oldToken.body.csrfToken)
      .send({ recoveryEmail: 'stale@test.dev' });
    expect(rejected.status).toBe(403);

    const freshToken = await request(app).get('/api/csrf-token').set('Cookie', staleCookies.join('; '));
    expect(freshToken.status).toBe(200);
    expect(freshToken.body.csrfToken).not.toBe(oldToken.body.csrfToken);
    const accepted = await request(app).post('/api/settings/recovery-email')
      .set('Cookie', [...newAuth, ...cookiePairs(freshToken.headers['set-cookie'])].join('; '))
      .set('x-csrf-token', freshToken.body.csrfToken)
      .send({ recoveryEmail: 'fresh@test.dev' });
    expect(accepted.status).toBe(200);
  });

  test('an attacker HTML form cannot change an existing recovery email', async () => {
    const agent = request.agent(app);
    const registration = await agent.post('/api/auth/register').send({
      name: 'Victim', email: `form${Date.now()}@test.dev`, password: 'secret123'
    });
    expect(registration.status).toBe(201);
    const token = await agent.get('/api/csrf-token');
    expect(token.status).toBe(200);
    const saved = await agent.post('/api/settings/recovery-email')
      .set('x-csrf-token', token.body.csrfToken).send({ recoveryEmail: 'legit@user.com' });
    expect(saved.status).toBe(200);
    const forged = await agent.post('/api/settings/recovery-email')
      .set('Origin', 'http://localhost:1337').type('form')
      .send({ recoveryEmail: 'attacker@evil.com' });
    expect(forged.status).toBe(403);
    const settings = await agent.get('/api/settings');
    expect(settings.status).toBe(200);
    expect(settings.body.settings.recoveryEmail).toBe('legit@user.com');
  });

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
