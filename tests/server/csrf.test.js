import request from 'supertest';
import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import app from '../../server/src/app.js';

let mongo;

beforeAll(async () => {
  process.env.JWT_SECRET = 'test-secret';
  process.env.JWT_EXPIRES_IN = '1h';
  process.env.CSRF_SECRET = 'test-csrf-secret';
  // npm pretest prepares the binary. Never start a background download in Jest.
  process.env.MONGOMS_RUNTIME_DOWNLOAD = 'false';
  mongo = new MongoMemoryServer();
  await mongo.start();
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
  test('the localhost attacker form cannot overwrite an existing email', async () => {
    const agent = request.agent(app);
    await agent.post('/api/auth/register').send({
      name: 'Form Victim', email: 'form-victim@test.dev', password: 'secret123'
    }).expect(201);
    const token = await agent.get('/api/csrf-token').expect(200);
    await agent.post('/api/settings/recovery-email')
      .set('x-csrf-token', token.body.csrfToken)
      .send({ recoveryEmail: 'original@test.dev' }).expect(200);
    await agent.post('/api/settings/recovery-email')
      .set('Origin', 'http://localhost:1337').type('form')
      .send({ recoveryEmail: 'attacker@evil.com' }).expect(403);
    const check = await agent.get('/api/settings').expect(200);
    expect(check.body.settings.recoveryEmail).toBe('original@test.dev');
  });

  test('tokens are session-bound and all other writes require protection', async () => {
    const first = await registerUser();
    const second = await registerUser();
    const token = await request(app).get('/api/csrf-token').set('Cookie', first).expect(200);
    const stolen = [...second, ...cookiePairs(token.headers['set-cookie'])];
    await request(app).post('/api/settings/recovery-email').set('Cookie', stolen)
      .set('x-csrf-token', token.body.csrfToken)
      .send({ recoveryEmail: 'attacker@evil.com' }).expect(403);
    for (const [method, path] of [['post', '/api/items'], ['patch', '/api/items/example'],
      ['delete', '/api/items/example'], ['post', '/api/auth/logout']]) {
      await request(app)[method](path).set('Cookie', second).send({}).expect(403);
    }
    await request(app).get('/api/csrf-token').expect(401);
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
