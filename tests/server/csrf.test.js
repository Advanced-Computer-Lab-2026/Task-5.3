import request from 'supertest';
import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import app from '../../server/src/app.js';
import { randomUUID } from 'node:crypto';

// A remote assignment database can throttle requests; local runs stay fast.
jest.setTimeout(process.env.TEST_MONGO_URI ? 120000 : 5000);

let mongo;
const testDatabaseName = `csrf_test_${randomUUID().replaceAll('-', '').slice(0, 24)}`;

beforeAll(async () => {
  process.env.JWT_SECRET = 'test-secret';
  process.env.JWT_EXPIRES_IN = '1h';
  process.env.CSRF_SECRET = 'test-csrf-secret';
  if (process.env.TEST_MONGO_URI) {
    // Always isolate external runs from the application's database.
    await mongoose.connect(process.env.TEST_MONGO_URI, {
      dbName: testDatabaseName, serverSelectionTimeoutMS: 15000
    });
  } else {
    mongo = await MongoMemoryServer.create();
    await mongoose.connect(mongo.getUri());
  }
}, 180000);

afterAll(async () => {
  try {
    if (process.env.TEST_MONGO_URI && mongoose.connection.readyState === 1 &&
        mongoose.connection.name === testDatabaseName) {
      // Assignment credentials allow CRUD but may forbid dropDatabase.
      await Promise.all(Object.values(mongoose.models).map(model => model.deleteMany({})));
    }
  } finally {
    await mongoose.disconnect();
    if (mongo) await mongo.stop();
  }
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

    // The real client must obtain a token for the authenticated session first.
    let cookies = [...authCookies];
    const headers = {};
    const tokenRes = await request(app).get('/api/csrf-token').set('Cookie', cookies.join('; '));
    expect(tokenRes.status).toBe(200);
    expect(tokenRes.body.csrfToken).toEqual(expect.any(String));
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

async function sessionToken(authCookies) {
  const res = await request(app).get('/api/csrf-token').set('Cookie', authCookies.join('; '));
  expect(res.status).toBe(200);
  expect(res.headers['cache-control']).toBe('no-store');
  return {
    token: res.body.csrfToken,
    cookies: [...authCookies, ...cookiePairs(res.headers['set-cookie'])]
  };
}

describe('CSRF session and route boundaries', () => {
  test('the localhost attacker form returns 403 and preserves the existing email', async () => {
    const auth = await registerUser();
    const { token, cookies } = await sessionToken(auth);
    const legitimate = await request(app).post('/api/settings/recovery-email')
      .set('Cookie', cookies.join('; ')).set('x-csrf-token', token)
      .send({ recoveryEmail: 'original@test.dev' });
    expect(legitimate.status).toBe(200);

    const forged = await request(app).post('/api/settings/recovery-email')
      .set('Cookie', cookies.join('; ')).set('Origin', 'http://localhost:1337')
      .type('form').send({ recoveryEmail: 'attacker@evil.com' });
    expect(forged.status).toBe(403);
    expect(forged.body.code).toBe('EBADCSRFTOKEN');
    const check = await request(app).get('/api/settings').set('Cookie', auth.join('; '));
    expect(check.body.settings.recoveryEmail).toBe('original@test.dev');
  });

  test('missing cookie, tampered header, body token, and another session token are rejected', async () => {
    const auth = await registerUser();
    const { token, cookies } = await sessionToken(auth);
    const other = await sessionToken(await registerUser());
    for (const [sentCookies, header, bodyToken] of [
      [auth, token, undefined],
      [cookies, 'tampered', undefined],
      [cookies, undefined, token],
      [[...auth, ...other.cookies.filter(c => !c.startsWith('token='))], other.token, undefined]
    ]) {
      let req = request(app).post('/api/settings/recovery-email').set('Cookie', sentCookies.join('; '));
      if (header) req = req.set('x-csrf-token', header);
      const res = await req.send({ recoveryEmail: 'attacker@evil.com', csrfToken: bodyToken });
      expect(res.status).toBe(403);
    }
  });

  test.each([
    ['post', '/api/items'], ['patch', '/api/items/000000000000000000000001'],
    ['delete', '/api/items/000000000000000000000001'],
    ['patch', '/api/users/000000000000000000000001'],
    ['delete', '/api/users/000000000000000000000001'], ['post', '/api/auth/logout']
  ])('%s %s requires a CSRF token', async (method, url) => {
    const auth = await registerUser();
    const res = await request(app)[method](url).set('Cookie', auth.join('; ')).send({});
    expect(res.status).toBe(403);
  });

  test('safe reads remain available and token issuance requires authentication', async () => {
    expect((await request(app).get('/api/health')).status).toBe(200);
    expect((await request(app).get('/api/items')).status).toBe(200);
    expect((await request(app).get('/api/csrf-token')).status).toBe(401);
    const auth = await registerUser();
    expect((await request(app).get('/api/settings').set('Cookie', auth.join('; '))).status).toBe(200);
  });

  test('a new login invalidates the previous login CSRF token and logout still works', async () => {
    const agent = request.agent(app);
    const credentials = { email: `sessions${Date.now()}@test.dev`, password: 'secret123' };
    expect((await agent.post('/api/auth/register').send({ name: 'Victim', ...credentials })).status).toBe(201);
    const before = await agent.get('/api/csrf-token');
    const login = await agent.post('/api/auth/login').send(credentials);
    expect(login.status).toBe(200);
    const after = await agent.get('/api/csrf-token');
    expect(after.body.csrfToken).not.toBe(before.body.csrfToken);
    const stale = await agent.post('/api/settings/recovery-email')
      .set('x-csrf-token', before.body.csrfToken).send({ recoveryEmail: 'stale@test.dev' });
    expect(stale.status).toBe(403);
    expect((await agent.post('/api/auth/logout').set('x-csrf-token', after.body.csrfToken)).status).toBe(200);
    expect((await agent.get('/api/auth/me')).status).toBe(401);
  });

  test('legitimate item and user writes still work with a CSRF token', async () => {
    const agent = request.agent(app);
    const registration = await agent.post('/api/auth/register').send({
      name: 'Owner', email: `owner${Date.now()}@test.dev`, password: 'secret123'
    });
    expect(registration.status).toBe(201);
    const { body: { csrfToken } } = await agent.get('/api/csrf-token');
    const created = await agent.post('/api/items').set('x-csrf-token', csrfToken)
      .send({ title: 'Lost backpack', location: 'Test library' });
    expect(created.status).toBe(201);
    const itemUrl = `/api/items/${created.body.item._id}`;
    const updated = await agent.patch(itemUrl).set('x-csrf-token', csrfToken).send({ status: 'found' });
    expect(updated.status).toBe(200);
    expect(updated.body.item.status).toBe('found');
    expect((await agent.delete(itemUrl).set('x-csrf-token', csrfToken)).status).toBe(200);
    const userUrl = `/api/users/${registration.body.user.id}`;
    const userUpdate = await agent.patch(userUrl).set('x-csrf-token', csrfToken).send({ name: 'Updated Owner' });
    expect(userUpdate.status).toBe(200);
    expect(userUpdate.body.user.name).toBe('Updated Owner');
    expect((await agent.delete(userUrl).set('x-csrf-token', csrfToken)).status).toBe(200);
  });
});
