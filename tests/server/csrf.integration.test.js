import request from 'supertest';
import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import app from '../../server/src/app.js';

let mongo;
let sequence = 0;

beforeAll(async () => {
  process.env.JWT_SECRET = 'focused-test-jwt-secret';
  process.env.JWT_EXPIRES_IN = '1h';
  process.env.CSRF_SECRET = 'focused-test-csrf-secret';
  mongo = await MongoMemoryServer.create();
  await mongoose.connect(mongo.getUri());
}, 60000);

afterAll(async () => {
  await mongoose.disconnect();
  if (mongo) await mongo.stop();
});

function cookiePairs(response) {
  return (response.headers['set-cookie'] || []).map((cookie) => cookie.split(';')[0]);
}

async function register() {
  sequence += 1;
  const email = `focused-${Date.now()}-${sequence}@test.dev`;
  const response = await request(app)
    .post('/api/auth/register')
    .send({ name: 'Focused User', email, password: 'secret123' });
  expect(response.status).toBe(201);
  return { email, user: response.body.user, authCookies: cookiePairs(response) };
}

async function csrfSession(authCookies) {
  const response = await request(app)
    .get('/api/csrf-token')
    .set('Cookie', authCookies.join('; '));
  expect(response.status).toBe(200);
  return {
    token: response.body.csrfToken,
    cookies: [...authCookies, ...cookiePairs(response)]
  };
}

describe('focused CSRF integration behavior', () => {
  test('pre-auth routes are exempt and token issuance requires authentication', async () => {
    const registered = await register();

    const login = await request(app)
      .post('/api/auth/login')
      .send({ email: registered.email, password: 'secret123' });
    expect(login.status).toBe(200);

    const unauthenticated = await request(app).get('/api/csrf-token');
    expect(unauthenticated.status).toBe(401);

    const tokenResponse = await request(app)
      .get('/api/csrf-token')
      .set('Cookie', registered.authCookies.join('; '));
    expect(tokenResponse.status).toBe(200);
    expect(typeof tokenResponse.body.csrfToken).toBe('string');
    expect(tokenResponse.body.csrfToken.length).toBeGreaterThan(20);
    expect(tokenResponse.headers['set-cookie'].join(';')).toMatch(/csrf-token=.*HttpOnly.*SameSite=Lax/i);
  });

  test('safe GETs need no CSRF header and CORS allows client credentials', async () => {
    const items = await request(app).get('/api/items');
    expect(items.status).toBe(200);

    const cors = await request(app)
      .options('/api/settings/recovery-email')
      .set('Origin', 'http://localhost:5175')
      .set('Access-Control-Request-Method', 'POST');
    expect(cors.status).toBe(204);
    expect(cors.headers['access-control-allow-origin']).toBe('http://localhost:5175');
    expect(cors.headers['access-control-allow-credentials']).toBe('true');
  });

  test('recovery email rejects missing, wrong, and mismatched proof without mutation', async () => {
    const victim = await register();
    const victimCsrf = await csrfSession(victim.authCookies);

    const legitimate = await request(app)
      .post('/api/settings/recovery-email')
      .set('Cookie', victimCsrf.cookies.join('; '))
      .set('x-csrf-token', victimCsrf.token)
      .send({ recoveryEmail: 'known-legitimate@test.dev' });
    expect(legitimate.status).toBe(200);

    for (const header of [undefined, 'attacker-supplied-token']) {
      let forged = request(app)
        .post('/api/settings/recovery-email')
        .set('Cookie', victimCsrf.cookies.join('; '))
        .send({ recoveryEmail: 'attacker@evil.com' });
      if (header) forged = forged.set('x-csrf-token', header);
      const response = await forged;
      expect(response.status).toBe(403);
    }

    const other = await register();
    const otherCsrf = await csrfSession(other.authCookies);
    const mismatched = await request(app)
      .post('/api/settings/recovery-email')
      .set('Cookie', victimCsrf.cookies.join('; '))
      .set('x-csrf-token', otherCsrf.token)
      .send({ recoveryEmail: 'attacker@evil.com' });
    expect(mismatched.status).toBe(403);

    const check = await request(app)
      .get('/api/settings')
      .set('Cookie', victim.authCookies.join('; '));
    expect(check.body.settings.recoveryEmail).toBe('known-legitimate@test.dev');
  });

  test('authentication errors remain 401 before CSRF validation', async () => {
    const response = await request(app)
      .post('/api/settings/recovery-email')
      .send({ recoveryEmail: 'attacker@evil.com' });
    expect(response.status).toBe(401);
  });

  test('item create, update, and delete require CSRF and work with valid proof', async () => {
    const owner = await register();
    const session = await csrfSession(owner.authCookies);
    const item = {
      title: `Focused item ${Date.now()}`,
      description: 'integration coverage',
      category: 'other',
      status: 'lost',
      location: `Lab ${sequence}`
    };

    const rejectedCreate = await request(app)
      .post('/api/items')
      .set('Cookie', owner.authCookies.join('; '))
      .send(item);
    expect(rejectedCreate.status).toBe(403);

    const created = await request(app)
      .post('/api/items')
      .set('Cookie', session.cookies.join('; '))
      .set('x-csrf-token', session.token)
      .send(item);
    expect(created.status).toBe(201);
    const itemId = created.body.item._id;

    const rejectedUpdate = await request(app)
      .patch(`/api/items/${itemId}`)
      .set('Cookie', owner.authCookies.join('; '))
      .send({ title: 'Forged change' });
    expect(rejectedUpdate.status).toBe(403);

    const updated = await request(app)
      .patch(`/api/items/${itemId}`)
      .set('Cookie', session.cookies.join('; '))
      .set('x-csrf-token', session.token)
      .send({ title: `${item.title} updated` });
    expect(updated.status).toBe(200);

    const rejectedDelete = await request(app)
      .delete(`/api/items/${itemId}`)
      .set('Cookie', owner.authCookies.join('; '));
    expect(rejectedDelete.status).toBe(403);

    const deleted = await request(app)
      .delete(`/api/items/${itemId}`)
      .set('Cookie', session.cookies.join('; '))
      .set('x-csrf-token', session.token);
    expect(deleted.status).toBe(200);
  });

  test('user writes and logout require valid CSRF proof', async () => {
    const account = await register();
    const session = await csrfSession(account.authCookies);

    const rejectedUpdate = await request(app)
      .patch(`/api/users/${account.user.id}`)
      .set('Cookie', account.authCookies.join('; '))
      .send({ name: 'Forged Name' });
    expect(rejectedUpdate.status).toBe(403);

    const updated = await request(app)
      .patch(`/api/users/${account.user.id}`)
      .set('Cookie', session.cookies.join('; '))
      .set('x-csrf-token', session.token)
      .send({ name: 'Updated Name' });
    expect(updated.status).toBe(200);

    const rejectedLogout = await request(app)
      .post('/api/auth/logout')
      .set('Cookie', account.authCookies.join('; '));
    expect(rejectedLogout.status).toBe(403);

    const logout = await request(app)
      .post('/api/auth/logout')
      .set('Cookie', session.cookies.join('; '))
      .set('x-csrf-token', session.token);
    expect(logout.status).toBe(200);
    expect(logout.headers['set-cookie'].join(';')).toMatch(/token=;/);

    const disposable = await register();
    const disposableSession = await csrfSession(disposable.authCookies);
    const rejectedDelete = await request(app)
      .delete(`/api/users/${disposable.user.id}`)
      .set('Cookie', disposable.authCookies.join('; '));
    expect(rejectedDelete.status).toBe(403);

    const deleted = await request(app)
      .delete(`/api/users/${disposable.user.id}`)
      .set('Cookie', disposableSession.cookies.join('; '))
      .set('x-csrf-token', disposableSession.token);
    expect(deleted.status).toBe(200);
  });
});
