import request from 'supertest';
import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import app from '../../server/src/app.js';

let mongo;
let counter = 0;

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
  return (setCookie || []).map(cookie => cookie.split(';')[0]);
}

async function registerUser() {
  counter += 1;
  const response = await request(app)
    .post('/api/auth/register')
    .send({
      name: 'Victim',
      email: `victim${Date.now()}_${counter}@test.dev`,
      password: 'secret123'
    });

  expect(response.status).toBe(201);
  return cookiePairs(response.headers['set-cookie']);
}

describe('Account settings CSRF protection', () => {
  test('an authenticated user can update their recovery email with a token', async () => {
    const cookies = await registerUser();
    const tokenResponse = await request(app)
      .get('/api/csrf-token')
      .set('Cookie', cookies.join('; '));

    expect(tokenResponse.status).toBe(200);
    const csrfToken = tokenResponse.body.csrfToken;
    const allCookies = [...cookies, ...cookiePairs(tokenResponse.headers['set-cookie'])];

    const updateResponse = await request(app)
      .post('/api/settings/recovery-email')
      .set('Cookie', allCookies.join('; '))
      .set('x-csrf-token', csrfToken)
      .send({ recoveryEmail: 'legit@user.com' });

    expect(updateResponse.status).toBe(200);

    const settingsResponse = await request(app)
      .get('/api/settings')
      .set('Cookie', cookies.join('; '));
    expect(settingsResponse.status).toBe(200);
    expect(settingsResponse.body.settings.recoveryEmail).toBe('legit@user.com');
  });

  test('a forged request without a CSRF token is rejected without changing settings', async () => {
    const cookies = await registerUser();

    const forgedResponse = await request(app)
      .post('/api/settings/recovery-email')
      .set('Cookie', cookies.join('; '))
      .set('Origin', 'http://attacker.evil')
      .send({ recoveryEmail: 'attacker@evil.com' });

    expect(forgedResponse.status).toBe(403);

    const settingsResponse = await request(app)
      .get('/api/settings')
      .set('Cookie', cookies.join('; '));
    expect(settingsResponse.status).toBe(200);
    expect(settingsResponse.body.settings.recoveryEmail).not.toBe('attacker@evil.com');
  });
});
