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
  counter++;

  const email = `victim${Date.now()}_${counter}@test.dev`;

  const response = await request(app)
    .post('/api/auth/register')
    .send({
      name: 'Victim',
      email,
      password: 'secret123'
    });

  expect(response.status).toBe(201);
  return cookiePairs(response.headers['set-cookie']);
}

describe('Account settings — recovery email CSRF protection', () => {
  test('a logged-in user can update their recovery email with a valid CSRF token', async () => {
    const authCookies = await registerUser();

    const tokenResponse = await request(app)
      .get('/api/csrf-token')
      .set('Cookie', authCookies.join('; '));

    expect(tokenResponse.status).toBe(200);
    expect(tokenResponse.body.csrfToken).toBeDefined();

    const cookies = [
      ...authCookies,
      ...cookiePairs(tokenResponse.headers['set-cookie'])
    ];

    const response = await request(app)
      .post('/api/settings/recovery-email')
      .set('Cookie', cookies.join('; '))
      .set('x-csrf-token', tokenResponse.body.csrfToken)
      .send({ recoveryEmail: 'legit@user.com' });

    expect(response.status).toBe(200);
  });

  test('a forged request without a CSRF token is rejected', async () => {
    const authCookies = await registerUser();

    const forged = await request(app)
      .post('/api/settings/recovery-email')
      .set('Cookie', authCookies.join('; '))
      .set('Origin', 'http://attacker.evil')
      .send({ recoveryEmail: 'attacker@evil.com' });

    expect(forged.status).toBe(403);
  });
});
