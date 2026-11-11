import request from 'supertest';
import jwt from 'jsonwebtoken';
import app from '../../server/src/app.js';

beforeAll(() => { process.env.JWT_SECRET = 'middleware-test-secret'; });

function session(id) {
  return `token=${jwt.sign({ id, jti: id }, process.env.JWT_SECRET)}`;
}

test('authenticated token issuance allows logout, while forged writes fail', async () => {
  const auth = session('first');
  const issued = await request(app).get('/api/csrf-token').set('Cookie', auth).expect(200);
  expect(issued.headers['cache-control']).toBe('no-store');
  const cookies = [auth, ...issued.headers['set-cookie'].map(c => c.split(';')[0])];
  await request(app).post('/api/settings/recovery-email').set('Cookie', cookies)
    .set('Origin', 'http://localhost:1337').type('form')
    .send({ recoveryEmail: 'attacker@evil.com' }).expect(403);
  await request(app).post('/api/auth/logout').set('Cookie', cookies)
    .set('x-csrf-token', 'invalid').expect(403);
  await request(app).post('/api/auth/logout').set('Cookie', cookies)
    .set('x-csrf-token', issued.body.csrfToken).expect(200);
});

test('a token and cookie from another session cannot authorize writes', async () => {
  const issued = await request(app).get('/api/csrf-token')
    .set('Cookie', session('first')).expect(200);
  const cookies = [session('second'), ...issued.headers['set-cookie'].map(c => c.split(';')[0])];
  await request(app).post('/api/auth/logout').set('Cookie', cookies)
    .set('x-csrf-token', issued.body.csrfToken).expect(403);
});
