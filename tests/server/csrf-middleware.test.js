import request from 'supertest';
import jwt from 'jsonwebtoken';
import app from '../../server/src/app.js';
import { Setting } from '../../server/src/models/Setting.js';

beforeAll(() => {
  process.env.JWT_SECRET = 'isolated-test-secret';
  process.env.CSRF_SECRET = 'isolated-csrf-secret';
});
afterEach(() => jest.restoreAllMocks());

function session() {
  return `token=${jwt.sign({ id: '507f1f77bcf86cd799439011', jti: Math.random().toString() }, process.env.JWT_SECRET)}`;
}

test('CSRF gate allows valid writes and rejects missing, tampered and foreign-session tokens', async () => {
  const write = jest.spyOn(Setting, 'findOneAndUpdate').mockResolvedValue({ recoveryEmail: 'valid@example.com' });
  const auth = session();
  const issued = await request(app).get('/api/csrf-token').set('Cookie', auth);
  expect(issued.status).toBe(200);
  expect(issued.headers['cache-control']).toBe('no-store');
  const csrfCookie = issued.headers['set-cookie'].map(c => c.split(';')[0]).join('; ');
  const cookie = `${auth}; ${csrfCookie}`;
  const valid = await request(app).post('/api/settings/recovery-email')
    .set('Cookie', cookie).set('x-csrf-token', issued.body.csrfToken)
    .send({ recoveryEmail: 'valid@example.com' });
  expect(valid.status).toBe(200);
  expect(write).toHaveBeenCalledTimes(1);
  for (const [cookies, token] of [
    [cookie, ''], [cookie, `${issued.body.csrfToken}bad`],
    [`${session()}; ${csrfCookie}`, issued.body.csrfToken], [auth, issued.body.csrfToken]
  ]) {
    const rejected = await request(app).post('/api/settings/recovery-email')
      .set('Cookie', cookies).set('x-csrf-token', token).type('form')
      .send({ recoveryEmail: 'attacker@example.com' });
    expect(rejected.status).toBe(403);
  }
  expect(write).toHaveBeenCalledTimes(1);
});

test('unauthenticated token requests fail and other authenticated writes require CSRF', async () => {
  expect((await request(app).get('/api/csrf-token')).status).toBe(401);
  for (const path of ['/api/items', '/api/users/507f1f77bcf86cd799439011', '/api/auth/logout']) {
    const res = await request(app).post(path).set('Cookie', session()).send({});
    expect(res.status).toBe(403);
  }
});
