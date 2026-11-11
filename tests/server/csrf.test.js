import { describe, expect, it } from '@jest/globals';
import request from 'supertest';

process.env.JWT_SECRET = 'test-jwt-secret';
const { default: app } = await import('../../server/src/app.js');

describe('CSRF protection', () => {
  it('issues a client-readable token and protects the recovery-email write', async () => {
    const tokenResponse = await request(app)
      .get('/api/csrf-token')
      .expect(200);
    const csrfCookie = tokenResponse.headers['set-cookie']
      .find((cookie) => cookie.startsWith('__Host-psifi.x-csrf-token='));

    expect(tokenResponse.body.csrfToken).toEqual(expect.any(String));
    expect(csrfCookie).toContain('SameSite=Lax');
    expect(csrfCookie).toContain('Secure');
    expect(csrfCookie).not.toContain('HttpOnly');

    const cookie = csrfCookie.split(';')[0];
    await request(app)
      .post('/api/settings/recovery-email')
      .set('Cookie', cookie)
      .send({})
      .expect(403);

    await request(app)
      .post('/api/settings/recovery-email')
      .set('Cookie', cookie)
      .set('X-CSRF-Token', tokenResponse.body.csrfToken)
      .send({})
      .expect(401);
  });

  it('protects other state-changing routes but exempts authentication routes', async () => {
    await request(app)
      .post('/api/items')
      .send({})
      .expect(403);

    await request(app)
      .post('/api/auth/logout')
      .expect(200, { ok: true });
  });

  it('does not require a CSRF token for safe methods', async () => {
    await request(app).get('/api/settings').expect(401);
    await request(app).head('/api/settings').expect(401);
    await request(app).options('/api/settings').expect(204);
  });
});
