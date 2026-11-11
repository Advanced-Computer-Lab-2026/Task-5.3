import assert from 'node:assert/strict';
import test from 'node:test';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import app from '../src/app.js';
import { Setting } from '../src/models/Setting.js';

process.env.JWT_SECRET = 'test-only-secret-not-for-production';

test('CSRF blocks forged writes and allows a valid recovery-email update', async () => {
  const authCookie = `token=${jwt.sign({ id: 'test-user' }, process.env.JWT_SECRET)}`;
  const browser = request.agent(app);
  const issued = await browser.get('/api/csrf-token').set('Cookie', authCookie).expect(200);
  assert.equal(issued.headers['cache-control'], 'no-store');
  const token = issued.body.csrfToken;
  const originalUpdate = Setting.findOneAndUpdate;
  let updates = 0;
  Setting.findOneAndUpdate = async (filter, update) => {
    updates += 1;
    assert.equal(filter.user, 'test-user');
    return { recoveryEmail: update.$set.recoveryEmail, notifications: true };
  };
  try {
    // Even with both cookies, the attacker's plain form lacks the header.
    await browser.post('/api/settings/recovery-email')
      .set('Cookie', authCookie).set('Origin', 'http://localhost:1337')
      .type('form').send({ recoveryEmail: 'attacker@example.com' }).expect(403);
    await browser.post('/api/settings/recovery-email')
      .set('Cookie', authCookie).set('x-csrf-token', 'forged')
      .send({ recoveryEmail: 'attacker@example.com' }).expect(403);
    const otherSession = `token=${jwt.sign({ id: 'another-user' }, process.env.JWT_SECRET)}`;
    await browser.post('/api/settings/recovery-email')
      .set('Cookie', otherSession).set('x-csrf-token', token)
      .send({ recoveryEmail: 'attacker@example.com' }).expect(403);
    assert.equal(updates, 0);
    const result = await browser.post('/api/settings/recovery-email')
      .set('Cookie', authCookie).set('x-csrf-token', token)
      .send({ recoveryEmail: 'owner@example.com' }).expect(200);
    assert.equal(result.body.settings.recoveryEmail, 'owner@example.com');
    assert.equal(updates, 1);
  } finally {
    Setting.findOneAndUpdate = originalUpdate;
  }
});

test('anonymous tokens protect auth writes and refresh after session changes', async () => {
  const browser = request.agent(app);
  const before = await browser.get('/api/csrf-token').expect(200);
  await browser.post('/api/auth/logout').expect(403);
  await browser.post('/api/auth/logout')
    .set('x-csrf-token', before.body.csrfToken).expect(200);
  const authCookie = `token=${jwt.sign({ id: 'logged-in-user' }, process.env.JWT_SECRET)}`;
  const after = await browser.get('/api/csrf-token').set('Cookie', authCookie).expect(200);
  assert.notEqual(after.body.csrfToken, before.body.csrfToken);
  await browser.post('/api/auth/logout').set('Cookie', authCookie)
    .set('x-csrf-token', after.body.csrfToken).expect(200);
  await request(app).get('/api/health').expect(200);
});
