const test = require('node:test');
const assert = require('node:assert');
const { isPrivate, flagsFor, parseTarget, scan } = require('../scanner');
const app = require('../server');

test('blocks private/internal IPs (SSRF guard)', () => {
  for (const ip of ['127.0.0.1', '10.0.0.5', '192.168.1.1', '172.16.0.1', '169.254.169.254', '::1'])
    assert.ok(isPrivate(ip), ip);
  assert.ok(!isPrivate('8.8.8.8'));
});
test('flags phishing-style hosts', () => {
  assert.ok(flagsFor('secure-login.example.xyz').length >= 2);
  assert.deepStrictEqual(flagsFor('example.com'), []);
});
test('rejects invalid targets', async () => {
  assert.throws(() => parseTarget('ftp://x.com'));
  assert.throws(() => parseTarget('localhost'));
  await assert.rejects(scan('http://127.0.0.1'), /Private|resolved|valid/);
});
test('API: health, auth guard, validation', async (t) => {
  const srv = app.listen(0);
  t.after(() => srv.close());
  const base = `http://127.0.0.1:${srv.address().port}/api`;
  assert.strictEqual((await fetch(base + '/health')).status, 200);
  assert.strictEqual((await fetch(base + '/scans')).status, 401);
  assert.strictEqual((await fetch(base + '/stats')).status, 401);
  const bad = await fetch(base + '/auth/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'x', password: '1' }) });
  assert.strictEqual(bad.status, 400);
});
