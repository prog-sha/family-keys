// Generated fixtures only: refresh/retry must preserve input and leave OK to the human.
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const script = fs.readFileSync(require('node:path').join(__dirname, '../web/intake.js'), 'utf8');
const tick = () => new Promise(resolve => setImmediate(resolve));
async function scenario(mode) {
  const elements = {};
  for (const id of ['paste-value','paste-otpauth','paste-ok','paste-error','paste-title','paste-purpose','paste-form-view','paste-done']) elements[id] = { value: '', hidden: false, disabled: false, textContent: '' };
  elements['paste-value'].value = 'fixture-entered-only';
  elements['paste-otpauth'].value = 'otpauth://totp/Fixture?secret=TESTFIXTURE';
  elements['paste-ok'].disabled = true;
  function form() { return { handlers: {}, cloneNode() { return form(); }, replaceWith(copy) { elements['paste-form'] = copy; }, addEventListener(type, fn) { this.handlers[type] = fn; } }; }
  elements['paste-form'] = form();
  const original = elements['paste-form'];
  const posts = []; let reads = 0;
  const document = { getElementById: id => elements[id], documentElement: { dataset: {} }, title: 'fixture' };
  vm.runInNewContext(script, { document, location: { pathname: '/intake/fixture' }, fetch: async (path, options = {}) => {
    if (options.method === 'POST') {
      posts.push({ ...JSON.parse(options.body), csrf: options.headers['X-Intake-CSRF'] });
      if (mode === 'stale' && posts.length === 1) return { ok: false, status: 403, json: async () => ({ code: 'INTAKE_NONCE_STALE' }) };
      return { ok: true, status: 200 };
    }
    if (mode === 'offline' && reads > 0) throw Error('fixture offline');
    reads++;
    return { ok: true, json: async () => ({ status: 'waiting', csrf: 'nonce-'+reads, title: 'fixture title', purpose: 'fixture purpose' }) };
  } });
  await tick();
  assert.notEqual(elements['paste-form'], original);
  assert.equal(elements['paste-value'].value, 'fixture-entered-only');
  assert.equal(posts.length, 0, 'loading/repairing a form must never submit it');
  assert.equal(elements['paste-ok'].disabled, false);
  await elements['paste-form'].handlers.submit({ preventDefault() {} });
  if (mode === 'offline') {
    assert.equal(posts.length, 0); assert.equal(elements['paste-value'].value, 'fixture-entered-only');
    assert.equal(elements['paste-otpauth'].value, 'otpauth://totp/Fixture?secret=TESTFIXTURE');
    assert.equal(elements['paste-error'].hidden, false);
  } else {
    assert.equal(posts.length, mode === 'stale' ? 2 : 1);
    assert(posts.every(p => p.value === 'fixture-entered-only'));
    assert(posts.every(p => p.otpauth === 'otpauth://totp/Fixture?secret=TESTFIXTURE'));
    assert.equal(posts[0].csrf, 'nonce-2', 'refresh confirmation before submitting');
    if (mode === 'stale') assert.equal(posts[1].csrf, 'nonce-3');
    assert.equal(elements['paste-value'].value, ''); assert.equal(elements['paste-done'].hidden, false);
    assert.equal(elements['paste-otpauth'].value, '');
  }
  assert.equal(elements['paste-ok'].disabled, false);
}
(async () => {
  for (const mode of ['normal','stale','offline']) await scenario(mode);
  console.log('PASS human-only submit, confirmation refresh/retry, and input preservation on errors');
})().catch(error => { console.error(error); process.exitCode = 1; });
