// Complete one human-input transaction without loading the vault or revealing its contents.
'use strict';
(() => {
const $ = id => document.getElementById(id);
// Replacing the form preserves input state and removes any old-version handlers.
const original = $('paste-form');
original.replaceWith(original.cloneNode(true));
$('paste-ok').disabled = false;
document.documentElement.dataset.intakeVersion = 'restart-safe';
let nonce = '';
let groupInputs;
let groupTotp;
function done() {
  for (const input of groupInputs || [$('paste-value')]) input.value = '';
  for (const input of groupTotp || [$('paste-otpauth')]) input.value = '';
  $('paste-form-view').hidden = true;
  $('paste-done').hidden = false;
  document.title = 'OK — Keys';
}
function setupGroup(items) {
  $('paste-title').textContent = t("Register multiple keys");
  const form = $('paste-form');
  $('paste-value').closest('label').remove();
  const totpTemplate = $('paste-totp');
  totpTemplate.remove();
  groupTotp = [];
  groupInputs = items.map(item => {
    const label = document.createElement('label');
    label.className = 'field';
    label.textContent = `${item.title} · ${item.variable}`;
    if (item.purpose) {
      const purpose = document.createElement('small');
      purpose.textContent = item.purpose;
      label.append(document.createElement('br'), purpose);
    }
    const input = document.createElement('input');
    input.type = 'password';
    input.autocomplete = 'off';
    input.spellcheck = false;
    input.required = true;
    input.dataset.variable = item.variable;
    label.append(input);
    form.insertBefore(label, $('paste-error'));
    const details = totpTemplate.cloneNode(true);
    details.removeAttribute('id');
    const totp = details.querySelector('input');
    totp.removeAttribute('id');
    totp.dataset.otpauthVariable = item.variable;
    form.insertBefore(details, $('paste-error'));
    groupTotp.push(totp);
    return input;
  });
  groupInputs[0]?.focus();
}
function error(message) { $('paste-error').textContent = message; $('paste-error').hidden = false; }
async function load() {
  const response = await fetch(location.pathname + '/info', { cache: 'no-store' });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error ? t(data.error) : t("Could not open the registration form."));
  if (data.status === 'completed') { done(); return false; }
  nonce = data.csrf;
  if (data.items) { if (!groupInputs) setupGroup(data.items); }
  else { $('paste-title').textContent = data.title; $('paste-purpose').textContent = data.purpose; }
  $('paste-error').hidden = true;
  return true;
}
$('paste-form').addEventListener('submit', async event => {
  event.preventDefault(); $('paste-ok').disabled = true; $('paste-error').hidden = true;
  try {
    // Refresh without reloading the page or clearing the person's entered value.
    if (!await load()) return;
    for (let attempt = 0; attempt < 2; attempt++) {
      const body = groupInputs ? { values: groupInputs.map(input => input.value) } : { value: $('paste-value').value };
      if (groupTotp) {
        const uris = groupTotp.map(input => input.value.trim());
        if (uris.some(Boolean)) body.otpauths = uris;
      } else {
        const uri = $('paste-otpauth').value.trim();
        if (uri) body.otpauth = uri;
      }
      const response = await fetch(location.pathname, { method: 'POST', cache: 'no-store', headers: { 'Content-Type': 'application/json', 'X-Intake-CSRF': nonce }, body: JSON.stringify(body) });
      if (response.ok) { done(); return; }
      const data = await response.json();
      if (attempt === 0 && response.status === 403 && data.code === 'INTAKE_NONCE_STALE') { if (!await load()) return; continue; }
      throw new Error(data.error ? t(data.error) : t("Could not save."));
    }
  } catch (e) { error(e.message); }
  finally { $('paste-ok').disabled = false; }
});
keysLocale.ready.then(load).catch(e => error(e.message));
})();
