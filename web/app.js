// Keep secret input ephemeral and render only metadata returned by the local server.
'use strict';
const $ = (id) => document.getElementById(id);
const state = { me: null, csrf: '', items: [], editing: null, deleting: '', devices: [] };
let familyDistribution;
let familyBusy = false;
let toastTimer;
let otpTimer;
let otpRaster;
let otpImageGeneration = 0;
let editorGeneration = 0;
function toast(text) { $('toast').textContent = text; $('toast').hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => $('toast').hidden = true, 3500); }
function showError(text) { $('error-banner').textContent = text; $('error-banner').hidden = false; }
async function api(path, options = {}) {
  const response = await fetch(path, { ...options, cache: 'no-store', headers: { 'Content-Type': 'application/json', 'X-Keys-CSRF': state.csrf, ...(options.headers || {}) } });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error ? t(data.error) : t("The request could not be completed."));
  return data;
}
function node(tag, className, text) { const el = document.createElement(tag); if (className) el.className = className; if (text !== undefined) el.textContent = text; return el; }
function button(text, handler, className = '') { const el = node('button', className, text); el.type = 'button'; el.addEventListener('click', handler); return el; }
function relativeTime(timestamp) { const days = Math.floor((Date.now() / 1000 - timestamp) / 86400); return days === 0 ? t("Updated today") : t("Updated {days} days ago").replace("{days}", days); }
function render() {
  const filtered = state.items;
  $('items').replaceChildren();
  for (const item of filtered) {
    const card = node('article', 'card');
    const top = node('div', 'card-top');
    const lower = `${item.name} ${item.aliases}`.toLowerCase();
    const service = lower.includes('discord') || lower.includes('\u30C7\u30A3\u30B9\u30B3\u30FC\u30C9') ? 'discord' : lower.includes('github') ? 'github' : 'generic';
    const icon = node('div', `service-icon ${service}`, service === 'discord' ? '◒' : service === 'github' ? '⌥' : '⌘');
    const label = node('div'); label.append(node('h3', '', item.name));
    top.append(icon, label, node('span', 'badge', item.owner === 'ALL' ? t("ALL · Shared") : item.owner));
    const vars = node('div', 'variable-list');
    item.variables.slice(0, 3).forEach(key => vars.append(node('code', '', key)));
    if (item.variables.length > 3) vars.append(node('code', '', `+${item.variables.length - 3}`));
    const bottom = node('div', 'card-bottom'); const actions = node('div', 'card-actions');
    actions.append(button(t("Edit"), () => openEditor(item)));
    if (item.variables.length > 0) actions.append(button(item.otp_variable ? t("Two-factor settings") : t("Add two-factor authentication"), () => openOtpSettings(item)));
    actions.append(button(t("Delete"), () => confirmDelete(item), 'delete'));
    bottom.append(node('span', '', relativeTime(item.updated)), actions); card.append(top, vars, bottom); $('items').append(card);
  }
  $('total').textContent = state.items.length; $('nav-count').textContent = state.items.length; $('list-count').textContent = `${filtered.length} ITEMS`;
  $('empty').hidden = filtered.length > 0;
  if (!filtered.length && $('search').value) {
    $('empty').querySelector('h2').textContent = t("No matching keys");
    $('empty').querySelector('p').textContent = t("Try a different name or purpose.");
  } else {
    $('empty').querySelector('h2').textContent = t("Add your first key");
    $('empty').querySelector('p').textContent = t("Use an ENV name and value to add a key.");
  }
}
let searchSequence = 0;
async function refresh() {
  const sequence = ++searchSequence;
  const data = await api(`/api/items?q=${encodeURIComponent($('search').value)}`);
  if (sequence !== searchSequence) return;
  state.items = data.items; render();
}
function clearSecret() {
  editorGeneration++;
  $('entry-env').value = '';
  $('entry-env').classList.add('masked');
  $('env-fields').replaceChildren();
  $('env-preview').open = false;
  $('env-preview').hidden = true;
  $('entry-note').value = '';
  $('otp-seed').value = '';
  $('editor-otp-code').textContent = '';
  clearTimeout(otpTimer);
  $('toggle-secret').textContent = t("Show values");
}
function addEnvField(field = {}) {
  const row = node('div', 'env-field-row');
  const nameLabel = node('label', 'field', t("ENV name (required)"));
  const name = node('input', 'env-name');
  name.required = true;
  name.maxLength = 256;
  name.pattern = '[A-Za-z_][A-Za-z0-9_]*';
  name.placeholder = t("Example: DISCORD_PASSWORD");
  name.autocomplete = 'off';
  name.value = field.name || '';
  nameLabel.append(name);
  const valueLabel = node('label', 'field', t("Value"));
  const value = node('textarea', $('entry-env').classList.contains('masked') ? 'env-value masked' : 'env-value');
  value.rows = 2;
  value.spellcheck = false;
  value.autocomplete = 'off';
  value.value = field.value ?? '';
  valueLabel.append(value);
  const remove = button(t("Remove ENV"), () => {
    row.remove();
    updateEnvFieldButtons();
  }, 'env-remove text-button small');
  row.append(nameLabel, valueLabel, remove);
  $('env-fields').append(row);
  updateEnvFieldButtons();
  return name;
}
function updateEnvFieldButtons() {
  const buttons = $('env-fields').querySelectorAll('.env-remove');
  for (const button of buttons) button.hidden = buttons.length === 1;
}
$('add-env-field').addEventListener('click', () => addEnvField().focus());
async function openEditor(item = null) {
  $('entry-form').reset();
  clearSecret();
  state.editing = item;
  $('add-env-field').hidden = Boolean(item);
  const generation = editorGeneration;
  $('entry-name').value = item?.name || '';
  $('otp-variable').value = item?.otp_variable || '';
  $('otp-remove-row').hidden = !item?.otp_variable;
  $('editor-title').textContent = item ? t("Edit key") : t("Add key");
  $('save-entry').textContent = item ? t("Save changes") : t("Save key");
  $('form-error').hidden = true;
  if (item) {
    try {
      const data = await api(`/api/items/${encodeURIComponent(item.id)}/reveal`, { method: 'POST', body: '{"fields":true}' });
      if (generation !== editorGeneration) return;
      state.editing = data.item;
      $('entry-note').value = data.note;
      $('entry-env').value = data.env;
      $('env-preview').hidden = !data.env;
      for (const field of data.fields) addEnvField(field);
    } catch (error) { showError(error.message); return; }
  }
  const configured = Boolean(state.editing?.otp_variable);
  $('editor-otp-row').hidden = !configured;
  $('editor-otp-replace').hidden = !configured;
  $('editor-otp-fields').hidden = configured;
  if (!$('env-fields').children.length) addEnvField();
  $('editor').showModal();
  $('entry-name').focus();
}
$('editor-otp-replace').addEventListener('click', () => {
  $('editor-otp-replace').hidden = true;
  $('editor-otp-fields').hidden = false;
  $('otp-seed').value = '';
  $('otp-seed').focus();
});
function openOtpSettings(item) {
  const dialog = $('otp-settings');
  $('otp-settings-form').reset();
  dialog.dataset.item = item.id;
  $('otp-settings-title').textContent = item.otp_variable ? t("Two-factor settings") : t("Add two-factor authentication");
  $('otp-settings-name').textContent = item.name;
  $('otp-settings-variable').replaceChildren(...item.variables.map(name => new Option(name, name)));
  $('otp-settings-variable').value = item.otp_variable || item.variables[0];
  otpRaster = null;
  otpImageGeneration++;
  $('otp-qr-status').hidden = true;
  const configured = Boolean(item.otp_variable);
  $('otp-settings-configured').hidden = !configured;
  $('otp-settings-replace').hidden = !configured;
  $('otp-settings-fields').hidden = configured;
  $('otp-settings-save').disabled = configured;
  $('otp-settings-seed').placeholder = t("Base32 or otpauth://…");
  $('otp-settings-error').hidden = true;
  dialog.showModal();
  $(configured ? 'otp-settings-replace' : 'otp-paste-area').focus();
}
$('otp-settings-replace').addEventListener('click', () => {
  $('otp-settings-replace').hidden = true;
  $('otp-settings-fields').hidden = false;
  $('otp-settings-seed').value = '';
  $('otp-settings-save').disabled = false;
  $('otp-settings-seed').focus();
});
async function readOtpImage(file) {
  const generation = ++otpImageGeneration;
  const status = $('otp-qr-status');
  const save = $('otp-settings-save');
  otpRaster = null;
  status.textContent = t("Preparing image…");
  status.hidden = false;
  save.disabled = true;
  try {
    if (!file.type.startsWith('image/') || file.size > 16 * 1024 * 1024) throw new Error(t("Choose an image smaller than 16 MB."));
    const image = await createImageBitmap(file);
    try {
      if (generation !== otpImageGeneration) return;
      const ratio = Math.min(1, 1400 / Math.max(image.width, image.height));
      const canvas = document.createElement('canvas');
      canvas.width = Math.floor(image.width * ratio);
      canvas.height = Math.floor(image.height * ratio);
      if (Math.min(canvas.width, canvas.height) < 21) throw new Error(t("The image is too small."));
      const context = canvas.getContext('2d', {willReadFrequently: true});
      context.fillStyle = '#fff';
      context.fillRect(0, 0, canvas.width, canvas.height);
      context.drawImage(image, 0, 0, canvas.width, canvas.height);
      const rgba = context.getImageData(0, 0, canvas.width, canvas.height).data;
      const gray = new Uint8Array(canvas.width * canvas.height);
      for (let i = 0; i < gray.length; i++) gray[i] = (54 * rgba[i * 4] + 183 * rgba[i * 4 + 1] + 19 * rgba[i * 4 + 2]) >> 8;
      let binary = '';
      for (let i = 0; i < gray.length; i += 16384) binary += String.fromCharCode(...gray.subarray(i, i + 16384));
      otpRaster = {width:canvas.width, height:canvas.height, gray:btoa(binary)};
      $('otp-settings-seed').value = '';
      status.textContent = t("QR image ready. Save to apply it.");
    } finally { image.close(); }
  } catch (error) {
    if (generation === otpImageGeneration) status.textContent = error.message || t("Could not open the image.");
  } finally { if (generation === otpImageGeneration) save.disabled = false; }
}
$('otp-qr-file').addEventListener('change', event => { if (event.target.files[0]) readOtpImage(event.target.files[0]); });
$('otp-settings').addEventListener('paste', event => {
  if ($('otp-settings-fields').hidden) return;
  const image = Array.from(event.clipboardData?.items || []).find(item => item.kind === 'file' && item.type.startsWith('image/'))?.getAsFile();
  if (!image) return;
  event.preventDefault();
  readOtpImage(image);
});
$('otp-settings-seed').addEventListener('input', () => {
  otpImageGeneration++;
  otpRaster = null;
  $('otp-qr-file').value = '';
  $('otp-qr-status').hidden = true;
  $('otp-settings-save').disabled = false;
});
$('otp-settings-form').addEventListener('submit', async event => {
  event.preventDefault();
  if ($('otp-settings-fields').hidden) return;
  const dialog = $('otp-settings');
  const submit = $('otp-settings-save');
  const errorText = $('otp-settings-error');
  submit.disabled = true;
  errorText.hidden = true;
  try {
    const body = { variable: $('otp-settings-variable').value };
    if (otpRaster) body.qr = otpRaster;
    else body.seed = $('otp-settings-seed').value.trim();
    await api(`/api/items/${encodeURIComponent(dialog.dataset.item)}/otp/settings`, { method: 'POST', body: JSON.stringify(body) });
    dialog.close();
    await refresh();
    toast(t("Two-factor settings saved"));
  } catch (error) {
    if (dialog.open) { errorText.textContent = error.message; errorText.hidden = false; }
    else showError(error.message);
  } finally { submit.disabled = false; }
});
$('close-otp-settings').addEventListener('click', () => $('otp-settings').close());
$('otp-settings').addEventListener('close', () => {
  otpImageGeneration++;
  otpRaster = null;
  $('otp-settings-form').reset();
});
$('editor-otp').addEventListener('click', async () => {
  const id = state.editing?.id;
  if (!id) return;
  const generation = editorGeneration;
  const output = $('editor-otp-code');
  clearTimeout(otpTimer);
  $('editor-otp').disabled = true;
  output.textContent = '';
  try {
    const result = await api(`/api/items/${encodeURIComponent(id)}/otp`, { method: 'POST', body: '{}' });
    if ($('editor').open && editorGeneration === generation) {
      output.textContent = result.code;
      otpTimer = setTimeout(() => { output.textContent = ''; }, result.expires_in * 1000);
    }
  } catch (error) { if ($('editor').open && editorGeneration === generation) output.textContent = error.message; }
  finally { $('editor-otp').disabled = false; }
});
function confirmDelete(item) { state.deleting = item.id; $('confirm-name').textContent = item.name; $('confirm').showModal(); }
async function switchView(view) {
  for (const name of ['vault', 'connect', 'family', 'skills', 'devices']) { $(`${name}-view`).hidden = view !== name; $(`nav-${name}`).classList.toggle('active', view === name); }
  $('breadcrumb').textContent = { vault: t("Vault"), connect: t("Connect an agent"), family: t("Family setup"), skills: t("Family skills"), devices: t("Allowed devices") }[view];
  $('error-banner').hidden = true;
  if (view === 'skills') { try { await refreshSkills(); } catch (error) { showError(error.message); } }
  if (view === 'family' && !familyDistribution) {
    try { fillFamilyDistribution(await api('/api/family-distribution')); }
    catch (error) { showError(error.message); }
  }
  if (view === 'devices') {
    $('device-denied').hidden = state.me.manage; $('device-form').hidden = !state.me.manage;
    if (state.me.manage) {
      const save = $('device-save');
      save.disabled = true;
      try {
        const data = await api('/api/devices');
        state.devices = data.devices;
        $('allowed-networks').value = data.allowed_networks.join('\n');
        $('allowed-ips').value = data.devices.map(device => device.ip).join('\n');
        save.disabled = false;
      } catch (error) { showError(error.message); }
    }
  }
}
function entries(field) { return [...new Set(field.value.split(/\r?\n/).map(line => line.trim()).filter(Boolean))]; }
function fillSkill(skill = {}) {
  $('skill-name').value = skill.name || '';
  $('skill-name').readOnly = Boolean(skill.name);
  $('skill-summary').value = skill.summary || '';
  $('skill-body').value = skill.body || '';
  $('skill-delete').hidden = !skill.name;
}
async function refreshSkills(name = '') {
  const {items} = await api('/api/skills');
  $('skill-select').replaceChildren(new Option(t("New"), ''), ...items.map(skill => new Option(skill.name, skill.name)));
  $('skill-select').value = name;
  fillSkill(name ? await api(`/api/skills/${encodeURIComponent(name)}`) : {});
}
$('skill-select').addEventListener('change', async event => {
  const name = event.target.value;
  try { fillSkill(name ? await api(`/api/skills/${encodeURIComponent(name)}`) : {}); }
  catch (error) { showError(error.message); }
});
$('skill-form').addEventListener('submit', async event => {
  event.preventDefault();
  const name = $('skill-name').value.trim();
  try {
    await api('/api/skills', { method:'POST', body: JSON.stringify({name, summary:$('skill-summary').value, body:$('skill-body').value}) });
    await refreshSkills(name);
    toast(t("Skill saved"));
  } catch (error) { showError(error.message); }
});
$('skill-delete').addEventListener('click', async () => {
  const name = $('skill-select').value;
  if (!name || !window.confirm(t("Delete {name}?").replace("{name}", name))) return;
  try { await api(`/api/skills/${encodeURIComponent(name)}`, {method:'DELETE'}); await refreshSkills(); }
  catch (error) { showError(error.message); }
});
$('entry-form').addEventListener('submit', async event => {
  event.preventDefault(); $('save-entry').disabled = true; $('form-error').hidden = true;
  const body = { name: $('entry-name').value.trim() || t("New entry"), note: $('entry-note').value };
  if (state.editing) {
    body.id = state.editing.id;
    body.revision = state.editing.revision;
    if (state.editing.aliases) body.aliases = state.editing.aliases;
  }
  body.env_fields = Array.from($('env-fields').children, row => ({
    name: row.querySelector('.env-name').value,
    value: row.querySelector('.env-value').value,
  }));
  const otpSeed = $('otp-seed').value.trim();
  const otpVariable = $('otp-variable').value.trim() || (otpSeed && body.env_fields.length === 1 ? body.env_fields[0].name : '');
  if ($('otp-remove').checked) body.otp = { remove: true };
  else if (otpVariable || otpSeed) body.otp = { variable: otpVariable, seed: otpSeed };
  try {
    await api('/api/items', { method: 'POST', body: JSON.stringify(body) });
    $('editor').close();
    await refresh();
    toast(t("Saved"));
  }
  catch (error) { $('form-error').textContent = error.message; $('form-error').hidden = false; }
  finally { $('save-entry').disabled = false; }
});
$('toggle-secret').addEventListener('click', () => {
  const masked = $('entry-env').classList.toggle('masked');
  $('env-fields').querySelectorAll('.env-value').forEach(field => field.classList.toggle('masked', masked));
  $('toggle-secret').textContent = masked ? t("Show values") : t("Hide values");
});
$('close-editor').addEventListener('click', () => $('editor').close());
$('editor').addEventListener('close', clearSecret);
$('cancel-delete').addEventListener('click', () => $('confirm').close());
$('do-delete').addEventListener('click', async () => { try { await api(`/api/items/${encodeURIComponent(state.deleting)}`, { method: 'DELETE' }); $('confirm').close(); await refresh(); toast(t("Key deleted")); } catch (error) { showError(error.message); } });
for (const id of ['add', 'empty-add']) $(id).addEventListener('click', () => openEditor());
for (const view of ['vault','connect','family','skills','devices']) $(`nav-${view}`).addEventListener('click', () => switchView(view));
$('intro-connect').addEventListener('click', () => switchView('connect'));
$('connect-family').addEventListener('click', () => switchView('family'));
function familyDraft() {
  return {guide: $('family-guide').value, skill: $('family-skill-source').value};
}
function updateFamilyButtons() {
  const {guide, skill} = familyDraft();
  const dirty = guide !== familyDistribution.guide || skill !== familyDistribution.skill;
  $('save-family-distribution').disabled = familyBusy || !dirty;
  $('copy-family-instructions').disabled = familyBusy || dirty;
  $('family-guide').readOnly = familyBusy;
  $('family-skill-source').readOnly = familyBusy;
}
function fillFamilyDistribution(distribution) {
  familyDistribution = distribution;
  $('family-guide').value = distribution.guide;
  $('family-skill-source').value = distribution.skill;
  $('family-distribution-form').hidden = false;
  updateFamilyButtons();
}
$('family-distribution-form').addEventListener('input', updateFamilyButtons);
$('family-distribution-form').addEventListener('submit', async event => {
  event.preventDefault();
  familyBusy = true;
  updateFamilyButtons();
  $('error-banner').hidden = true;
  try {
    const data = await api('/api/family-distribution', {method: 'POST', body: JSON.stringify({...familyDraft(), revision: familyDistribution.revision})});
    fillFamilyDistribution(data);
    $('family-instructions').value = '';
    $('family-instructions').hidden = true;
    toast(t("Distribution text saved"));
  } catch (error) { showError(error.message); }
  finally { familyBusy = false; updateFamilyButtons(); }
});
$('copy-family-instructions').addEventListener('click', async () => {
  const field = $('family-instructions');
  familyBusy = true;
  updateFamilyButtons();
  $('error-banner').hidden = true;
  try {
    const { instructions } = await api('/api/family-invite', { method: 'POST', body: '{}' });
    field.value = instructions;
    field.hidden = false;
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(field.value);
      } else {
        field.focus(); field.select();
        if (!document.execCommand('copy')) throw new Error('Copy unavailable');
      }
      toast(t("Instructions copied"));
    } catch {
      field.focus(); field.select();
      showError(t("The instructions are selected. Use Copy to grab them."));
    }
  } catch (error) {
    showError(error.message);
  } finally {
    familyBusy = false;
    updateFamilyButtons();
  }
});
let searchTimer; $('search').addEventListener('input', () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => refresh().catch(error => showError(error.message)), 180); });
document.addEventListener('keydown', event => { if (event.key === '/' && !['INPUT','TEXTAREA','SELECT'].includes(document.activeElement.tagName) && !$('editor').open) { event.preventDefault(); $('search').focus(); } });
$('device-form').addEventListener('submit', async event => {
  event.preventDefault();
  const save = $('device-save');
  save.disabled = true;
  $('error-banner').hidden = true;
  const field = $('allowed-networks');
  const ipField = $('allowed-ips');
  const previous = new Map(state.devices.map(device => [device.ip, device]));
  const devices = entries(ipField).map(ip => previous.get(ip) || { ip, name: ip });
  try {
    const data = await api('/api/devices', { method: 'POST', body: JSON.stringify({ devices, allowed_networks: entries(field) }) });
    state.devices = devices;
    ipField.value = devices.map(device => device.ip).join('\n');
    field.value = data.allowed_networks.join('\n');
    toast(t("Access settings saved"));
  } catch (error) { showError(error.message); }
  finally { save.disabled = false; }
});
async function boot() {
  const ticketId = new URLSearchParams(location.hash.slice(1)).get('intake');
  if (ticketId && /^[0-9a-f-]{36}$/.test(ticketId)) {
    location.replace(`/intake/${ticketId}`);
    return;
  }
  const data = await api('/api/status');
  if (data.authenticated === false) { document.body.classList.add('locked'); $('login-view').hidden = false; return; }
  document.body.classList.remove('locked'); state.me = data.device; state.csrf = data.csrf;
  $('avatar').textContent = 'ALL'; $('identity-name').textContent = t("Family shared"); $('identity-ip').textContent = state.me.ip; $('mcp-config').textContent = JSON.stringify({ mcpServers: { 'family-keys': { type: 'http', url: data.mcp_url } } }, null, 2);
  if (location.protocol !== 'https:') { const badge = document.querySelector('.secure'); badge.replaceChildren(node('i'), document.createTextNode(t("LAN connection"))); }
  await refresh();
}
$('login-form').addEventListener('submit', async event => {
  event.preventDefault(); $('login-button').disabled = true; $('login-error').hidden = true;
  try { await api('/api/login', { method: 'POST', body: JSON.stringify({ password: $('login-password').value }) }); $('login-password').value = ''; await boot(); }
  catch (error) { $('login-error').textContent = error.message; $('login-error').hidden = false; }
  finally { $('login-button').disabled = false; }
});
$('logout').addEventListener('click', async () => {
  try {
    await api('/api/logout', { method: 'POST', body: '{}' });
    location.reload();
  } catch (error) { showError(error.message); }
});
keysLocale.ready.then(boot).catch(() => showError(t("Could not connect. Check the server IP, port, and status.")));
