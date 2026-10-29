import * as vault from '../lib/vault.js';
import { normalizeAccount, parseOtpauthUri, totp } from '../lib/totp.js';

const EXPIRING_SECONDS = 5;

const $ = (id) => document.getElementById(id);

const fields = {
  issuer: $('f-issuer'),
  label: $('f-label'),
  secret: $('f-secret'),
  algorithm: $('f-algorithm'),
  digits: $('f-digits'),
  period: $('f-period'),
};

let rows = [];
let editingId = null;
let deleteArmed = false;
let tickTimer = null;
let toastTimer = null;

function show(view) {
  for (const el of document.querySelectorAll('.view')) el.hidden = el.id !== `view-${view}`;
  clearInterval(tickTimer);
  if (view === 'list') {
    tick();
    tickTimer = setInterval(tick, 250);
  }
}

function showError(id, message) {
  const el = $(id);
  el.textContent = message;
  el.hidden = !message;
}

function toast(message) {
  const el = $('toast');
  el.textContent = message;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, 1500);
}

// ---- Locked ----

function showLocked() {
  $('unlock-password').value = '';
  showError('unlock-error', '');
  show('locked');
  $('unlock-password').focus();
}

$('unlock-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = $('unlock-submit');
  button.disabled = true;
  button.textContent = 'Unlocking…';
  try {
    await vault.unlock($('unlock-password').value);
    showList();
  } catch (err) {
    showError('unlock-error', err.message);
    $('unlock-password').select();
  } finally {
    button.disabled = false;
    button.textContent = 'Unlock';
  }
});

// ---- List ----

function displayName(account) {
  return account.issuer || account.label;
}

function formatCode(code) {
  const mid = Math.floor(code.length / 2);
  return `${code.slice(0, mid)} ${code.slice(mid)}`;
}

function showList() {
  $('btn-lock').hidden = !vault.isEncrypted();
  $('unencrypted-warning').hidden = vault.isEncrypted();
  renderList();
  show('list');
}

function renderList() {
  const accounts = [...vault.getAccounts()].sort((a, b) =>
    displayName(a).localeCompare(displayName(b), undefined, { sensitivity: 'base' }));
  rows = accounts.map(buildRow);
  $('accounts').replaceChildren(...rows.map((row) => row.li));
  applyFilter();
}

function buildRow(account) {
  const li = $('tpl-account').content.firstElementChild.cloneNode(true);
  li.querySelector('.issuer').textContent = displayName(account);
  li.querySelector('.label').textContent = account.issuer ? account.label : '';

  const row = {
    account,
    li,
    code: li.querySelector('.code'),
    progress: li.querySelector('.progress'),
    counter: null,
    value: null,
  };

  li.addEventListener('click', () => copy(row));
  li.addEventListener('keydown', (event) => {
    if (event.target === li && (event.key === 'Enter' || event.key === ' ')) {
      event.preventDefault();
      copy(row);
    }
  });
  li.querySelector('.edit').addEventListener('click', (event) => {
    event.stopPropagation();
    openEditor(account);
  });
  return row;
}

function tick() {
  const now = Date.now();
  for (const row of rows) {
    const { period } = row.account;
    const counter = Math.floor(now / 1000 / period);
    const remaining = period - ((now / 1000) % period);
    row.progress.setAttribute('stroke-dashoffset', String(100 * (1 - remaining / period)));
    row.li.classList.toggle('expiring', remaining <= EXPIRING_SECONDS);

    if (counter !== row.counter) {
      row.counter = counter;
      totp(row.account, now).then(
        (value) => {
          if (row.counter !== counter) return;
          row.value = value;
          row.code.textContent = formatCode(value);
        },
        (err) => {
          row.value = null;
          row.code.textContent = 'error';
          row.li.title = err.message;
        },
      );
    }
  }
}

async function copy(row) {
  if (!row.value) return;
  try {
    await navigator.clipboard.writeText(row.value);
    toast(`Copied code for ${displayName(row.account)}`);
  } catch {
    toast('Could not copy to the clipboard');
  }
}

function applyFilter() {
  const query = $('search').value.trim().toLowerCase();
  let visible = 0;
  for (const row of rows) {
    const haystack = `${row.account.issuer} ${row.account.label}`.toLowerCase();
    row.li.hidden = query !== '' && !haystack.includes(query);
    if (!row.li.hidden) visible++;
  }
  $('empty').hidden = rows.length > 0;
  $('no-match').hidden = rows.length === 0 || visible > 0;
}

$('search').addEventListener('input', applyFilter);
$('search').addEventListener('keydown', (event) => {
  if (event.key !== 'Enter') return;
  const first = rows.find((row) => !row.li.hidden);
  if (first) copy(first);
});

$('btn-add').addEventListener('click', () => openEditor());

$('btn-lock').addEventListener('click', async () => {
  await vault.lock();
  showLocked();
});

async function openSettings(event) {
  event.preventDefault();
  await (globalThis.browser ?? globalThis.chrome).runtime.openOptionsPage();
  window.close();
}

$('btn-settings').addEventListener('click', openSettings);
$('set-password').addEventListener('click', openSettings);

// ---- Add / edit ----

function fillFields(account) {
  const algorithm = account.algorithm ?? 'SHA1';
  const digits = account.digits ?? 6;
  const period = account.period ?? 30;
  fields.issuer.value = account.issuer ?? '';
  fields.label.value = account.label ?? '';
  fields.secret.value = account.secret ?? '';
  fields.algorithm.value = algorithm;
  fields.digits.value = String(digits);
  fields.period.value = String(period);
  $('advanced').open = algorithm !== 'SHA1' || digits !== 6 || period !== 30;
}

function resetDelete() {
  deleteArmed = false;
  $('btn-delete').textContent = 'Delete';
  $('btn-delete').classList.remove('confirm');
}

function openEditor(account = null) {
  editingId = account?.id ?? null;
  $('edit-title').textContent = account ? 'Edit account' : 'Add account';
  $('uri-field').hidden = account !== null;
  $('f-uri').value = '';
  fillFields(account ?? {});
  resetDelete();
  $('btn-delete').hidden = account === null;
  showError('edit-error', '');
  show('edit');
  (account ? fields.issuer : $('f-uri')).focus();
}

$('f-uri').addEventListener('input', () => {
  const uri = $('f-uri').value.trim();
  if (!uri) {
    showError('edit-error', '');
    return;
  }
  try {
    fillFields(parseOtpauthUri(uri));
    showError('edit-error', '');
  } catch (err) {
    showError('edit-error', err.message);
  }
});

$('edit-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  let account;
  try {
    account = normalizeAccount({
      id: editingId,
      issuer: fields.issuer.value,
      label: fields.label.value,
      secret: fields.secret.value,
      algorithm: fields.algorithm.value,
      digits: fields.digits.value,
      period: fields.period.value,
    });
  } catch (err) {
    showError('edit-error', err.message);
    return;
  }

  const accounts = [...vault.getAccounts()];
  const index = accounts.findIndex((a) => a.id === account.id);
  if (index === -1) accounts.push(account);
  else accounts[index] = account;

  try {
    await vault.saveAccounts(accounts);
  } catch (err) {
    showError('edit-error', `Could not save: ${err.message}`);
    return;
  }
  toast(index === -1 ? 'Account added' : 'Account saved');
  showList();
});

$('btn-delete').addEventListener('click', async () => {
  if (!deleteArmed) {
    deleteArmed = true;
    $('btn-delete').textContent = 'Really delete?';
    $('btn-delete').classList.add('confirm');
    return;
  }
  try {
    await vault.saveAccounts(vault.getAccounts().filter((a) => a.id !== editingId));
  } catch (err) {
    showError('edit-error', `Could not delete: ${err.message}`);
    return;
  }
  toast('Account deleted');
  showList();
});

$('btn-cancel').addEventListener('click', showList);

// ---- Start ----

try {
  await vault.open();
  if (vault.isLocked()) showLocked();
  else showList();
} catch (err) {
  document.body.textContent = `Could not open Reynard: ${err.message}`;
}
