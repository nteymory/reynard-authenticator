import * as vault from '../lib/vault.js';
import { parseOtpauthUri, toOtpauthUri } from '../lib/totp.js';

const $ = (id) => document.getElementById(id);

let pendingImport = null;

function showMessage(id, message) {
  const el = $(id);
  el.textContent = message;
  el.hidden = !message;
}

function render() {
  const locked = vault.isLocked();
  $('card-locked').hidden = !locked;
  $('unlocked').hidden = locked;
  if (locked) {
    $('unlock-password').focus();
    return;
  }

  const encrypted = vault.isEncrypted();
  const count = vault.getAccounts().length;
  $('password-status').textContent = encrypted
    ? 'Your accounts are encrypted with your password. If you forget it they cannot be recovered.'
    : 'No password is set, so your secrets are stored unencrypted in your browser profile.';
  $('pw-submit').textContent = encrypted ? 'Change password' : 'Set password';
  $('pw-remove').hidden = !encrypted;
  $('auto-lock-field').hidden = !encrypted;
  $('account-count').textContent = `${count} ${count === 1 ? 'account' : 'accounts'}.`;
  $('export-note').textContent = encrypted
    ? 'The .json backup is encrypted with your current password.'
    : 'No password is set, so the .json backup is unencrypted too.';
}

function download(filename, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function today() {
  return new Date().toISOString().slice(0, 10);
}

// ---- Unlock ----

$('unlock-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = $('unlock-submit');
  button.disabled = true;
  try {
    await vault.unlock($('unlock-password').value);
    $('unlock-password').value = '';
    showMessage('unlock-error', '');
    render();
  } catch (err) {
    showMessage('unlock-error', err.message);
  } finally {
    button.disabled = false;
  }
});

// ---- Password ----

$('password-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  showMessage('password-error', '');
  showMessage('password-success', '');
  const password = $('pw-new').value;
  if (password !== $('pw-confirm').value) {
    showMessage('password-error', 'The passwords do not match.');
    return;
  }
  const wasEncrypted = vault.isEncrypted();
  $('pw-submit').disabled = true;
  try {
    await vault.setPassword(password);
    $('pw-new').value = '';
    $('pw-confirm').value = '';
    showMessage('password-success', wasEncrypted ? 'Password changed.' : 'Password set. Your accounts are now encrypted.');
    render();
  } catch (err) {
    showMessage('password-error', err.message);
  } finally {
    $('pw-submit').disabled = false;
  }
});

function showRemoveForm(visible) {
  $('password-form').hidden = visible;
  $('remove-form').hidden = !visible;
  $('pw-current').value = '';
  showMessage('remove-error', '');
  if (visible) $('pw-current').focus();
}

$('pw-remove').addEventListener('click', () => {
  showMessage('password-error', '');
  showMessage('password-success', '');
  showRemoveForm(true);
});

$('pw-remove-cancel').addEventListener('click', () => showRemoveForm(false));

$('remove-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  showMessage('remove-error', '');
  $('pw-remove-submit').disabled = true;
  try {
    await vault.removePassword($('pw-current').value);
    showRemoveForm(false);
    showMessage('password-success', 'Password removed.');
    render();
  } catch (err) {
    showMessage('remove-error', err.message);
    $('pw-current').select();
  } finally {
    $('pw-remove-submit').disabled = false;
  }
});

// ---- Export ----

$('export-json').addEventListener('click', async () => {
  const backup = await vault.exportBackup();
  download(`reynard-backup-${today()}.json`, JSON.stringify(backup, null, 2), 'application/json');
});

$('export-uris').addEventListener('click', async () => {
  if (!confirm('This file will contain your secret keys in plain text. Anyone who reads it can generate your codes. Continue?')) return;
  try {
    await vault.reload();
  } catch (err) {
    alert(err.message);
    return;
  }
  const lines = vault.getAccounts().map(toOtpauthUri);
  download(`reynard-otpauth-${today()}.txt`, `${lines.join('\n')}\n`, 'text/plain');
});

// ---- Import ----

function looksEncrypted(text) {
  try {
    return JSON.parse(text)?.encrypted === true;
  } catch {
    return false;
  }
}

async function parseImport(text, password) {
  const trimmed = text.trim();
  if (!trimmed) throw new Error('The file is empty.');
  if (trimmed.startsWith('{')) {
    let backup;
    try {
      backup = JSON.parse(trimmed);
    } catch {
      throw new Error('The file is not valid JSON.');
    }
    return vault.readBackup(backup, password);
  }

  const accounts = [];
  trimmed.split(/\r?\n/).forEach((line, i) => {
    const entry = line.trim();
    if (!entry || entry.startsWith('#')) return;
    try {
      accounts.push(parseOtpauthUri(entry));
    } catch (err) {
      throw new Error(`Line ${i + 1}: ${err.message}`);
    }
  });
  return accounts;
}

async function mergeAccounts(incoming) {
  await vault.reload();
  const existing = vault.getAccounts();
  const identity = (a) => `${a.secret}|${a.issuer}|${a.label}`;
  const seen = new Set(existing.map(identity));
  const ids = new Set(existing.map((a) => a.id));
  const added = [];
  for (const account of incoming) {
    if (seen.has(identity(account))) continue;
    seen.add(identity(account));
    const copy = ids.has(account.id) ? { ...account, id: crypto.randomUUID() } : account;
    ids.add(copy.id);
    added.push(copy);
  }
  if (added.length) await vault.saveAccounts([...existing, ...added]);
  return { added: added.length, skipped: incoming.length - added.length };
}

$('import-file').addEventListener('change', async () => {
  showMessage('import-error', '');
  showMessage('import-result', '');
  pendingImport = null;
  $('import-submit').disabled = true;
  const file = $('import-file').files[0];
  if (!file) return;
  pendingImport = await file.text();
  $('import-password-field').hidden = !looksEncrypted(pendingImport);
  $('import-submit').disabled = false;
});

$('import-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (pendingImport === null) return;
  showMessage('import-error', '');
  $('import-submit').disabled = true;
  try {
    const incoming = await parseImport(pendingImport, $('import-password').value);
    const { added, skipped } = await mergeAccounts(incoming);
    showMessage('import-result', `Imported ${added} ${added === 1 ? 'account' : 'accounts'}`
      + (skipped ? `, skipped ${skipped} you already had.` : '.'));
    pendingImport = null;
    $('import-form').reset();
    $('import-password-field').hidden = true;
    render();
  } catch (err) {
    showMessage('import-error', err.message);
    $('import-submit').disabled = false;
  }
});

// ---- Auto-lock ----

$('auto-lock').addEventListener('change', async () => {
  await vault.setAutoLockMinutes(Number($('auto-lock').value));
});

// This tab can stay open indefinitely, so check again whenever it comes back into focus.
window.addEventListener('focus', async () => {
  await vault.checkAutoLock();
  render();
});

// ---- Start ----

await vault.open();
$('auto-lock').value = String(await vault.getAutoLockMinutes());
render();
