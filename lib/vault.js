// Persistence and optional password encryption for the account list.
//
// Data lives in the extension's storage.local when the "storage" permission
// is granted, and falls back to the add-on origin's localStorage when it
// isn't, so the permission can be dropped from the manifest without code
// changes. (Browsers wipe add-on localStorage when you clear site data, so
// the permission is the safer default.)

import { normalizeAccount } from './totp.js';

const VAULT_KEY = 'vault';
const SESSION_KEY = 'vaultKey';
const USED_KEY = 'vaultUsed';
const AUTO_LOCK_KEY = 'autoLockMinutes';
const DEFAULT_AUTO_LOCK_MINUTES = 5;
const PBKDF2_ITERATIONS = 600_000;
const MAX_ITERATIONS = 10_000_000;

// Firefox names the extension API `browser`, Chrome names it `chrome`.
const api = globalThis.browser ?? globalThis.chrome;
const local = api?.storage?.local;
// In-memory only, cleared when the browser quits; lets the vault stay unlocked
// between popup openings without writing the key to disk.
const session = api?.storage?.session;

const state = { locked: false, accounts: [], key: null, kdf: null };

function toB64(buffer) {
  const bytes = new Uint8Array(buffer);
  let text = '';
  for (const b of bytes) text += String.fromCharCode(b);
  return btoa(text);
}

function fromB64(text) {
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

async function readLocal(name) {
  if (local) return (await local.get(name))[name] ?? null;
  const raw = localStorage.getItem(name);
  return raw ? JSON.parse(raw) : null;
}

async function writeLocal(name, value) {
  if (local) {
    await local.set({ [name]: value });
  } else {
    localStorage.setItem(name, JSON.stringify(value));
  }
}

const readStored = () => readLocal(VAULT_KEY);
const writeStored = (value) => writeLocal(VAULT_KEY, value);

async function rememberKey(key) {
  if (!session) return;
  await session.set({
    [SESSION_KEY]: toB64(await crypto.subtle.exportKey('raw', key)),
    [USED_KEY]: Date.now(),
  });
}

async function forgetKey() {
  if (session) await session.remove([SESSION_KEY, USED_KEY]);
}

// Returns the remembered key and counts this as use, or null (forgetting the
// key) when it has gone unused for longer than the auto-lock time.
async function recallKey() {
  if (!session) return null;
  const { [SESSION_KEY]: raw, [USED_KEY]: used = 0 } = await session.get([SESSION_KEY, USED_KEY]);
  if (!raw) return null;
  const minutes = await getAutoLockMinutes();
  if (minutes > 0 && Date.now() - used > minutes * 60_000) {
    await forgetKey();
    return null;
  }
  await session.set({ [USED_KEY]: Date.now() });
  return crypto.subtle.importKey('raw', fromB64(raw), 'AES-GCM', true, ['encrypt', 'decrypt']);
}

// Minutes of disuse before the vault locks again; 0 means only when the browser quits.
export async function getAutoLockMinutes() {
  return (await readLocal(AUTO_LOCK_KEY)) ?? DEFAULT_AUTO_LOCK_MINUTES;
}

export async function setAutoLockMinutes(minutes) {
  if (!Number.isInteger(minutes) || minutes < 0) throw new Error('Invalid auto-lock time.');
  await writeLocal(AUTO_LOCK_KEY, minutes);
}

async function deriveKey(password, kdf) {
  if (!Number.isInteger(kdf?.iterations) || kdf.iterations < 1 || kdf.iterations > MAX_ITERATIONS) {
    throw new Error('Unsupported key-derivation settings.');
  }
  const base = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: fromB64(kdf.salt), iterations: kdf.iterations },
    base,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );
}

async function encrypt(key, kdf, accounts) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(accounts)),
  );
  return { version: 1, encrypted: true, kdf, iv: toB64(iv), data: toB64(data) };
}

async function decrypt(key, stored) {
  let plain;
  try {
    plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(stored.iv) }, key, fromB64(stored.data));
  } catch {
    throw new Error('Wrong password.');
  }
  return JSON.parse(new TextDecoder().decode(plain));
}

// The accounts as stored right now. Another extension page (the popup, or a
// second settings tab) may have changed them since this page loaded, so read
// them fresh before rewriting the whole list.
async function readAccounts() {
  const stored = await readStored();
  if (!stored) return [];
  const stale = new Error('Reynard was changed in another window. Reload this page and try again.');
  if (!stored.encrypted) {
    if (state.key) throw stale;
    return stored.accounts ?? [];
  }
  if (!state.key) throw stale;
  try {
    return await decrypt(state.key, stored);
  } catch {
    throw stale;
  }
}

export function isLocked() {
  return state.locked;
}

export function isEncrypted() {
  return state.kdf !== null;
}

export function getAccounts() {
  return state.locked ? [] : state.accounts;
}

export async function open() {
  const stored = await readStored();
  state.key = null;
  state.kdf = null;
  state.locked = false;
  state.accounts = [];
  if (!stored) return;
  if (!stored.encrypted) {
    state.accounts = stored.accounts ?? [];
    return;
  }

  state.kdf = stored.kdf;
  try {
    const key = await recallKey();
    if (key) {
      state.accounts = await decrypt(key, stored);
      state.key = key;
      return;
    }
  } catch {
    await forgetKey();
  }
  state.locked = true;
}

export async function unlock(password) {
  const stored = await readStored();
  const key = await deriveKey(password, stored.kdf);
  state.accounts = await decrypt(key, stored);
  state.key = key;
  state.kdf = stored.kdf;
  state.locked = false;
  await rememberKey(key);
}

export async function lock() {
  state.key = null;
  state.accounts = [];
  state.locked = true;
  await forgetKey();
}

// For pages that stay open: locks if the vault has gone unused past the
// auto-lock time (or was locked elsewhere), otherwise counts as use.
export async function checkAutoLock() {
  if (state.locked || !state.key || !session) return;
  if (!(await recallKey())) await lock();
}

// Refreshes the in-memory accounts from storage; call before changing the list.
export async function reload() {
  if (state.locked) throw new Error('The vault is locked.');
  state.accounts = await readAccounts();
}

export async function saveAccounts(accounts) {
  if (state.locked) throw new Error('The vault is locked.');
  const stored = state.key
    ? await encrypt(state.key, state.kdf, accounts)
    : { version: 1, encrypted: false, accounts };
  await writeStored(stored);
  state.accounts = accounts;
}

// Sets or changes the vault password.
export async function setPassword(password) {
  if (state.locked) throw new Error('The vault is locked.');
  if (!password) throw new Error('Enter a password.');
  const accounts = await readAccounts();
  const kdf = {
    name: 'PBKDF2',
    hash: 'SHA-256',
    iterations: PBKDF2_ITERATIONS,
    salt: toB64(crypto.getRandomValues(new Uint8Array(16))),
  };
  state.key = await deriveKey(password, kdf);
  state.kdf = kdf;
  await rememberKey(state.key);
  await saveAccounts(accounts);
}

// Removes the vault password, but only when given the current one.
export async function removePassword(password) {
  if (state.locked) throw new Error('The vault is locked.');
  if (!state.kdf) throw new Error('No password is set.');
  const stored = await readStored();
  const accounts = await decrypt(await deriveKey(password, stored.kdf), stored);
  state.key = null;
  state.kdf = null;
  await forgetKey();
  await saveAccounts(accounts);
}

// The vault exactly as stored: encrypted when a password is set.
export async function exportBackup() {
  return (await readStored()) ?? { version: 1, encrypted: false, accounts: [] };
}

export async function readBackup(backup, password) {
  if (!backup || typeof backup !== 'object' || backup.version !== 1) {
    throw new Error('This is not a Reynard backup file.');
  }
  let accounts = backup.accounts;
  if (backup.encrypted) {
    if (!password) throw new Error('This backup is encrypted. Enter the password it was made with.');
    accounts = await decrypt(await deriveKey(password, backup.kdf), backup);
  }
  if (!Array.isArray(accounts)) throw new Error('The backup contains no accounts.');
  return accounts.map(normalizeAccount);
}
