// TOTP (RFC 6238) on top of WebCrypto HMAC. No dependencies.

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const HASHES = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };
const DIGITS = [6, 7, 8];

export function normalizeSecret(secret) {
  return String(secret).toUpperCase().replace(/[\s=-]/g, '');
}

export function base32Decode(input) {
  const out = [];
  let bits = 0;
  let value = 0;
  for (const ch of normalizeSecret(input)) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error(`Invalid character "${ch}" in secret key.`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
      value &= (1 << bits) - 1;
    }
  }
  return new Uint8Array(out);
}

// Validates an account-like object and returns a clean copy. Throws with a
// user-facing message on bad input.
export function normalizeAccount(input) {
  const issuer = String(input.issuer ?? '').trim();
  const label = String(input.label ?? '').trim();
  if (!issuer && !label) throw new Error('Give the account an issuer or a name.');

  const secret = normalizeSecret(input.secret ?? '');
  if (!secret) throw new Error('A secret key is required.');
  if (base32Decode(secret).length === 0) throw new Error('The secret key is too short.');

  const algorithm = String(input.algorithm ?? 'SHA1').toUpperCase().replace('-', '');
  if (!HASHES[algorithm]) throw new Error(`Unsupported algorithm "${input.algorithm}".`);

  const digits = Number(input.digits ?? 6);
  if (!DIGITS.includes(digits)) throw new Error('Digits must be 6, 7 or 8.');

  const period = Number(input.period ?? 30);
  if (!Number.isInteger(period) || period < 1 || period > 300) {
    throw new Error('Period must be a whole number of seconds between 1 and 300.');
  }

  return { id: input.id || crypto.randomUUID(), issuer, label, secret, algorithm, digits, period };
}

const keyCache = new Map();

async function hmacKey(secret, algorithm) {
  const cacheKey = `${algorithm}:${secret}`;
  let key = keyCache.get(cacheKey);
  if (!key) {
    key = await crypto.subtle.importKey(
      'raw', base32Decode(secret), { name: 'HMAC', hash: HASHES[algorithm] }, false, ['sign'],
    );
    keyCache.set(cacheKey, key);
  }
  return key;
}

export async function totp(account, now = Date.now()) {
  const counter = Math.floor(now / 1000 / account.period);
  const message = new ArrayBuffer(8);
  const view = new DataView(message);
  view.setUint32(0, Math.floor(counter / 0x100000000));
  view.setUint32(4, counter >>> 0);

  const key = await hmacKey(account.secret, account.algorithm);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, message));
  const offset = sig[sig.length - 1] & 0x0f;
  const binary = ((sig[offset] & 0x7f) << 24) | (sig[offset + 1] << 16)
    | (sig[offset + 2] << 8) | sig[offset + 3];
  return String(binary % 10 ** account.digits).padStart(account.digits, '0');
}

function safeDecode(text) {
  try {
    return decodeURIComponent(text);
  } catch {
    return text;
  }
}

// Parses otpauth://totp/Issuer:account?secret=...&issuer=...
export function parseOtpauthUri(uri) {
  const match = /^otpauth:\/\/([a-z]+)\/([^?#]*)(?:\?([^#]*))?/i.exec(String(uri).trim());
  if (!match) throw new Error('That is not an otpauth:// link.');
  if (match[1].toLowerCase() !== 'totp') {
    throw new Error(`Only time-based (TOTP) codes are supported, not "${match[1]}".`);
  }

  const params = new URLSearchParams(match[3] ?? '');
  let label = safeDecode(match[2]);
  let issuer = params.get('issuer') ?? '';
  const colon = label.indexOf(':');
  if (colon !== -1) {
    if (!issuer) issuer = label.slice(0, colon);
    label = label.slice(colon + 1);
  }

  return normalizeAccount({
    issuer,
    label,
    secret: params.get('secret') ?? '',
    algorithm: params.get('algorithm') || undefined,
    digits: params.get('digits') || undefined,
    period: params.get('period') || undefined,
  });
}

export function toOtpauthUri(account) {
  const name = account.issuer ? `${account.issuer}:${account.label}` : account.label;
  const params = new URLSearchParams({
    secret: account.secret,
    algorithm: account.algorithm,
    digits: String(account.digits),
    period: String(account.period),
  });
  if (account.issuer) params.set('issuer', account.issuer);
  return `otpauth://totp/${encodeURIComponent(name)}?${params}`;
}
