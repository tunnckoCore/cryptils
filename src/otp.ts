import { base32 } from '@scure/base';

import type { HashAlgo, HexString, SecretKey, TokenResult } from './types.ts';
import { randomBytes, toBytes } from './utils.ts';

export async function getHotpToken(
  secret: SecretKey,
  options?: { algorithm?: HashAlgo; digits?: number; counter?: string | number },
): Promise<TokenResult> {
  const opts = { algorithm: 'SHA-256', digits: 6, counter: 0, ...options };
  const algorithm = normalizeAlgo(opts.algorithm);
  const digest = await createHmac(secret, hotpCounter(opts.counter), algorithm);

  return hmacDigestToToken(digest, opts.digits);
}

export async function getTotpToken(
  secret: SecretKey,
  options?: { algorithm?: HashAlgo; digits?: number; period?: number; timestamp?: number },
): Promise<TokenResult> {
  const opts = { algorithm: 'SHA-256', digits: 6, period: 30, timestamp: Date.now(), ...options };
  const algorithm = normalizeAlgo(opts.algorithm);

  return getHotpToken(secret, {
    ...opts,
    algorithm,
    counter: totpCounter(opts.period, opts.timestamp),
  });
}

export function generateBase32Secret(secret?: Uint8Array) {
  return base32.encode(secret || randomBytes(32)).slice(0, 24);

  // or basic/standalone version
  // RFC 4648 base32 alphabet without pad
  // const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  // return randomBytes(size).reduce(
  //   (acc, value) => acc + BASE32_ALPHABET[Math.floor((value * BASE32_ALPHABET.length) / 256)],
  //   '',
  // );
}

function normalizeAlgo(algo: HashAlgo) {
  return algo.toUpperCase().replace('-', '').replace('SHA', 'SHA-') as HashAlgo;
}

/**
 * Generate OTP URI
 * See https://github.com/google/google-authenticator/wiki/Key-Uri-Format
 *
 * @param label label
 * @param username username
 * @param secret secret
 * @param issuer issuer
 * @returns URI
 */
export function getTokenUri(secret: string, options = {}) {
  const opts = {
    secret,
    label: 'alice2',
    username: '',
    issuer: 'myapp',
    algorithm: 'SHA-256',
    digits: 6, // force 6, cuz buggy when another
    period: 30,
    ...options,
  };

  opts.algorithm = normalizeAlgo(opts.algorithm).replace('-', '');

  const { label, username, ...rest } = opts;

  const params = new URLSearchParams(
    Object.entries(rest).map(([key, value]) => [
      key.toLowerCase(),
      encodeURIComponent(String(value)),
    ]),
  );

  if (!params.get('issuer')) {
    params.delete('issuer');
  }

  if (!params.get('username')) {
    params.delete('username');
  }

  const url = `otpauth://totp/${encodeURIComponent(label)}${username ? ':' + encodeURIComponent(username) : ''}?`;
  return url + params.toString();
}

export function hotpCounter(counter: string | number): HexString {
  const hexCounter = Number(counter).toString(16) as HexString;
  return hexCounter.padStart(16, '0');
}

export function totpCounter(period = 30, timestamp = Date.now()) {
  return hotpCounter(Math.floor(timestamp / 1000 / period));
}

export async function createHmac(
  secret: SecretKey,
  counter: Uint8Array | string = '0',
  algorithm: HashAlgo = 'SHA-256',
): Promise<Uint8Array> {
  const algo = normalizeAlgo(algorithm);
  const key = await createHmacKey(secret, algo);
  const digest = await createHmacDigest(key, counter);

  return new Uint8Array(digest);
}

export async function createHmacKey(secret: SecretKey, algorithm: HashAlgo = 'SHA-256') {
  const algo = normalizeAlgo(algorithm);
  return await crypto.subtle.importKey(
    'raw',
    typeof secret === 'string' ? toBytes(secret) : secret,
    typeof algo === 'string' ? { name: 'HMAC', hash: algo } : algo,
    false,
    ['sign'],
  );
}

export async function createHmacDigest(key: CryptoKey, counter: Uint8Array | string) {
  return crypto.subtle.sign('HMAC', key, toBytes(counter));
}

export function hmacDigestToToken(hmacDigest: Uint8Array, digits = 6): TokenResult {
  const digest = hmacDigest;
  // @ts-ignore bruh
  const offset = digest[digest.length - 1] & 0xf;
  const binary =
    // @ts-ignore bruh
    ((digest[offset] & 0x7f) << 24) |
    // @ts-ignore bruh
    ((digest[offset + 1] & 0xff) << 16) |
    // @ts-ignore bruh
    ((digest[offset + 2] & 0xff) << 8) |
    // @ts-ignore bruh
    (digest[offset + 3] & 0xff);

  const token = binary % Math.pow(10, digits);
  return String(token).padStart(digits, '0');
}

/**
 * Validate HOTP/TOTP token, defaults to HOTP

 * @param secret secret
 * @param token token
 * @param timestamp optional, timestamp used for deterministic unit tests (defaults to current timestamp)
 * @returns boolean
 */
export async function validateToken(
  secret: string,
  token: string,
  options: {
    algorithm?: HashAlgo;
    digits?: number;
    counter?: string | number;
    timestamp?: number;
  } = { counter: 0 },
) {
  if (!/[0-9]/g.test(token)) {
    return false;
  }

  const getToken = options.timestamp ? getTotpToken : getHotpToken;
  const tkn = await getToken(secret, options);

  return tkn === String(token);
}

export function validateHotpToken(secret, token, options = {}) {
  const opts = { counter: 0, ...options };

  // force HMAC-based method
  // @ts-ignore bruh
  delete opts?.timestamp;

  return validateToken(secret, token, opts);
}

export function validateTotpToken(secret, token, options = {}) {
  const opts = { timestamp: Date.now(), ...options };

  // force Time-TOP method
  // @ts-ignore bruh
  delete opts?.counter;

  return validateToken(secret, token, opts);
}
