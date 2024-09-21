// import { randomBytes } from '@noble/hashes/utils';
// import { base32 } from '@scure/base';

import { hexToBytes, randomBytes } from '@noble/hashes/utils';
import { base32 } from '@scure/base';
import * as otp from 'micro-key-producer/otp.js';

import type { HexString } from './types';
import { isHex } from './utils';

// import type { HashAlgo, HexString, SecretKey, TokenResult } from './types.ts';
// import { toBytes } from './utils.ts';

// export async function getHotpToken(
//   secret: SecretKey,
//   options?: { algorithm?: HashAlgo; digits?: number; counter?: string | number },
// ): Promise<TokenResult> {
//   const opts = { algorithm: 'SHA-1', digits: 6, counter: 0, ...options };
//   opts.digits = opts.interval ?? opts.digits;

//   const algorithm = normalizeAlgo(opts.algorithm);
//   const digest = await createHmac(secret, hotpCounter(opts.counter), algorithm);

//   return hmacDigestToToken(digest, opts.digits);
// }

// export async function getTotpToken(
//   secret: SecretKey,
//   options?: { algorithm?: HashAlgo; digits?: number; period?: number; timestamp?: number },
// ): Promise<TokenResult> {
//   const opts = { algorithm: 'SHA-1', digits: 6, period: 30, timestamp: Date.now(), ...options };
//   opts.digits = opts.interval ?? opts.digits;
//   const algorithm = normalizeAlgo(opts.algorithm);

//   return getHotpToken(secret, {
//     ...opts,
//     algorithm,
//     counter: totpCounter(opts.period, opts.timestamp),
//   });
// }

// export function generateBase32Secret(secret?: Uint8Array) {
//   return base32.encode(secret || randomBytes(32)).slice(0, 24);

//   // or basic/standalone version
//   // RFC 4648 base32 alphabet without pad
//   // const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
//   // return randomBytes(size).reduce(
//   //   (acc, value) => acc + BASE32_ALPHABET[Math.floor((value * BASE32_ALPHABET.length) / 256)],
//   //   '',
//   // );
// }

// function normalizeAlgo(algo: HashAlgo) {
//   return algo.toUpperCase().replace('-', '').replace('SHA', 'SHA-') as HashAlgo;
// }

/**
 * Generate OTP URI
 * See https://github.com/google/google-authenticator/wiki/Key-Uri-Format
 *
 * @param key the base32 secret in Uint8Array, HexString or Base32Secret format
 * @param options.label label for account
 * @param options.username username for account
 * @param options.issuer issuer of the token
 * @param options.digits length of the token
 * @param options.interval interval, or "period", for TOTP/HTOP
 * @param options.algorithm one of SHA-1, SHA-256, SHA-512 algorithm; default is SHA-1
 * @returns URI
 */
export function getTokenUri(key: Uint8Array | HexString | Base32Secret, options = {}) {
  const secret = getOtpSecret(key, false) as Uint8Array;
  const opts = {
    secret,
    label: '',
    username: '',
    issuer: 'myapp',
    algorithm: 'SHA-1',
    digits: 6,
    interval: 30,
    ...options,
  };
  opts.algorithm = opts.algorithm.replace('-', '');

  // @ts-ignore bruh
  opts.period = opts.interval;

  // @ts-ignore bruh
  delete opts.interval;

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

// export function hotpCounter(counter: string | number): HexString {
//   const hexCounter = Number(counter).toString(16) as HexString;
//   return hexCounter.padStart(16, '0');
// }

// export function totpCounter(period = 30, timestamp = Date.now()) {
//   //  Math.floor(timestamp / 1000 / period)
//   return hotpCounter( Math.floor(timestamp / (period * 1000)));
// }

// export async function createHmac(
//   secret: SecretKey,
//   counter: number | string = 0,
//   algorithm: HashAlgo = 'SHA-1',
// ): Promise<Uint8Array> {
//   const algo = normalizeAlgo(algorithm);
//   const key = await createHmacKey(secret, algo);
//   const digest = await createHmacDigest(key, counter);

//   return new Uint8Array(digest);
// }

// export async function createHmacKey(secret: SecretKey, algorithm: HashAlgo = 'SHA-1') {
//   const algo = normalizeAlgo(algorithm);
//   return await crypto.subtle.importKey(
//     'raw',
//     typeof secret === 'string' ? toBytes(secret) : secret,
//     typeof algo === 'string' ? { name: 'HMAC', hash: algo } : algo,
//     false,
//     ['sign'],
//   );
// }

// export async function createHmacDigest(key: CryptoKey, counter: number | string) {
//   return crypto.subtle.sign('HMAC', key, toBytes(String(counter)));
// }

// export function hmacDigestToToken(hmacDigest: Uint8Array, digits = 6): TokenResult {
//   const digest = hmacDigest;
//   // @ts-ignore bruh
//   const offset = digest[digest.length - 1] & 0xf;
//   const binary =
//     // @ts-ignore bruh
//     ((digest[offset] & 0x7f) << 24) |
//     // @ts-ignore bruh
//     ((digest[offset + 1] & 0xff) << 16) |
//     // @ts-ignore bruh
//     ((digest[offset + 2] & 0xff) << 8) |
//     // @ts-ignore bruh
//     (digest[offset + 3] & 0xff);

//   const token = binary % Math.pow(10, digits);
//   return String(token).padStart(digits, '0');
// }

// /**
//  * Validate HOTP/TOTP token, defaults to HOTP

//  * @param secret secret
//  * @param token token
//  * @param timestamp optional, timestamp used for deterministic unit tests (defaults to current timestamp)
//  * @returns boolean
//  */
// export async function validateToken(
//   secret: string,
//   token: string,
//   options: {
//     algorithm?: HashAlgo;
//     digits?: number;
//     counter?: string | number;
//     timestamp?: number;
//   } = { counter: 0 },
// ) {
//   if (!/[0-9]/g.test(token)) {
//     return false;
//   }

//   const getToken = options.timestamp ? getTotpToken : getHotpToken;
//   const tkn = await getToken(secret, options);

//   return tkn === String(token);
// }

// export function validateHotpToken(secret, token, options = {}) {
//   const opts = { counter: 0, ...options };

//   // force HMAC-based method
//   // @ts-ignore bruh
//   delete opts?.timestamp;

//   return validateToken(secret, token, opts);
// }

// export function validateTotpToken(secret, token, options = {}) {
//   const opts = { timestamp: Date.now(), ...options };

//   // force Time-TOP method
//   // @ts-ignore bruh
//   delete opts?.counter;

//   return validateToken(secret, token, opts);
// }

export type Base32Secret = string;
export type OtpOptions = {
  algorithm?: string;
  counter?: number | bigint;
  interval?: number;
  digits?: number;
};

export function parseOtpSecret(secret: Base32Secret): Uint8Array {
  const len = Math.ceil(secret.length / 8) * 8;
  return base32.decode(secret.padEnd(len, '=').toUpperCase());
}

export function validateHotp(
  key: Uint8Array | HexString | Base32Secret,
  token: string,
  options?: OtpOptions,
) {
  const secret = getOtpSecret(key, false) as Uint8Array;

  return token === getHotp(secret, options);
}

export function validateTotp(
  key: Uint8Array | HexString | Base32Secret,
  token: string,
  options?: OtpOptions,
) {
  const secret = getOtpSecret(key, false) as Uint8Array;

  return token === getTotp(secret, options);
}

export function getOtpSecret(
  secret?: Uint8Array | HexString | Base32Secret,
  encode = true,
  size = 20,
): Uint8Array | Base32Secret {
  if (typeof secret === 'string') {
    if (isHex(secret)) {
      secret = hexToBytes(secret);
    } else {
      secret = parseOtpSecret(secret);
    }
  }

  const rnd = randomBytes(size);
  return encode ? base32.encode(secret || rnd) : secret || rnd;
}

export function getHotp(key: Uint8Array | HexString | Base32Secret, options?: OtpOptions) {
  const secret = getOtpSecret(key, false) as Uint8Array;

  const config = {
    secret,
    counter: 0,
    algorithm: 'sha1',
    interval: 30,
    digits: 6,
    ...options,
  };
  config.algorithm = config.algorithm.replace('-', '').toLowerCase();

  const token = otp.hotp(config, config.counter || 0);

  return token;
}

export function getTotp(
  key: Uint8Array | HexString | Base32Secret,
  options?: Omit<OtpOptions, 'counter'> & { timestamp?: number },
) {
  const config = {
    algorithm: 'sha1',
    interval: 30,
    digits: 6,
    timestamp: Date.now(),
    ...options,
  };

  const counter = Math.floor(config.timestamp / (config.interval * 1000));
  const token = getHotp(key, { ...options, counter });

  return token;
}
