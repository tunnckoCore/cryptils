import { toBytes } from './utils.ts';

export type HexString = string;
export type SecretKey = Uint8Array | HexString;
export type HashAlgo = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512';
export type Token = string;

export async function hotp(
  secret: SecretKey,
  options?: { algo?: HashAlgo; digits?: number; counter?: string | number },
): Promise<Token> {
  const opts = { digits: 6, counter: 0, ...options };
  const digest = await createHmac(secret, hotpCounter(opts.counter), opts.algo);

  return hmacDigestToToken(digest, opts.digits);
}

export async function totp(
  secret: SecretKey,
  options?: { algo?: HashAlgo; digits?: number; period?: number; timestamp?: number },
): Promise<Token> {
  const opts = { algo: 'SHA-256', digits: 6, period: 30, timestamp: Date.now(), ...options };
  const algo = opts.algo.toUpperCase().replace('-', '').replace('SHA', 'SHA-') as HashAlgo;

  return hotp(secret, { ...opts, algo, counter: totpCounter(opts.period, opts.timestamp) });
  // const digest = await createHmac(secret, totpCounter(opts.period, opts.timestamp), opts.algo);
  // return hmacDigestToToken(digest, opts.digits);
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
  algo: HashAlgo = 'SHA-256',
): Promise<Uint8Array> {
  const key = await createHmacKey(secret, algo);
  const digest = await createHmacDigest(key, counter);

  return new Uint8Array(digest);
}

export async function createHmacKey(secret: SecretKey, algo: HashAlgo = 'SHA-256') {
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

export function hmacDigestToToken(hmacDigest: Uint8Array, digits = 6): Token {
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
