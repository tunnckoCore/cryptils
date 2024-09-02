// import QRCode from 'qrcode';

import { bytesToHex, toBytes } from '@noble/hashes/utils';
import { base16, base32 } from '@scure/base';

import { hexToBytes, randomBytes } from './src/index';

// import {
//   generateBase32Secret,
//   generateToken,
//   generateUri,
//   validateToken,
// } from './src/native-totp.ts';

// // With promises

// const secret = generateBase32Secret();
// // => QZL7HPXH4TPPSNCN2746GS3J

// // const secret = 'LR5ZHWGPEHWYBD4UMGFYUPEC';

// const options = { secret };
// const token = await generateToken(secret);
// // => 687531

// const valid = await validateToken(secret, token);
// // => true

// const uri = generateUri(options);

// console.log(await QRCode.toString(uri));

// console.log(secret, token, valid, uri);
// console.log();

// console.log(base32.encode(randomBytes(24)));

export type HexString = string;
export type SecretKey = Uint8Array | HexString;
export type HashAlgo = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512';
export type Token = string;

async function hotp(
  secret: SecretKey,
  options?: { algo?: HashAlgo; digits?: number; counter?: string | number },
): Promise<Token> {
  const opts = { digits: 6, counter: 0, ...options };
  const digest = await createHmac(secret, hotpCounter(opts.counter), opts.algo);

  return hmacDigestToToken(digest, opts.digits);
}

async function totp(
  secret: SecretKey,
  options?: { algo?: HashAlgo; digits?: number; period?: number; timestamp?: number },
): Promise<Token> {
  const opts = { algo: 'SHA-256', digits: 6, period: 30, timestamp: Date.now(), ...options };
  const algo = opts.algo.toUpperCase().replace('-', '').replace('SHA', 'SHA-') as HashAlgo;

  return hotp(secret, { ...opts, algo, counter: totpCounter(opts.period, opts.timestamp) });
  // const digest = await createHmac(secret, totpCounter(opts.period, opts.timestamp), opts.algo);
  // return hmacDigestToToken(digest, opts.digits);
}

function hotpCounter(counter: string | number): HexString {
  const hexCounter = Number(counter).toString(16) as HexString;
  return hexCounter.padStart(16, '0');
}

function totpCounter(period = 30, timestamp = Date.now()) {
  return hotpCounter(Math.floor(timestamp / 1000 / period));
}

async function createHmac(
  secret: SecretKey,
  counter: Uint8Array | string = '0',
  algo: HashAlgo = 'SHA-256',
): Promise<Uint8Array> {
  const key = await createHmacKey(secret, algo);
  const digest = await createHmacDigest(key, counter);

  return new Uint8Array(digest);
}

async function createHmacKey(secret: SecretKey, algo: HashAlgo = 'SHA-256') {
  return await crypto.subtle.importKey(
    'raw',
    typeof secret === 'string' ? toBytes(secret) : secret,
    typeof algo === 'string' ? { name: 'HMAC', hash: algo } : algo,
    false,
    ['sign'],
  );
}

async function createHmacDigest(key: CryptoKey, counter: Uint8Array | string) {
  return crypto.subtle.sign('HMAC', key, toBytes(counter));
}

function hmacDigestToToken(hmacDigest: Uint8Array, digits = 6): Token {
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

// const secret = randomBytes(32);
const secret = '829a466c302e70ef9941ac49a0af1b486283a811e1e275bff39f43c4e45331e7';
const hotpToken = await hotp(secret, { counter: 1, digits: 10 });
const totpToken = await totp(secret, { period: 5 });

console.log({
  secret,
  hotpToken,
  totpToken,
});
