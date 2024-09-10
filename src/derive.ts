import { schnorr } from '@noble/curves/secp256k1';
import { hmac } from '@noble/hashes/hmac';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { scrypt } from '@noble/hashes/scrypt';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { entropyToMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { mask as secureMask } from 'micro-key-producer/password.js';

import { bech32encode } from './bech32encode.ts';
import { privateKeyToEthereumAddress } from './ethereum.ts';
import type { KeysResult, SpectreOptions, SpectreResult } from './types.ts';
import { toBytes } from './utils.ts';

// Master Password Algorithm (by Maarten Billemont),
// his latest version on Spectre.app is V3(2015:01)
// It can use either Scrypt or PBKDF2 as KDF,
// optionally pass different hash (default sha256) and iterations count
export function spectreV4(
  user: Uint8Array | string,
  pass: Uint8Array | string,
  name: string,
  options?: SpectreOptions,
) {
  const opts = {
    template: '111vvc-CvAvc1-cAvv1',
    hash: sha256,
    kdf: defaultKdfFnPBKDF2,
    iterations: 2 ** 18, // 262144
    ...options,
  };

  // N = 32768, r = 8, p = 2, dkLen = 64
  // user-key = scrypt( secret, name, N, r, p, dkLen )

  // @ts-ignore bruh
  if (opts.kdf === 'scrypt' || (opts.kdf && opts.kdf.name === 'scrypt')) {
    opts.kdf = defaultScryptFn;
  } else if (opts.kdf === 'pbkdf2' || (opts.kdf && opts.kdf.name === 'pbkdf2')) {
    opts.kdf = defaultKdfFnPBKDF2;
  }

  const userKey = opts.kdf(toBytes(pass), toBytes(user), opts);

  // site-key = HMAC-SHA-256( siteName + siteCounter, userKey )
  const secret = hmac(sha256, userKey, name);

  // password = passwordMask( template, siteKey )
  const { password: pass_ } = secureMask(opts.template).apply(secret);

  return { secret, name, user, pass: pass_ } as SpectreResult;
}

// salt/user is kdf salt, key/pass is kdf key
function defaultScryptFn(key, salt, _opts = {}) {
  return scrypt(toBytes(key), toBytes(salt), {
    // @ts-ignore bruh
    N: _opts.iterations,
    r: 8,
    p: 1,
    ..._opts,
    dkLen: 64,
  });
}

// salt/user is kdf salt, key/pass is kdf key
function defaultKdfFnPBKDF2(key, salt, _opts = {}) {
  return pbkdf2(sha256, toBytes(key), toBytes(salt), {
    // @ts-ignore bruh
    c: _opts.iterations,
    ..._opts,
    dkLen: 64,
  });
}

export function deriveAccount(
  user: Uint8Array | string,
  pass: Uint8Array | string,
  name: string,
  options?: SpectreOptions,
) {
  const { secret, ...account } = spectreV4(user, pass, name, options);

  return account as Omit<SpectreResult, 'secret'>;
}

export function deriveCryptoAccount(
  user: Uint8Array | string,
  pass: Uint8Array | string,
  name: string,
  options?: SpectreOptions,
) {
  const { secret, ...account } = spectreV4(user, pass, name, options);
  const keys = deriveKeys(secret);

  return { ...account, keys } as Omit<SpectreResult, 'secret'> & { keys: KeysResult };
}

export function deriveKeys(secret: Uint8Array | string): KeysResult {
  const mnemonic = deriveMnemonic(secret);
  const privkey = bytesToHex(toBytes(secret));
  const pubkey = schnorr.getPublicKey(secret);

  return {
    // secret,
    mnemonic,
    privkey,
    pubkey: bytesToHex(pubkey),
    npub: bech32encode('npub', pubkey),
    nsec: bech32encode('nsec', secret),
    nrepo: bech32encode('nrepo', pubkey),
    bitcoin: bech32encode('bc', pubkey, true),
    litecoin: bech32encode('ltc', pubkey, true),
    vertcoin: bech32encode('vtc', pubkey, true),
    ethereum: privateKeyToEthereumAddress(pubkey), // accepts secret or pubkey, pass `true` as second argument to use pubkey
  };
}

export function deriveMnemonic(secret: Uint8Array | string, size = 32, wordlist_ = wordlist) {
  // if hexstring, convert to bytes
  // if string (utf8), convert to bytes
  // if bytes, passthrough
  secret = toBytes(secret);

  if (secret.length !== 16 && secret.length !== 32) {
    throw new Error('Invalid entropy length: 16 or 32 bytes');
  }

  if (size === 16) {
    secret = secret.slice(0, 16);
  }

  return entropyToMnemonic(secret, wordlist_);
}
