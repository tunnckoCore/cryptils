// Master Password Algorithm (by Maarten Billemont),
// his latest version on Spectre.app is V3(2015:01)
// while this one is using PBKDF2 instead of Scrypt,

import { schnorr } from '@noble/curves/secp256k1';
import { hmac } from '@noble/hashes/hmac';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { scrypt } from '@noble/hashes/scrypt';
import { sha256 } from '@noble/hashes/sha256';
import { wordlist } from '@scure/bip39/wordlists/english';
import { mask as secureMask } from 'micro-key-producer/password.js';

import { privateKeyToEthereumAddress } from './ethereum.ts';
import type { Input, KeysResult, SpectreOptions, SpectreResult } from './types.ts';
import { bech32encode, bytesToHex, entropyToMnemonic, hexToBytes, toBytes } from './utils.ts';

// optionally pass different hash (default sha256) and iterations count

export function spectreV4(user: string, pass: Input, name: string, options?: SpectreOptions) {
  const opts = {
    template: '111vvc-CvAvc1-cAvv1',
    hash: sha256,
    kdf: defaultKDF,
    iterations: 2 ** 18, // 262144
    ...options,
  };

  // N = 32768, r = 8, p = 2, dkLen = 64
  // user-key = scrypt( secret, name, N, r, p, dkLen )

  if (opts.kdf === 'scrypt' || (opts.kdf && opts.kdf.name === 'scrypt')) {
    opts.kdf = (_user, _pass, _opts) =>
      scrypt(toBytes(_user), toBytes(_pass), {
        // @ts-ignore bruh
        N: _opts.iterations,
        r: 8,
        p: 2,
        ..._opts,
        dkLen: 64,
      });
  }

  const userKey = opts.kdf(toBytes(user), toBytes(pass), opts);

  // site-key = HMAC-SHA-256( siteName + siteCounter, userKey )
  const secret = hmac(sha256, userKey, name);

  // password = passwordMask( template, siteKey )
  const { password: pass_ } = secureMask(opts.template).apply(secret);

  return { secret, name, user, pass: pass_ } as SpectreResult;
}

export function defaultKDF(_user, _pass, _opts = {}) {
  return pbkdf2(sha256, toBytes(_pass), toBytes(_user), {
    // @ts-ignore bruh
    c: _opts.iterations,
    ..._opts,
    dkLen: 64,
  });
}

export function deriveAccount(user: string, pass: Input, name: string, options?: SpectreOptions) {
  const { secret, ...account } = spectreV4(user, pass, name, options);

  return account as Omit<SpectreResult, 'secret'>;
}

export function deriveCryptoAccount(
  user: string,
  pass: Input,
  name: string,
  options?: SpectreOptions,
) {
  const { secret, ...account } = spectreV4(user, pass, name, options);
  const keys = deriveKeys(secret);

  return { ...account, keys } as Omit<SpectreResult, 'secret'> & { keys: KeysResult };
}

export function deriveKeys(secret: Input): KeysResult {
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

export function deriveMnemonic(secret: Input, size = 32, wordlist_ = wordlist) {
  if (typeof secret === 'string') {
    secret = hexToBytes(secret);
  }

  if (secret.length !== 16 && secret.length !== 32) {
    throw new Error('Invalid entropy length: 16 or 32 bytes');
  }

  if (size === 16) {
    secret = secret.slice(0, 16);
  }

  return entropyToMnemonic(secret, wordlist_);
}
