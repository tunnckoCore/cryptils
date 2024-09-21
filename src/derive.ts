import { ed25519 } from '@noble/curves/ed25519';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import { hmac } from '@noble/hashes/hmac';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { scrypt } from '@noble/hashes/scrypt';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, randomBytes } from '@noble/hashes/utils';
import { entropyToMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { mask as secureMask } from 'micro-key-producer/password.js';

import { bech32encode } from './bech32encode.ts';
import { privateKeyToEthereumAddress } from './ethereum.ts';
import type { HexString, SpectreOptions, SpectreResult } from './types.ts';
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
    iterations: 2 ** 19, // 18 = 262144, 19 = 524288, 20 = 1048576
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

  return { secret, account: name, persona: user, masterpass: pass_ } as SpectreResult;
}

// salt/user is kdf salt, key/pass is kdf key
function defaultScryptFn(key, salt, _opts = {}) {
  return scrypt(toBytes(key), toBytes(salt), {
    // @ts-ignore bruh
    N: _opts.iterations || 2 ** 19,
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
    c: _opts.iterations || 2 ** 19,
    ..._opts,
    dkLen: 64,
  });
}

// used to derive all kinds of keys, including Nostr, Ethereum, Bitcoin, Litecoin, Vertcoin
// for lower-level you can use deriveKey directly or the Nostr, Ethereum, Bitcoin specific ones.
export function deriveCryptoKeys(secret: Uint8Array | string, kdf = defaultKdfFnPBKDF2) {
  // const mnemonic = deriveMnemonic(secret);
  // const privkey = bytesToHex(toBytes(secret));
  const salt = ed25519.getPublicKey(toBytes(secret));

  return {
    nostr: deriveNostrKeys(secret, salt, kdf),
    ethereum: deriveEthereumKeys(secret, salt, kdf),
    bitcoin: deriveBitcoinKeys(secret, kdf),
    litecoin: deriveKey('ltc', secret, salt, true, kdf),
    vertcoin: deriveKey('vtc', secret, salt, true, kdf),
  };
}

export function deriveNostrKeys(secret, pubkey = randomBytes(32), kdf = defaultKdfFnPBKDF2) {
  // we derive a general Nostr secret key (uint8array) and pubkey
  const nostr = deriveKey('nostr', secret, pubkey, false, kdf) as DeriveKeyResult & {
    npub: `npub1${string}`;
    nsec: `nsec1${string}`;
    nrepo: `nrepo1${string}`;
  };

  // @ts-ignore bruh
  delete nostr.address;

  // from derived privkey and pubkey, we derive nostr-specific addresses for nsec, npub and nrepo
  nostr.npub = bech32encode('npub', nostr.pubkey) as (typeof nostr)['npub'];
  nostr.nsec = bech32encode('nsec', nostr.privkey) as (typeof nostr)['nsec'];
  nostr.nrepo = bech32encode('nrepo', nostr.pubkey) as (typeof nostr)['nrepo'];

  return nostr as DeriveKeyResult & {
    npub: `npub1${string}`;
    nsec: `nsec1${string}`;
    nrepo: `nrepo1${string}`;
  };
}

export function deriveEthereumKeys(secret, pubkey = randomBytes(32), kdf = defaultKdfFnPBKDF2) {
  const ethereum = deriveKey('ethereum', secret, pubkey, false, kdf);
  ethereum.address = privateKeyToEthereumAddress(ethereum.privkey) as `0x${string}`;
  ethereum.pubkey = bytesToHex(
    secp256k1.getPublicKey(toBytes(ethereum.privkey), false),
  ) as HexString;

  return ethereum;
}

export function deriveBitcoinKeys(secret: any, kdf = defaultKdfFnPBKDF2) {
  // doesn't matter that it's ed25519, we just need a salt "pubkey", a thing based on the secret
  // this salt-pubkey is used in specific way in the derivation process:
  // - the secretKey + bech32(prefix, saltPubkey) is used in KDF to generate userKey
  // - prefix in this function specifically is "bc" (in nostr it's "nostr", in ethereum it's "ethereum")
  // - this userKey + "{prefix} seedkey" is passed through HMAC-SHA256 to get the final "secret/entropy/mnemonic/seed"
  const saltKey = ed25519.getPublicKey(secret);
  return deriveKey('bc', secret, saltKey, true, kdf);
}

type DeriveKeyResult = {
  mnemonic: string;
  salt: Uint8Array;
  pubkey: HexString;
  privkey: HexString;
  address: string;
};

export function deriveKey(
  prefix,
  key,
  pub,
  isAddr = false,
  kdf = defaultKdfFnPBKDF2,
): DeriveKeyResult {
  const salt = pub || randomBytes(32);
  const bechaddy = bech32encode(prefix, salt);
  // the secretKey + bech32(prefix, saltPubkey) is used in KDF to generate userKey
  const usageKey = kdf(key, toBytes(bechaddy));
  // this usageKey + "{prefix} seedkey" is passed through HMAC-SHA256 to get the final "secret/entropy/mnemonic/seed"
  // - prefix is usually "bc/ltc/vtc", or in nostr it's "nostr", in ethereum it's "ethereum"
  const secret = hmac(sha256, usageKey, prefix + ' seedkey');
  // then we derive the mnemonic from that secret
  const mnemonic = entropyToMnemonic(secret, wordlist);

  // in bitcoin, litecoin, vertcoin case it's schnor; for nostr and ethereum these 2 are overwritten anyway
  const pubkey = schnorr.getPublicKey(secret);
  const address = bech32encode(prefix, pubkey, isAddr);

  return { mnemonic, salt, privkey: bytesToHex(secret), pubkey: bytesToHex(pubkey), address };
}

export function deriveMnemonic(secret: Uint8Array | string, size = 32, wordlist_ = wordlist) {
  // if hexstring, convert to bytes
  // if string (utf8), convert to bytes
  // if bytes, passthrough
  secret = toBytes(secret);

  if (secret.length !== 16 && secret.length !== 32) {
    throw new Error('Invalid entropy length: 16 or 32 bytes');
  }

  // if size is set to 16 but the given secret is bigger, we get just the first 16 bytes
  if (size === 16) {
    secret = secret.slice(0, 16);
  }

  return entropyToMnemonic(secret, wordlist_);
}
