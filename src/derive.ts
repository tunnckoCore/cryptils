import { ed25519, hashToCurve as ed25519hashToCurve } from '@noble/curves/ed25519';
import {
  schnorr,
  secp256k1,
  hashToCurve as secp256k1hashToCurve,
  encodeToCurve as secpkEncodeToCurve,
} from '@noble/curves/secp256k1';
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
import type { DeriveKeyResult, HexString, SpectreOptions, SpectreResult } from './types.ts';
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

  return { secret, account: name, persona: user, securepass: pass_ } as SpectreResult;
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
export function deriveCryptoKeys(
  secretKey: Uint8Array | HexString,
  saltKey = ed25519.getPublicKey(toBytes(secretKey)),
  kdfFn = defaultKdfFnPBKDF2,
) {
  const ltc = deriveKey('ltc', secretKey, saltKey, kdfFn);
  const ltcPrivkey = bytesToHex(ltc.secret);
  const ltcPubkey = bytesToHex(schnorr.getPublicKey(toBytes(ltcPrivkey))) as HexString;
  const ltcAddress = bech32encode('ltc', ltcPubkey, true);

  const vtc = deriveKey('vtc', secretKey, saltKey, kdfFn);
  const vtcPrivkey = bytesToHex(vtc.secret);
  const vtcPubkey = bytesToHex(schnorr.getPublicKey(toBytes(vtcPrivkey))) as HexString;
  const vtcAddress = bech32encode('vtc', ltcPubkey, true);

  return {
    nostr: deriveNostrKeys(secretKey, saltKey, kdfFn),
    ethereum: deriveEthereumKeys(secretKey, saltKey, kdfFn),
    bitcoin: deriveBitcoinKeys(secretKey, saltKey, kdfFn),
    litecoin: { ...ltc, privkey: ltcPrivkey, pubkey: ltcPubkey, address: ltcAddress },
    vertcoin: { ...vtc, privkey: vtcPrivkey, pubkey: vtcPubkey, address: vtcAddress },
  };
}

export function deriveNostrKeys(
  secretKey: Uint8Array | HexString,
  saltKey = ed25519.getPublicKey(toBytes(secretKey)),
  kdfFn = defaultKdfFnPBKDF2,
) {
  // we derive a general Nostr secretKey (uint8array) and pubkey
  const nostr = deriveKey('nostr', secretKey, saltKey, kdfFn);

  // @ts-ixgnore the `toRawBytes` DOES exists
  const ed25519curveSecret = ed25519hashToCurve(nostr.secret).toRawBytes();

  // convert a generated random secret, to a specific ed25519 curve point
  const privkey = bytesToHex(ed25519curveSecret);

  // the returned pubkey from deriveKey is schnorr one, make sure it's ed25519
  const pubkey = bytesToHex(ed25519.getPublicKey(privkey));

  // from derived privkey and pubkey, we derive nostr-specific addresses for nsec, npub and nrepo
  const npub = bech32encode('npub', pubkey);
  const nsec = bech32encode('nsec', privkey);
  const nrepo = bech32encode('nrepo', pubkey);

  return { ...nostr, privkey, pubkey, npub, nsec, nrepo } as DeriveKeyResult & {
    privkey: HexString;
    pubkey: HexString;
    npub: `npub1${string}`;
    nsec: `nsec1${string}`;
    nrepo: `nrepo1${string}`;
  };
}

export function deriveEthereumKeys(
  secretKey: Uint8Array | HexString,
  saltKey = ed25519.getPublicKey(toBytes(secretKey)),
  kdf = defaultKdfFnPBKDF2,
) {
  const ethereum = deriveKey('ethereum', secretKey, saltKey, kdf);

  // @ts-iXXgnore the `toRawBytes` DOES exists - seems like we don't need such convert?
  // const secp25k1curveSecret = secp256k1hashToCurve(ethereum.secret).toRawBytes();
  // const secp25k1curveSecret = secpkEncodeToCurve(ethereum.secret);

  // console.log({ secp25k1curveSecret }, 'bruh', secp25k1curveSecret.toRawBytes());
  // // convert a generated random secret, to a specific secp256k1 curve point
  // const privkey = bytesToHex(secp25k1curveSecret.toRawBytes());
  // console.log({ privkey });

  const privkey = bytesToHex(ethereum.secret);

  const address = privateKeyToEthereumAddress(privkey) as `0x${string}`;
  const pubkey = bytesToHex(secp256k1.getPublicKey(toBytes(privkey), true)) as HexString;
  const pubkeyUncompressed = bytesToHex(
    secp256k1.getPublicKey(toBytes(privkey), false),
  ) as HexString;

  return { privkey, pubkey, pubkeyUncompressed, address } as DeriveKeyResult & {
    privkey: HexString;
    pubkey: HexString;
    pubkeyUncompressed: HexString;
    address: `0x${string}`;
  };
}

export function deriveBitcoinKeys(
  secretKey: Uint8Array | HexString,
  saltKey = ed25519.getPublicKey(toBytes(secretKey)),
  kdf = defaultKdfFnPBKDF2,
) {
  // doesn't matter that it's ed25519, we just need a salt "pubkey", a thing based on the secret
  // this salt-pubkey is used in specific way in the derivation process:
  // - the secretKey + bech32(prefix, saltPubkey) is used in KDF to generate userKey
  // - prefix in this function specifically is "bc" (in nostr it's "nostr", in ethereum it's "ethereum")
  // - this userKey + "{prefix} seedkey" is passed through HMAC-SHA256 to get the final "secret/entropy/mnemonic/seed"
  // const saltKey = ed25519.getPublicKey(secretKey);
  const bitcoin = deriveKey('bc', secretKey, saltKey, kdf);

  // @ts-iXXgnore the `toRawBytes` DOES exists
  // do we need to convert to secp256k1 eventho we use/need schnorr? - seems like we don't
  // const secp25k1curveSecret = secp256k1hashToCurve(bitcoin.secret).toRawBytes();
  // const privkey = bytesToHex(secp25k1curveSecret);

  const privkey = bytesToHex(bitcoin.secret);
  const pubkey = bytesToHex(schnorr.getPublicKey(toBytes(privkey))) as HexString;
  const address = bech32encode('bc', pubkey, true);

  return { ...bitcoin, privkey, pubkey, address } as DeriveKeyResult & {
    privkey: HexString;
    pubkey: HexString;
    address: `0x${string}`;
  };
}

export function deriveKey(
  prefix: string,
  key: Uint8Array | HexString,
  pub?: Uint8Array | HexString,
  kdf = defaultKdfFnPBKDF2,
): DeriveKeyResult {
  const salt = toBytes(pub || ed25519.getPublicKey(toBytes(key)));
  const bechaddy = bech32encode(prefix, salt);
  // the secretKey + bech32(prefix, saltPubkey) is used in KDF to generate userKey
  const usageKey = kdf(key, toBytes(bechaddy));
  // this usageKey + "{prefix} seedkey" is passed through HMAC-SHA256 to get the final "secret/entropy/mnemonic/seed"
  // - prefix is usually "bc/ltc/vtc", or in nostr it's "nostr", in ethereum it's "ethereum"
  const secret = hmac(sha256, usageKey, prefix + ' seedkey');
  // then we derive the mnemonic from that secret
  const mnemonic = entropyToMnemonic(secret, wordlist);

  return { mnemonic, salt, secret };
}

export function deriveMnemonic(secret: Uint8Array | HexString, size = 32, wordlist_ = wordlist) {
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
