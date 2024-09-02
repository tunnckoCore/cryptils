import { gcm } from '@noble/ciphers/webcrypto';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import { hmac } from '@noble/hashes/hmac';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { keccak_256 } from '@noble/hashes/sha3';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, randomBytes, toBytes } from '@noble/hashes/utils';
import { bech32, bech32m } from '@scure/base';
import { entropyToMnemonic, mnemonicToEntropy } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { mask as secureMask } from 'micro-key-producer/password.js';
import { combine as combineKey, split as splitKey } from 'shamir-secret-sharing';

// Master Password Algorithm (by Maarten Billemont),
// his latest version on Spectre.app is V3(2015:01)
// while this one is using PBKDF2 instead of Scrypt,
// optionally pass different hash (default sha256) and iterations count
export function spectreV4(
  user: Uint8Array | string,
  pass: Uint8Array | string,
  name: Uint8Array | string,
  options?: { template?: string; hash?: any; iterations?: number },
) {
  const opts = { template: '111vvc-CvAvc1-cAvv1', hash: sha256, iterations: 300500, ...options };

  // N = 32768, r = 8, p = 2, dkLen = 64
  // user-key = scrypt( secret, name, N, r, p, dkLen )
  // const userKey = scrypt(toBytes(secret), toBytes(username), { N: 2 ** 15, r: 8, p: 2, dkLen: 64 });
  //
  // use pbkdf2 instead of scrypt
  const userKey = pbkdf2(opts.hash, toBytes(pass), toBytes(user), {
    c: opts.iterations,
    dkLen: 64,
  });

  // site-key = HMAC-SHA-256( siteName + siteCounter, userKey )
  const secret = hmac(sha256, userKey, name);

  // password = passwordMask( template, siteKey )
  const { password: pass_ } = secureMask(opts.template).apply(secret);

  return { secret, name, user, pass: pass_ };
}

export function deriveAccount(
  user: Uint8Array | string,
  pass: Uint8Array | string,
  name: Uint8Array | string,
  options?: { template?: string; hash?: any; iterations?: number },
) {
  const { secret, ...account } = spectreV4(user, pass, name, options);

  return account;
}

export function deriveCryptoAccount(
  user: Uint8Array | string,
  pass: Uint8Array | string,
  name: Uint8Array | string,
  options?: { template?: string; hash?: any; iterations?: number },
) {
  const { secret, ...account } = spectreV4(user, pass, name, options);
  const keys = deriveKeys(secret);

  return { ...account, keys };
}

export function deriveKeys(secret: Uint8Array) {
  const mnemonic = deriveMnemonic(secret);
  const privkey = bytesToHex(secret);
  const pubkey = schnorr.getPublicKey(secret);

  return {
    // secret,
    mnemonic,
    privkey,
    pubkey: bytesToHex(pubkey),
    npub: bech32encode('npub', pubkey),
    nsec: bech32encode('nsec', secret),
    nrepo: bech32encode('nrepo', pubkey),
    ethereum: privateKeyToEthereumAddress(pubkey), // accepts secret or pubkey, pass `true` as second argument to use pubkey
    bitcoin: bech32encode('bc', pubkey, true),
    litecoin: bech32encode('ltc', pubkey, true),
    vertcoin: bech32encode('vtc', pubkey, true),
  };
}

export function deriveMnemonic(secret: Uint8Array | string, size = 32) {
  if (typeof secret === 'string') {
    secret = hexToBytes(secret);
  }

  if (secret.length !== 16 && secret.length !== 32) {
    throw new Error('Invalid entropy length: 16 or 32 bytes');
  }

  if (size === 16) {
    secret = secret.slice(0, 16);
  }

  return entropyToMnemonic(secret, wordlist);
}

export function bech32encode(
  prefix: string,
  key: Uint8Array | string,
  isAddr = false,
  limit = 1000,
) {
  const data = typeof key === 'string' ? hexToBytes(key) : key;
  const bech = isAddr ? bech32m : bech32;
  const words = bech.toWords(data);
  return bech.encode(prefix, isAddr ? [1, ...words] : words, isAddr ? 1500 : limit);
}

export async function encryptWithSecret(
  plaintext: Uint8Array | string,
  key: Uint8Array | string,
  salt?: Uint8Array,
) {
  const secret = typeof key === 'string' ? hexToBytes(key).slice(1) : key;
  const salt_ = salt ? toBytes(salt) : randomBytes(32);
  const cipher = gcm(secret, salt_);

  const ciphertext = [
    'aes256gcm',
    bytesToHex(salt_),
    bytesToHex(await cipher.encrypt(toBytes(plaintext))),
  ].join('_');

  return ciphertext;
}

export async function decryptWithSecret(ciphertext, key) {
  const [_algo, salt, data] = ciphertext.split('_');
  const secret = typeof key === 'string' ? hexToBytes(key) : key;
  const cipher = gcm(secret, hexToBytes(salt));

  return new TextDecoder('utf-8').decode(await cipher.decrypt(hexToBytes(data)));
}

export function privateKeyToEthereumAddress(key: Uint8Array | string): `0x${string}` {
  const publicKey = secp256k1.getPublicKey(key, false).slice(1);

  const hash = keccak_256(publicKey).slice(12);

  return checksumEthereumAddress(bytesToHex(hash));
}

export function checksumEthereumAddress(address: string) {
  const _address = address.toLowerCase();
  const addressHash = bytesToHex(keccak_256(address.toLowerCase()));

  let checksumAddress = '0x';

  for (let i = 0; i < _address.length; i++) {
    // If ith character is 8 to f then make it uppercase
    if (parseInt(addressHash[i] as string, 16) > 7) {
      checksumAddress += (_address[i] as string).toUpperCase();
    } else {
      checksumAddress += _address[i];
    }
  }

  return checksumAddress as `0x${string}`;
}

export async function splitKeyToShares(
  key: Uint8Array | string,
  threshold: number,
  shares: number,
) {
  return (await splitKey(typeof key === 'string' ? hexToBytes(key) : key, shares, threshold)).map(
    bytesToHex,
  );
}

export async function combineSharesToKey(shares: string[]) {
  return combineKey(shares.map((x) => (typeof x === 'string' ? hexToBytes(x) : x)));
}

export {
  combineKey,
  splitKey,
  bytesToHex,
  hexToBytes,
  randomBytes,
  entropyToMnemonic,
  mnemonicToEntropy,
};
