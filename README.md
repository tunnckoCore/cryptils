# cryptils [![npm version][npmv-img]][npmv-url] [![License][license-img]][license-url] [![Libera Manifesto][libera-manifesto-img]][libera-manifesto-url]

[npmv-url]: https://www.npmjs.com/package/cryptils
[npmv-img]: https://badgen.net/npm/v/cryptils?icon=npm&cache=300
[license-url]: https://github.com/tunnckoCore/cryptils/blob/master/LICENSE.md
[license-img]: https://badgen.net/npm/license/cryptils?cache=300
[libera-manifesto-url]: https://liberamanifesto.com
[libera-manifesto-img]: https://badgen.net/badge/libera/manifesto/grey
[nostr-ready-url]: https://nostr.com
[nostr-ready-img]: https://badgen.net/badge/nostr/ready/purple
[bitcoin-ready-url]: https://bitcoin.org
[bitcoin-ready-img]: https://badgen.net/badge/bitcoin/ready/orange
[prs-welcome-img]: https://badgen.net/badge/PRs/welcome/green?cache=300
[prs-welcome-url]: http://makeapullrequest.com
[last-commit-img]: https://badgen.net/github/last-commit/tunnckoCore/cryptils
[last-commit-url]: https://github.com/tunnckoCore/cryptils/commits/master
[codestyle-url]: https://github.com/airbnb/javascript
[codestyle-img]:
  https://badgen.net/badge/code%20style/airbnb%20%2B%20prettier/ff5a5f?icon=airbnb&cache=300

[![Code style][codestyle-img]][codestyle-url]
[![bunning](https://github.com/tunnckoCore/cryptils/actions/workflows/ci.yml/badge.svg)](https://github.com/tunnckoCore/cryptils/actions/workflows/ci.yml)
[![bitcoin ready][bitcoin-ready-img]][bitcoin-ready-url]
[![nostr ready][nostr-ready-img]][nostr-ready-url]
[![Make A Pull Request][prs-welcome-img]][prs-welcome-url]
[![Time Since Last Commit][last-commit-img]][last-commit-url]

Utilities around Spectre / Master Password Algorithm (by Maarten Billemont), implemented in
TypeScript, using Noble &amp; Scure cryptography by @paulmillr. Used for deriving stateless accounts
&amp; passwords, 2fa, shamir secret sharing, crypto/bitcoin/nostr public and private keys, and more.

## Highlights

- Don't store, derive! Derive passwords and keys from a master password and a name
- Uses audited Noble & Scure cryptography by [@paulmillr](//github.com/paulmillr)
- TypeScript implementation of [Spectre](https://spectre.app) /
  [Master Password Algorithm](<https://en.wikipedia.org/wiki/Master_Password_(algorithm)>) by
  [Maarten Billemont](https://twitter.com/lhunath)
- Stateless account & password derivation
- Stateless Crypto, Bitcoin, Nostr public and private keys derivation
- Support for Shamir Secret Sharing

## Install

```
npm add cryptils
bun add cryptils
deno add npm:cryptils
```

## Usage

```typescript
import {
  bech32encode,
  deriveAccount,
  deriveCryptoAccount,
  deriveKeys,
  randomBytes,
  spectreV4,
  splitKeyToShares,
} from 'cryptils';

const usrName = 'wgw';
const passwd = 'secret master password';

// Derive password for `wgw` user on `twitter.com` and `github.com`,
const twitter = deriveAccount(usrName, passwd, 'twitter.com');
const github = deriveAccount(usrName, passwd, 'github.com');

// in addition to above, it uses the generated secret
// to derive crypto keys like ethereum address, bitcoin keys and nostr keys
const crypto_1 = deriveCryptoAccount(usrName, passwd, 'crypto.0');
const crypto_2 = deriveCryptoAccount(usrName, passwd, 'crypto.1');
const { secret: crypto_3_secret, ...crypto_3 } = spectreV4(usrName, passwd, 'crypto.2');

// deriveKeys is used inside `deriveCryptoKeys`, it's standalone function
const crypto_3_keys = deriveKeys(crypto_3_secret);

// Using Shamir Secret Sharing, split the secret into 3 keys and 5 shares
const crypto_3_keys_shares = await splitKeyToShares(crypto_3_secret, 3, 5);

const info = {
  twitter,
  github,
  crypto_1,
  crypto_2,
  crypto_3: { ...crypto_3, keys: crypto_3_keys, shares: crypto_3_keys_shares },
};

console.log();
console.log(JSON.stringify(info, null, 2));
console.log();

const rndSecret = randomBytes(32);
const otherKeys = deriveKeys(rndSecret);
console.log('other keys:', otherKeys);

// create Bitcoin bech32 bc1p address from a public key
const bc1p = bech32encode('bc', otherKeys.pubkey, true);
console.log('bc1p:', bc1p, bc1p === otherKeys.bitcoin);
```

## Docs

```typescript
declare type Options = { template?: string; hash?: any; iterations?: number };
declare type Result = { secret: Uint8Array; name: string; user: string; pass: string };
declare type Hex = string;

declare type Keys = {
  mnemonic: string;
  privkey: Hex;
  pubkey: Hex;
  npub: string; // npub1...abc
  nsec: string; // nsec1...abc
  nrepo: string; // nrepo1...abc
  ethereum: `0x${string}`; // 0x1987...abc
  bitcoin: string; // bc1p...abc
  litecoin: string; // ltc1p...abc
  vertcoin: string; // vtc1p...abc
};

declare function spectreV4(user: string, pass: string, name: string, options?: Options): Result;

declare function deriveKeys(secret: Uint8Array): Keys;
declare function deriveMnemonic(secret: string, size?: 16 | 32): string;

declare function deriveAccount(
  user: string,
  pass: string,
  name: string,
  options?: Options,
): Omit<Result, 'secret'>;

declare function deriveCryptoAccount(
  user: string,
  pass: string,
  name: string,
  options?: Options,
): Omit<Result, 'secret'> & Keys;

declare function bech32encode(
  prefix: string,
  key: Uint8Array | string,
  isAddr: boolean,
  limit: number,
): string;

declare function decryptWithSecret(ciphertext: string, key: Uint8Array | string): Promise<string>;
declare function encryptWithSecret(
  plaintext: Uint8Array | string,
  key: Uint8Array | string,
  salt?: Uint8Array,
): Promise<string>;

declare function privateKeyToEthereumAddress(key: Uint8Array | string): `0x${string}`;
declare function checksumEthereumAddress(address: string): `0x${string}`;

declare function combineSharesToKey(shares: string[]): Hex;
declare function splitKeyToShares(
  key: Uint8Array | string,
  threshold: number,
  shares: number,
): Hex[];
```

## LICENSE

SPDX-License-Identifier: MPL-2.0
