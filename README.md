# cryptils [![npm version][npmv-img]][npmv-url] [![License][license-img]][license-url] [![Libera Manifesto][libera-manifesto-img]][libera-manifesto-url]

[npmv-url]: https://www.npmjs.com/package/cryptils
[npmv-img]: https://badgen.net/npm/v/cryptils?icon=npm
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
- Cloud-less & storage-less password manager, stateless password derivation
- Uses **only** audited Noble & Scure cryptography by [@paulmillr](//github.com/paulmillr)
- TypeScript implementation of [Spectre.app](https://spectre.app) /
  [Master Password Algorithm](<https://en.wikipedia.org/wiki/Master_Password_(algorithm)>) by
  [Maarten Billemont](https://twitter.com/lhunath)
- Stateless account & password derivation - no need to store anything
- Stateless wallet/keys derivation for Ethereum, Bitcoin, Litecoin, Vertcoin, Nostr
- Support for splitting the secret key with Shamir Secret Sharing scheme
- AES-256-GCM encrypt/decrypt a private thing using the secret key
- Generate and validate 2FA tokens (HOTP & TOTP)
  - RFC 4226 & RFC 6238
  - support `SHA-1`, `SHA-256`, `SHA-512` hashing algorithms
  - support different digits lengths, up to 10

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

### Example with 2FA OTP

```typescript
import {
  generateBase32Secret,
  getHotpToken,
  getTokenUri,
  getTotpToken,
  validateHotpToken,
  validateToken,
  validateTotpToken,
} from 'cryptils';
import qrcode from 'qrcode';

const secret = generateBase32Secret();
const token = await getTotpToken(secret);
const valid = await validateTotpToken(secret, token);

console.log({ secret, token, valid });

const hotpToken = await getHotpToken(secret);
console.log({ hotpToken, valid: await validateHotpToken(secret, hotpToken) });
```

### Example with AES-256-GCM

```typescript
import { decryptWithSecret, encryptWithSecret } from 'cryptils/aes';
import { spectreV4 } from 'cryptils/derive';
import { randomBytes } from 'cryptils/utils';

const account = spectreV4('usrname', 'foo pass bar', 'twt.com');

// or try with random one
const secret = randomBytes(32);

console.log({ account });

const encrypted = await encryptWithSecret(account.pass, account.secret);
const decrypted = await decryptWithSecret(encrypted, account.secret);

console.log({ encrypted, decrypted, same: decrypted === account.pass });
```

### Types

```typescript
export type SpectreOptions = { template?: string; hash?: any; iterations?: number };
export type SpectreResult = { secret: Uint8Array; name: string; user: string; pass: string };

export type HexString = string;
export type Input = Uint8Array | string;
export type SecretKey = Uint8Array | HexString;
export type HashAlgo = 'SHA-1' | 'SHA-256' | 'SHA-512' | string;
export type TokenResult = string;

export type KeysResult = {
  mnemonic: string;
  privkey: HexString;
  pubkey: HexString;
  npub: string; // npub1...abc
  nsec: string; // nsec1...abc
  nrepo: string; // nrepo1...abc
  ethereum: `0x${string}`; // 0x1987...abc
  bitcoin: string; // bc1p...abc
  litecoin: string; // ltc1p...abc
  vertcoin: string; // vtc1p...abc
};
```

## LICENSE

SPDX-License-Identifier: MPL-2.0
