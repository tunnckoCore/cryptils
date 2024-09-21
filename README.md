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
import { deriveCryptoKeys, spectreV4 } from 'cryptils/derive';

// personal name (can be anything), master password, account name (or site url + handle)
const wgw = spectreV4('some persona', 'fool master pawdy', 'twitter.com/wgw_eth');
const keys = deriveCryptoKeys(wgw.secret);

console.log('privkey', bytesToHex(wgw.secret));
console.log('wiggle account:', wgw);
// => { secret: uint8array, persona: string, securepass: string, account: string }

console.log('crypto keys:', keys);
// => { bitcoin, nostr, ethereum, litecoin, vertcoin }
```

or using separate functions, to save on computation

```typescript
import { deriveBitcoinKeys, deriveEthereumKeys, deriveNostrKeys, spectreV4 } from 'cryptils/derive';

const wgw = spectreV4('some persona', 'fool master pawdy', 'twitter.com/wgw_eth');

console.log('btc1', deriveBitcoinKeys(wgw.secret));
console.log('btc2', deriveBitcoinKeys(randomBytes(32)));
// => { mnemonic, salt, privkey, pubkey, address }

console.log('eth', deriveEthereumKeys(wgw.secret));
// => { mnemonic, salt, privkey, pubkey, address }

console.log('nostr', deriveNostrKeys(wgw.secret));
// => { mnemonic salt, privkey, pubkey, npub, nsec, nrepo }
```

## Docs

### Example with 2FA OTP

```typescript
import {
  getHotp,
  getOtpSecret,
  getTokenUri,
  getTotp,
  parseOtpSecret,
  validateHotp,
  validateTotp,
} from 'cryptils/otp';
import qrcode from 'qrcode';

// accepts secret uint8array, secret as base32 string, or hex string,
// if not passed anything it will generate random secret
const secret = getOtpSecret();
const token = await getTotp(secret, { digits: 8, algorithm: 'SHA-512' });
const valid = await validateTotp(secret, token, { digits: 8, algorithm: 'SHA-512' });

console.log({ secret, token, valid });

const hotp = await getHotp(secret);
console.log({ hotp, valid: await validateHotp(secret, hotpToken) });

const parsedSecret = parseOtpSecret('5DXDAFF6BALL25TOYZXJHDCW4LY4OWTH');
const uri = getTokenUri(secret, { issuer: 'MyApp', username: 'barry' });
cosole.log({ parsedSecret, uri });

console.log(await qrcode.toString(uri));
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

const encrypted = await encryptWithSecret(account.securepass, account.secret);
const decrypted = await decryptWithSecret(encrypted, account.secret);

console.log({ encrypted, decrypted, same: decrypted === account.securepass });
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
```

## LICENSE

SPDX-License-Identifier: MPL-2.0
