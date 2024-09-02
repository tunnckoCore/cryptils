# cryptils

Utilities around Spectre / Master Password Algorithm (by Maarten Billemont), implemented in
TypeScript, using Noble &amp; Scure cryptography by @paulmillr. Used for deriving stateless accounts
&amp; passwords, 2fa, shamir secret sharing, crypto/bitcoin/nostr public and private keys, and more.

## Highlights

- Uses audited Noble & Scure cryptography by [@paulmillr](//github.com/paulmillr)
- TypeScript implementation of [Spectre](https://spectre.app) /
  [Master Password Algorithm](<https://en.wikipedia.org/wiki/Master_Password_(algorithm)>) by
  [Maarten Billemont](https://twitter.com/lhunath)
- Stateless account & password derivation
- Stateless Crypto, Bitcoin, Nostr public and private keys derivation
- Support for Shamir Secret Sharing

## Install

```
npm install cryptils
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

const twitter = deriveAccount('exmpl', 'foo bar baz', 'twitter.com');
const github = deriveAccount('exmpl', 'foo bar baz', 'github.com');
const crypto_1 = deriveCryptoAccount('exmpl', 'foo bar baz', 'crypto.0');
const crypto_2 = deriveCryptoAccount('exmpl', 'foo bar baz', 'crypto.1');
const { secret: crypto_3_secret, ...crypto_3 } = spectreV4('exmpl', 'foo bar baz', 'crypto.2');

const crypto_3_keys = deriveKeys(crypto_3_secret);
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

const bc1p = bech32encode('bc', otherKeys.pubkey, true);
console.log('bc1p:', bc1p, bc1p === otherKeys.bitcoin);
```

# LICENSE

SPDX-License-Identifier: MPL-2.0
