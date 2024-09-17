import { randomBytes } from '@noble/hashes/utils';

import { bech32encode } from './src/bech32encode.ts';
import {
  deriveAccount,
  deriveCryptoAccount,
  deriveKeys,
  spectreV4,
  splitKeyToShares,
} from './src/index.ts';

const twitter = deriveAccount('exmpl', 'foo bar baz', 'twitter.com');
const github = deriveAccount('exmpl', 'foo bar baz', 'github.com');
const crypto_1 = deriveCryptoAccount('exmpl', 'foo bar baz', 'crypto.0');
const crypto_2 = deriveCryptoAccount('exmpl', 'foo bar baz', 'crypto.1');
const { secret: crypto_3_secret, ...crypto_3 } = spectreV4('exmpl', 'foo bar baz', 'crypto.2');
const withScrypt = spectreV4('exmpl', 'foo bar baz', 'woho.ex', {
  kdf: 'scrypt',
  iterations: 2 ** 17,
});

console.log({ withScrypt });

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
