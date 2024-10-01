import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex, randomBytes } from '@noble/hashes/utils';

import {
  deriveBitcoinKeys,
  deriveCryptoKeys,
  deriveEthereumKeys,
  deriveKey,
  deriveNostrKeys,
  encryptWithSecret,
  spectreV4,
} from './src/index.ts';

// const crypto_1 = deriveCryptoAccount(
//   'some persona',
//   'fool master brick pawdy',
//   'twitter.com/wgw_eth',
// );
// console.log(crypto_1);

// personal name (can be anything), master password, account name (or site url + handle)
const wgw = spectreV4('some persona', 'fool master brick pawdy', 'twitter.com/wgw_eth');
const keys = deriveCryptoKeys(wgw.secret);

console.log({ wgw, keys }, bytesToHex(wgw.secret));

console.log('encrypt with btc secret', await encryptWithSecret(keys.bitcoin.privkey, wgw.secret));

console.log('btc1', deriveBitcoinKeys(randomBytes(32)));
console.log('btc2', deriveBitcoinKeys(randomBytes(32)));
// console.log('btc3', deriveBitcoinKeys(randomBytes(32)));
// console.log('btc4', deriveBitcoinKeys(randomBytes(32)));

// const saltkey = ed25519.getPublicKey(result.secret);
// console.log('ethereumxxxxxxx:', deriveEthereumKeys(result.secret, saltkey));
// console.log('bitcoin:', deriveKey('bc', result.secret, saltkey));
// console.log('nostr:', deriveNostrKeys(result.secret, saltkey));
// console.log({ result });
