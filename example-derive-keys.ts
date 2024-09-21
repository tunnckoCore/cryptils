import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex, randomBytes } from '@noble/hashes/utils';

import {
  deriveBitcoinKeys,
  deriveCryptoAccount,
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

console.log('encrypted btc', await encryptWithSecret(keys.bitcoin.privkey, wgw.secret));

// console.log('btc1', deriveBitcoinKeys(randomBytes(32)));
// console.log('btc2', deriveBitcoinKeys(randomBytes(32)));
// console.log('btc3', deriveBitcoinKeys(randomBytes(32)));
// console.log('btc4', deriveBitcoinKeys(randomBytes(32)));

// const tempkey = ed25519.getPublicKey(result.secret);
// console.log('ethereumxxxxxxx:', deriveEthereumKeys(result.secret, tempkey));
// console.log('bitcoin:', deriveKey('bc', result.secret, tempkey));
// console.log('nostr:', deriveNostrKeys(result.secret, tempkey));
// console.log({ result });
