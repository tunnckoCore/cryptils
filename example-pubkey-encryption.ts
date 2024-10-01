import { bytesToUtf8 } from '@noble/ciphers/utils';
import { ed25519 } from '@noble/curves/ed25519';
import { base64urlnopad } from '@scure/base';

import { deriveBitcoinKeys, deriveNostrKeys, spectreV4 } from './src/derive.ts';
import { convertSchnorrTo, decryptWithPrivkey, encryptToPubkey } from './src/pke.ts';

// recommended `iterations` is >= 2**18, this is only for faster example run
const aliceRoot = spectreV4('alice', 'foo bar', 'crypto.0', { iterations: 2 ** 10 });
const barryRoot = spectreV4('barry', 'quxie zazzy', 'crypto.0', { iterations: 2 ** 10 });

const aliceBitcoin = deriveBitcoinKeys(aliceRoot.secret);
const barryBitcoin = deriveBitcoinKeys(barryRoot.secret);

console.log({ aliceBitcoin, barryBitcoin });

// convert Bitcoin keys to ed25519 or secp256k1, usable as encryption keys
// in case of Nostr and Ethereum keys, that's not needed
const aliceKeys = convertSchnorrTo(ed25519, aliceBitcoin);
const barryKeys = convertSchnorrTo(ed25519, barryBitcoin);

console.log({ aliceKeys, barryKeys });

const message = 'hello world';

// use the same curve as use for the keys above;
// encryption also creates and retuns a signature
// decryption also verifies the signature
const encrypted = await encryptToPubkey(ed25519, message, aliceKeys.privkey, barryKeys.pubkey);
const decrypted = await decryptWithPrivkey(ed25519, encrypted, barryKeys.privkey, aliceKeys.pubkey);

// results are encoded with base64urlNoPad (could use {base64urlnopad} from '@scure/base')
console.log({ encrypted, decrypted: bytesToUtf8(decrypted) });

const aliceNostr = deriveNostrKeys(aliceRoot.secret);
const barryNostr = deriveNostrKeys(barryRoot.secret);

console.log({ aliceNostr, barryNostr });

const encr2 = await encryptToPubkey(ed25519, message, aliceNostr.privkey, barryNostr.pubkey);
const decr2 = await decryptWithPrivkey(ed25519, encr2, barryNostr.privkey);

console.log({ encr2, decr2: bytesToUtf8(decr2) });
