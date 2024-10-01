import { bytesToUtf8 } from '@noble/ciphers/utils';
import { ed25519 } from '@noble/curves/ed25519';
import { secp256k1 } from '@noble/curves/secp256k1';
import { hexToBytes } from '@noble/hashes/utils';

import { deriveBitcoinKeys, deriveEthereumKeys, deriveNostrKeys, spectreV4 } from './src/derive.ts';
import { convertSchnorrTo, decryptWithPrivkey, encryptToPubkey } from './src/pke.ts';
import { toBytes } from './src/utils.ts';

// recommended `iterations` is >= 2**18, this is only for faster example run
const aliceRoot = spectreV4('alice', 'foo bar', 'crypto.0', { iterations: 2 ** 10 });
const barryRoot = spectreV4('barry', 'quxie zazzy', 'crypto.0', { iterations: 2 ** 10 });

console.log({ aliceRoot, barryRoot });

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

const nostrEncr = await encryptToPubkey(ed25519, message, aliceNostr.privkey, barryNostr.pubkey);
const nostrDecr = await decryptWithPrivkey(ed25519, nostrEncr, barryNostr.privkey);

console.log({ nostrEncr, nostrDec: bytesToUtf8(nostrDecr) });

const aliceEth = deriveEthereumKeys(aliceRoot.secret);
const barryEth = deriveEthereumKeys(barryRoot.secret);

const ethEncrypted = await encryptToPubkey(secp256k1, message, aliceEth.privkey, barryEth.pubkey);
const ethDecrypted = await decryptWithPrivkey(secp256k1, ethEncrypted, barryEth.privkey);

console.log({ ethEncrypted, ethDecrypted: bytesToUtf8(ethDecrypted) });
