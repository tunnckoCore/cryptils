import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';

import { bytesToHex } from './utils.ts';

export function privateKeyToEthereumAddress(key: Uint8Array | string): `0x${string}` {
  const publicKey = secp256k1.getPublicKey(key, false).slice(1);

  const hash = keccak_256(publicKey).slice(12);

  return checksumEthereumAddress(bytesToHex(hash));
}

export function checksumEthereumAddress(address: string): `0x${string}` {
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
