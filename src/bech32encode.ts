import { hexToBytes } from '@noble/hashes/utils';
import { bech32, bech32m } from '@scure/base';

// a mix of bech32 and bech32m, pass 3rd argument to true to use bech32m
export function bech32encode(
  prefix: string,
  key: Uint8Array | string,
  isAddr: boolean = false,
  limit: number = 1000,
): string {
  const data = typeof key === 'string' ? hexToBytes(key) : key;
  const bech = isAddr ? bech32m : bech32;
  const words = bech.toWords(data);
  return bech.encode(prefix, isAddr ? [1, ...words] : words, isAddr ? 1500 : limit);
}
