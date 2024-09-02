import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils';
import { bech32, bech32m } from '@scure/base';
import { entropyToMnemonic, mnemonicToEntropy } from '@scure/bip39';

/**
 * Normalizes (non-hex) string or Uint8Array to Uint8Array.
 * Warning: when Uint8Array is passed, it would NOT get copied.
 * Keep in mind for future mutable operations.
 */
export function toBytes(data: Uint8Array | string): Uint8Array {
  if (typeof data === 'string') data = utf8ToBytes(data);
  assertBytes(data);
  return data;
}

export function isBytes(a: unknown): a is Uint8Array {
  return (
    a instanceof Uint8Array ||
    (a != null && typeof a === 'object' && a.constructor.name === 'Uint8Array')
  );
}

export function assertBytes(b: Uint8Array | undefined, ...lengths: number[]) {
  if (!isBytes(b)) throw new Error('Uint8Array expected');
  if (lengths.length > 0 && !lengths.includes(b.length))
    throw new Error(`Uint8Array expected of length ${lengths}, not of length=${b.length}`);
}

export function utf8ToBytes(str: string): Uint8Array {
  if (typeof str !== 'string') throw new Error(`utf8ToBytes expected string, got ${typeof str}`);
  return new Uint8Array(new TextEncoder().encode(str)); // https://bugzil.la/1681809
}

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

export { bytesToHex, hexToBytes, randomBytes, entropyToMnemonic, mnemonicToEntropy };
