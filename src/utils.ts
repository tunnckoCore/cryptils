import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils';
import { bech32, bech32m } from '@scure/base';
import { entropyToMnemonic, mnemonicToEntropy } from '@scure/bip39';

/**
 * Normalizes (non-hex) string or Uint8Array to Uint8Array.
 * Warning: when Uint8Array is passed, it would NOT get copied.
 * Keep in mind for future mutable operations.
 */
// if hexstring, convert to bytes
// if string (utf8), convert to bytes
// if bytes, passthrough
export function toBytes(data: Uint8Array | string): Uint8Array {
  if (isHex(data as string)) data = hexToBytes(data as string);
  if (typeof data === 'string') data = utf8ToBytes(data);
  return data;
}

export function isHex(str: string) {
  if (!str || typeof str !== 'string') {
    return false;
  }

  const val = str.replace(/\s/g, '');

  if (/^[0-9a-fA-F]*$/.test(val) && val.length % 2 === 0) {
    return true;
  }

  return false;
}

export function isBytes(a: unknown): a is Uint8Array {
  return (
    a instanceof Uint8Array ||
    (a != null && typeof a === 'object' && a.constructor.name === 'Uint8Array')
  );
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
