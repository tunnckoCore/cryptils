import { hexToBytes } from '@noble/hashes/utils';

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
