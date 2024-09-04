import { gcm } from '@noble/ciphers/webcrypto';

import type { SecretKey } from './types.ts';
import { bytesToHex, hexToBytes, randomBytes, toBytes } from './utils.ts';

export async function encryptWithSecret(
  plaintext: Uint8Array | string,
  key: SecretKey,
  salt?: Uint8Array,
) {
  const secret = typeof key === 'string' ? hexToBytes(key).slice(1) : key;
  const salt_ = salt ? toBytes(salt) : randomBytes(32);
  const cipher = gcm(secret, salt_);

  const ciphertext = [
    'aes256gcm',
    bytesToHex(salt_),
    bytesToHex(await cipher.encrypt(toBytes(plaintext))),
  ].join('_');

  return ciphertext;
}

export async function decryptWithSecret(
  ciphertext: string,
  key: Uint8Array | string,
): Promise<string> {
  const startIndex = ciphertext.indexOf('_');
  const endIndex = ciphertext.lastIndexOf('_');
  const salt = ciphertext.slice(startIndex + 1, endIndex);
  const data = ciphertext.slice(endIndex + 1);
  const cipher = gcm(toBytes(key), toBytes(salt));

  return new TextDecoder('utf-8').decode(await cipher.decrypt(hexToBytes(data)));
}
