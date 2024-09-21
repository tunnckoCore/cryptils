import type { Pbkdf2Opt } from '@noble/hashes/pbkdf2';
import type { ScryptOpts } from '@noble/hashes/scrypt';
import type { Input as HashesInput } from '@noble/hashes/utils';

declare interface KdfFn {
  (key: HashesInput, salt: HashesInput, opts: ScryptOpts | Pbkdf2Opt | any): Uint8Array;
}

export type SpectreOptions = {
  template?: string;
  hash?: any;
  iterations?: number;
  kdf?: 'scrypt' | 'pbkdf2' | KdfFn;
  r?: any;
  p?: any;
} & Record<string, any>;
export type SpectreResult = {
  secret: Uint8Array;
  account: string;
  persona: string;
  masterpass: string;
};

export type HexString = string;
export type SecretKey = Uint8Array | HexString;
export type HashAlgo = 'SHA-1' | 'SHA-256' | 'SHA-512' | string;
export type TokenResult = string;

// export type KeysResult = {
//   // mnemonic: string;
//   // privkey: HexString;
//   // pubkey: HexString;
//   npub: string; // npub1...abc
//   nsec: string; // nsec1...abc
//   nrepo: string; // nrepo1...abc
//   ethereum: `0x${string}`; // 0x1987...abc
//   bitcoin: string; // bc1p...abc
//   litecoin: string; // ltc1p...abc
//   vertcoin: string; // vtc1p...abc
// };
