export type SpectreOptions = {
  template?: string;
  hash?: any;
  iterations?: number;
  kdf?: 'scrypt' | 'pbkdf2' | any;
  r?: any;
  p?: any;
} & Record<string, any>;
export type SpectreResult = { secret: Uint8Array; name: string; user: string; pass: string };

export type HexString = string;
export type Input = Uint8Array | string;
export type SecretKey = Uint8Array | HexString;
export type HashAlgo = 'SHA-1' | 'SHA-256' | 'SHA-512' | string;
export type TokenResult = string;

export type KeysResult = {
  mnemonic: string;
  privkey: HexString;
  pubkey: HexString;
  npub: string; // npub1...abc
  nsec: string; // nsec1...abc
  nrepo: string; // nrepo1...abc
  ethereum: `0x${string}`; // 0x1987...abc
  bitcoin: string; // bc1p...abc
  litecoin: string; // ltc1p...abc
  vertcoin: string; // vtc1p...abc
};
