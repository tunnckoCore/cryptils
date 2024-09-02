declare type Options = { template?: string; hash?: any; iterations?: number };
declare type Result = { secret: Uint8Array; name: string; user: string; pass: string };
declare type Hex = string;

declare type Keys = {
  mnemonic: string;
  privkey: Hex;
  pubkey: Hex;
  npub: string; // npub1...abc
  nsec: string; // nsec1...abc
  nrepo: string; // nrepo1...abc
  ethereum: `0x${string}`; // 0x1987...abc
  bitcoin: string; // bc1p...abc
  litecoin: string; // ltc1p...abc
  vertcoin: string; // vtc1p...abc
};

declare function spectreV4(user: string, pass: string, name: string, options?: Options): Result;

declare function deriveKeys(secret: Uint8Array): Keys;
declare function deriveMnemonic(secret: string, size?: 16 | 32): string;

declare function deriveAccount(
  user: string,
  pass: string,
  name: string,
  options?: Options,
): Omit<Result, 'secret'>;

declare function deriveCryptoAccount(
  user: string,
  pass: string,
  name: string,
  options?: Options,
): Omit<Result, 'secret'> & Keys;

declare function bech32encode(
  prefix: string,
  key: Uint8Array | string,
  isAddr: boolean,
  limit: number,
): string;

declare function decryptWithSecret(ciphertext: string, key: Uint8Array | string): Promise<string>;
declare function encryptWithSecret(
  plaintext: Uint8Array | string,
  key: Uint8Array | string,
  salt?: Uint8Array,
): Promise<string>;

declare function privateKeyToEthereumAddress(key: Uint8Array | string): `0x${string}`;
declare function checksumEthereumAddress(address: string): `0x${string}`;

declare function combineSharesToKey(shares: string[]): Hex;
declare function splitKeyToShares(
  key: Uint8Array | string,
  threshold: number,
  shares: number,
): Hex[];
