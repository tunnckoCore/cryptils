import { combine as combineKey, split as splitKey } from 'shamir-secret-sharing';

import type { HexString } from './types.ts';
import { bytesToHex, hexToBytes } from './utils.ts';

export async function splitKeyToShares(
  key: Uint8Array | string,
  threshold: number,
  shares: number,
): Promise<HexString[]> {
  return (await splitKey(typeof key === 'string' ? hexToBytes(key) : key, shares, threshold)).map(
    (x) => bytesToHex(x),
  );
}

export async function combineSharesToKey(shares: HexString[] | Uint8Array[]) {
  const _shares = shares.map((x) =>
    x && typeof x === 'string' ? hexToBytes(x as HexString) : (x as Uint8Array),
  ) as HexString[] | Uint8Array[];

  return combineKey(_shares as any);
}
