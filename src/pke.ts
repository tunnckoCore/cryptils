import { gcm } from '@noble/ciphers/webcrypto';
import { edwardsToMontgomeryPriv, edwardsToMontgomeryPub, x25519 } from '@noble/curves/ed25519';
import { secp256k1 } from '@noble/curves/secp256k1';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, randomBytes } from '@noble/hashes/utils';
import { base64urlnopad } from '@scure/base';

import type { HexString } from './types.ts';
import { toBytes } from './utils.ts';

// supports secp256k1, ed25519, and x25519 keys
export function getSharedSecret(
  curve,
  privkey: string | HexString | Uint8Array,
  pub: string | HexString | Uint8Array,
) {
  // pseudo check for {secp256k1} @noble/curves/secp256k1
  const isSecpk = Boolean(
    curve.create && curve.CURVE?.lowS && curve.getSharedSecret && curve.getPublicKey,
  );

  if (isSecpk) {
    const secret = secp256k1.getSharedSecret(toBytes(privkey), toBytes(pub)).slice(1);
    return { fromSecp256k1: true, secret };
  }

  // pseudo check for {x25519} @noble/curves/ed25519
  const isX25519 = Boolean(curve.scalarMult && curve.scalarMultBase && curve.getSharedSecret);
  if (isX25519) {
    const secret = x25519.getSharedSecret(toBytes(privkey), toBytes(pub));
    return { fromX25519: true, secret };
  }

  // pseudo check for {ed25519} @noble/curves/ed25519
  const isEd25519 = Boolean(
    curve.CURVE?.nBitLength &&
      curve.CURVE?.nByteLength &&
      curve.CURVE?.Fp &&
      curve.sign &&
      curve.getPublicKey &&
      curve.ExtendedPoint,
  );

  // if ED25519, convert them to x25519
  if (isEd25519) {
    const secret = x25519.getSharedSecret(
      edwardsToMontgomeryPriv(toBytes(privkey)),
      edwardsToMontgomeryPub(toBytes(pub)),
    );

    return { fromEd25519: true, secret };
  }

  throw new Error("unsupported curve: only Noble's secp256k1, ed25519, and x25519");
}

// Note: supports only AES-GCM (256) for the moment
// encodes results with `base64urlnopad`
export async function encryptToPubkey(
  curve,
  plaintext: string | Uint8Array,
  _fromPriv: string | HexString | Uint8Array,
  _to: string | HexString | Uint8Array,
) {
  const NONCE = 32;
  const nonce = randomBytes(NONCE);
  // console.log({ _fromPriv, _to });

  const shared = getSharedSecret(curve, _fromPriv, _to);
  // Note: support xchacha20poly1305 & xsalsa20poly1305?
  const encrypted = await gcm(shared.secret, nonce).encrypt(toBytes(plaintext));

  const ciphertext = new Uint8Array([...nonce, ...encrypted]);
  const hashtext = hmac(sha256, ciphertext, toBytes(plaintext));
  const signature = curve.sign(hashtext, toBytes(_fromPriv));
  const enctext = new Uint8Array([
    ...(shared.fromSecp256k1 ? (signature as any).toCompactRawBytes() : signature),
    ...ciphertext,
  ]);
  const prenonce = toBytes(_to).slice(0, NONCE);

  // Note: support xchacha20poly1305 & xsalsa20poly1305?
  const ctext = await gcm(shared.secret, prenonce).encrypt(enctext);
  const presig = curve.sign(ctext, toBytes(_fromPriv));

  return {
    signer: bytesToHex(curve.getPublicKey(toBytes(_fromPriv))),
    ciphertext: base64urlnopad.encode(ctext),
    signature: base64urlnopad.encode(
      shared.fromSecp256k1 ? (presig as any).toCompactRawBytes() : presig,
    ),
  };
}

// Note: supports only AES-GCM (256) for the moment
// expects data encoded with `base64urlnopad`
export async function decryptWithPrivkey(
  curve,
  data: { ciphertext: string; signature: string; signer?: HexString },
  _toPrivkey: string | HexString | Uint8Array,
  _from?: string | HexString | Uint8Array,
) {
  const NONCE = 32;
  const { ciphertext, signature, signer } = data;
  const cbytes = base64urlnopad.decode(ciphertext);
  const presig = base64urlnopad.decode(signature);

  if (!signer) {
    throw new Error('No signer provider');
  }

  const fromPub = toBytes(_from || signer || '');

  let verified = curve.verify(presig, cbytes, fromPub);

  if (!verified) {
    throw new Error('Presig verification failed');
  }

  const shared = getSharedSecret(curve, _toPrivkey, fromPub);
  const prenonce = curve.getPublicKey(toBytes(_toPrivkey)).slice(0, NONCE);

  // Note: support xchacha20poly1305 & xsalsa20poly1305?
  const cts = await gcm(shared.secret, prenonce).decrypt(cbytes);
  const realsig = cts.slice(0, 64);
  const ctext = cts.slice(64);
  const nonce = ctext.slice(0, NONCE);
  const encrypted = ctext.slice(NONCE);

  // Note: support xchacha20poly1305 & xsalsa20poly1305?
  const plaintext = await gcm(shared.secret, nonce).decrypt(encrypted);
  const messageHash = hmac(sha256, ctext, plaintext);

  verified = curve.verify(realsig, messageHash, toBytes(fromPub));
  if (!verified) {
    throw new Error('Signature verification failed');
  }

  return plaintext;
}

// Useful when we have Schnorr keys like Bitcoin one, and we want to encrypt "using them",
// thus we use the public/private keypair to derive another secret with HMAC-SHA256,
// and pub/priv keypair from that secret
export function convertSchnorrTo(
  curve,
  identity: {
    privkey: string | HexString | Uint8Array;
    pubkey: string | HexString | Uint8Array;
  },
) {
  const privkey = hmac(sha256, toBytes(identity.privkey), toBytes(identity.pubkey));
  const pubkey = curve.getPublicKey(privkey);

  return { privkey, pubkey };
}
