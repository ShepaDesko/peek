/**
 * HKDF-SHA256 (RFC 5869) built from HMAC, split into extract and expand.
 *
 * WebCrypto only exposes the combined extract-then-expand form, but the Go
 * reference implementation uses expand alone for the sub-keys. Implementing
 * both halves here keeps the two sides byte-identical, which is exactly what
 * crypto/vectors/v1.json checks.
 */
import { buf, concat } from "./bytes";

const HASH_LEN = 32;

async function hmacKey(key: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", buf(key), { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
}

export async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const k = await hmacKey(key);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, buf(data)));
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf(data)));
}

export async function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array> {
  return hmacSha256(salt.length === 0 ? new Uint8Array(HASH_LEN) : salt, ikm);
}

export async function hkdfExpand(
  prk: Uint8Array,
  info: Uint8Array,
  length: number,
): Promise<Uint8Array> {
  const blocks = Math.ceil(length / HASH_LEN);
  if (blocks > 255) throw new Error("hkdf: requested output too long");
  let previous: Uint8Array = new Uint8Array(0);
  const chunks: Uint8Array[] = [];
  for (let i = 1; i <= blocks; i++) {
    previous = await hmacSha256(prk, concat(previous, info, new Uint8Array([i])));
    chunks.push(previous);
  }
  return concat(...chunks).slice(0, length);
}

export async function hkdf(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Promise<Uint8Array> {
  return hkdfExpand(await hkdfExtract(salt, ikm), info, length);
}
