/**
 * Peek zero-knowledge secret format, version v1 — browser implementation.
 *
 * Mirror of internal/crypto/crypto.go. Both sides are pinned together by
 * crypto/vectors/v1.json; change one without the other and the tests fail.
 *
 * Nothing in this module ever sends anything anywhere: the caller decides
 * what reaches the server, and the content key only ever lives in the URL
 * fragment, which browsers do not transmit.
 */
import { argon2id } from "hash-wasm";
import { b64urlDecode, b64urlEncode, buf, concat, randomBytes, utf8 } from "./bytes";
import { hkdf, hkdfExpand, sha256 } from "./hkdf";

export const VERSION = "v1";
export const CONTENT_KEY_LEN = 32;
export const SALT_LEN = 16;
export const NONCE_LEN = 12;
export const ID_LEN = 16;

const INFO_KEY = utf8("peek-key-v1");
const INFO_ENC = utf8("peek-enc-v1");
const INFO_READ = utf8("peek-read-v1");
const AAD_PREFIX = "peek-v1|";

/** Defaults mirrored from internal/crypto: ~19 MiB, two passes. */
export const DEFAULT_KDF = {
  memoryKiB: 19456,
  iterations: 2,
  parallelism: 1,
} as const;

export interface KdfParams {
  salt: Uint8Array;
  memoryKiB: number;
  iterations: number;
  parallelism: number;
}

export interface Keys {
  final: Uint8Array;
  enc: Uint8Array;
  readToken: Uint8Array;
  readTokenHash: Uint8Array;
}

export function newContentKey(): Uint8Array {
  return randomBytes(CONTENT_KEY_LEN);
}

export function newKdfParams(): KdfParams {
  return { salt: randomBytes(SALT_LEN), ...DEFAULT_KDF };
}

export function newId(): string {
  return b64urlEncode(randomBytes(ID_LEN));
}

export function validId(id: string): boolean {
  if (!/^[A-Za-z0-9_-]{22}$/.test(id)) return false;
  try {
    return b64urlDecode(id).length === ID_LEN;
  } catch {
    return false;
  }
}

export function aad(secretId: string): Uint8Array {
  return utf8(AAD_PREFIX + secretId);
}

export function encodeFragment(contentKey: Uint8Array): string {
  return `${VERSION}.${b64urlEncode(contentKey)}`;
}

export function decodeFragment(fragment: string): Uint8Array {
  const trimmed = fragment.trim().replace(/^#/, "");
  const dot = trimmed.indexOf(".");
  if (dot < 0 || trimmed.slice(0, dot) !== VERSION) {
    throw new Error("peek: unsupported link format");
  }
  const key = b64urlDecode(trimmed.slice(dot + 1));
  if (key.length !== CONTENT_KEY_LEN) throw new Error("peek: malformed key in link");
  return key;
}

/**
 * deriveKeys reproduces the Go derivation exactly:
 *   A     = passphrase ? Argon2id(passphrase, salt, params) : nothing
 *   final = HKDF-SHA256(ikm = contentKey || A, salt, "peek-key-v1")
 *   enc   = HKDF-Expand(final, "peek-enc-v1")
 *   token = HKDF-Expand(final, "peek-read-v1")
 */
export async function deriveKeys(
  contentKey: Uint8Array,
  passphrase: string,
  params: KdfParams,
): Promise<Keys> {
  if (contentKey.length !== CONTENT_KEY_LEN) throw new Error("peek: bad content key length");
  if (params.salt.length === 0) throw new Error("peek: empty KDF salt");

  let ikm = contentKey;
  if (passphrase !== "") {
    const stretched = (await argon2id({
      password: passphrase,
      salt: params.salt,
      parallelism: params.parallelism,
      iterations: params.iterations,
      memorySize: params.memoryKiB,
      hashLength: 32,
      outputType: "binary",
    })) as Uint8Array;
    ikm = concat(contentKey, stretched);
  }

  const final = await hkdf(ikm, params.salt, INFO_KEY, 32);
  const enc = await hkdfExpand(final, INFO_ENC, 32);
  const readToken = await hkdfExpand(final, INFO_READ, 32);
  const readTokenHash = await sha256(readToken);
  return { final, enc, readToken, readTokenHash };
}

async function gcmKey(key: Uint8Array, usage: KeyUsage): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", buf(key), "AES-GCM", false, [usage]);
}

/** seal returns nonce || ciphertext, as the Go side does. */
export async function seal(
  encKey: Uint8Array,
  additional: Uint8Array,
  plaintext: Uint8Array,
  nonce: Uint8Array = randomBytes(NONCE_LEN),
): Promise<Uint8Array> {
  if (nonce.length !== NONCE_LEN) throw new Error("peek: bad nonce length");
  const key = await gcmKey(encKey, "encrypt");
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: buf(nonce), additionalData: buf(additional), tagLength: 128 },
      key,
      buf(plaintext),
    ),
  );
  return concat(nonce, ct);
}

export async function open(
  encKey: Uint8Array,
  additional: Uint8Array,
  blob: Uint8Array,
): Promise<Uint8Array> {
  if (blob.length < NONCE_LEN + 16) throw new Error("peek: ciphertext too short");
  const key = await gcmKey(encKey, "decrypt");
  try {
    const pt = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: buf(blob.slice(0, NONCE_LEN)),
        additionalData: buf(additional),
        tagLength: 128,
      },
      key,
      buf(blob.slice(NONCE_LEN)),
    );
    return new Uint8Array(pt);
  } catch {
    throw new Error("peek: cannot decrypt (wrong key or passphrase)");
  }
}

export { b64urlDecode, b64urlEncode, fromUtf8, utf8 } from "./bytes";
export * from "./payload";
