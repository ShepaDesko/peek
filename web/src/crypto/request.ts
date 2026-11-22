/**
 * Secret requests ("send me the password for account X") — browser side.
 *
 * Mirror of internal/crypto/request.go, pinned by crypto/vectors/v1.json.
 *
 * The requester generates a P-256 key pair. The public key goes to the server
 * with the request and is handed to every depositor; the private key never
 * leaves the fragment of the requester's own receipt link. A deposit is an
 * ordinary v1 secret whose content key is wrapped with ECIES: ephemeral ECDH,
 * HKDF-SHA256, AES-256-GCM.
 *
 * P-256 rather than X25519 because WebCrypto has had P-256 ECDH everywhere for
 * a decade, and Peek runs in managed browsers that are often several versions
 * behind (docs/DECISIONS.md).
 */
import { b64urlDecode, b64urlEncode, buf, concat, equalBytes, randomBytes, utf8 } from "./bytes";
import { hkdf } from "./hkdf";
import { NONCE_LEN, open, seal } from "./index";

export const REQUEST_PRIVATE_KEY_LEN = 32;
export const REQUEST_PUBLIC_KEY_LEN = 65;
export const REQUEST_SECRET_LEN = REQUEST_PRIVATE_KEY_LEN + REQUEST_PUBLIC_KEY_LEN;
export const REQUEST_BOX_LEN = REQUEST_PUBLIC_KEY_LEN + NONCE_LEN + 32 + 16;

const INFO_REQUEST = utf8("peek-request-v1");
const REQUEST_AAD_PREFIX = "peek-req-v1|";
const REQUEST_FRAGMENT_V1 = "v1r";

const ECDH_P256 = { name: "ECDH", namedCurve: "P-256" } as const;

export interface RequestKey {
  priv: Uint8Array;
  pub: Uint8Array;
}

export function requestAad(requestId: string): Uint8Array {
  return utf8(REQUEST_AAD_PREFIX + requestId);
}

/** generateRequestKey produces the requester's key pair. */
export async function generateRequestKey(): Promise<RequestKey> {
  const pair = await crypto.subtle.generateKey(ECDH_P256, true, ["deriveBits"]);
  const pub = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  if (!jwk.d) throw new Error("peek: private key export failed");
  const priv = b64urlDecode(jwk.d);
  if (priv.length !== REQUEST_PRIVATE_KEY_LEN || pub.length !== REQUEST_PUBLIC_KEY_LEN) {
    throw new Error("peek: unexpected P-256 key size");
  }
  return { priv, pub };
}

async function importPublic(pub: Uint8Array): Promise<CryptoKey> {
  if (pub.length !== REQUEST_PUBLIC_KEY_LEN || pub[0] !== 0x04) {
    throw new Error("peek: malformed secret-request key");
  }
  // importKey rejects a point that is not on the curve, which is the check
  // that matters here: an invalid point would attack our own ECDH.
  return crypto.subtle.importKey("raw", buf(pub), ECDH_P256, false, []);
}

/**
 * importPrivate rebuilds the private key from the fragment. WebCrypto cannot
 * take the raw scalar on its own — a JWK needs x and y — which is why the
 * fragment carries the public point alongside it.
 */
async function importPrivate(key: RequestKey): Promise<CryptoKey> {
  if (key.priv.length !== REQUEST_PRIVATE_KEY_LEN || key.pub.length !== REQUEST_PUBLIC_KEY_LEN) {
    throw new Error("peek: malformed secret-request key");
  }
  return crypto.subtle.importKey(
    "jwk",
    {
      kty: "EC",
      crv: "P-256",
      d: b64urlEncode(key.priv),
      x: b64urlEncode(key.pub.slice(1, 33)),
      y: b64urlEncode(key.pub.slice(33, 65)),
      ext: true,
    },
    ECDH_P256,
    false,
    ["deriveBits"],
  );
}

/**
 * requestKey derives the wrapping key:
 *   Z   = ECDH(ephemeral private, requester public)
 *   key = HKDF-SHA256(Z || ephPub || reqPub, salt = nil, "peek-request-v1")
 * Both public keys are in the IKM, so the derivation is bound to the exact
 * pair of keys involved.
 */
async function wrappingKey(
  z: Uint8Array,
  ephPub: Uint8Array,
  reqPub: Uint8Array,
): Promise<Uint8Array> {
  return hkdf(concat(z, ephPub, reqPub), new Uint8Array(0), INFO_REQUEST, 32);
}

/** sealToRequest wraps a content key for the holder of the request private key. */
export async function sealToRequest(
  requesterPub: Uint8Array,
  requestId: string,
  contentKey: Uint8Array,
  nonce: Uint8Array = randomBytes(NONCE_LEN),
): Promise<Uint8Array> {
  const pub = await importPublic(requesterPub);
  const eph = await crypto.subtle.generateKey(ECDH_P256, true, ["deriveBits"]);
  const ephPub = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));
  const z = new Uint8Array(
    await crypto.subtle.deriveBits({ name: "ECDH", public: pub }, eph.privateKey, 256),
  );
  const key = await wrappingKey(z, ephPub, requesterPub);
  return concat(ephPub, await seal(key, requestAad(requestId), contentKey, nonce));
}

/** openFromRequest unwraps a content key with the requester's private key. */
export async function openFromRequest(
  key: RequestKey,
  requestId: string,
  box: Uint8Array,
): Promise<Uint8Array> {
  if (box.length !== REQUEST_BOX_LEN) throw new Error("peek: malformed deposit");
  const priv = await importPrivate(key);
  const ephPub = box.slice(0, REQUEST_PUBLIC_KEY_LEN);
  const eph = await importPublic(ephPub);
  const z = new Uint8Array(
    await crypto.subtle.deriveBits({ name: "ECDH", public: eph }, priv, 256),
  );
  const wrapping = await wrappingKey(z, ephPub, key.pub);
  return open(wrapping, requestAad(requestId), box.slice(REQUEST_PUBLIC_KEY_LEN));
}

/** encodeRequestFragment renders the fragment of the requester's receipt link. */
export function encodeRequestFragment(key: RequestKey): string {
  return `${REQUEST_FRAGMENT_V1}.${b64urlEncode(concat(key.priv, key.pub))}`;
}

/**
 * decodeRequestFragment parses a receipt fragment and checks that the two
 * halves belong together, so a mangled link fails here rather than later with
 * an opaque decryption error.
 */
export async function decodeRequestFragment(fragment: string): Promise<RequestKey> {
  const trimmed = fragment.trim().replace(/^#/, "");
  const dot = trimmed.indexOf(".");
  if (dot < 0 || trimmed.slice(0, dot) !== REQUEST_FRAGMENT_V1) {
    throw new Error("peek: unsupported request link format");
  }
  const blob = b64urlDecode(trimmed.slice(dot + 1));
  if (blob.length !== REQUEST_SECRET_LEN) throw new Error("peek: malformed secret-request key");
  const key: RequestKey = {
    priv: blob.slice(0, REQUEST_PRIVATE_KEY_LEN),
    pub: blob.slice(REQUEST_PRIVATE_KEY_LEN),
  };
  // WebCrypto is not required to check that d matches (x, y), and a fragment
  // whose halves disagree would otherwise fail much later with an opaque
  // "cannot decrypt". A round trip through the construction itself is the
  // check that holds in every implementation, and it costs two ECDH
  // operations.
  const probe = randomBytes(32);
  const box = await sealToRequest(key.pub, "self-check", probe);
  let back: Uint8Array;
  try {
    back = await openFromRequest(key, "self-check", box);
  } catch {
    throw new Error("peek: malformed secret-request key");
  }
  if (!equalBytes(back, probe)) throw new Error("peek: malformed secret-request key");
  return key;
}

/**
 * The deposit link's fragment carries the symmetric request key — which
 * decrypts the prompt and proves possession to the server — and the
 * requester's public key.
 *
 * The public key is in the link rather than fetched from the server on
 * purpose. A server that served its own public key instead could read every
 * deposit; a browser that only ever takes it from the fragment cannot be
 * fooled that way, and that is what makes a secret request safe against the
 * instance hosting it.
 */
const DEPOSIT_FRAGMENT_V1 = "v1q";
export const DEPOSIT_SECRET_LEN = 32 + REQUEST_PUBLIC_KEY_LEN;

export function encodeDepositFragment(requestKey: Uint8Array, pub: Uint8Array): string {
  if (requestKey.length !== 32 || pub.length !== REQUEST_PUBLIC_KEY_LEN) {
    throw new Error("peek: malformed secret-request key");
  }
  return `${DEPOSIT_FRAGMENT_V1}.${b64urlEncode(concat(requestKey, pub))}`;
}

export function decodeDepositFragment(fragment: string): {
  requestKey: Uint8Array;
  pub: Uint8Array;
} {
  const trimmed = fragment.trim().replace(/^#/, "");
  const dot = trimmed.indexOf(".");
  if (dot < 0 || trimmed.slice(0, dot) !== DEPOSIT_FRAGMENT_V1) {
    throw new Error("peek: unsupported request link format");
  }
  const blob = b64urlDecode(trimmed.slice(dot + 1));
  if (blob.length !== DEPOSIT_SECRET_LEN) throw new Error("peek: malformed secret-request key");
  const pub = blob.slice(32);
  if (pub[0] !== 0x04) throw new Error("peek: malformed secret-request key");
  return { requestKey: blob.slice(0, 32), pub };
}
