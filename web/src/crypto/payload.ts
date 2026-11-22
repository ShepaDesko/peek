/** Plaintext payload sealed into every secret. Mirror of internal/crypto/payload.go. */

export type PayloadKind = "text" | "url" | "file";

/**
 * One attachment. The name, the type and above all the key are here, inside
 * the sealed payload: the server stores the id and the byte count and has no
 * way to learn the rest.
 */
export interface FileRef {
  id: string;
  name: string;
  mime?: string;
  /** Plaintext size, for the interface. The stored stream is a little longer. */
  size: number;
  /** base64url per-file key. */
  key: string;
  /** Plaintext chunk size the stream was sealed with. */
  chunk_size: number;
}

export interface Payload {
  v: 1;
  kind: PayloadKind;
  text?: string;
  url?: string;
  /** Optional note from the sender; encrypted like the rest. */
  message?: string;
  files?: FileRef[];
}

export function marshalPayload(p: Payload): Uint8Array {
  if (p.kind !== "text" && p.kind !== "url" && p.kind !== "file") {
    throw new Error("peek: unknown payload kind");
  }
  return new TextEncoder().encode(JSON.stringify({ ...p, v: 1 }));
}

export function unmarshalPayload(bytes: Uint8Array): Payload {
  const parsed: unknown = JSON.parse(new TextDecoder().decode(bytes));
  if (typeof parsed !== "object" || parsed === null) throw new Error("peek: malformed payload");
  const p = parsed as Payload;
  if (p.v !== 1) throw new Error("peek: unsupported payload version");
  return p;
}
