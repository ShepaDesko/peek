/** Plaintext payload sealed into every secret. Mirror of internal/crypto/payload.go. */

export type PayloadKind = "text" | "url" | "file";

export interface FileRef {
  id: string;
  name: string;
  mime?: string;
  size: number;
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
