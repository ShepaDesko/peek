/**
 * Chunked file encryption, version v1 — browser implementation.
 *
 * Mirror of internal/crypto/file.go, pinned by crypto/vectors/v1.json.
 *
 * The construction is STREAM: a random per-stream nonce prefix, the chunk
 * counter inside the nonce, and a final-chunk flag byte. That authenticates
 * the order of the chunks and the end of the stream, so a reordered or
 * truncated file fails loudly instead of decrypting to something shorter.
 *
 * File names and MIME types are not here: they live in the sealed payload, so
 * the server only ever sees an opaque blob and its length.
 */
import { buf, concat, randomBytes, utf8 } from "./bytes";
import { hkdfExpand } from "./hkdf";

export const FILE_MAGIC = "PEEKF1";
export const FILE_NONCE_PREFIX_LEN = 7;
export const FILE_HEADER_LEN = FILE_MAGIC.length + 4 + FILE_NONCE_PREFIX_LEN;
export const FILE_KEY_LEN = 32;
export const TAG_LEN = 16;

export const DEFAULT_CHUNK_SIZE = 1 << 20;
export const MIN_CHUNK_SIZE = 1 << 10;
export const MAX_CHUNK_SIZE = 8 << 20;

const INFO_FILE = utf8("peek-file-v1");

export class TruncatedError extends Error {
  constructor() {
    super("peek: file stream is truncated");
    this.name = "TruncatedError";
  }
}

export interface FileHeader {
  chunkSize: number;
  noncePrefix: Uint8Array;
}

export function newFileKey(): Uint8Array {
  return randomBytes(FILE_KEY_LEN);
}

export function newFileHeader(chunkSize: number = DEFAULT_CHUNK_SIZE): FileHeader {
  if (chunkSize < MIN_CHUNK_SIZE || chunkSize > MAX_CHUNK_SIZE) {
    throw new Error(`peek: chunk size ${chunkSize} out of range`);
  }
  return { chunkSize, noncePrefix: randomBytes(FILE_NONCE_PREFIX_LEN) };
}

/** headerBytes is both the stream preamble and the AAD of every chunk. */
export function headerBytes(h: FileHeader): Uint8Array {
  const out = new Uint8Array(FILE_HEADER_LEN);
  out.set(utf8(FILE_MAGIC), 0);
  new DataView(out.buffer).setUint32(FILE_MAGIC.length, h.chunkSize, false);
  out.set(h.noncePrefix, FILE_MAGIC.length + 4);
  return out;
}

export function parseFileHeader(bytes: Uint8Array): FileHeader {
  if (bytes.length < FILE_HEADER_LEN) throw new Error("peek: not a Peek file stream");
  for (let i = 0; i < FILE_MAGIC.length; i++) {
    if (bytes[i] !== FILE_MAGIC.charCodeAt(i)) throw new Error("peek: not a Peek file stream");
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const chunkSize = view.getUint32(FILE_MAGIC.length, false);
  if (chunkSize < MIN_CHUNK_SIZE || chunkSize > MAX_CHUNK_SIZE) {
    throw new Error("peek: not a Peek file stream");
  }
  return {
    chunkSize,
    noncePrefix: bytes.slice(FILE_MAGIC.length + 4, FILE_HEADER_LEN),
  };
}

/** chunkNonce is prefix || counter (uint32 BE) || final flag. */
export function chunkNonce(h: FileHeader, index: number, final: boolean): Uint8Array {
  const nonce = new Uint8Array(FILE_NONCE_PREFIX_LEN + 5);
  nonce.set(h.noncePrefix, 0);
  new DataView(nonce.buffer).setUint32(FILE_NONCE_PREFIX_LEN, index, false);
  nonce[FILE_NONCE_PREFIX_LEN + 4] = final ? 1 : 0;
  return nonce;
}

/**
 * deriveFileKey expands the per-file key carried in the payload into the key
 * that actually encrypts chunks; the raw key is never used directly.
 */
export async function deriveFileKey(fileKey: Uint8Array): Promise<Uint8Array> {
  if (fileKey.length !== FILE_KEY_LEN) throw new Error("peek: bad file key length");
  return hkdfExpand(fileKey, INFO_FILE, 32);
}

/** encryptedFileSize is the exact stream length the server will receive. */
export function encryptedFileSize(plainSize: number, chunkSize: number): number {
  if (plainSize < 0 || chunkSize <= 0) return 0;
  let chunks = Math.floor(plainSize / chunkSize);
  if (plainSize % chunkSize !== 0 || plainSize === 0) chunks++;
  return FILE_HEADER_LEN + plainSize + chunks * TAG_LEN;
}

async function gcm(key: Uint8Array, usage: KeyUsage): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", buf(key), "AES-GCM", false, [usage]);
}

/** Seals one chunk at a time, in order. */
export class FileSealer {
  readonly header: FileHeader;
  private readonly aad: Uint8Array;
  private key: CryptoKey | null = null;
  private readonly rawKey: Uint8Array;
  private index = 0;
  private done = false;

  constructor(derivedKey: Uint8Array, header: FileHeader) {
    this.rawKey = derivedKey;
    this.header = header;
    this.aad = headerBytes(header);
  }

  /** The stream preamble; write it before any chunk. */
  headerBytes(): Uint8Array {
    return this.aad;
  }

  async seal(plaintext: Uint8Array, final: boolean): Promise<Uint8Array> {
    if (this.done) throw new Error("peek: stream already finished");
    if (!final && plaintext.length !== this.header.chunkSize) {
      throw new Error("peek: non-final chunk must be exactly one chunk long");
    }
    if (plaintext.length > this.header.chunkSize) throw new Error("peek: chunk too large");
    this.key ??= await gcm(this.rawKey, "encrypt");
    const ct = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: buf(chunkNonce(this.header, this.index, final)),
        additionalData: buf(this.aad),
        tagLength: 128,
      },
      this.key,
      buf(plaintext),
    );
    this.index++;
    this.done = final;
    return new Uint8Array(ct);
  }
}

/** Opens one chunk at a time, in order. */
export class FileOpener {
  readonly header: FileHeader;
  private readonly aad: Uint8Array;
  private key: CryptoKey | null = null;
  private readonly rawKey: Uint8Array;
  private index = 0;
  private done = false;

  constructor(derivedKey: Uint8Array, header: FileHeader) {
    this.rawKey = derivedKey;
    this.header = header;
    this.aad = headerBytes(header);
  }

  get sealedChunkSize(): number {
    return this.header.chunkSize + TAG_LEN;
  }

  async open(sealed: Uint8Array, final: boolean): Promise<Uint8Array> {
    if (this.done) throw new Error("peek: stream already finished");
    if (sealed.length < TAG_LEN || sealed.length > this.sealedChunkSize) {
      throw new Error("peek: malformed chunk");
    }
    this.key ??= await gcm(this.rawKey, "decrypt");
    const pt = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: buf(chunkNonce(this.header, this.index, final)),
        additionalData: buf(this.aad),
        tagLength: 128,
      },
      this.key,
      buf(sealed),
    );
    this.index++;
    this.done = final;
    return new Uint8Array(pt);
  }
}

/** sealFile encrypts a whole plaintext held in memory. */
export async function sealFile(
  fileKey: Uint8Array,
  chunkSize: number,
  plaintext: Uint8Array,
  header?: FileHeader,
): Promise<Uint8Array> {
  const h = header ?? newFileHeader(chunkSize);
  const sealer = new FileSealer(await deriveFileKey(fileKey), h);
  const parts: Uint8Array[] = [sealer.headerBytes()];
  for (let off = 0; ; off += h.chunkSize) {
    const end = Math.min(off + h.chunkSize, plaintext.length);
    const final = off + h.chunkSize >= plaintext.length;
    parts.push(await sealer.seal(plaintext.subarray(off, end), final));
    if (final) break;
  }
  return concat(...parts);
}

/** openFile decrypts a whole stream held in memory. */
export async function openFile(fileKey: Uint8Array, stream: Uint8Array): Promise<Uint8Array> {
  if (stream.length < FILE_HEADER_LEN) throw new Error("peek: not a Peek file stream");
  const h = parseFileHeader(stream.subarray(0, FILE_HEADER_LEN));
  const opener = new FileOpener(await deriveFileKey(fileKey), h);
  const body = stream.subarray(FILE_HEADER_LEN);
  const sealedLen = opener.sealedChunkSize;
  const parts: Uint8Array[] = [];
  for (let off = 0; ; off += sealedLen) {
    if (off >= body.length) throw new TruncatedError();
    const end = Math.min(off + sealedLen, body.length);
    const final = off + sealedLen >= body.length;
    try {
      parts.push(await opener.open(body.subarray(off, end), final));
    } catch (err) {
      if (final) throw new TruncatedError();
      throw err;
    }
    if (final) break;
  }
  return concat(...parts);
}

/**
 * sealBlob encrypts a File or Blob chunk by chunk without ever holding the
 * whole plaintext: each slice is read, sealed and dropped. The result is a
 * Blob, which the browser streams to the server from disk.
 */
export async function sealBlob(
  fileKey: Uint8Array,
  blob: Blob,
  chunkSize: number = DEFAULT_CHUNK_SIZE,
  onProgress?: (done: number, total: number) => void,
): Promise<Blob> {
  const h = newFileHeader(chunkSize);
  const sealer = new FileSealer(await deriveFileKey(fileKey), h);
  const parts: BlobPart[] = [sealer.headerBytes().slice() as unknown as BlobPart];
  const total = blob.size;
  for (let off = 0; ; off += chunkSize) {
    const end = Math.min(off + chunkSize, total);
    const final = off + chunkSize >= total;
    const slice = new Uint8Array(await blob.slice(off, end).arrayBuffer());
    parts.push((await sealer.seal(slice, final)) as unknown as BlobPart);
    onProgress?.(end, total);
    if (final) break;
  }
  return new Blob(parts, { type: "application/octet-stream" });
}

/**
 * openBlob decrypts a stream into a Blob of the given MIME type, chunk by
 * chunk, so a 100 MiB download does not need the whole plaintext in one
 * contiguous array.
 */
export async function openBlob(
  fileKey: Uint8Array,
  stream: Blob,
  mime: string,
  onProgress?: (done: number, total: number) => void,
): Promise<Blob> {
  if (stream.size < FILE_HEADER_LEN) throw new Error("peek: not a Peek file stream");
  const h = parseFileHeader(new Uint8Array(await stream.slice(0, FILE_HEADER_LEN).arrayBuffer()));
  const opener = new FileOpener(await deriveFileKey(fileKey), h);
  const sealedLen = opener.sealedChunkSize;
  const bodyLen = stream.size - FILE_HEADER_LEN;
  const parts: BlobPart[] = [];
  for (let off = 0; ; off += sealedLen) {
    if (off >= bodyLen) throw new TruncatedError();
    const end = Math.min(off + sealedLen, bodyLen);
    const final = off + sealedLen >= bodyLen;
    const slice = new Uint8Array(
      await stream.slice(FILE_HEADER_LEN + off, FILE_HEADER_LEN + end).arrayBuffer(),
    );
    try {
      parts.push((await opener.open(slice, final)) as unknown as BlobPart);
    } catch (err) {
      if (final) throw new TruncatedError();
      throw err;
    }
    onProgress?.(end, bodyLen);
    if (final) break;
  }
  return new Blob(parts, { type: mime || "application/octet-stream" });
}
