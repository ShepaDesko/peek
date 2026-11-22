import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { b64urlDecode, b64urlEncode } from "./bytes";
import {
  deriveFileKey,
  encryptedFileSize,
  FILE_HEADER_LEN,
  newFileKey,
  openBlob,
  openFile,
  parseFileHeader,
  sealBlob,
  sealFile,
  TAG_LEN,
  TruncatedError,
} from "./file";

interface FileVector {
  name: string;
  file_key_b64: string;
  chunk_size: number;
  nonce_prefix_b64: string;
  plaintext_b64: string;
  expect: { derived_key_b64: string; stream_b64: string; stream_len: number };
}

const vectorsPath = fileURLToPath(new URL("../../../crypto/vectors/v1.json", import.meta.url));
const vectors = JSON.parse(readFileSync(vectorsPath, "utf8")) as { file_cases: FileVector[] };

describe("chunked file vectors", () => {
  it("has cases to check", () => {
    expect(vectors.file_cases.length).toBeGreaterThan(0);
  });

  for (const c of vectors.file_cases) {
    it(`matches Go for ${c.name}`, async () => {
      const fileKey = b64urlDecode(c.file_key_b64);
      const plaintext = b64urlDecode(c.plaintext_b64);

      expect(b64urlEncode(await deriveFileKey(fileKey))).toBe(c.expect.derived_key_b64);

      const stream = await sealFile(fileKey, c.chunk_size, plaintext, {
        chunkSize: c.chunk_size,
        noncePrefix: b64urlDecode(c.nonce_prefix_b64),
      });
      expect(b64urlEncode(stream)).toBe(c.expect.stream_b64);
      expect(stream.length).toBe(c.expect.stream_len);
      expect(encryptedFileSize(plaintext.length, c.chunk_size)).toBe(c.expect.stream_len);

      const back = await openFile(fileKey, b64urlDecode(c.expect.stream_b64));
      expect(b64urlEncode(back)).toBe(c.plaintext_b64);
    });
  }
});

describe("chunked file format", () => {
  const chunk = 1024;

  it("round trips every size boundary", async () => {
    const key = newFileKey();
    for (const size of [0, 1, chunk - 1, chunk, chunk + 1, 3 * chunk, 3 * chunk + 7]) {
      const plain = new Uint8Array(size);
      for (let i = 0; i < size; i++) plain[i] = (i * 31) & 0xff;
      const stream = await sealFile(key, chunk, plain);
      expect(stream.length).toBe(encryptedFileSize(size, chunk));
      expect(await openFile(key, stream)).toEqual(plain);
    }
  });

  it("detects truncation", async () => {
    const key = newFileKey();
    const plain = new Uint8Array(3 * chunk).fill(7);
    const stream = await sealFile(key, chunk, plain);
    // Every chunk left is valid; only the missing final flag says so.
    const cut = stream.slice(0, FILE_HEADER_LEN + 2 * (chunk + TAG_LEN));
    await expect(openFile(key, cut)).rejects.toThrow(TruncatedError);
  });

  it("detects reordering", async () => {
    const key = newFileKey();
    const plain = new Uint8Array(3 * chunk);
    for (let i = 0; i < plain.length; i++) plain[i] = Math.floor(i / chunk);
    const stream = await sealFile(key, chunk, plain);

    const sealedLen = chunk + TAG_LEN;
    const swapped = stream.slice();
    const first = swapped.slice(FILE_HEADER_LEN, FILE_HEADER_LEN + sealedLen);
    const second = swapped.slice(FILE_HEADER_LEN + sealedLen, FILE_HEADER_LEN + 2 * sealedLen);
    swapped.set(second, FILE_HEADER_LEN);
    swapped.set(first, FILE_HEADER_LEN + sealedLen);

    await expect(openFile(key, swapped)).rejects.toThrow();
  });

  it("authenticates the header", async () => {
    const key = newFileKey();
    const stream = await sealFile(key, chunk, new TextEncoder().encode("hello"));
    const tampered = stream.slice();
    tampered[FILE_HEADER_LEN - 1] ^= 0x01;
    await expect(openFile(key, tampered)).rejects.toThrow();
    expect(() => parseFileHeader(new TextEncoder().encode("NOTPEEK0123456789"))).toThrow();
  });

  it("refuses the wrong key", async () => {
    const stream = await sealFile(newFileKey(), chunk, new TextEncoder().encode("x"));
    await expect(openFile(newFileKey(), stream)).rejects.toThrow();
  });

  it("round trips a Blob the way the upload path does", async () => {
    const key = newFileKey();
    const plain = new Uint8Array(2 * chunk + 123);
    for (let i = 0; i < plain.length; i++) plain[i] = i & 0xff;

    const seen: number[] = [];
    const sealedBlob = await sealBlob(key, new Blob([plain]), chunk, (done) => seen.push(done));
    expect(seen[seen.length - 1]).toBe(plain.length);
    expect(sealedBlob.size).toBe(encryptedFileSize(plain.length, chunk));

    // The streaming path and the in-memory path are one format, not two.
    const viaMemory = await openFile(key, new Uint8Array(await sealedBlob.arrayBuffer()));
    expect(viaMemory).toEqual(plain);

    const out = await openBlob(key, sealedBlob, "application/pdf");
    expect(out.type).toBe("application/pdf");
    expect(new Uint8Array(await out.arrayBuffer())).toEqual(plain);
  });

  it("round trips an empty Blob", async () => {
    const key = newFileKey();
    const sealedBlob = await sealBlob(key, new Blob([]), chunk);
    const out = await openBlob(key, sealedBlob, "text/plain");
    expect(out.size).toBe(0);
  });
});
