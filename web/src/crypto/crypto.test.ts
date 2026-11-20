import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  aad,
  b64urlDecode,
  b64urlEncode,
  decodeFragment,
  deriveKeys,
  encodeFragment,
  marshalPayload,
  newContentKey,
  newId,
  open,
  seal,
  unmarshalPayload,
  validId,
  VERSION,
} from ".";

interface Vector {
  name: string;
  content_key_b64: string;
  passphrase: string;
  kdf: { salt_b64: string; memory_kib: number; iterations: number; parallelism: number };
  secret_id: string;
  nonce_b64: string;
  plaintext_utf8: string;
  expect: {
    final_key_b64: string;
    enc_key_b64: string;
    read_token_b64: string;
    read_token_hash_b64: string;
    sealed_b64: string;
    fragment: string;
  };
}

const vectorsPath = fileURLToPath(new URL("../../../crypto/vectors/v1.json", import.meta.url));
const vectors = JSON.parse(readFileSync(vectorsPath, "utf8")) as {
  version: string;
  cases: Vector[];
};

describe("shared crypto vectors", () => {
  it("targets the implemented format version", () => {
    expect(vectors.version).toBe(VERSION);
    expect(vectors.cases.length).toBeGreaterThan(0);
  });

  for (const c of vectors.cases) {
    it(`matches Go for ${c.name}`, async () => {
      const contentKey = b64urlDecode(c.content_key_b64);
      const keys = await deriveKeys(contentKey, c.passphrase, {
        salt: b64urlDecode(c.kdf.salt_b64),
        memoryKiB: c.kdf.memory_kib,
        iterations: c.kdf.iterations,
        parallelism: c.kdf.parallelism,
      });

      expect(b64urlEncode(keys.final)).toBe(c.expect.final_key_b64);
      expect(b64urlEncode(keys.enc)).toBe(c.expect.enc_key_b64);
      expect(b64urlEncode(keys.readToken)).toBe(c.expect.read_token_b64);
      expect(b64urlEncode(keys.readTokenHash)).toBe(c.expect.read_token_hash_b64);

      const sealed = await seal(
        keys.enc,
        aad(c.secret_id),
        new TextEncoder().encode(c.plaintext_utf8),
        b64urlDecode(c.nonce_b64),
      );
      expect(b64urlEncode(sealed)).toBe(c.expect.sealed_b64);

      const plain = await open(keys.enc, aad(c.secret_id), b64urlDecode(c.expect.sealed_b64));
      expect(new TextDecoder().decode(plain)).toBe(c.plaintext_utf8);
      expect(encodeFragment(contentKey)).toBe(c.expect.fragment);
    }, 20000);
  }
});

describe("format guards", () => {
  it("refuses a ciphertext bound to another secret id", async () => {
    const key = new Uint8Array(32).fill(7);
    const sealed = await seal(key, aad("id-one"), new TextEncoder().encode("hello"));
    await expect(open(key, aad("id-two"), sealed)).rejects.toThrow();
  });

  it("round trips fragments and rejects junk", () => {
    const key = newContentKey();
    expect(decodeFragment("#" + encodeFragment(key))).toEqual(key);
    for (const bad of ["", "v0.AAAA", "v1.AAAA"]) {
      expect(() => decodeFragment(bad)).toThrow();
    }
  });

  it("validates ids", () => {
    expect(validId(newId())).toBe(true);
    for (const bad of ["", "short", "x".repeat(23), "!!!!!!!!!!!!!!!!!!!!!!"]) {
      expect(validId(bad)).toBe(false);
    }
  });

  it("round trips payloads", () => {
    const bytes = marshalPayload({ v: 1, kind: "text", text: "hello", message: "salut" });
    const back = unmarshalPayload(bytes);
    expect(back.text).toBe("hello");
    expect(back.message).toBe("salut");
    expect(() => unmarshalPayload(new TextEncoder().encode('{"v":9}'))).toThrow();
  });

  it("derives a different read token for a wrong passphrase", async () => {
    const key = newContentKey();
    const params = { salt: new Uint8Array(16).fill(3), memoryKiB: 8192, iterations: 1, parallelism: 1 };
    const good = await deriveKeys(key, "right", params);
    const bad = await deriveKeys(key, "wrong", params);
    expect(b64urlEncode(good.readTokenHash)).not.toBe(b64urlEncode(bad.readTokenHash));
  }, 20000);
});
