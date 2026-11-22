import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { b64urlDecode, b64urlEncode } from "./bytes";
import {
  decodeDepositFragment,
  decodeRequestFragment,
  encodeDepositFragment,
  encodeRequestFragment,
  generateRequestKey,
  openFromRequest,
  REQUEST_BOX_LEN,
  sealToRequest,
} from "./request";

interface RequestVector {
  name: string;
  requester_private_b64: string;
  requester_public_b64: string;
  ephemeral_private_b64: string;
  nonce_b64: string;
  request_id: string;
  content_key_b64: string;
  expect: { ephemeral_public_b64: string; box_b64: string; fragment: string };
}

const vectorsPath = fileURLToPath(new URL("../../../crypto/vectors/v1.json", import.meta.url));
const vectors = JSON.parse(readFileSync(vectorsPath, "utf8")) as {
  request_cases: RequestVector[];
};

describe("secret-request vectors", () => {
  it("has cases to check", () => {
    expect(vectors.request_cases.length).toBeGreaterThan(0);
  });

  for (const c of vectors.request_cases) {
    it(`opens the Go box for ${c.name}`, async () => {
      const key = {
        priv: b64urlDecode(c.requester_private_b64),
        pub: b64urlDecode(c.requester_public_b64),
      };
      // The box is not reproducible without the ephemeral key, but opening
      // what Go sealed is the property that matters: one format, two sides.
      const back = await openFromRequest(key, c.request_id, b64urlDecode(c.expect.box_b64));
      expect(b64urlEncode(back)).toBe(c.content_key_b64);
      expect(encodeRequestFragment(key)).toBe(c.expect.fragment);
      expect(b64urlDecode(c.expect.box_b64).length).toBe(REQUEST_BOX_LEN);
    });

    it(`refuses the box of ${c.name} under another request id`, async () => {
      const key = {
        priv: b64urlDecode(c.requester_private_b64),
        pub: b64urlDecode(c.requester_public_b64),
      };
      await expect(
        openFromRequest(key, c.request_id + "x", b64urlDecode(c.expect.box_b64)),
      ).rejects.toThrow();
    });
  }
});

describe("secret requests", () => {
  it("round trips a wrapped content key", async () => {
    const key = await generateRequestKey();
    expect(key.priv.length).toBe(32);
    expect(key.pub.length).toBe(65);

    const contentKey = crypto.getRandomValues(new Uint8Array(32));
    const box = await sealToRequest(key.pub, "req-1", contentKey);
    expect(box.length).toBe(REQUEST_BOX_LEN);
    expect(await openFromRequest(key, "req-1", box)).toEqual(contentKey);
  });

  it("binds a deposit to its request", async () => {
    const key = await generateRequestKey();
    const contentKey = crypto.getRandomValues(new Uint8Array(32));
    const box = await sealToRequest(key.pub, "req-1", contentKey);
    await expect(openFromRequest(key, "req-2", box)).rejects.toThrow();
  });

  it("refuses an unrelated private key", async () => {
    const key = await generateRequestKey();
    const other = await generateRequestKey();
    const box = await sealToRequest(key.pub, "req", crypto.getRandomValues(new Uint8Array(32)));
    await expect(openFromRequest(other, "req", box)).rejects.toThrow();
  });

  it("refuses a substituted ephemeral public key", async () => {
    const key = await generateRequestKey();
    const other = await generateRequestKey();
    const box = await sealToRequest(key.pub, "req", crypto.getRandomValues(new Uint8Array(32)));
    const tampered = box.slice();
    tampered.set(other.pub, 0);
    await expect(openFromRequest(key, "req", tampered)).rejects.toThrow();
  });

  it("round trips the receipt fragment and rejects junk", async () => {
    const key = await generateRequestKey();
    const parsed = await decodeRequestFragment("#" + encodeRequestFragment(key));
    expect(parsed.priv).toEqual(key.priv);
    expect(parsed.pub).toEqual(key.pub);

    await expect(decodeRequestFragment("v1.AAAA")).rejects.toThrow();
    await expect(decodeRequestFragment("v1r.AAAA")).rejects.toThrow();
  });

  it("rejects a fragment whose halves do not match", async () => {
    const key = await generateRequestKey();
    const other = await generateRequestKey();
    const mixed = encodeRequestFragment({ priv: key.priv, pub: other.pub });
    await expect(decodeRequestFragment(mixed)).rejects.toThrow();
  });
});

describe("deposit links", () => {
  it("round trips the deposit fragment", async () => {
    const key = await generateRequestKey();
    const requestKey = crypto.getRandomValues(new Uint8Array(32));
    const frag = encodeDepositFragment(requestKey, key.pub);
    const back = decodeDepositFragment("#" + frag);
    expect(back.requestKey).toEqual(requestKey);
    expect(back.pub).toEqual(key.pub);
  });

  it("keeps the three fragment kinds apart", async () => {
    const key = await generateRequestKey();
    const requestKey = crypto.getRandomValues(new Uint8Array(32));
    const deposit = encodeDepositFragment(requestKey, key.pub);
    const tracking = encodeRequestFragment(key);
    expect(() => decodeDepositFragment(tracking)).toThrow();
    await expect(decodeRequestFragment(deposit)).rejects.toThrow();
  });
});
