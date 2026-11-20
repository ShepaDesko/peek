/**
 * WebAuthn plumbing.
 *
 * The browser API speaks ArrayBuffers and the server speaks JSON, so the
 * challenge and the credential have to be converted on the way in and out.
 * Everything else — the signing, the user verification, the origin check — is
 * the browser's and the authenticator's job.
 */
import { b64urlDecode, b64urlEncode } from "../crypto/bytes";

export function passkeysAvailable(): boolean {
  return typeof window !== "undefined" && typeof window.PublicKeyCredential === "function";
}

/** Decodes the base64url fields the server sends into the buffers the API wants. */
function toBuffer(value: unknown): ArrayBuffer {
  const bytes = b64urlDecode(String(value));
  return bytes.slice().buffer as ArrayBuffer;
}

function reviveCreationOptions(
  options: Record<string, unknown>,
): PublicKeyCredentialCreationOptions {
  const user = options.user as { id: string; name: string; displayName: string };
  const exclude = (options.excludeCredentials ?? []) as {
    id: string;
    type: string;
    transports?: string[];
  }[];
  return {
    ...(options as unknown as PublicKeyCredentialCreationOptions),
    challenge: toBuffer(options.challenge),
    user: { ...user, id: toBuffer(user.id) },
    excludeCredentials: exclude.map((c) => ({
      id: toBuffer(c.id),
      type: "public-key" as const,
      transports: c.transports as AuthenticatorTransport[] | undefined,
    })),
  };
}

function reviveRequestOptions(options: Record<string, unknown>): PublicKeyCredentialRequestOptions {
  const allow = (options.allowCredentials ?? []) as {
    id: string;
    type: string;
    transports?: string[];
  }[];
  return {
    ...(options as unknown as PublicKeyCredentialRequestOptions),
    challenge: toBuffer(options.challenge),
    allowCredentials: allow.map((c) => ({
      id: toBuffer(c.id),
      type: "public-key" as const,
      transports: c.transports as AuthenticatorTransport[] | undefined,
    })),
  };
}

function encode(buffer: ArrayBuffer | null): string {
  if (!buffer) return "";
  return b64urlEncode(new Uint8Array(buffer));
}

/** Creates a credential and returns what the server expects back. */
export async function createCredential(options: Record<string, unknown>): Promise<unknown> {
  const credential = (await navigator.credentials.create({
    publicKey: reviveCreationOptions(options),
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("peek: no credential was created");

  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    id: credential.id,
    rawId: encode(credential.rawId),
    type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      clientDataJSON: encode(response.clientDataJSON),
      attestationObject: encode(response.attestationObject),
      transports: response.getTransports?.() ?? [],
    },
  };
}

/** Signs a challenge with an existing credential. */
export async function getCredential(options: Record<string, unknown>): Promise<unknown> {
  const credential = (await navigator.credentials.get({
    publicKey: reviveRequestOptions(options),
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("peek: no credential was returned");

  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: encode(credential.rawId),
    type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      clientDataJSON: encode(response.clientDataJSON),
      authenticatorData: encode(response.authenticatorData),
      signature: encode(response.signature),
      userHandle: encode(response.userHandle),
    },
  };
}

/** True when the user cancelled or the browser refused, which is not an error. */
export function isCancellation(err: unknown): boolean {
  return (
    err instanceof DOMException && (err.name === "NotAllowedError" || err.name === "AbortError")
  );
}
