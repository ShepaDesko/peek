import { auth } from "./api";
import type { Translate } from "./i18n";
import { createCredential, getCredential, isCancellation, passkeysAvailable } from "./webauthn";

/** The two WebAuthn ceremonies, each as one call the pages can await. */

export async function passkeySignIn(): Promise<void> {
  if (!passkeysAvailable()) throw new Error("unsupported");
  const start = await auth.passkeyLoginStart();
  const response = await getCredential(start.options.publicKey);
  await auth.passkeyLoginFinish(start.challenge_id, response);
}

export async function passkeyRegister(name: string): Promise<void> {
  if (!passkeysAvailable()) throw new Error("unsupported");
  const start = await auth.passkeyRegisterStart();
  const response = await createCredential(start.options.publicKey);
  await auth.passkeyRegisterFinish(start.challenge_id, name, response);
}

/**
 * Turns a failed ceremony into a message, or null when the user simply
 * cancelled — which is not a failure and deserves no red banner.
 */
export function createCredentialError(err: unknown, t: Translate): string | null {
  if (isCancellation(err)) return null;
  if (err instanceof Error && err.message === "unsupported") {
    return t("passkey.unsupported");
  }
  if (err instanceof Error) return err.message;
  return t("error.generic");
}
