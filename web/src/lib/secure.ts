/**
 * Secure-context detection.
 *
 * Browsers only expose WebCrypto (crypto.subtle) in a secure context: HTTPS,
 * or localhost. Peek does every bit of its encryption there, so on a plain
 * HTTP origin the interface cannot work at all.
 *
 * Without this check the failure surfaces as "Cannot read properties of
 * undefined (reading 'importKey')", which tells an administrator nothing.
 * Found by opening a real instance over http:// on a LAN address.
 */

export function isCryptoAvailable(): boolean {
  try {
    return (
      typeof globalThis.crypto !== "undefined" &&
      typeof globalThis.crypto.subtle !== "undefined" &&
      typeof globalThis.crypto.subtle.importKey === "function"
    );
  } catch {
    return false;
  }
}

/** True when the browser considers this origin secure (HTTPS or localhost). */
export function isSecureContext(): boolean {
  return typeof window !== "undefined" && window.isSecureContext === true;
}
