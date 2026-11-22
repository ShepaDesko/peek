/**
 * Attachments, browser side.
 *
 * A file is encrypted here, chunk by chunk, before a byte of it leaves the
 * tab: the server stores an opaque stream and its length, and learns neither
 * the name, the type nor the key. The per-file key travels inside the sealed
 * payload of each recipient's secret, so one upload serves N links.
 */
import { b64urlDecode, b64urlEncode, type FileRef } from "../crypto";
import {
  DEFAULT_CHUNK_SIZE,
  encryptedFileSize,
  newFileKey,
  openBlob,
  sealBlob,
} from "../crypto/file";
import { api, type FileClaim } from "./api";

/** One attachment on its way out. */
export interface PendingAttachment {
  /** The reference that goes into the sealed payload, key included. */
  ref: FileRef;
  /** The claim the creation request presents to attach the blob. */
  claim: FileClaim;
}

export interface UploadProgress {
  /** 0 while encrypting, then the bytes actually sent. */
  sent: number;
  total: number;
  phase: "encrypting" | "uploading" | "done";
}

/**
 * encryptAndUpload seals one file and sends it.
 *
 * The two phases are reported separately because they feel different: a
 * hundred megabytes of AES-GCM takes a visible moment before the first byte
 * is even sent, and a progress bar stuck at zero looks like a hung page.
 */
export async function encryptAndUpload(
  file: File,
  chunkSize: number = DEFAULT_CHUNK_SIZE,
  onProgress?: (p: UploadProgress) => void,
): Promise<PendingAttachment> {
  const key = newFileKey();
  const total = encryptedFileSize(file.size, chunkSize);

  onProgress?.({ sent: 0, total, phase: "encrypting" });
  const sealed = await sealBlob(key, file, chunkSize);

  onProgress?.({ sent: 0, total, phase: "uploading" });
  const up = await api.uploadFile(sealed, (sent) => {
    onProgress?.({ sent, total, phase: "uploading" });
  });
  onProgress?.({ sent: total, total, phase: "done" });

  return {
    ref: {
      id: up.id,
      name: file.name,
      mime: file.type || "application/octet-stream",
      size: file.size,
      key: b64urlEncode(key),
      chunk_size: chunkSize,
    },
    claim: { id: up.id, token: up.token },
  };
}

/**
 * fetchAndDecrypt downloads one attachment with the grant a reveal handed out,
 * then decrypts it into a Blob the browser can save.
 */
export async function fetchAndDecrypt(ref: FileRef, grant: string): Promise<Blob> {
  const stream = await api.downloadFile(ref.id, grant);
  return openBlob(b64urlDecode(ref.key), stream, ref.mime || "application/octet-stream");
}

/** saveBlob hands a decrypted file to the browser's own download machinery. */
export function saveBlob(blob: Blob, name: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name || "download";
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Revoking immediately can cancel the download in some browsers; a tick is
  // enough, and the URL dies with the tab anyway.
  window.setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/** humanSize formats a byte count for a file list. */
export function humanSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} o`;
  const units = ["Ko", "Mo", "Go"];
  let value = bytes / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i++;
  }
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[i]}`;
}
