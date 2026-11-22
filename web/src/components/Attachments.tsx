import { useState } from "react";
import type { FileRef } from "../crypto";
import { fetchAndDecrypt, humanSize, saveBlob } from "../lib/files";
import type { Translate } from "../lib/i18n";
import { Banner } from "../ui";

/**
 * The attachment list a recipient sees after revealing.
 *
 * Each file is fetched with the grant the reveal handed out, decrypted here
 * and handed to the browser's own download machinery. Nothing is written to
 * disk until the authentication tag of every chunk has checked out, so a
 * truncated or tampered stream never reaches the file system.
 */
export default function Attachments({
  files,
  grant,
  t,
}: {
  files: FileRef[];
  grant: string | undefined;
  t: Translate;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (files.length === 0) return null;

  async function download(ref: FileRef) {
    if (!grant) return;
    setError(null);
    setBusy(ref.id);
    try {
      const blob = await fetchAndDecrypt(ref, grant);
      saveBlob(blob, ref.name);
    } catch (err) {
      setError(t("reveal.files.failed", { error: err instanceof Error ? err.message : "?" }));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="space-y-3">
      <p className="peek-muted text-xs font-semibold tracking-wide uppercase">
        {t("reveal.files")}
      </p>
      <ul className="space-y-2">
        {files.map((f) => (
          <li
            key={f.id}
            className="flex items-center gap-3 rounded-xl border px-3 py-2 text-sm"
            style={{ borderColor: "var(--peek-border)" }}
          >
            <span className="min-w-0 flex-1 truncate font-medium">{f.name}</span>
            <span className="peek-muted shrink-0 text-xs">{humanSize(f.size)}</span>
            <button
              type="button"
              className="peek-btn peek-btn-primary shrink-0 text-xs"
              disabled={!grant || busy !== null}
              onClick={() => void download(f)}
            >
              {busy === f.id ? t("reveal.files.downloading") : t("reveal.files.download")}
            </button>
          </li>
        ))}
      </ul>
      <p className="peek-muted text-xs leading-relaxed">{t("reveal.files.window")}</p>
      {error ? <Banner tone="danger">{error}</Banner> : null}
    </div>
  );
}
