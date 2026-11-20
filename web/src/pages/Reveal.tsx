import { useEffect, useState } from "react";
import {
  aad,
  b64urlDecode,
  b64urlEncode,
  decodeFragment,
  deriveKeys,
  open as openSealed,
  unmarshalPayload,
  type Payload,
} from "../crypto";
import { ApiError, api, type SecretMeta } from "../lib/api";
import { formatWhen } from "../lib/format";
import type { Lang, Translate } from "../lib/i18n";
import { Banner, Card, CopyButton, Field, Spinner } from "../ui";
import { describeError } from "./Create";

interface Props {
  id: string;
  fragment: string;
  t: Translate;
  lang: Lang;
}

type Phase = "loading" | "gone" | "ready" | "revealing" | "revealed";

export default function Reveal({ id, fragment, t, lang }: Props) {
  const [phase, setPhase] = useState<Phase>("loading");
  const [meta, setMeta] = useState<SecretMeta | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [payload, setPayload] = useState<Payload | null>(null);
  const [visible, setVisible] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [attemptsLeft, setAttemptsLeft] = useState<number | null>(null);
  const [lastView, setLastView] = useState(false);
  const [deleted, setDeleted] = useState(false);
  const [readToken, setReadToken] = useState<Uint8Array | null>(null);

  let contentKey: Uint8Array | null = null;
  let keyError = false;
  try {
    contentKey = decodeFragment(fragment);
  } catch {
    keyError = true;
  }

  // Fetching the metadata is a page view, not a read: the server consumes
  // nothing here, which is what makes link previews harmless.
  useEffect(() => {
    let cancelled = false;
    api
      .meta(id)
      .then((m) => {
        if (cancelled) return;
        setMeta(m);
        setPhase("ready");
      })
      .catch((err) => {
        if (cancelled) return;
        if (err instanceof ApiError && (err.status === 404 || err.status === 410)) {
          setPhase("gone");
          return;
        }
        setError(describeError(err, t));
        setPhase("gone");
      });
    return () => {
      cancelled = true;
    };
  }, [id, t]);

  if (keyError || !contentKey) {
    return (
      <Card>
        <h1 className="text-xl font-semibold">{t("reveal.noKey.title")}</h1>
        <p className="peek-muted mt-2 text-sm leading-relaxed">{t("reveal.noKey.body")}</p>
      </Card>
    );
  }

  const key = contentKey;

  async function reveal(event: React.FormEvent) {
    event.preventDefault();
    if (!meta) return;
    setError(null);
    setPhase("revealing");
    try {
      const keys = await deriveKeys(key, meta.has_passphrase ? passphrase : "", {
        salt: b64urlDecode(meta.kdf.salt),
        memoryKiB: meta.kdf.memory_kib,
        iterations: meta.kdf.iterations,
        parallelism: meta.kdf.parallelism,
      });

      // The server checks the read token before releasing anything, so a wrong
      // passphrase costs no read.
      const response = await api.reveal(id, b64urlEncode(keys.readToken));
      const sealed = b64urlDecode(response.ciphertext);
      const plain = await openSealed(keys.enc, aad(id), sealed);
      setPayload(unmarshalPayload(plain));
      setReadToken(keys.readToken);
      setLastView(response.destroyed);
      setPhase("revealed");
      setPassphrase("");
    } catch (err) {
      if (err instanceof ApiError && err.status === 403) {
        setAttemptsLeft(err.attemptsLeft ?? null);
        setError(t("reveal.badToken"));
        setPhase("ready");
        return;
      }
      if (err instanceof ApiError && err.status === 410) {
        setError(t("reveal.locked"));
        setPhase("gone");
        return;
      }
      if (err instanceof ApiError && err.status === 404) {
        setPhase("gone");
        return;
      }
      setError(describeError(err, t));
      setPhase("ready");
    }
  }

  async function removeNow() {
    if (!readToken) return;
    try {
      await api.deleteByRecipient(id, b64urlEncode(readToken));
      setDeleted(true);
    } catch (err) {
      setError(describeError(err, t));
    }
  }

  if (phase === "loading") {
    return (
      <Card>
        <Spinner label={t("app.loading")} />
      </Card>
    );
  }

  if (phase === "gone") {
    return (
      <Card className="space-y-2">
        <h1 className="text-xl font-semibold">{t("reveal.gone.title")}</h1>
        <p className="peek-muted text-sm leading-relaxed">{t("reveal.gone.body")}</p>
        {error ? <Banner tone="danger">{error}</Banner> : null}
      </Card>
    );
  }

  if (phase === "revealed" && payload) {
    const text = payload.kind === "url" ? (payload.url ?? "") : (payload.text ?? "");
    return (
      <div className="space-y-5">
        <Card className="space-y-4">
          <h1 className="text-xl font-semibold">{t("reveal.title")}</h1>

          {payload.message ? (
            <div className="rounded-xl border p-3" style={{ borderColor: "var(--peek-border)" }}>
              <p className="peek-muted text-xs font-semibold uppercase tracking-wide">
                {t("reveal.message")}
              </p>
              <p className="mt-1 text-sm leading-relaxed">{payload.message}</p>
            </div>
          ) : null}

          {payload.kind === "url" ? (
            <div className="space-y-3">
              <p className="break-all rounded-xl border p-3 font-mono text-sm" style={{ borderColor: "var(--peek-border)" }}>
                {text}
              </p>
              <div className="flex flex-wrap gap-2">
                {/* Never an automatic redirect: the recipient decides. */}
                <a
                  href={text}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="peek-btn peek-btn-primary"
                >
                  {t("reveal.open")}
                </a>
                <CopyButton value={text} label={t("reveal.copy")} copiedLabel={t("reveal.copied")} />
              </div>
            </div>
          ) : (
            <div className="space-y-3">
              <pre
                className="max-h-80 overflow-auto rounded-xl border p-3 font-mono text-sm whitespace-pre-wrap break-all"
                style={{ borderColor: "var(--peek-border)" }}
              >
                {visible ? text : "•".repeat(Math.min(text.length, 48))}
              </pre>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  className="peek-btn peek-btn-ghost"
                  onClick={() => setVisible((v) => !v)}
                >
                  {visible ? t("reveal.hide") : t("reveal.show")}
                </button>
                <CopyButton value={text} label={t("reveal.copy")} copiedLabel={t("reveal.copied")} />
                {meta?.deletable_by_recipient && !deleted ? (
                  <button type="button" className="peek-btn peek-btn-danger" onClick={removeNow}>
                    {t("reveal.delete")}
                  </button>
                ) : null}
              </div>
            </div>
          )}

          {deleted ? <Banner tone="success">{t("reveal.deleted")}</Banner> : null}
          {lastView ? <Banner tone="warning">{t("reveal.consumed")}</Banner> : null}
          {error ? <Banner tone="danger">{error}</Banner> : null}
        </Card>
      </div>
    );
  }

  // Ready: the retrieval step. Nothing has been consumed yet.
  const remaining = meta?.views_remaining ?? 1;
  return (
    <form onSubmit={reveal} className="space-y-5">
      <Card className="space-y-4">
        <header className="space-y-1">
          <h1 className="text-xl font-semibold">{t("reveal.title")}</h1>
          <p className="peek-muted text-sm leading-relaxed">{t("reveal.warning")}</p>
        </header>

        <div className="flex flex-wrap gap-2 text-xs">
          <span className="peek-chip">{t("reveal.remaining", { n: remaining })}</span>
          {meta?.expires_at ? (
            <span className="peek-chip">
              {t("reveal.expires", { when: formatWhen(meta.expires_at, lang) })}
            </span>
          ) : null}
        </div>

        {remaining === 1 ? <Banner tone="warning">{t("reveal.lastView")}</Banner> : null}

        {meta?.has_passphrase ? (
          <Field
            label={t("reveal.passphrase")}
            htmlFor="passphrase"
            hint={t("reveal.passphrase.hint")}
          >
            <input
              id="passphrase"
              type="password"
              required
              autoFocus
              className="peek-input"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              autoComplete="off"
            />
          </Field>
        ) : null}

        {error ? (
          <Banner tone="danger">
            {error}
            {attemptsLeft !== null ? (
              <p className="mt-1 text-xs">{t("reveal.attempts", { n: attemptsLeft })}</p>
            ) : null}
          </Banner>
        ) : null}

        <button type="submit" className="peek-btn peek-btn-primary w-full" disabled={phase === "revealing"}>
          {phase === "revealing" ? <Spinner label={t("reveal.revealing")} /> : t("reveal.button")}
        </button>
      </Card>
    </form>
  );
}
