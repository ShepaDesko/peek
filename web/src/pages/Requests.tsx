import { useCallback, useEffect, useMemo, useState } from "react";
import QRCode from "qrcode";
import {
  aad,
  b64urlDecode,
  b64urlEncode,
  deriveKeys,
  marshalPayload,
  newContentKey,
  newId,
  newKdfParams,
  open as openSealed,
  seal,
  unmarshalPayload,
  type FileRef,
} from "../crypto";
import { randomBytes } from "../crypto/bytes";
import { sha256 } from "../crypto/hkdf";
import {
  decodeDepositFragment,
  decodeRequestFragment,
  encodeDepositFragment,
  encodeRequestFragment,
  generateRequestKey,
  openFromRequest,
  sealToRequest,
  type RequestKey,
} from "../crypto/request";
import Attachments from "../components/Attachments";
import {
  ApiError,
  api,
  type DepositInfo,
  type Policy,
  type SecretRequestReceipt,
} from "../lib/api";
import { formatWhen } from "../lib/format";
import type { Lang, Translate } from "../lib/i18n";
import { isCryptoAvailable, isSecureContext } from "../lib/secure";
import { Banner, Card, CopyButton, Field, Spinner } from "../ui";
import { describeError } from "./Create";

/**
 * Secret requests, browser side — the inverted flow.
 *
 * The requester generates a P-256 key pair here. The private half goes into
 * the fragment of their own tracking link and nowhere else; the public half
 * goes into the deposit link they send, so the depositor's browser never has
 * to ask the server for it. A server that answered with its own key would
 * otherwise be able to read every answer.
 */

const DEPOSIT_CHOICES = [1, 2, 3, 5, 10];

// --- asking ------------------------------------------------------------------

export function AskSecret({ t, policy }: { t: Translate; policy: Policy | null }) {
  const [prompt, setPrompt] = useState("");
  const [label, setLabel] = useState("");
  const [ttl, setTtl] = useState(86400);
  const [deposits, setDeposits] = useState(1);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<{ deposit: string; tracking: string } | null>(null);
  const [qr, setQr] = useState<string | null>(null);
  const ready = isCryptoAvailable() && isSecureContext();

  useEffect(() => {
    if (!policy) return;
    setTtl(Math.min(policy.default_ttl_seconds, policy.max_ttl_seconds));
    setDeposits(Math.min(1, policy.max_deposits || 1));
  }, [policy]);

  useEffect(() => {
    if (!done) return;
    let cancelled = false;
    // Rendered locally: contacting a QR service would hand it the key.
    QRCode.toDataURL(done.deposit, { errorCorrectionLevel: "M", margin: 1, width: 200 })
      .then((url) => {
        if (!cancelled) setQr(url);
      })
      .catch(() => setQr(null));
    return () => {
      cancelled = true;
    };
  }, [done]);

  const depositChoices = useMemo(
    () => DEPOSIT_CHOICES.filter((n) => n <= (policy?.max_deposits ?? 1)),
    [policy],
  );

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const id = newId();
      const pair = await generateRequestKey();
      // The symmetric request key plays exactly the role a content key plays
      // for a secret: it seals the prompt and it proves possession.
      const requestKey = newContentKey();
      const kdf = newKdfParams();
      if (policy?.kdf) {
        kdf.memoryKiB = policy.kdf.memory_kib;
        kdf.iterations = policy.kdf.iterations;
        kdf.parallelism = policy.kdf.parallelism;
      }
      const keys = await deriveKeys(requestKey, "", kdf);
      const sealedPrompt = await seal(keys.enc, aad(id), new TextEncoder().encode(prompt.trim()));

      const receiptToken = randomBytes(32);
      const receiptTokenHash = await sha256(receiptToken);

      await api.createSecretRequest({
        id,
        public_key: b64urlEncode(pair.pub),
        read_token_hash: b64urlEncode(keys.readTokenHash),
        receipt_token_hash: b64urlEncode(receiptTokenHash),
        prompt_enc: b64urlEncode(sealedPrompt),
        kdf: {
          salt: b64urlEncode(kdf.salt),
          memory_kib: kdf.memoryKiB,
          iterations: kdf.iterations,
          parallelism: kdf.parallelism,
        },
        ttl_seconds: ttl,
        max_deposits: deposits,
      });

      const origin = window.location.origin;
      const tracking =
        `${origin}/qs/${id}#${encodeRequestFragment(pair)}` +
        `~${b64urlEncode(requestKey)}~${b64urlEncode(receiptToken)}`;
      setDone({
        deposit: `${origin}/q/${id}#${encodeDepositFragment(requestKey, pair.pub)}`,
        tracking,
      });
      setBusy(false);
    } catch (err) {
      setError(describeError(err, t));
      setBusy(false);
    }
  }

  if (done) {
    return (
      <Card className="space-y-5">
        <header className="space-y-1">
          <h1 className="text-xl font-semibold">{t("ask.title")}</h1>
          <p className="peek-muted text-sm leading-relaxed">{label || prompt}</p>
        </header>

        <Field label={t("ask.link")} htmlFor="deposit-link">
          <div className="flex items-center gap-2">
            <input
              id="deposit-link"
              readOnly
              className="peek-input flex-1 font-mono text-xs"
              value={done.deposit}
            />
            <CopyButton
              value={done.deposit}
              label={t("reveal.copy")}
              copiedLabel={t("reveal.copied")}
            />
          </div>
        </Field>
        {qr ? (
          <img
            src={qr}
            alt={t("ask.link")}
            width={200}
            height={200}
            className="rounded-xl border p-2"
            style={{ borderColor: "var(--peek-border)" }}
          />
        ) : null}

        <Field label={t("ask.follow")} htmlFor="tracking-link" hint={t("ask.follow.hint")}>
          <div className="flex items-center gap-2">
            <input
              id="tracking-link"
              readOnly
              className="peek-input flex-1 font-mono text-xs"
              value={done.tracking}
            />
            <CopyButton
              value={done.tracking}
              label={t("reveal.copy")}
              copiedLabel={t("reveal.copied")}
            />
          </div>
        </Field>

        <a
          className="peek-btn peek-btn-primary inline-flex w-fit"
          href={done.tracking.slice(window.location.origin.length)}
        >
          {t("ask.open")}
        </a>
      </Card>
    );
  }

  return (
    <form onSubmit={submit} className="space-y-5">
      <Card className="space-y-5">
        <header className="space-y-1">
          <h1 className="text-xl font-semibold">{t("ask.title")}</h1>
          <p className="peek-muted text-sm leading-relaxed">{t("ask.subtitle")}</p>
        </header>

        <Field label={t("ask.prompt")} htmlFor="prompt">
          <textarea
            id="prompt"
            required
            rows={3}
            className="peek-input"
            placeholder={t("ask.prompt.placeholder")}
            value={prompt}
            onChange={(e) => setPrompt(e.target.value)}
            maxLength={500}
          />
        </Field>

        <Field label={t("ask.label")} htmlFor="ask-label">
          <input
            id="ask-label"
            className="peek-input"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            maxLength={80}
          />
        </Field>

        <div className="grid gap-5 sm:grid-cols-2">
          <Field label={t("create.expiry")} htmlFor="ask-ttl">
            <select
              id="ask-ttl"
              className="peek-input"
              value={ttl}
              onChange={(e) => setTtl(Number(e.target.value))}
            >
              {[300, 3600, 86400, 604800, 2592000]
                .filter((s) => s <= (policy?.max_ttl_seconds ?? 2592000))
                .map((s) => (
                  <option key={s} value={s}>
                    {t(
                      s === 300
                        ? "expiry.5m"
                        : s === 3600
                          ? "expiry.1h"
                          : s === 86400
                            ? "expiry.24h"
                            : s === 604800
                              ? "expiry.7d"
                              : "expiry.30d",
                    )}
                  </option>
                ))}
            </select>
          </Field>

          {depositChoices.length > 1 ? (
            <Field label={t("ask.deposits")} htmlFor="ask-deposits">
              <select
                id="ask-deposits"
                className="peek-input"
                value={deposits}
                onChange={(e) => setDeposits(Number(e.target.value))}
              >
                {depositChoices.map((n) => (
                  <option key={n} value={n}>
                    {n === 1 ? t("ask.deposits.one") : t("ask.deposits.many", { n })}
                  </option>
                ))}
              </select>
            </Field>
          ) : null}
        </div>

        {error ? (
          <Banner tone="danger" title={t("ask.error")}>
            {error}
          </Banner>
        ) : null}

        <button
          type="submit"
          className="peek-btn peek-btn-primary w-full sm:w-auto"
          disabled={busy || !ready}
        >
          {busy ? <Spinner label={t("ask.submitting")} /> : t("ask.submit")}
        </button>
      </Card>
    </form>
  );
}

// --- depositing --------------------------------------------------------------

export function Deposit({
  id,
  fragment,
  t,
  policy,
}: {
  id: string;
  fragment: string;
  t: Translate;
  policy: Policy | null;
}) {
  const [phase, setPhase] = useState<"loading" | "gone" | "ready" | "sending" | "done">("loading");
  const [prompt, setPrompt] = useState("");
  const [answer, setAnswer] = useState("");
  const [error, setError] = useState<string | null>(null);
  // Derived once, when the prompt is opened: the same read token proves
  // possession again when the answer is deposited.
  const [readToken, setReadToken] = useState<Uint8Array | null>(null);
  const parsed = useMemo(() => {
    try {
      return decodeDepositFragment(fragment);
    } catch {
      return null;
    }
  }, [fragment]);

  useEffect(() => {
    if (!parsed) return;
    let cancelled = false;
    (async () => {
      try {
        const meta = await api.requestMeta(id);
        const keys = await deriveKeys(parsed.requestKey, "", {
          salt: b64urlDecode(meta.kdf.salt),
          memoryKiB: meta.kdf.memory_kib,
          iterations: meta.kdf.iterations,
          parallelism: meta.kdf.parallelism,
        });
        const opened = await api.openRequest(id, b64urlEncode(keys.readToken));
        if (!cancelled) setReadToken(keys.readToken);
        const plain = await openSealed(keys.enc, aad(id), b64urlDecode(opened.prompt_enc));
        if (cancelled) return;
        setPrompt(new TextDecoder().decode(plain));
        setPhase("ready");
      } catch (err) {
        if (cancelled) return;
        if (err instanceof ApiError && (err.status === 404 || err.status === 410)) {
          setPhase("gone");
          return;
        }
        setError(describeError(err, t));
        setPhase("gone");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [id, parsed, t]);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (!parsed || !readToken) return;
    setError(null);
    setPhase("sending");
    try {
      // The deposit is an ordinary secret. What makes it a deposit is that its
      // content key is wrapped to the requester's public key, so the requester
      // alone can derive the read token and open it.
      const secretID = newId();
      const contentKey = newContentKey();
      const kdf = newKdfParams();
      if (policy?.kdf) {
        kdf.memoryKiB = policy.kdf.memory_kib;
        kdf.iterations = policy.kdf.iterations;
        kdf.parallelism = policy.kdf.parallelism;
      }
      const keys = await deriveKeys(contentKey, "", kdf);
      const payload = marshalPayload({ v: 1, kind: "text", text: answer });
      const sealed = await seal(keys.enc, aad(secretID), payload);
      const receiptToken = randomBytes(32);
      const receiptTokenHash = await sha256(receiptToken);

      // The public key comes from the fragment, never from the server: that
      // is what stops the instance substituting its own and reading answers.
      const wrapped = await sealToRequest(parsed.pub, id, contentKey);

      await api.deposit(id, {
        read_token: b64urlEncode(readToken),
        wrapped_key: b64urlEncode(wrapped),
        secret: {
          id: secretID,
          kind: "text",
          ciphertext: b64urlEncode(sealed),
          read_token_hash: b64urlEncode(keys.readTokenHash),
          receipt_token_hash: b64urlEncode(receiptTokenHash),
          kdf: {
            salt: b64urlEncode(kdf.salt),
            memory_kib: kdf.memoryKiB,
            iterations: kdf.iterations,
            parallelism: kdf.parallelism,
          },
          has_passphrase: false,
          // The requester is the only reader, and they read it once.
          ttl_seconds: Math.min(policy?.max_ttl_seconds ?? 604800, 604800),
          views: 1,
          retrieval_step: false,
          deletable_by_recipient: false,
        },
      });
      setAnswer("");
      setPhase("done");
    } catch (err) {
      if (err instanceof ApiError && err.status === 410) {
        setPhase("gone");
        return;
      }
      setError(describeError(err, t));
      setPhase("ready");
    }
  }

  if (!parsed) {
    return (
      <Card>
        <h1 className="text-xl font-semibold">{t("reveal.noKey.title")}</h1>
        <p className="peek-muted mt-2 text-sm leading-relaxed">{t("reveal.noKey.body")}</p>
      </Card>
    );
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
        <h1 className="text-xl font-semibold">{t("deposit.gone.title")}</h1>
        <p className="peek-muted text-sm leading-relaxed">{t("deposit.gone.body")}</p>
        {error ? <Banner tone="danger">{error}</Banner> : null}
      </Card>
    );
  }

  if (phase === "done") {
    return (
      <Card className="space-y-2">
        <h1 className="text-xl font-semibold">{t("deposit.done.title")}</h1>
        <p className="peek-muted text-sm leading-relaxed">{t("deposit.done.body")}</p>
      </Card>
    );
  }

  return (
    <form onSubmit={submit} className="space-y-5">
      <Card className="space-y-5">
        <header className="space-y-1">
          <h1 className="text-xl font-semibold">{t("deposit.title")}</h1>
        </header>

        <div className="rounded-xl border p-3" style={{ borderColor: "var(--peek-border)" }}>
          <p className="peek-muted text-xs font-semibold tracking-wide uppercase">
            {t("deposit.prompt")}
          </p>
          <p className="mt-1 text-sm leading-relaxed">{prompt}</p>
        </div>

        <Field label={t("deposit.secret")} htmlFor="answer">
          <textarea
            id="answer"
            required
            rows={4}
            className="peek-input font-mono"
            value={answer}
            onChange={(e) => setAnswer(e.target.value)}
            spellCheck={false}
            autoComplete="off"
          />
        </Field>

        {error ? (
          <Banner tone="danger" title={t("deposit.error")}>
            {error}
          </Banner>
        ) : null}

        <button
          type="submit"
          className="peek-btn peek-btn-primary w-full sm:w-auto"
          disabled={phase === "sending" || !isCryptoAvailable() || !isSecureContext()}
        >
          {phase === "sending" ? <Spinner label={t("deposit.submitting")} /> : t("deposit.submit")}
        </button>
      </Card>
    </form>
  );
}

// --- tracking ----------------------------------------------------------------

interface ReadDeposit {
  secretID: string;
  text: string;
  files: FileRef[];
  grant?: string;
}

export function RequestStatus({
  id,
  fragment,
  t,
  lang,
}: {
  id: string;
  fragment: string;
  t: Translate;
  lang: Lang;
}) {
  const [key, setKey] = useState<RequestKey | null>(null);
  const [tokens, setTokens] = useState<{ requestKey: Uint8Array; receipt: Uint8Array } | null>(
    null,
  );
  const [receipt, setReceipt] = useState<SecretRequestReceipt | null>(null);
  // Deposits accumulate and are never dropped. Reading one consumes it, so the
  // very next refresh would otherwise make the answer vanish from under the
  // person who asked for it.
  const [seen, setSeen] = useState<DepositInfo[]>([]);
  const [read, setRead] = useState<Record<string, ReadDeposit>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [closed, setClosed] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [bad, setBad] = useState(false);

  // The fragment holds three things: the key pair, the request key and the
  // receipt token. Parsing it is asynchronous because checking that the key
  // pair is coherent means using it.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const parts = fragment.replace(/^#/, "").split("~");
      if (parts.length !== 3) {
        setBad(true);
        return;
      }
      try {
        const pair = await decodeRequestFragment(parts[0]);
        const requestKey = b64urlDecode(parts[1]);
        const receiptToken = b64urlDecode(parts[2]);
        if (cancelled) return;
        setKey(pair);
        setTokens({ requestKey, receipt: receiptToken });
      } catch {
        if (!cancelled) setBad(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [fragment]);

  const refresh = useCallback(async () => {
    if (!tokens) return;
    try {
      const fresh = await api.requestReceipt(id, b64urlEncode(tokens.receipt));
      setReceipt(fresh);
      setSeen((current) => {
        const known = new Set(current.map((d) => d.secret_id));
        const added = fresh.deposits.filter((d) => !known.has(d.secret_id));
        return added.length > 0 ? [...current, ...added] : current;
      });
      setError(null);
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        setClosed(true);
        return;
      }
      setError(describeError(err, t));
    }
  }, [id, tokens, t]);

  useEffect(() => {
    if (!tokens) return;
    void refresh();
    // The requester watches this page while the other person answers.
    const timer = window.setInterval(() => void refresh(), 10000);
    return () => window.clearInterval(timer);
  }, [refresh, tokens]);

  async function readDeposit(d: DepositInfo) {
    if (!key) return;
    setError(null);
    setBusy(d.secret_id);
    try {
      // Unwrap the content key with the private half from our own fragment,
      // then the deposit is an ordinary secret and reads like one.
      const contentKey = await openFromRequest(key, id, b64urlDecode(d.wrapped_key));
      const keys = await deriveKeys(contentKey, "", {
        salt: b64urlDecode(d.kdf.salt),
        memoryKiB: d.kdf.memory_kib,
        iterations: d.kdf.iterations,
        parallelism: d.kdf.parallelism,
      });
      const response = await api.reveal(d.secret_id, b64urlEncode(keys.readToken));
      const plain = await openSealed(keys.enc, aad(d.secret_id), b64urlDecode(response.ciphertext));
      const payload = unmarshalPayload(plain);
      setRead((current) => ({
        ...current,
        [d.secret_id]: {
          secretID: d.secret_id,
          text: payload.text ?? payload.url ?? "",
          files: payload.files ?? [],
          grant: response.download_token,
        },
      }));
      void refresh();
    } catch (err) {
      setError(describeError(err, t));
    } finally {
      setBusy(null);
    }
  }

  async function closeRequest() {
    if (!tokens) return;
    try {
      await api.closeRequest(id, b64urlEncode(tokens.receipt));
      setClosed(true);
    } catch (err) {
      setError(describeError(err, t));
    }
  }

  if (bad) {
    return (
      <Card>
        <h1 className="text-xl font-semibold">{t("reveal.noKey.title")}</h1>
        <p className="peek-muted mt-2 text-sm leading-relaxed">{t("reveal.noKey.body")}</p>
      </Card>
    );
  }
  if (!receipt && !closed) {
    return (
      <Card>
        <Spinner label={t("app.loading")} />
      </Card>
    );
  }

  const depositLink =
    key && tokens
      ? `${window.location.origin}/q/${id}#${encodeDepositFragment(tokens.requestKey, key.pub)}`
      : "";

  return (
    <div className="space-y-5">
      <Card className="space-y-4">
        <header className="space-y-1">
          <h1 className="text-xl font-semibold">{t("qstatus.title")}</h1>
          {receipt ? (
            <p className="peek-muted text-sm">
              {t("qstatus.remaining", { n: receipt.deposits_remaining })} ·{" "}
              {t("reveal.expires", { when: formatWhen(receipt.expires_at, lang) })}
            </p>
          ) : null}
        </header>

        {closed ? <Banner tone="warning">{t("qstatus.closed")}</Banner> : null}

        {!closed && depositLink ? (
          <Field label={t("qstatus.link")} htmlFor="deposit-again">
            <div className="flex items-center gap-2">
              <input
                id="deposit-again"
                readOnly
                className="peek-input flex-1 font-mono text-xs"
                value={depositLink}
              />
              <CopyButton
                value={depositLink}
                label={t("reveal.copy")}
                copiedLabel={t("reveal.copied")}
              />
            </div>
          </Field>
        ) : null}

        {error ? (
          <Banner tone="danger" title={t("qstatus.error")}>
            {error}
          </Banner>
        ) : null}

        {!closed ? (
          <button type="button" className="peek-btn peek-btn-danger w-fit" onClick={closeRequest}>
            {t("qstatus.close")}
          </button>
        ) : null}
      </Card>

      <Card className="space-y-4">
        <h2 className="text-lg font-semibold">{t("qstatus.deposits")}</h2>
        {seen.length === 0 ? (
          <p className="peek-muted text-sm leading-relaxed">{t("qstatus.none")}</p>
        ) : (
          <ol className="space-y-4">
            {seen.map((d, i) => {
              const got = read[d.secret_id];
              return (
                <li
                  key={d.secret_id}
                  className="rounded-xl border p-4"
                  style={{ borderColor: "var(--peek-border)" }}
                >
                  <div className="flex items-center justify-between gap-3">
                    <p className="text-sm font-semibold">{t("qstatus.deposit.n", { n: i + 1 })}</p>
                    <span className="peek-muted text-xs">{formatWhen(d.created_at, lang)}</span>
                  </div>
                  {got ? (
                    <div className="mt-3 space-y-3">
                      {got.text ? (
                        <>
                          <pre
                            className="max-h-60 overflow-auto rounded-xl border p-3 font-mono text-sm break-all whitespace-pre-wrap"
                            style={{ borderColor: "var(--peek-border)" }}
                          >
                            {got.text}
                          </pre>
                          <CopyButton
                            value={got.text}
                            label={t("reveal.copy")}
                            copiedLabel={t("reveal.copied")}
                          />
                        </>
                      ) : null}
                      <Attachments files={got.files} grant={got.grant} t={t} />
                    </div>
                  ) : (
                    <button
                      type="button"
                      className="peek-btn peek-btn-primary mt-3 text-sm"
                      disabled={busy !== null || d.views_remaining <= 0}
                      onClick={() => void readDeposit(d)}
                    >
                      {busy === d.secret_id ? t("qstatus.reading") : t("qstatus.read")}
                    </button>
                  )}
                </li>
              );
            })}
          </ol>
        )}
      </Card>
    </div>
  );
}
