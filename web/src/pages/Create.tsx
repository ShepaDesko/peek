import { useEffect, useMemo, useState } from "react";
import {
  aad,
  b64urlEncode,
  deriveKeys,
  marshalPayload,
  newContentKey,
  newId,
  newKdfParams,
  seal,
  type FileRef,
} from "../crypto";
import { randomBytes } from "../crypto/bytes";
import { sha256 } from "../crypto/hkdf";
import { ApiError, api, type CreateRequest, type FileClaim, type Policy } from "../lib/api";
import { encryptAndUpload, humanSize } from "../lib/files";
import {
  defaultPasswordOptions,
  entropyBits,
  entropyLabel,
  generatePassword,
  type PasswordOptions,
} from "../lib/password";
import type { Translate } from "../lib/i18n";
import { isCryptoAvailable, isSecureContext } from "../lib/secure";
import { Banner, Card, CopyButton, Field, IconKey, Spinner, Toggle } from "../ui";

interface Props {
  t: Translate;
  policy: Policy | null;
  policyError: string | null;
}

type Kind = "text" | "url" | "file";

/** One attachment in flight, as the form sees it. */
interface Attachment {
  key: string;
  name: string;
  size: number;
  state: "working" | "done" | "failed";
  phase: "encrypting" | "uploading" | "done";
  percent: number;
  ref?: FileRef;
  claim?: FileClaim;
  error?: string;
}

/** One recipient of a multi-recipient bundle, with its own settings. */
interface Recipient {
  key: string;
  label: string;
  ttl: number;
  views: number;
  passphrase: string;
}

/** A created link, shown once on the result card. */
interface CreatedLink {
  label: string;
  share: string;
  receipt: string;
}

const EXPIRY_CHOICES: {
  seconds: number;
  key: "expiry.5m" | "expiry.1h" | "expiry.24h" | "expiry.7d" | "expiry.30d";
}[] = [
  { seconds: 300, key: "expiry.5m" },
  { seconds: 3600, key: "expiry.1h" },
  { seconds: 86400, key: "expiry.24h" },
  { seconds: 604800, key: "expiry.7d" },
  { seconds: 2592000, key: "expiry.30d" },
];

export default function Create({ t, policy, policyError }: Props) {
  const [kind, setKind] = useState<Kind>("text");
  const [secret, setSecret] = useState("");
  const [message, setMessage] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [ttl, setTtl] = useState(86400);
  const [views, setViews] = useState(1);
  const [retrievalStep, setRetrievalStep] = useState(true);
  const [deletable, setDeletable] = useState(false);
  const [showGenerator, setShowGenerator] = useState(false);
  const [genOpts, setGenOpts] = useState<PasswordOptions>(defaultPasswordOptions);
  const [attachments, setAttachments] = useState<Attachment[]>([]);
  const [multi, setMulti] = useState(false);
  const [recipients, setRecipients] = useState<Recipient[]>([]);
  const [results, setResults] = useState<CreatedLink[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Without WebCrypto there is nothing to submit: App already explains why.
  const cryptoReady = isCryptoAvailable() && isSecureContext();

  // Defaults follow the instance policy, so an admin's choices are what a user
  // sees first.
  useEffect(() => {
    if (!policy) return;
    setTtl(clampTtl(policy.default_ttl_seconds, policy.max_ttl_seconds));
    setViews(Math.min(Math.max(policy.default_views, 1), policy.max_views));
    if (policy.force_retrieval_step) setRetrievalStep(true);
  }, [policy]);

  const expiryChoices = useMemo(() => {
    const max = policy?.max_ttl_seconds ?? 2592000;
    const allowed = EXPIRY_CHOICES.filter((c) => c.seconds <= max);
    return allowed.length > 0 ? allowed : [EXPIRY_CHOICES[0]];
  }, [policy]);

  const viewChoices = useMemo(() => {
    const max = policy?.max_views ?? 100;
    return [1, 2, 3, 5, 10, 25, 50, 100].filter((v) => v <= max);
  }, [policy]);

  const passphraseRequired = policy?.require_passphrase ?? false;
  const filesAllowed = (policy?.allowed_kinds ?? []).includes("file") && policy?.storage !== false;
  const maxFiles = policy?.max_files_per_secret ?? 10;
  const maxRecipients = policy?.max_recipients ?? 10;
  const bits = entropyBits(genOpts);
  const entropy = entropyLabel(bits);
  const uploading = attachments.some((a) => a.state === "working");
  const readyFiles = attachments.filter((a) => a.state === "done" && a.ref && a.claim);

  async function addFiles(list: FileList | null) {
    if (!list || list.length === 0) return;
    setError(null);
    const chunk = policy?.file_chunk_size ?? 1 << 20;
    const maxBytes = policy?.max_file_bytes ?? 0;

    const chosen = Array.from(list);
    if (attachments.length + chosen.length > maxFiles) {
      setError(t("create.files.tooMany", { n: maxFiles }));
      return;
    }

    for (const file of chosen) {
      if (maxBytes > 0 && file.size > maxBytes) {
        setError(t("create.files.tooLarge", { name: file.name, size: humanSize(maxBytes) }));
        continue;
      }
      const key = `${file.name}-${file.size}-${Math.random().toString(36).slice(2)}`;
      setAttachments((list) => [
        ...list,
        {
          key,
          name: file.name,
          size: file.size,
          state: "working",
          phase: "encrypting",
          percent: 0,
        },
      ]);
      try {
        const pending = await encryptAndUpload(file, chunk, (p) => {
          setAttachments((list) =>
            list.map((a) =>
              a.key === key
                ? {
                    ...a,
                    phase: p.phase,
                    percent: p.total > 0 ? Math.round((p.sent / p.total) * 100) : 0,
                  }
                : a,
            ),
          );
        });
        setAttachments((list) =>
          list.map((a) =>
            a.key === key
              ? {
                  ...a,
                  state: "done",
                  phase: "done",
                  percent: 100,
                  ref: pending.ref,
                  claim: pending.claim,
                }
              : a,
          ),
        );
      } catch (err) {
        const text = describeError(err, t);
        setAttachments((list) =>
          list.map((a) => (a.key === key ? { ...a, state: "failed", error: text } : a)),
        );
        setError(t("create.files.failed", { name: file.name, error: text }));
      }
    }
  }

  function removeAttachment(key: string) {
    // The blob stays on the server until its upload window closes, then the
    // purge collects it. Nothing points at it in the meantime.
    setAttachments((list) => list.filter((a) => a.key !== key));
  }

  function addRecipient() {
    setRecipients((list) =>
      list.length >= maxRecipients
        ? list
        : [
            ...list,
            {
              key: Math.random().toString(36).slice(2),
              label: "",
              ttl,
              views,
              passphrase: "",
            },
          ],
    );
  }

  function toggleMulti(on: boolean) {
    setMulti(on);
    if (on && recipients.length === 0) {
      setRecipients([
        { key: "a", label: "", ttl, views, passphrase: "" },
        { key: "b", label: "", ttl, views, passphrase: "" },
      ]);
    }
  }

  function patchRecipient(key: string, patch: Partial<Recipient>) {
    setRecipients((list) => list.map((r) => (r.key === key ? { ...r, ...patch } : r)));
  }

  /** buildOne seals the payload for one recipient and returns its request. */
  async function buildOne(
    recipientPassphrase: string,
    recipientTtl: number,
    recipientViews: number,
    files: FileRef[],
  ): Promise<{ body: CreateRequest; share: string; receipt: string }> {
    const id = newId();
    const contentKey = newContentKey();
    const kdf = newKdfParams();
    if (policy?.kdf) {
      kdf.memoryKiB = policy.kdf.memory_kib;
      kdf.iterations = policy.kdf.iterations;
      kdf.parallelism = policy.kdf.parallelism;
    }
    const keys = await deriveKeys(contentKey, recipientPassphrase, kdf);

    const trimmed = secret.trim();
    const payload = marshalPayload({
      v: 1,
      kind: files.length > 0 ? "file" : kind === "url" ? "url" : "text",
      text: kind === "text" && trimmed ? trimmed : undefined,
      url: kind === "url" && trimmed ? trimmed : undefined,
      message: message.trim() || undefined,
      files: files.length > 0 ? files : undefined,
    });
    const sealed = await seal(keys.enc, aad(id), payload);

    // The receipt token authorises status checks and burning. It is random,
    // and the server only stores its hash.
    const receiptToken = randomBytes(32);
    const receiptTokenHash = await sha256(receiptToken);

    const body: CreateRequest = {
      id,
      kind: files.length > 0 ? "file" : kind,
      ciphertext: b64urlEncode(sealed),
      read_token_hash: b64urlEncode(keys.readTokenHash),
      receipt_token_hash: b64urlEncode(receiptTokenHash),
      kdf: {
        salt: b64urlEncode(kdf.salt),
        memory_kib: kdf.memoryKiB,
        iterations: kdf.iterations,
        parallelism: kdf.parallelism,
      },
      has_passphrase: recipientPassphrase !== "",
      ttl_seconds: recipientTtl,
      views: recipientViews,
      retrieval_step: retrievalStep,
      deletable_by_recipient: deletable,
    };
    const origin = window.location.origin;
    return {
      body,
      share: `${origin}/s/${id}#v1.${b64urlEncode(contentKey)}`,
      // Both tokens live in the fragment, so neither the server nor any proxy
      // in between ever sees them.
      receipt: `${origin}/r/${id}#v1.${b64urlEncode(contentKey)}~${b64urlEncode(receiptToken)}`,
    };
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);

    const trimmed = secret.trim();
    const files = readyFiles.map((a) => a.ref!);
    if (kind === "file") {
      if (files.length === 0) {
        setError(t("create.files.empty"));
        return;
      }
    } else if (!trimmed) {
      setError(t("create.empty"));
      return;
    }
    if (uploading) return;

    const blocks: Recipient[] = multi
      ? recipients
      : [{ key: "one", label: "", ttl, views, passphrase }];
    if (passphraseRequired && blocks.some((r) => r.passphrase === "")) {
      setError(t("create.passphrase.required"));
      return;
    }
    if (blocks.length > maxRecipients) {
      setError(t("create.recipients.max", { n: maxRecipients }));
      return;
    }

    setBusy(true);
    try {
      // Everything below happens in this tab. The server receives the sealed
      // payloads, two digests per link and the chosen limits — never a key.
      const built = [];
      for (const r of blocks) {
        built.push({
          ...(await buildOne(r.passphrase, r.ttl, r.views, files)),
          label: r.label,
        });
      }
      const claims: FileClaim[] = readyFiles.map((a) => a.claim!);

      if (built.length === 1) {
        await api.create(claims.length > 0 ? { ...built[0].body, files: claims } : built[0].body);
        // Replace, so Back does not return to a form holding the plaintext.
        const target = built[0].receipt.slice(window.location.origin.length);
        window.history.replaceState(null, "", target);
        window.dispatchEvent(new PopStateEvent("popstate"));
        return;
      }

      await api.createBundle(
        built.map((b) => b.body),
        claims,
      );
      setResults(built.map((b) => ({ label: b.label, share: b.share, receipt: b.receipt })));
      setSecret("");
      setAttachments([]);
      setBusy(false);
    } catch (err) {
      setError(describeError(err, t));
      setBusy(false);
    }
  }

  if (policyError) {
    return (
      <Card>
        <h1 className="text-2xl leading-tight font-bold tracking-tight">
          {t("create.disabled.title")}
        </h1>
        <p className="peek-muted mt-2 text-sm leading-relaxed">{policyError}</p>
      </Card>
    );
  }

  if (results) {
    return (
      <Card className="space-y-5">
        <header className="space-y-1">
          <h1 className="text-2xl leading-tight font-bold tracking-tight">
            {t("create.result.title", { n: results.length })}
          </h1>
          <p className="peek-muted text-sm leading-relaxed">{t("create.result.hint")}</p>
        </header>
        <ol className="space-y-4">
          {results.map((r, i) => (
            <li
              key={r.share}
              className="rounded-xl border p-4"
              style={{ borderColor: "var(--peek-border)" }}
            >
              <p className="text-sm font-semibold">
                {r.label || t("create.recipients.n", { n: i + 1 })}
              </p>
              <div className="mt-3 space-y-2">
                <LinkRow label={t("create.result.link")} value={r.share} t={t} />
                <LinkRow label={t("create.result.receipt")} value={r.receipt} t={t} />
              </div>
            </li>
          ))}
        </ol>
        <button
          type="button"
          className="peek-btn peek-btn-primary"
          onClick={() => {
            setResults(null);
            setMulti(false);
            setRecipients([]);
          }}
        >
          {t("create.result.new")}
        </button>
      </Card>
    );
  }

  return (
    <form onSubmit={submit} className="space-y-5">
      <Card className="space-y-5">
        <header className="space-y-2">
          <h1 className="text-2xl leading-tight font-bold tracking-tight">{t("create.title")}</h1>
          {/* The one sentence that says what the product is. It was a grey
              caption under the title, which is where a reader's eye goes
              last; the key marks it as a guarantee rather than a subtitle. */}
          <p className="peek-muted flex items-start gap-2 text-sm leading-relaxed">
            <IconKey />
            {t("create.subtitle")}
          </p>
        </header>

        <div
          role="group"
          className="inline-flex rounded-xl border p-1"
          style={{ borderColor: "var(--peek-border)" }}
        >
          {(filesAllowed ? (["text", "url", "file"] as Kind[]) : (["text", "url"] as Kind[])).map(
            (option) => (
              <button
                key={option}
                type="button"
                aria-pressed={kind === option}
                onClick={() => setKind(option)}
                className={
                  "peek-btn peek-toggle px-3 py-1.5 text-sm " +
                  (kind === option ? "peek-toggle-on" : "peek-btn-ghost")
                }
              >
                {t(
                  option === "text"
                    ? "create.kind.text"
                    : option === "url"
                      ? "create.kind.url"
                      : "create.kind.file",
                )}
              </button>
            ),
          )}
        </div>

        {kind !== "file" ? (
          <Field label={t("create.secret")} htmlFor="secret">
            {kind === "text" ? (
              <textarea
                id="secret"
                required
                rows={4}
                className="peek-input font-mono"
                placeholder={t("create.secret.placeholder")}
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                spellCheck={false}
                autoComplete="off"
                autoCapitalize="off"
              />
            ) : (
              <input
                id="secret"
                required
                type="url"
                inputMode="url"
                className="peek-input font-mono"
                placeholder={t("create.url.placeholder")}
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                autoComplete="off"
              />
            )}
          </Field>
        ) : null}

        {kind === "text" ? (
          <div className="space-y-3">
            <button
              type="button"
              className="peek-btn peek-btn-ghost text-sm"
              aria-expanded={showGenerator}
              onClick={() => setShowGenerator((v) => !v)}
            >
              {t("create.generate")}
            </button>

            {showGenerator ? (
              <div className="rounded-xl border p-4" style={{ borderColor: "var(--peek-border)" }}>
                <div className="flex flex-wrap items-end gap-4">
                  <div className="space-y-1">
                    <label htmlFor="gen-length" className="block text-xs font-semibold">
                      {t("create.generate.length")}: {genOpts.length}
                    </label>
                    <input
                      id="gen-length"
                      type="range"
                      min={8}
                      max={64}
                      value={genOpts.length}
                      onChange={(e) => setGenOpts({ ...genOpts, length: Number(e.target.value) })}
                      className="w-40 accent-[var(--peek-primary)]"
                    />
                  </div>
                  {(
                    [
                      ["upper", "A-Z"],
                      ["digits", "0-9"],
                      ["symbols", "!@#"],
                      ["excludeAmbiguous", "no l/1/O/0"],
                    ] as const
                  ).map(([key, label]) => (
                    <label key={key} className="flex items-center gap-1.5 text-xs font-medium">
                      <input
                        type="checkbox"
                        checked={genOpts[key]}
                        onChange={(e) => setGenOpts({ ...genOpts, [key]: e.target.checked })}
                        className="size-3.5 accent-[var(--peek-primary)]"
                      />
                      {label}
                    </label>
                  ))}
                </div>
                <div className="mt-3 flex flex-wrap items-center gap-3">
                  <button
                    type="button"
                    className="peek-btn peek-btn-primary text-sm"
                    onClick={() => setSecret(generatePassword(genOpts))}
                  >
                    {t("create.generate")}
                  </button>
                  <span
                    className="peek-chip"
                    style={{
                      color:
                        entropy.tone === "weak"
                          ? "var(--peek-danger)"
                          : entropy.tone === "fair"
                            ? "var(--peek-warning)"
                            : "var(--peek-success)",
                    }}
                  >
                    {t("create.entropy")}: {entropy.label}
                  </span>
                </div>
              </div>
            ) : null}
          </div>
        ) : null}

        {filesAllowed ? (
          <Field
            label={t("create.files")}
            htmlFor="files"
            hint={t("create.files.hint", { size: humanSize(policy?.max_file_bytes ?? 0) })}
          >
            <input
              id="files"
              type="file"
              multiple
              className="peek-input peek-file"
              onChange={(e) => {
                void addFiles(e.target.files);
                e.target.value = "";
              }}
            />
          </Field>
        ) : null}

        {attachments.length > 0 ? (
          <ul className="space-y-2">
            {attachments.map((a) => (
              <li
                key={a.key}
                className="flex items-center gap-3 rounded-xl border px-3 py-2 text-sm"
                style={{ borderColor: "var(--peek-border)" }}
              >
                <span className="min-w-0 flex-1 truncate font-medium">{a.name}</span>
                <span className="peek-muted shrink-0 text-xs">{humanSize(a.size)}</span>
                <span className="peek-muted shrink-0 text-xs">
                  {a.state === "failed"
                    ? a.error
                    : a.state === "done"
                      ? "✓"
                      : a.phase === "encrypting"
                        ? t("create.files.encrypting")
                        : t("create.files.uploading", { percent: a.percent })}
                </span>
                <button
                  type="button"
                  className="peek-btn peek-btn-ghost shrink-0 text-xs"
                  onClick={() => removeAttachment(a.key)}
                >
                  {t("create.files.remove")}
                </button>
              </li>
            ))}
          </ul>
        ) : null}

        <Field label={t("create.message")} htmlFor="message">
          <input
            id="message"
            className="peek-input"
            placeholder={t("create.message.placeholder")}
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            maxLength={500}
          />
        </Field>
      </Card>

      <Card className="space-y-5">
        {multi ? null : (
          <div className="grid gap-5 sm:grid-cols-2">
            <Field label={t("create.expiry")} htmlFor="ttl">
              <select
                id="ttl"
                className="peek-input peek-select"
                value={ttl}
                onChange={(e) => setTtl(Number(e.target.value))}
              >
                {expiryChoices.map((choice) => (
                  <option key={choice.seconds} value={choice.seconds}>
                    {t(choice.key)}
                  </option>
                ))}
              </select>
            </Field>

            <Field label={t("create.views")} htmlFor="views">
              <select
                id="views"
                className="peek-input peek-select"
                value={views}
                onChange={(e) => setViews(Number(e.target.value))}
              >
                {viewChoices.map((v) => (
                  <option key={v} value={v}>
                    {v === 1 ? t("create.views.one") : t("create.views.many", { n: v })}
                  </option>
                ))}
              </select>
            </Field>
          </div>
        )}

        {multi ? null : (
          <Field
            label={t("create.passphrase")}
            htmlFor="passphrase"
            hint={t("create.passphrase.hint")}
          >
            <input
              id="passphrase"
              type="password"
              className="peek-input"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              autoComplete="new-password"
              required={passphraseRequired}
            />
          </Field>
        )}

        <div className="space-y-3">
          <Toggle
            id="retrieval"
            checked={retrievalStep}
            disabled={policy?.force_retrieval_step}
            onChange={setRetrievalStep}
            label={t("create.retrieval")}
            hint={t("create.retrieval.hint")}
          />
          <Toggle
            id="deletable"
            checked={deletable}
            onChange={setDeletable}
            label={t("create.deletable")}
          />
          {maxRecipients > 1 ? (
            <Toggle
              id="multi"
              checked={multi}
              onChange={toggleMulti}
              label={t("create.recipients")}
              hint={t("create.recipients.hint")}
            />
          ) : null}
        </div>

        {multi ? (
          <div className="space-y-3">
            {recipients.map((r, i) => (
              <fieldset
                key={r.key}
                className="rounded-xl border p-4"
                style={{ borderColor: "var(--peek-border)" }}
              >
                <legend className="px-1 text-xs font-semibold">
                  {t("create.recipients.n", { n: i + 1 })}
                </legend>
                <div className="grid gap-3 sm:grid-cols-2">
                  <Field label={t("create.recipients.label")} htmlFor={`label-${r.key}`}>
                    <input
                      id={`label-${r.key}`}
                      className="peek-input"
                      value={r.label}
                      onChange={(e) => patchRecipient(r.key, { label: e.target.value })}
                      maxLength={80}
                    />
                  </Field>
                  <Field label={t("create.passphrase")} htmlFor={`pass-${r.key}`}>
                    <input
                      id={`pass-${r.key}`}
                      type="password"
                      className="peek-input"
                      value={r.passphrase}
                      onChange={(e) => patchRecipient(r.key, { passphrase: e.target.value })}
                      autoComplete="new-password"
                      required={passphraseRequired}
                    />
                  </Field>
                  <Field label={t("create.expiry")} htmlFor={`ttl-${r.key}`}>
                    <select
                      id={`ttl-${r.key}`}
                      className="peek-input peek-select"
                      value={r.ttl}
                      onChange={(e) => patchRecipient(r.key, { ttl: Number(e.target.value) })}
                    >
                      {expiryChoices.map((choice) => (
                        <option key={choice.seconds} value={choice.seconds}>
                          {t(choice.key)}
                        </option>
                      ))}
                    </select>
                  </Field>
                  <Field label={t("create.views")} htmlFor={`views-${r.key}`}>
                    <select
                      id={`views-${r.key}`}
                      className="peek-input peek-select"
                      value={r.views}
                      onChange={(e) => patchRecipient(r.key, { views: Number(e.target.value) })}
                    >
                      {viewChoices.map((v) => (
                        <option key={v} value={v}>
                          {v === 1 ? t("create.views.one") : t("create.views.many", { n: v })}
                        </option>
                      ))}
                    </select>
                  </Field>
                </div>
                {recipients.length > 2 ? (
                  <button
                    type="button"
                    className="peek-btn peek-btn-ghost mt-3 text-xs"
                    onClick={() => setRecipients((l) => l.filter((x) => x.key !== r.key))}
                  >
                    {t("create.recipients.remove")}
                  </button>
                ) : null}
              </fieldset>
            ))}
            <button
              type="button"
              className="peek-btn peek-btn-ghost text-sm"
              onClick={addRecipient}
              disabled={recipients.length >= maxRecipients}
            >
              {t("create.recipients.add")}
            </button>
          </div>
        ) : null}

        {error ? (
          <Banner tone="danger" title={t("create.error")}>
            {error}
          </Banner>
        ) : null}

        {/* The page's one action, at the size of one. Everything above it is
            a setting with a sensible default; this is the only control a
            sender has to find. */}
        <button
          type="submit"
          className="peek-btn peek-btn-primary peek-btn-lg sm:w-auto sm:min-w-64 sm:px-8"
          disabled={busy || uploading || !cryptoReady}
        >
          {busy ? <Spinner label={t("create.submitting")} /> : t("create.submit")}
        </button>
      </Card>
    </form>
  );
}

function LinkRow({ label, value, t }: { label: string; value: string; t: Translate }) {
  return (
    <div className="flex items-center gap-2">
      <span className="peek-muted w-40 shrink-0 text-xs font-semibold" aria-hidden="true">
        {label}
      </span>
      <input
        readOnly
        aria-label={label}
        className="peek-input flex-1 font-mono text-xs"
        value={value}
      />
      <CopyButton value={value} label={t("reveal.copy")} copiedLabel={t("reveal.copied")} />
    </div>
  );
}

function clampTtl(value: number, max: number): number {
  const allowed = EXPIRY_CHOICES.filter((c) => c.seconds <= max).map((c) => c.seconds);
  if (allowed.includes(value)) return value;
  // Pick the closest offered choice at or below the policy ceiling.
  const candidates = allowed.filter((v) => v <= value);
  return candidates.length > 0 ? Math.max(...candidates) : (allowed[0] ?? 300);
}

export function describeError(err: unknown, t: Translate): string {
  if (err instanceof ApiError) {
    if (err.status === 0) return t("error.network");
    if (err.status === 429) return t("error.rate");
    return err.message || t("error.generic");
  }
  if (err instanceof Error) return err.message;
  return t("error.generic");
}
