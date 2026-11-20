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
} from "../crypto";
import { randomBytes } from "../crypto/bytes";
import { sha256 } from "../crypto/hkdf";
import { ApiError, api, type Policy } from "../lib/api";
import {
  defaultPasswordOptions,
  entropyBits,
  entropyLabel,
  generatePassword,
  type PasswordOptions,
} from "../lib/password";
import type { Translate } from "../lib/i18n";
import { Banner, Card, Field, Spinner, Toggle } from "../ui";

interface Props {
  t: Translate;
  policy: Policy | null;
  policyError: string | null;
}

type Kind = "text" | "url";

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
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
  const bits = entropyBits(genOpts);
  const entropy = entropyLabel(bits);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);

    const trimmed = secret.trim();
    if (!trimmed) {
      setError(t("create.empty"));
      return;
    }
    if (passphraseRequired && passphrase === "") {
      setError(t("create.passphrase.required"));
      return;
    }

    setBusy(true);
    try {
      // Everything below happens in this tab. The server receives the sealed
      // payload, two digests and the chosen limits — never the key.
      const id = newId();
      const contentKey = newContentKey();
      const kdf = newKdfParams();
      if (policy?.kdf) {
        kdf.memoryKiB = policy.kdf.memory_kib;
        kdf.iterations = policy.kdf.iterations;
        kdf.parallelism = policy.kdf.parallelism;
      }
      const keys = await deriveKeys(contentKey, passphrase, kdf);

      const payload = marshalPayload({
        v: 1,
        kind,
        text: kind === "text" ? trimmed : undefined,
        url: kind === "url" ? trimmed : undefined,
        message: message.trim() || undefined,
      });
      const sealed = await seal(keys.enc, aad(id), payload);

      // The receipt token authorises status checks and burning. It is random,
      // and the server only stores its hash.
      const receiptToken = randomBytes(32);
      const receiptTokenHash = await sha256(receiptToken);

      const created = await api.create({
        id,
        kind,
        ciphertext: b64urlEncode(sealed),
        read_token_hash: b64urlEncode(keys.readTokenHash),
        receipt_token_hash: b64urlEncode(receiptTokenHash),
        kdf: {
          salt: b64urlEncode(kdf.salt),
          memory_kib: kdf.memoryKiB,
          iterations: kdf.iterations,
          parallelism: kdf.parallelism,
        },
        has_passphrase: passphrase !== "",
        ttl_seconds: ttl,
        views,
        retrieval_step: retrievalStep,
        deletable_by_recipient: deletable,
      });

      // Both tokens live in the fragment of the receipt URL, so neither the
      // server nor any proxy in between ever sees them.
      const fragment = `v1.${b64urlEncode(contentKey)}~${b64urlEncode(receiptToken)}`;
      const target = `/r/${created.id}#${fragment}`;
      // Replace, so Back does not return to a form holding the plaintext.
      window.history.replaceState(null, "", target);
      window.dispatchEvent(new PopStateEvent("popstate"));
    } catch (err) {
      setError(describeError(err, t));
      setBusy(false);
    }
  }

  if (policyError) {
    return (
      <Card>
        <h1 className="text-xl font-semibold">{t("create.disabled.title")}</h1>
        <p className="peek-muted mt-2 text-sm leading-relaxed">{policyError}</p>
      </Card>
    );
  }

  return (
    <form onSubmit={submit} className="space-y-5">
      <Card className="space-y-5">
        <header className="space-y-1">
          <h1 className="text-xl font-semibold">{t("create.title")}</h1>
          <p className="peek-muted text-sm leading-relaxed">{t("create.subtitle")}</p>
        </header>

        <div
          role="group"
          className="inline-flex rounded-xl border p-1"
          style={{ borderColor: "var(--peek-border)" }}
        >
          {(["text", "url"] as Kind[]).map((option) => (
            <button
              key={option}
              type="button"
              aria-pressed={kind === option}
              onClick={() => setKind(option)}
              className="rounded-lg px-3 py-1.5 text-sm font-medium"
              style={
                kind === option
                  ? { background: "var(--peek-primary)", color: "var(--peek-on-primary)" }
                  : undefined
              }
            >
              {option === "text" ? t("create.kind.text") : t("create.kind.url")}
            </button>
          ))}
        </div>

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
        <div className="grid gap-5 sm:grid-cols-2">
          <Field label={t("create.expiry")} htmlFor="ttl">
            <select
              id="ttl"
              className="peek-input"
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
              className="peek-input"
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
        </div>

        {error ? (
          <Banner tone="danger" title={t("create.error")}>
            {error}
          </Banner>
        ) : null}

        <button
          type="submit"
          className="peek-btn peek-btn-primary w-full sm:w-auto"
          disabled={busy}
        >
          {busy ? <Spinner label={t("create.submitting")} /> : t("create.submit")}
        </button>
      </Card>
    </form>
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
