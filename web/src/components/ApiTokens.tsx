import { useCallback, useEffect, useState } from "react";
import { auth, type ApiTokenInfo } from "../lib/api";
import { formatDateTime } from "../lib/format";
import type { Lang, Translate, TranslationKey } from "../lib/i18n";
import { Banner, Card, CopyButton, Field, Spinner } from "../ui";
import { describeError } from "../pages/Create";

/**
 * API tokens, on the account page.
 *
 * The clear text appears once, in the response to the creation call, and the
 * card says so in as many words. Everything else — the listing, the audit
 * trail, the database — holds a digest and a name.
 */

const EXPIRY_CHOICES: { seconds: number; key: TranslationKey }[] = [
  { seconds: 0, key: "tokens.expiry.never" },
  { seconds: 30 * 86400, key: "tokens.expiry.30d" },
  { seconds: 90 * 86400, key: "tokens.expiry.90d" },
  { seconds: 365 * 86400, key: "tokens.expiry.1y" },
];

export default function ApiTokens({ t, lang }: { t: Translate; lang: Lang }) {
  const [tokens, setTokens] = useState<ApiTokenInfo[] | null>(null);
  const [scopes, setScopes] = useState<string[]>([]);
  const [name, setName] = useState("");
  const [chosen, setChosen] = useState<string[]>(["secrets:write"]);
  const [ttl, setTtl] = useState(90 * 86400);
  const [busy, setBusy] = useState(false);
  const [issued, setIssued] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const out = await auth.tokens();
      setTokens(out.tokens ?? []);
      setScopes(out.scopes ?? []);
      setError(null);
    } catch (err) {
      setError(describeError(err, t));
      setTokens([]);
    }
  }, [t]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function create(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const out = await auth.createToken(name.trim(), chosen, ttl);
      setIssued(out.token);
      setName("");
      await refresh();
    } catch (err) {
      setError(describeError(err, t));
    } finally {
      setBusy(false);
    }
  }

  async function revoke(id: string) {
    setError(null);
    try {
      await auth.revokeToken(id);
      await refresh();
    } catch (err) {
      setError(describeError(err, t));
    }
  }

  function toggleScope(scope: string) {
    setChosen((current) =>
      current.includes(scope) ? current.filter((s) => s !== scope) : [...current, scope],
    );
  }

  function scopeLabel(scope: string): string {
    // The scope names are a fixed set, so the keys exist; an unknown one from
    // a newer server falls back to its own name rather than a blank line.
    const key = `tokens.scope.${scope}` as TranslationKey;
    const label = t(key);
    return label === key ? scope : label;
  }

  return (
    <Card className="space-y-5">
      <header className="space-y-1">
        <h2 className="text-lg font-semibold">{t("tokens.title")}</h2>
        <p className="peek-muted text-sm leading-relaxed">{t("tokens.subtitle")}</p>
      </header>

      {issued ? (
        <Banner tone="warning" title={t("tokens.created.title")}>
          <p>{t("tokens.created.body")}</p>
          <div className="mt-2 flex flex-col gap-2 sm:flex-row sm:items-center">
            <input
              readOnly
              aria-label={t("tokens.created.title")}
              className="peek-input font-mono text-xs sm:flex-1"
              value={issued}
            />
            <CopyButton
              value={issued}
              label={t("reveal.copy")}
              copiedLabel={t("reveal.copied")}
              className="peek-btn peek-btn-ghost max-sm:w-full"
            />
          </div>
          <p className="mt-2 text-xs">{t("tokens.created.usage")}</p>
          <pre className="mt-1 overflow-x-auto text-xs">
            {`curl -H "Authorization: Bearer ${issued.slice(0, 12)}…" \\\n  ${window.location.origin}/api/v1/policy`}
          </pre>
        </Banner>
      ) : null}

      {tokens === null ? (
        <Spinner label={t("app.loading")} />
      ) : tokens.length === 0 ? (
        <p className="peek-muted text-sm">{t("tokens.none")}</p>
      ) : (
        <ul className="space-y-2">
          {tokens.map((token) => {
            const expired =
              !token.revoked && !!token.expires_at && new Date(token.expires_at) <= new Date();
            const state = token.revoked
              ? t("tokens.revoked")
              : expired
                ? t("tokens.expired")
                : t("tokens.active");
            return (
              <li
                key={token.id}
                className="rounded-xl border p-3 text-sm"
                style={{ borderColor: "var(--peek-border)" }}
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">{token.name}</span>
                  <span className="peek-chip">{state}</span>
                  <span className="peek-muted font-mono text-xs">{token.id}</span>
                  {token.revoked || expired ? null : (
                    <button
                      type="button"
                      className="peek-btn peek-btn-ghost ml-auto text-xs"
                      onClick={() => void revoke(token.id)}
                    >
                      {t("tokens.revoke")}
                    </button>
                  )}
                </div>
                <p className="peek-muted mt-1 text-xs">
                  {token.scopes.join(" · ")} — {t("tokens.lastUsed")}:{" "}
                  {token.last_used_at
                    ? formatDateTime(token.last_used_at, lang)
                    : t("tokens.lastUsed.never")}
                  {token.expires_at
                    ? ` — ${t("tokens.expiry")}: ${formatDateTime(token.expires_at, lang)}`
                    : ""}
                </p>
              </li>
            );
          })}
        </ul>
      )}

      <form
        onSubmit={create}
        className="space-y-4 border-t pt-4"
        style={{ borderColor: "var(--peek-border)" }}
      >
        <Field label={t("tokens.name")} htmlFor="token-name">
          <input
            id="token-name"
            required
            className="peek-input"
            placeholder={t("tokens.name.placeholder")}
            value={name}
            onChange={(e) => setName(e.target.value)}
            maxLength={80}
          />
        </Field>

        <fieldset className="space-y-2">
          <legend className="text-xs font-semibold">{t("tokens.scopes")}</legend>
          {(scopes.length > 0 ? scopes : ["secrets:write"]).map((scope) => (
            <label key={scope} className="flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                className="mt-1 size-3.5 accent-[var(--peek-primary)]"
                checked={chosen.includes(scope)}
                onChange={() => toggleScope(scope)}
              />
              <span>
                <code className="text-xs">{scope}</code>
                <span className="peek-muted block text-xs">{scopeLabel(scope)}</span>
              </span>
            </label>
          ))}
        </fieldset>

        <Field label={t("tokens.expiry")} htmlFor="token-ttl">
          <select
            id="token-ttl"
            className="peek-input peek-select"
            value={ttl}
            onChange={(e) => setTtl(Number(e.target.value))}
          >
            {EXPIRY_CHOICES.map((choice) => (
              <option key={choice.seconds} value={choice.seconds}>
                {t(choice.key)}
              </option>
            ))}
          </select>
        </Field>

        {error ? (
          <Banner tone="danger" title={t("tokens.error")}>
            {error}
          </Banner>
        ) : null}

        <button
          type="submit"
          className="peek-btn peek-btn-primary"
          disabled={busy || chosen.length === 0 || name.trim() === ""}
        >
          {busy ? <Spinner label={t("tokens.creating")} /> : t("tokens.create")}
        </button>
      </form>
    </Card>
  );
}
