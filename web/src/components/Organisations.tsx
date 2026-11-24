import { useCallback, useEffect, useState } from "react";
import { platform, type DnsRecord, type OrgDomain, type OrgInfo } from "../lib/api";
import { formatWhen } from "../lib/format";
import type { Lang, Translate } from "../lib/i18n";
import { Banner, Card, CopyButton, Field, Spinner } from "../ui";
import { describeError } from "../pages/Create";

/**
 * Organisations, on the administration page.
 *
 * Only ever rendered on an instance with multi_org = true, and only for the
 * platform role. A single-tenant installation does not show the tab at all:
 * the brief asks for the notion to be hidden, not greyed out.
 *
 * The part worth getting right is the domain. A domain resolves to nothing
 * until a TXT record proves it, so the record is shown where it is needed —
 * next to the domain, copyable, with the exact name and value — and the verify
 * button says what the resolver actually saw when it fails. "Verification
 * failed" with nothing else is how this feature gets abandoned.
 */
export default function Organisations({
  t,
  lang,
  onError,
}: {
  t: Translate;
  lang: Lang;
  onError: (message: string | null) => void;
}) {
  const [orgs, setOrgs] = useState<OrgInfo[] | null>(null);
  const [slug, setSlug] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const out = await platform.orgs();
      setOrgs(out.orgs ?? []);
      onError(null);
    } catch (err) {
      onError(describeError(err, t));
      setOrgs([]);
    }
  }, [onError, t]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function create(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      await platform.createOrg(slug.trim(), name.trim());
      setSlug("");
      setName("");
      await refresh();
    } catch (err) {
      onError(describeError(err, t));
    } finally {
      setBusy(false);
    }
  }

  if (orgs === null) {
    return (
      <Card>
        <Spinner label={t("app.loading")} />
      </Card>
    );
  }

  return (
    <div className="space-y-5">
      <Card className="space-y-4">
        <header className="space-y-1">
          <h2 className="text-lg font-semibold">{t("orgs.title")}</h2>
          <p className="peek-muted text-sm leading-relaxed">{t("orgs.subtitle")}</p>
        </header>

        <form onSubmit={create} className="grid gap-3 sm:grid-cols-[1fr_1fr_auto] sm:items-end">
          <Field label={t("orgs.slug")} htmlFor="org-slug" hint={t("orgs.slug.hint")}>
            <input
              id="org-slug"
              required
              className="peek-input"
              placeholder="acme"
              value={slug}
              onChange={(e) => setSlug(e.target.value)}
              maxLength={60}
            />
          </Field>
          <Field label={t("orgs.name")} htmlFor="org-name">
            <input
              id="org-name"
              className="peek-input"
              placeholder="ACME Ltd"
              value={name}
              onChange={(e) => setName(e.target.value)}
              maxLength={120}
            />
          </Field>
          <button
            type="submit"
            className="peek-btn peek-btn-primary"
            disabled={busy || slug.trim() === ""}
          >
            {busy ? <Spinner label={t("orgs.creating")} /> : t("orgs.create")}
          </button>
        </form>
      </Card>

      {orgs.map((org) => (
        <OrgCard key={org.id} org={org} t={t} lang={lang} onError={onError} onChanged={refresh} />
      ))}
    </div>
  );
}

function OrgCard({
  org,
  t,
  lang,
  onError,
  onChanged,
}: {
  org: OrgInfo;
  t: Translate;
  lang: Lang;
  onError: (message: string | null) => void;
  onChanged: () => Promise<void>;
}) {
  const [domain, setDomain] = useState("");
  const [record, setRecord] = useState<DnsRecord | null>(null);
  const [checking, setChecking] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<{ domain: string; message: string } | null>(null);
  const isDefault = org.slug === "default";

  async function addDomain(event: React.FormEvent) {
    event.preventDefault();
    try {
      const out = await platform.addDomain(org.id, domain.trim());
      setRecord(out.record);
      setDomain("");
      await onChanged();
    } catch (err) {
      onError(describeError(err, t));
    }
  }

  async function verify(name: string) {
    setChecking(name);
    setOutcome(null);
    try {
      const out = await platform.verifyDomain(org.id, name);
      if (out.verified) {
        setOutcome({ domain: name, message: t("orgs.domain.verified") });
        setRecord(null);
      } else {
        // What the resolver saw, verbatim: "no such record" and "a record
        // with the wrong value" need different actions from the operator.
        setOutcome({ domain: name, message: out.error ?? t("orgs.domain.notYet") });
        if (out.record) setRecord(out.record);
      }
      await onChanged();
    } catch (err) {
      onError(describeError(err, t));
    } finally {
      setChecking(null);
    }
  }

  async function act(fn: () => Promise<unknown>) {
    try {
      await fn();
      await onChanged();
    } catch (err) {
      onError(describeError(err, t));
    }
  }

  return (
    <Card className="space-y-4">
      <header className="flex flex-wrap items-baseline gap-2">
        <h3 className="text-base font-semibold">{org.name || org.slug}</h3>
        <code className="peek-muted text-xs">{org.slug}</code>
        {org.status === "suspended" ? (
          <span className="peek-chip">{t("orgs.suspended")}</span>
        ) : null}
        <span className="peek-muted ml-auto text-xs">
          {t("orgs.counts")
            .replace("{users}", String(org.counts.users))
            .replace("{secrets}", String(org.counts.secrets))}
        </span>
      </header>

      <ul className="space-y-2">
        {(org.domains ?? []).map((d) => (
          <li
            key={d.domain}
            className="rounded-xl border p-3 text-sm"
            style={{ borderColor: "var(--peek-border)" }}
          >
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-medium">{d.domain}</span>
              <span className="peek-chip">
                {d.verified_at ? t("orgs.domain.ok") : t("orgs.domain.pending")}
              </span>
              {d.primary ? <span className="peek-chip">{t("orgs.domain.primary")}</span> : null}
              <span className="ml-auto flex gap-2">
                <button
                  type="button"
                  className="peek-btn peek-btn-ghost text-xs"
                  onClick={() => void verify(d.domain)}
                  disabled={checking === d.domain}
                >
                  {checking === d.domain ? (
                    <Spinner label={t("orgs.domain.checking")} />
                  ) : (
                    t("orgs.domain.verify")
                  )}
                </button>
                {d.verified_at && !d.primary ? (
                  <button
                    type="button"
                    className="peek-btn peek-btn-ghost text-xs"
                    onClick={() => void act(() => platform.setPrimaryDomain(org.id, d.domain))}
                  >
                    {t("orgs.domain.makePrimary")}
                  </button>
                ) : null}
                <button
                  type="button"
                  className="peek-btn peek-btn-ghost text-xs"
                  onClick={() => void act(() => platform.removeDomain(org.id, d.domain))}
                >
                  {t("orgs.domain.remove")}
                </button>
              </span>
            </div>
            {d.last_error && !d.verified_at ? (
              <p className="peek-muted mt-1 text-xs">{d.last_error}</p>
            ) : null}
            {d.last_checked_at ? (
              <p className="peek-muted mt-1 text-xs">
                {t("orgs.domain.lastCheck")}: {formatWhen(d.last_checked_at, lang)}
              </p>
            ) : null}
            {outcome?.domain === d.domain ? (
              <div className="mt-2">
                <Banner tone={d.verified_at ? "success" : "warning"}>{outcome.message}</Banner>
              </div>
            ) : null}
          </li>
        ))}
        {(org.domains ?? []).length === 0 ? (
          <li className="peek-muted text-sm">{t("orgs.domain.none")}</li>
        ) : null}
      </ul>

      {record ? <RecordCard record={record} t={t} /> : null}
      {!record && (org.domains ?? []).some((d: OrgDomain) => !d.verified_at) ? (
        <p className="peek-muted text-xs leading-relaxed">{t("orgs.domain.recordHint")}</p>
      ) : null}

      <form onSubmit={addDomain} className="flex flex-wrap items-end gap-2">
        <div className="flex-1">
          <Field label={t("orgs.domain.add")} htmlFor={`domain-${org.id}`}>
            <input
              id={`domain-${org.id}`}
              className="peek-input"
              placeholder="secrets.acme.com"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
            />
          </Field>
        </div>
        <button type="submit" className="peek-btn peek-btn-ghost" disabled={domain.trim() === ""}>
          {t("orgs.domain.declare")}
        </button>
      </form>

      {isDefault ? (
        <p className="peek-muted text-xs leading-relaxed">{t("orgs.default.hint")}</p>
      ) : (
        <div
          className="flex flex-wrap gap-2 border-t pt-3"
          style={{ borderColor: "var(--peek-border)" }}
        >
          <button
            type="button"
            className="peek-btn peek-btn-ghost text-xs"
            onClick={() =>
              void act(() =>
                platform.updateOrg(org.id, {
                  status: org.status === "suspended" ? "active" : "suspended",
                }),
              )
            }
          >
            {org.status === "suspended" ? t("orgs.resume") : t("orgs.suspend")}
          </button>
          <button
            type="button"
            className="peek-btn peek-btn-ghost text-xs"
            onClick={() => void act(() => platform.deleteOrg(org.id))}
            disabled={org.counts.users > 0 || org.counts.secrets > 0}
            title={
              org.counts.users > 0 || org.counts.secrets > 0 ? t("orgs.delete.blocked") : undefined
            }
          >
            {t("orgs.delete")}
          </button>
        </div>
      )}
    </Card>
  );
}

/** The record to publish, copyable field by field. */
function RecordCard({ record, t }: { record: DnsRecord; t: Translate }) {
  return (
    <div
      className="space-y-2 rounded-xl border p-3"
      style={{ borderColor: "var(--peek-border)", background: "var(--peek-surface-2)" }}
    >
      <p className="text-sm font-medium">{t("orgs.domain.publish")}</p>
      <dl className="space-y-2 text-xs">
        {[
          { label: t("orgs.record.type"), value: record.type },
          { label: t("orgs.record.name"), value: record.name },
          { label: t("orgs.record.value"), value: record.value },
        ].map((row) => (
          <div key={row.label} className="flex flex-col gap-2 sm:flex-row sm:items-center">
            <dt className="peek-muted sm:w-16 sm:shrink-0">{row.label}</dt>
            <dd className="flex min-w-0 flex-col gap-2 sm:flex-1 sm:flex-row sm:items-center">
              <input
                readOnly
                aria-label={row.label}
                className="peek-input font-mono text-xs sm:flex-1"
                value={row.value}
              />
              <CopyButton
                value={row.value}
                label={t("reveal.copy")}
                copiedLabel={t("reveal.copied")}
                className="peek-btn peek-btn-ghost max-sm:w-full"
              />
            </dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
