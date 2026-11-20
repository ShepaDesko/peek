import { useCallback, useEffect, useState } from "react";
import {
  admin,
  type AuditEntry,
  type InvitationInfo,
  type Me,
  type Role,
  type User,
} from "../lib/api";
import { formatWhen } from "../lib/format";
import type { Lang, Translate } from "../lib/i18n";
import { Banner, Card, CopyButton, Field, Spinner } from "../ui";
import { describeError } from "./Create";

interface Props {
  t: Translate;
  lang: Lang;
  me: Me;
}

type Tab = "users" | "audit" | "instance";

const ROLES: Role[] = ["admin", "manager", "member", "auditor"];

export default function Admin({ t, lang, me }: Props) {
  const [tab, setTab] = useState<Tab>(me.can_manage ? "users" : "audit");
  const [error, setError] = useState<string | null>(null);

  const tabs: { id: Tab; label: string; visible: boolean }[] = [
    { id: "users", label: t("admin.tab.users"), visible: !!me.can_manage },
    { id: "audit", label: t("admin.tab.audit"), visible: !!me.can_audit },
    { id: "instance", label: t("admin.tab.instance"), visible: !!me.can_administer },
  ];

  return (
    <div className="space-y-5">
      <Card className="space-y-4">
        <h1 className="text-xl font-semibold">{t("admin.title")}</h1>
        <div role="tablist" className="flex flex-wrap gap-2">
          {tabs
            .filter((item) => item.visible)
            .map((item) => (
              <button
                key={item.id}
                role="tab"
                type="button"
                aria-selected={tab === item.id}
                onClick={() => setTab(item.id)}
                className="peek-btn peek-btn-ghost px-3 py-1.5 text-sm"
                style={
                  tab === item.id
                    ? {
                        background: "var(--peek-primary)",
                        color: "var(--peek-on-primary)",
                        borderColor: "transparent",
                      }
                    : undefined
                }
              >
                {item.label}
              </button>
            ))}
        </div>
        {error ? <Banner tone="danger">{error}</Banner> : null}
      </Card>

      {tab === "users" && me.can_manage ? (
        <UsersTab t={t} lang={lang} me={me} onError={setError} />
      ) : null}
      {tab === "audit" && me.can_audit ? <AuditTab t={t} lang={lang} onError={setError} /> : null}
      {tab === "instance" && me.can_administer ? <InstanceTab t={t} onError={setError} /> : null}
    </div>
  );
}

function UsersTab({
  t,
  lang,
  me,
  onError,
}: {
  t: Translate;
  lang: Lang;
  me: Me;
  onError: (message: string | null) => void;
}) {
  const [users, setUsers] = useState<User[]>([]);
  const [invitations, setInvitations] = useState<InvitationInfo[]>([]);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("member");
  const [busy, setBusy] = useState(false);
  const [inviteLink, setInviteLink] = useState<string | null>(null);
  const [mailNotice, setMailNotice] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [u, i] = await Promise.all([admin.users(), admin.invitations()]);
      setUsers(u.users);
      setInvitations(i.invitations);
    } catch (err) {
      onError(describeError(err, t));
    }
  }, [onError, t]);

  useEffect(() => {
    void load();
  }, [load]);

  async function invite(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    onError(null);
    setInviteLink(null);
    setMailNotice(null);
    try {
      const res = await admin.createUser({ email, role, invite: true });
      setEmail("");
      if (res.link) setInviteLink(res.link);
      setMailNotice(res.mail_sent ? t("admin.invite.sent") : t("admin.invite.noMail"));
      await load();
    } catch (err) {
      onError(describeError(err, t));
    } finally {
      setBusy(false);
    }
  }

  async function update(user: User, changes: Partial<Pick<User, "role" | "status">>) {
    try {
      await admin.updateUser(user.id, {
        display_name: user.display_name,
        role: changes.role ?? user.role,
        status: changes.status ?? user.status,
      });
      await load();
    } catch (err) {
      onError(describeError(err, t));
    }
  }

  async function remove(user: User) {
    if (!window.confirm(t("admin.users.deleteConfirm", { email: user.email }))) return;
    try {
      await admin.deleteUser(user.id);
      await load();
    } catch (err) {
      onError(describeError(err, t));
    }
  }

  async function revokeInvitation(id: string) {
    try {
      await admin.revokeInvitation(id);
      await load();
    } catch (err) {
      onError(describeError(err, t));
    }
  }

  return (
    <div className="space-y-5">
      <Card className="space-y-4">
        <h2 className="font-semibold">{t("admin.invite.title")}</h2>
        <form onSubmit={invite} className="flex flex-wrap items-end gap-3">
          <div className="grow">
            <Field label={t("login.email")} htmlFor="invite-email">
              <input
                id="invite-email"
                type="email"
                className="peek-input"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </Field>
          </div>
          <Field label={t("admin.users.role")} htmlFor="invite-role">
            <select
              id="invite-role"
              className="peek-input w-auto"
              value={role}
              onChange={(e) => setRole(e.target.value as Role)}
            >
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {t(`role.${r}` as Parameters<Translate>[0])}
                </option>
              ))}
            </select>
          </Field>
          <button type="submit" className="peek-btn peek-btn-primary" disabled={busy}>
            {busy ? <Spinner label={t("app.loading")} /> : t("admin.invite.submit")}
          </button>
        </form>

        {mailNotice ? <Banner tone="info">{mailNotice}</Banner> : null}
        {inviteLink ? (
          <div className="space-y-2">
            <p className="text-sm font-medium">{t("admin.invite.link")}</p>
            <div className="flex flex-col gap-2 sm:flex-row">
              <input
                readOnly
                value={inviteLink}
                className="peek-input font-mono text-xs"
                aria-label={t("admin.invite.link")}
              />
              <CopyButton
                value={inviteLink}
                label={t("receipt.copy")}
                copiedLabel={t("receipt.copied")}
              />
            </div>
          </div>
        ) : null}

        {invitations.length > 0 ? (
          <ul className="space-y-2">
            {invitations.map((inv) => (
              <li
                key={inv.id}
                className="flex flex-wrap items-center justify-between gap-2 rounded-xl border px-3 py-2 text-sm"
                style={{ borderColor: "var(--peek-border)" }}
              >
                <span>
                  {inv.email} · {t(`role.${inv.role}` as Parameters<Translate>[0])}
                  <span className="peek-muted ml-2 text-xs">
                    {t("admin.invite.expires", { when: formatWhen(inv.expires_at, lang) })}
                  </span>
                </span>
                <button
                  type="button"
                  className="peek-btn peek-btn-ghost px-3 py-1 text-xs"
                  onClick={() => revokeInvitation(inv.id)}
                >
                  {t("admin.invite.revoke")}
                </button>
              </li>
            ))}
          </ul>
        ) : null}
      </Card>

      <Card className="overflow-x-auto p-0">
        <table className="w-full text-sm">
          <caption className="sr-only">{t("admin.tab.users")}</caption>
          <thead>
            <tr
              className="peek-muted border-b text-left"
              style={{ borderColor: "var(--peek-border)" }}
            >
              <th scope="col" className="px-4 py-3 font-medium">
                {t("login.email")}
              </th>
              <th scope="col" className="px-4 py-3 font-medium">
                {t("admin.users.role")}
              </th>
              <th scope="col" className="px-4 py-3 font-medium">
                {t("admin.users.status")}
              </th>
              <th scope="col" className="px-4 py-3 font-medium">
                {t("account.totp.short")}
              </th>
              <th scope="col" className="px-4 py-3 font-medium">
                {t("account.lastLogin")}
              </th>
              <th scope="col" className="px-4 py-3 font-medium">
                <span className="sr-only">{t("dashboard.col.actions")}</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {users.map((user) => {
              const self = user.id === me.user?.id;
              return (
                <tr
                  key={user.id}
                  className="border-b last:border-0"
                  style={{ borderColor: "var(--peek-border)" }}
                >
                  <td className="px-4 py-3">
                    {user.email}
                    {self ? (
                      <span className="peek-muted ml-2 text-xs">{t("admin.users.you")}</span>
                    ) : null}
                  </td>
                  <td className="px-4 py-3">
                    <select
                      className="peek-input w-auto py-1 text-xs"
                      value={user.role}
                      disabled={self}
                      aria-label={t("admin.users.role")}
                      onChange={(e) => update(user, { role: e.target.value as Role })}
                    >
                      {ROLES.map((r) => (
                        <option key={r} value={r}>
                          {t(`role.${r}` as Parameters<Translate>[0])}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td className="px-4 py-3">
                    <span className="peek-chip">
                      {t(`status.${user.status}` as Parameters<Translate>[0])}
                    </span>
                  </td>
                  <td className="px-4 py-3">{user.has_totp ? t("app.yes") : t("app.no")}</td>
                  <td className="peek-muted px-4 py-3">{formatWhen(user.last_login_at, lang)}</td>
                  <td className="px-4 py-3 text-right">
                    {self ? null : (
                      <div className="flex justify-end gap-2">
                        <button
                          type="button"
                          className="peek-btn peek-btn-ghost px-3 py-1 text-xs"
                          onClick={() =>
                            update(user, {
                              status: user.status === "disabled" ? "active" : "disabled",
                            })
                          }
                        >
                          {user.status === "disabled"
                            ? t("admin.users.enable")
                            : t("admin.users.disable")}
                        </button>
                        <button
                          type="button"
                          className="peek-btn peek-btn-danger px-3 py-1 text-xs"
                          onClick={() => remove(user)}
                        >
                          {t("app.remove")}
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </Card>
    </div>
  );
}

function AuditTab({
  t,
  lang,
  onError,
}: {
  t: Translate;
  lang: Lang;
  onError: (message: string | null) => void;
}) {
  const [events, setEvents] = useState<AuditEntry[]>([]);
  const [event, setEvent] = useState("");
  const [secretID, setSecretID] = useState("");
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params: Record<string, string> = { limit: "200" };
      if (event) params.event = event;
      if (secretID) params.secret_id = secretID;
      const res = await admin.audit(params);
      setEvents(res.events);
    } catch (err) {
      onError(describeError(err, t));
    } finally {
      setLoading(false);
    }
  }, [event, secretID, onError, t]);

  useEffect(() => {
    void load();
  }, [load]);

  const exportHref = (format: string) => {
    const params = new URLSearchParams({ format });
    if (event) params.set("event", event);
    if (secretID) params.set("secret_id", secretID);
    return `/api/v1/audit/export?${params.toString()}`;
  };

  return (
    <Card className="space-y-4">
      <div className="flex flex-wrap items-end gap-3">
        <Field label={t("admin.audit.event")} htmlFor="audit-event">
          <input
            id="audit-event"
            className="peek-input"
            value={event}
            onChange={(e) => setEvent(e.target.value)}
            placeholder="secret.revealed"
          />
        </Field>
        <Field label={t("admin.audit.secret")} htmlFor="audit-secret">
          <input
            id="audit-secret"
            className="peek-input font-mono"
            value={secretID}
            onChange={(e) => setSecretID(e.target.value)}
          />
        </Field>
        <a className="peek-btn peek-btn-ghost" href={exportHref("csv")} download>
          {t("admin.audit.csv")}
        </a>
        <a className="peek-btn peek-btn-ghost" href={exportHref("json")} download>
          {t("admin.audit.json")}
        </a>
      </div>

      {loading ? (
        <Spinner label={t("app.loading")} />
      ) : events.length === 0 ? (
        <p className="peek-muted text-sm">{t("admin.audit.empty")}</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <caption className="sr-only">{t("admin.tab.audit")}</caption>
            <thead>
              <tr
                className="peek-muted border-b text-left"
                style={{ borderColor: "var(--peek-border)" }}
              >
                <th scope="col" className="px-2 py-2 font-medium">
                  {t("admin.audit.when")}
                </th>
                <th scope="col" className="px-2 py-2 font-medium">
                  {t("admin.audit.event")}
                </th>
                <th scope="col" className="px-2 py-2 font-medium">
                  {t("admin.audit.secret")}
                </th>
                <th scope="col" className="px-2 py-2 font-medium">
                  {t("admin.audit.ip")}
                </th>
                <th scope="col" className="px-2 py-2 font-medium">
                  {t("admin.audit.detail")}
                </th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr
                  key={e.id}
                  className="border-b last:border-0"
                  style={{ borderColor: "var(--peek-border)" }}
                >
                  <td className="peek-muted whitespace-nowrap px-2 py-2">
                    {formatWhen(e.at, lang)}
                  </td>
                  <td className="px-2 py-2 font-mono text-xs">{e.event}</td>
                  <td className="px-2 py-2 font-mono text-xs">{e.secret_id ?? "—"}</td>
                  <td className="peek-muted px-2 py-2 text-xs">{e.ip ?? "—"}</td>
                  <td className="peek-muted px-2 py-2 text-xs">
                    {e.detail
                      ? Object.entries(e.detail)
                          .map(([k, v]) => `${k}=${v}`)
                          .join(" ")
                      : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

function InstanceTab({ t, onError }: { t: Translate; onError: (message: string | null) => void }) {
  const [info, setInfo] = useState<Awaited<ReturnType<typeof admin.instance>> | null>(null);

  useEffect(() => {
    admin
      .instance()
      .then(setInfo)
      .catch((err) => onError(describeError(err, t)));
  }, [onError, t]);

  if (!info) {
    return (
      <Card>
        <Spinner label={t("app.loading")} />
      </Card>
    );
  }

  return (
    <Card className="space-y-3">
      <h2 className="font-semibold">{t("admin.tab.instance")}</h2>
      <dl className="divide-y text-sm" style={{ borderColor: "var(--peek-border)" }}>
        <div className="flex justify-between py-2">
          <dt className="peek-muted">{t("admin.instance.version")}</dt>
          <dd className="font-mono">{info.version}</dd>
        </div>
        <div className="flex justify-between py-2">
          <dt className="peek-muted">{t("admin.instance.crypto")}</dt>
          <dd className="font-mono">{info.crypto_version}</dd>
        </div>
        <div className="flex justify-between py-2">
          <dt className="peek-muted">{t("admin.instance.driver")}</dt>
          <dd className="font-mono">{info.driver}</dd>
        </div>
        <div className="flex justify-between py-2">
          <dt className="peek-muted">{t("admin.instance.active")}</dt>
          <dd>{info.active_secrets}</dd>
        </div>
        <div className="flex justify-between py-2">
          <dt className="peek-muted">{t("admin.instance.split")}</dt>
          <dd>{info.public_listener ? t("app.yes") : t("app.no")}</dd>
        </div>
      </dl>
      <p className="peek-muted text-xs leading-relaxed">{t("admin.instance.hint")}</p>
    </Card>
  );
}
