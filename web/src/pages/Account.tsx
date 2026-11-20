import { useCallback, useEffect, useState } from "react";
import QRCode from "qrcode";
import { auth, type Me, type PasskeyInfo, type SessionInfo } from "../lib/api";
import { formatWhen } from "../lib/format";
import type { Lang, Translate } from "../lib/i18n";
import { createCredentialError, passkeyRegister } from "../lib/passkeyFlow";
import { passkeysAvailable } from "../lib/webauthn";
import { Banner, Card, CopyButton, Field, Row, Spinner } from "../ui";
import { describeError } from "./Create";

interface Props {
  t: Translate;
  lang: Lang;
  me: Me;
  refresh: () => Promise<unknown>;
}

/**
 * Everything an account holder controls about their own sign-in: the
 * password, the second factor, the recovery codes, the passkeys and the live
 * sessions.
 */
export default function Account({ t, lang, me, refresh }: Props) {
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  return (
    <div className="space-y-5">
      <Card className="space-y-2">
        <h1 className="text-xl font-semibold">{t("account.title")}</h1>
        <dl className="divide-y" style={{ borderColor: "var(--peek-border)" }}>
          <Row label={t("account.email")}>{me.user?.email}</Row>
          <Row label={t("account.role")}>
            {t(`role.${me.user?.role}` as Parameters<Translate>[0])}
          </Row>
          <Row label={t("account.lastLogin")}>{formatWhen(me.user?.last_login_at, lang)}</Row>
        </dl>
        {notice ? <Banner tone="success">{notice}</Banner> : null}
        {error ? <Banner tone="danger">{error}</Banner> : null}
      </Card>

      <PasswordCard t={t} onDone={(msg) => setNotice(msg)} onError={setError} />
      <TOTPCard t={t} me={me} refresh={refresh} onError={setError} />
      {me.passkeys ? <PasskeysCard t={t} lang={lang} onError={setError} /> : null}
      <SessionsCard t={t} lang={lang} onError={setError} />
    </div>
  );
}

function PasswordCard({
  t,
  onDone,
  onError,
}: {
  t: Translate;
  onDone: (message: string) => void;
  onError: (message: string | null) => void;
}) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    onError(null);
    try {
      await auth.changePassword(current, next);
      setCurrent("");
      setNext("");
      onDone(t("account.password.changed"));
    } catch (err) {
      onError(describeError(err, t));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <form onSubmit={submit} className="space-y-4">
        <h2 className="font-semibold">{t("account.password.title")}</h2>
        <p className="peek-muted text-sm leading-relaxed">{t("account.password.hint")}</p>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label={t("account.password.current")} htmlFor="current">
            <input
              id="current"
              type="password"
              className="peek-input"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
              autoComplete="current-password"
              required
            />
          </Field>
          <Field label={t("account.password.next")} htmlFor="next">
            <input
              id="next"
              type="password"
              className="peek-input"
              value={next}
              onChange={(e) => setNext(e.target.value)}
              autoComplete="new-password"
              minLength={12}
              required
            />
          </Field>
        </div>
        <button type="submit" className="peek-btn peek-btn-primary" disabled={busy}>
          {busy ? <Spinner label={t("app.loading")} /> : t("account.password.submit")}
        </button>
      </form>
    </Card>
  );
}

function TOTPCard({
  t,
  me,
  refresh,
  onError,
}: {
  t: Translate;
  me: Me;
  refresh: () => Promise<unknown>;
  onError: (message: string | null) => void;
}) {
  const [uri, setUri] = useState<string | null>(null);
  const [secret, setSecret] = useState("");
  const [qr, setQr] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!uri) {
      setQr(null);
      return;
    }
    let cancelled = false;
    // Rendered locally: handing the seed to a QR service would defeat the point.
    QRCode.toDataURL(uri, { errorCorrectionLevel: "M", margin: 1, width: 200 })
      .then((url) => !cancelled && setQr(url))
      .catch(() => setQr(null));
    return () => {
      cancelled = true;
    };
  }, [uri]);

  async function start() {
    setBusy(true);
    onError(null);
    try {
      const res = await auth.startTotp();
      setUri(res.uri);
      setSecret(res.secret);
    } catch (err) {
      onError(describeError(err, t));
    } finally {
      setBusy(false);
    }
  }

  async function confirm(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    onError(null);
    try {
      const res = await auth.confirmTotp(code.trim());
      setCodes(res.recovery_codes);
      setUri(null);
      setCode("");
      await refresh();
    } catch (err) {
      onError(describeError(err, t));
    } finally {
      setBusy(false);
    }
  }

  async function disable(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    onError(null);
    try {
      await auth.disableTotp(password);
      setPassword("");
      setCodes(null);
      await refresh();
    } catch (err) {
      onError(describeError(err, t));
    } finally {
      setBusy(false);
    }
  }

  async function regenerate() {
    setBusy(true);
    onError(null);
    try {
      const res = await auth.regenerateRecoveryCodes();
      setCodes(res.recovery_codes);
    } catch (err) {
      onError(describeError(err, t));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card className="space-y-4">
      <div className="space-y-1">
        <h2 className="font-semibold">{t("account.totp.title")}</h2>
        <p className="peek-muted text-sm leading-relaxed">{t("account.totp.hint")}</p>
      </div>

      {codes ? (
        <div className="space-y-3">
          <Banner tone="warning" title={t("account.totp.codes.title")}>
            {t("account.totp.codes.hint")}
          </Banner>
          <ul className="grid grid-cols-2 gap-2 font-mono text-sm sm:grid-cols-3">
            {codes.map((c) => (
              <li
                key={c}
                className="rounded-lg border px-2 py-1"
                style={{ borderColor: "var(--peek-border)" }}
              >
                {c}
              </li>
            ))}
          </ul>
          <div className="flex flex-wrap gap-2">
            <CopyButton
              value={codes.join("\n")}
              label={t("account.totp.codes.copy")}
              copiedLabel={t("receipt.copied")}
            />
            <button
              type="button"
              className="peek-btn peek-btn-ghost"
              onClick={() => setCodes(null)}
            >
              {t("account.totp.codes.done")}
            </button>
          </div>
        </div>
      ) : null}

      {me.has_totp ? (
        <form onSubmit={disable} className="space-y-3">
          <Banner tone="success">{t("account.totp.enabled", { n: me.recovery_left ?? 0 })}</Banner>
          <div className="flex flex-wrap items-end gap-3">
            <div className="grow">
              <Field label={t("account.totp.confirmPassword")} htmlFor="totp-password">
                <input
                  id="totp-password"
                  type="password"
                  className="peek-input"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
                  required
                />
              </Field>
            </div>
            <button type="submit" className="peek-btn peek-btn-danger" disabled={busy}>
              {t("account.totp.disable")}
            </button>
            <button
              type="button"
              className="peek-btn peek-btn-ghost"
              onClick={regenerate}
              disabled={busy}
            >
              {t("account.totp.regenerate")}
            </button>
          </div>
        </form>
      ) : uri ? (
        <form onSubmit={confirm} className="space-y-4">
          <div className="flex flex-wrap items-start gap-5">
            {qr ? (
              <img
                src={qr}
                width={200}
                height={200}
                alt={t("account.totp.qr")}
                className="rounded-lg bg-white p-2"
              />
            ) : (
              <Spinner label={t("app.loading")} />
            )}
            <div className="space-y-2">
              <p className="text-sm">{t("account.totp.scan")}</p>
              <p className="peek-muted text-xs">{t("account.totp.manual")}</p>
              <code
                className="block break-all rounded-lg border px-2 py-1 font-mono text-xs"
                style={{ borderColor: "var(--peek-border)" }}
              >
                {secret}
              </code>
            </div>
          </div>
          <Field label={t("account.totp.code")} htmlFor="totp-code">
            <input
              id="totp-code"
              className="peek-input w-40 font-mono tracking-widest"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              inputMode="numeric"
              autoComplete="one-time-code"
              required
            />
          </Field>
          <div className="flex flex-wrap gap-2">
            <button type="submit" className="peek-btn peek-btn-primary" disabled={busy}>
              {busy ? <Spinner label={t("app.loading")} /> : t("account.totp.confirm")}
            </button>
            <button type="button" className="peek-btn peek-btn-ghost" onClick={() => setUri(null)}>
              {t("app.cancel")}
            </button>
          </div>
        </form>
      ) : (
        <button type="button" className="peek-btn peek-btn-primary" onClick={start} disabled={busy}>
          {busy ? <Spinner label={t("app.loading")} /> : t("account.totp.enable")}
        </button>
      )}
    </Card>
  );
}

function PasskeysCard({
  t,
  lang,
  onError,
}: {
  t: Translate;
  lang: Lang;
  onError: (message: string | null) => void;
}) {
  const [keys, setKeys] = useState<PasskeyInfo[]>([]);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const supported = passkeysAvailable();

  const load = useCallback(async () => {
    try {
      const res = await auth.passkeys();
      setKeys(res.passkeys);
    } catch (err) {
      onError(describeError(err, t));
    }
  }, [onError, t]);

  useEffect(() => {
    void load();
  }, [load]);

  async function add(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    onError(null);
    try {
      await passkeyRegister(name.trim());
      setName("");
      await load();
    } catch (err) {
      const message = createCredentialError(err, t);
      if (message) onError(message);
    } finally {
      setBusy(false);
    }
  }

  async function remove(id: string) {
    if (!window.confirm(t("account.passkeys.removeConfirm"))) return;
    try {
      await auth.deletePasskey(id);
      await load();
    } catch (err) {
      onError(describeError(err, t));
    }
  }

  return (
    <Card className="space-y-4">
      <div className="space-y-1">
        <h2 className="font-semibold">{t("account.passkeys.title")}</h2>
        <p className="peek-muted text-sm leading-relaxed">{t("account.passkeys.hint")}</p>
      </div>

      {keys.length > 0 ? (
        <ul className="space-y-2">
          {keys.map((key) => (
            <li
              key={key.id}
              className="flex flex-wrap items-center justify-between gap-2 rounded-xl border px-3 py-2"
              style={{ borderColor: "var(--peek-border)" }}
            >
              <div>
                <p className="text-sm font-medium">{key.name || t("account.passkeys.unnamed")}</p>
                <p className="peek-muted text-xs">
                  {t("account.passkeys.added", { when: formatWhen(key.created_at, lang) })}
                  {key.last_used_at
                    ? ` · ${t("account.passkeys.used", { when: formatWhen(key.last_used_at, lang) })}`
                    : ""}
                </p>
              </div>
              <button
                type="button"
                className="peek-btn peek-btn-danger px-3 py-1 text-xs"
                onClick={() => remove(key.id)}
              >
                {t("app.remove")}
              </button>
            </li>
          ))}
        </ul>
      ) : null}

      {supported ? (
        <form onSubmit={add} className="flex flex-wrap items-end gap-3">
          <div className="grow">
            <Field label={t("account.passkeys.name")} htmlFor="passkey-name">
              <input
                id="passkey-name"
                className="peek-input"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder={t("account.passkeys.placeholder")}
              />
            </Field>
          </div>
          <button type="submit" className="peek-btn peek-btn-primary" disabled={busy}>
            {busy ? <Spinner label={t("app.loading")} /> : t("account.passkeys.add")}
          </button>
        </form>
      ) : (
        <Banner tone="info">{t("passkey.unsupported")}</Banner>
      )}
    </Card>
  );
}

function SessionsCard({
  t,
  lang,
  onError,
}: {
  t: Translate;
  lang: Lang;
  onError: (message: string | null) => void;
}) {
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const res = await auth.sessions();
      setSessions(res.sessions);
    } catch (err) {
      onError(describeError(err, t));
    }
  }, [onError, t]);

  useEffect(() => {
    void load();
  }, [load]);

  async function revokeOthers() {
    setBusy(true);
    try {
      await auth.revokeOtherSessions();
      await load();
    } catch (err) {
      onError(describeError(err, t));
    } finally {
      setBusy(false);
    }
  }

  async function revoke(id: string) {
    try {
      await auth.revokeSession(id);
      await load();
    } catch (err) {
      onError(describeError(err, t));
    }
  }

  return (
    <Card className="space-y-4">
      <div className="space-y-1">
        <h2 className="font-semibold">{t("account.sessions.title")}</h2>
        <p className="peek-muted text-sm leading-relaxed">{t("account.sessions.hint")}</p>
      </div>

      <ul className="space-y-2">
        {sessions.map((sess) => (
          <li
            key={sess.id}
            className="flex flex-wrap items-center justify-between gap-2 rounded-xl border px-3 py-2"
            style={{ borderColor: "var(--peek-border)" }}
          >
            <div>
              <p className="text-sm font-medium">
                {sess.current ? t("account.sessions.current") : t("account.sessions.other")}
                {sess.ip ? ` · ${sess.ip}` : ""}
              </p>
              <p className="peek-muted text-xs">
                {t("account.sessions.seen", { when: formatWhen(sess.last_seen_at, lang) })}
                {sess.user_agent ? ` · ${shorten(sess.user_agent)}` : ""}
              </p>
            </div>
            {sess.current ? null : (
              <button
                type="button"
                className="peek-btn peek-btn-ghost px-3 py-1 text-xs"
                onClick={() => revoke(sess.id)}
              >
                {t("account.sessions.revoke")}
              </button>
            )}
          </li>
        ))}
      </ul>

      {sessions.length > 1 ? (
        <button
          type="button"
          className="peek-btn peek-btn-danger"
          onClick={revokeOthers}
          disabled={busy}
        >
          {t("account.sessions.revokeOthers")}
        </button>
      ) : null}
    </Card>
  );
}

function shorten(userAgent: string): string {
  return userAgent.length > 48 ? `${userAgent.slice(0, 48)}…` : userAgent;
}
