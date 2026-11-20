import { useEffect, useState } from "react";
import { ApiError, auth, invitationApi, type Role } from "../lib/api";
import type { Translate } from "../lib/i18n";
import { navigate } from "../lib/session";
import { Banner, Card, Field, Spinner } from "../ui";
import { describeError } from "./Create";
import { signInError } from "./Login";

/**
 * The three pages that create or recover an account from a link: the first
 * administrator of a fresh instance, an invitation, and a password reset.
 *
 * All three end in the same place — signed in, or told plainly why not.
 */

interface BaseProps {
  t: Translate;
  onSignedIn: () => Promise<unknown>;
}

export function Bootstrap({ t, onSignedIn }: BaseProps) {
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await auth.bootstrap(email, password, name);
      await onSignedIn();
      navigate("/dashboard");
    } catch (err) {
      setError(describeError(err, t));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="mx-auto max-w-md">
      <Card className="space-y-4">
        <header className="space-y-1">
          <h1 className="text-xl font-semibold">{t("bootstrap.title")}</h1>
          <p className="peek-muted text-sm leading-relaxed">{t("bootstrap.hint")}</p>
        </header>

        <Field label={t("login.email")} htmlFor="bootstrap-email">
          <input
            id="bootstrap-email"
            type="email"
            className="peek-input"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoComplete="username"
            autoFocus
            required
          />
        </Field>
        <Field label={t("bootstrap.name")} htmlFor="bootstrap-name">
          <input
            id="bootstrap-name"
            className="peek-input"
            value={name}
            onChange={(e) => setName(e.target.value)}
            autoComplete="name"
          />
        </Field>
        <Field label={t("login.password")} htmlFor="bootstrap-password" hint={t("password.hint")}>
          <input
            id="bootstrap-password"
            type="password"
            className="peek-input"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="new-password"
            minLength={12}
            required
          />
        </Field>

        {error ? <Banner tone="danger">{error}</Banner> : null}

        <button type="submit" className="peek-btn peek-btn-primary w-full" disabled={busy}>
          {busy ? <Spinner label={t("app.loading")} /> : t("bootstrap.submit")}
        </button>
      </Card>
    </form>
  );
}

export function AcceptInvitation({ t, onSignedIn }: BaseProps) {
  const token = window.location.hash.replace(/^#/, "");
  const [preview, setPreview] = useState<{
    email: string;
    role: Role;
    new_account: boolean;
  } | null>(null);
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!token) {
      setLoading(false);
      setError(t("invitation.missing"));
      return;
    }
    invitationApi
      .preview(token)
      .then(setPreview)
      .catch((err) =>
        setError(err instanceof ApiError ? t("invitation.invalid") : describeError(err, t)),
      )
      .finally(() => setLoading(false));
  }, [token, t]);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await invitationApi.accept(token, password, name);
      await onSignedIn();
      navigate("/dashboard");
    } catch (err) {
      setError(describeError(err, t));
    } finally {
      setBusy(false);
    }
  }

  if (loading) {
    return (
      <Card className="mx-auto max-w-md">
        <Spinner label={t("app.loading")} />
      </Card>
    );
  }

  if (!preview) {
    return (
      <Card className="mx-auto max-w-md space-y-2">
        <h1 className="text-xl font-semibold">{t("invitation.invalidTitle")}</h1>
        <p className="peek-muted text-sm leading-relaxed">{error ?? t("invitation.invalid")}</p>
      </Card>
    );
  }

  return (
    <form onSubmit={submit} className="mx-auto max-w-md">
      <Card className="space-y-4">
        <header className="space-y-1">
          <h1 className="text-xl font-semibold">{t("invitation.title")}</h1>
          <p className="peek-muted text-sm leading-relaxed">
            {t("invitation.hint", {
              email: preview.email,
              role: t(`role.${preview.role}` as Parameters<Translate>[0]),
            })}
          </p>
        </header>

        {preview.new_account ? (
          <Field label={t("bootstrap.name")} htmlFor="invite-name">
            <input
              id="invite-name"
              className="peek-input"
              value={name}
              onChange={(e) => setName(e.target.value)}
              autoComplete="name"
            />
          </Field>
        ) : null}

        <Field label={t("invitation.password")} htmlFor="invite-password" hint={t("password.hint")}>
          <input
            id="invite-password"
            type="password"
            className="peek-input"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="new-password"
            minLength={12}
            autoFocus
            required
          />
        </Field>

        {error ? <Banner tone="danger">{error}</Banner> : null}

        <button type="submit" className="peek-btn peek-btn-primary w-full" disabled={busy}>
          {busy ? <Spinner label={t("app.loading")} /> : t("invitation.submit")}
        </button>
      </Card>
    </form>
  );
}

export function ResetPassword({ t }: { t: Translate }) {
  const token = window.location.hash.replace(/^#/, "");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await auth.resetPassword(token, password);
      setDone(true);
    } catch (err) {
      setError(signInError(err, t));
    } finally {
      setBusy(false);
    }
  }

  if (done) {
    return (
      <Card className="mx-auto max-w-md space-y-3">
        <h1 className="text-xl font-semibold">{t("reset.doneTitle")}</h1>
        <p className="peek-muted text-sm leading-relaxed">{t("reset.doneBody")}</p>
        <button
          type="button"
          className="peek-btn peek-btn-primary"
          onClick={() => navigate("/login")}
        >
          {t("login.title")}
        </button>
      </Card>
    );
  }

  return (
    <form onSubmit={submit} className="mx-auto max-w-md">
      <Card className="space-y-4">
        <header className="space-y-1">
          <h1 className="text-xl font-semibold">{t("reset.title")}</h1>
          <p className="peek-muted text-sm leading-relaxed">{t("reset.hint")}</p>
        </header>

        {token ? null : <Banner tone="danger">{t("reset.missing")}</Banner>}

        <Field label={t("invitation.password")} htmlFor="reset-password" hint={t("password.hint")}>
          <input
            id="reset-password"
            type="password"
            className="peek-input"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="new-password"
            minLength={12}
            autoFocus
            required
          />
        </Field>

        {error ? <Banner tone="danger">{error}</Banner> : null}

        <button
          type="submit"
          className="peek-btn peek-btn-primary w-full"
          disabled={busy || !token}
        >
          {busy ? <Spinner label={t("app.loading")} /> : t("reset.submit")}
        </button>
      </Card>
    </form>
  );
}
