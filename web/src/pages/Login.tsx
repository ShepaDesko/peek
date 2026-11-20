import { useState } from "react";
import { ApiError, auth } from "../lib/api";
import type { Translate } from "../lib/i18n";
import { navigate } from "../lib/session";
import { createCredentialError, passkeySignIn } from "../lib/passkeyFlow";
import { Banner, Card, Field, Spinner } from "../ui";

interface Props {
  t: Translate;
  onSignedIn: () => Promise<unknown>;
  /** True when the session is already waiting for a second factor. */
  pending?: boolean;
  passkeysEnabled?: boolean;
}

type Step = "password" | "mfa" | "forgot";

export default function Login({ t, onSignedIn, pending, passkeysEnabled }: Props) {
  const [step, setStep] = useState<Step>(pending ? "mfa" : "password");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function submitPassword(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await auth.login(email, password);
      setPassword("");
      if (res.mfa_required) {
        setStep("mfa");
        return;
      }
      await onSignedIn();
      navigate("/dashboard");
    } catch (err) {
      setError(signInError(err, t));
    } finally {
      setBusy(false);
    }
  }

  async function submitCode(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await auth.mfa(code.trim());
      setCode("");
      await onSignedIn();
      navigate("/dashboard");
    } catch (err) {
      setError(signInError(err, t));
    } finally {
      setBusy(false);
    }
  }

  async function submitForgot(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await auth.forgotPassword(email);
      setNotice(res.mail_configured ? t("login.forgot.sent") : t("login.forgot.noMail"));
      setStep("password");
    } catch (err) {
      setError(signInError(err, t));
    } finally {
      setBusy(false);
    }
  }

  async function withPasskey() {
    setBusy(true);
    setError(null);
    try {
      await passkeySignIn();
      await onSignedIn();
      navigate("/dashboard");
    } catch (err) {
      const message = createCredentialError(err, t);
      if (message) setError(message);
    } finally {
      setBusy(false);
    }
  }

  if (step === "mfa") {
    return (
      <form onSubmit={submitCode} className="mx-auto max-w-md">
        <Card className="space-y-4">
          <header className="space-y-1">
            <h1 className="text-xl font-semibold">{t("login.mfa.title")}</h1>
            <p className="peek-muted text-sm leading-relaxed">{t("login.mfa.hint")}</p>
          </header>

          <Field label={t("login.mfa.code")} htmlFor="code">
            <input
              id="code"
              className="peek-input font-mono tracking-widest"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              autoComplete="one-time-code"
              inputMode="text"
              autoFocus
              required
            />
          </Field>

          {error ? <Banner tone="danger">{error}</Banner> : null}

          <button type="submit" className="peek-btn peek-btn-primary w-full" disabled={busy}>
            {busy ? <Spinner label={t("app.loading")} /> : t("login.mfa.submit")}
          </button>
          <p className="peek-muted text-xs">{t("login.mfa.recovery")}</p>
        </Card>
      </form>
    );
  }

  if (step === "forgot") {
    return (
      <form onSubmit={submitForgot} className="mx-auto max-w-md">
        <Card className="space-y-4">
          <header className="space-y-1">
            <h1 className="text-xl font-semibold">{t("login.forgot.title")}</h1>
            <p className="peek-muted text-sm leading-relaxed">{t("login.forgot.hint")}</p>
          </header>

          <Field label={t("login.email")} htmlFor="forgot-email">
            <input
              id="forgot-email"
              type="email"
              className="peek-input"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="email"
              autoFocus
              required
            />
          </Field>

          {error ? <Banner tone="danger">{error}</Banner> : null}

          <div className="flex flex-wrap gap-2">
            <button type="submit" className="peek-btn peek-btn-primary" disabled={busy}>
              {busy ? <Spinner label={t("app.loading")} /> : t("login.forgot.submit")}
            </button>
            <button
              type="button"
              className="peek-btn peek-btn-ghost"
              onClick={() => setStep("password")}
            >
              {t("app.back")}
            </button>
          </div>
        </Card>
      </form>
    );
  }

  return (
    <form onSubmit={submitPassword} className="mx-auto max-w-md">
      <Card className="space-y-4">
        <header className="space-y-1">
          <h1 className="text-xl font-semibold">{t("login.title")}</h1>
          <p className="peek-muted text-sm leading-relaxed">{t("login.subtitle")}</p>
        </header>

        {notice ? <Banner tone="success">{notice}</Banner> : null}

        <Field label={t("login.email")} htmlFor="email">
          <input
            id="email"
            type="email"
            className="peek-input"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoComplete="username"
            autoFocus
            required
          />
        </Field>

        <Field label={t("login.password")} htmlFor="password">
          <input
            id="password"
            type="password"
            className="peek-input"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
          />
        </Field>

        {error ? <Banner tone="danger">{error}</Banner> : null}

        <button type="submit" className="peek-btn peek-btn-primary w-full" disabled={busy}>
          {busy ? <Spinner label={t("app.loading")} /> : t("login.submit")}
        </button>

        {passkeysEnabled ? (
          <button
            type="button"
            className="peek-btn peek-btn-ghost w-full"
            onClick={withPasskey}
            disabled={busy}
          >
            {t("login.passkey")}
          </button>
        ) : null}

        <button
          type="button"
          className="peek-muted w-full text-xs underline"
          onClick={() => setStep("forgot")}
        >
          {t("login.forgot.link")}
        </button>
      </Card>
    </form>
  );
}

/** Turns an API error into something worth reading. */
export function signInError(err: unknown, t: Translate): string {
  if (err instanceof ApiError) {
    switch (err.code) {
      case "invalid_credentials":
        return t("login.error.credentials");
      case "locked":
        return t("login.error.locked");
      case "disabled":
        return t("login.error.disabled");
      case "bad_code":
        return t("login.error.code");
      case "no_session":
        return t("login.error.expired");
      case "csrf":
        return t("login.error.csrf");
      case "rate_limited":
        return t("error.rate");
      default:
        return err.message || t("error.generic");
    }
  }
  return err instanceof Error ? err.message : t("error.generic");
}
