import { useEffect, useMemo, useState } from "react";
import { ApiError, api, type Branding, type Policy } from "./lib/api";
import { LANGS, browserLang, storeLang, storedLang, translator, type Lang } from "./lib/i18n";
import { isCryptoAvailable, isSecureContext } from "./lib/secure";
import { navigate, replace, useSession } from "./lib/session";
import Account from "./pages/Account";
import Admin from "./pages/Admin";
import Create from "./pages/Create";
import Dashboard from "./pages/Dashboard";
import Login from "./pages/Login";
import { AcceptInvitation, Bootstrap, ResetPassword } from "./pages/Onboarding";
import Receipt from "./pages/Receipt";
import Reveal from "./pages/Reveal";
import { Banner, Card, Spinner } from "./ui";

type Theme = "system" | "light" | "dark";

/**
 * Routing by hand. The routes are few and flat, and a router dependency would
 * cost the recipient page more than it saves here.
 */
type Route =
  | { name: "create" }
  | { name: "reveal"; id: string; fragment: string }
  | { name: "receipt"; id: string; fragment: string }
  | { name: "login" }
  | { name: "bootstrap" }
  | { name: "invitation" }
  | { name: "reset" }
  | { name: "dashboard" }
  | { name: "account" }
  | { name: "admin" };

function parseRoute(): Route {
  const path = window.location.pathname.replace(/\/+$/, "") || "/";
  const fragment = window.location.hash.replace(/^#/, "");

  const reveal = /^\/s\/([A-Za-z0-9_-]{22})$/.exec(path);
  if (reveal) return { name: "reveal", id: reveal[1], fragment };
  const receipt = /^\/r\/([A-Za-z0-9_-]{22})$/.exec(path);
  if (receipt) return { name: "receipt", id: receipt[1], fragment };

  switch (path) {
    case "/login":
      return { name: "login" };
    case "/bootstrap":
      return { name: "bootstrap" };
    case "/invitation":
      return { name: "invitation" };
    case "/reset":
      return { name: "reset" };
    case "/dashboard":
      return { name: "dashboard" };
    case "/account":
      return { name: "account" };
    case "/admin":
      return { name: "admin" };
    default:
      return { name: "create" };
  }
}

export default function App() {
  const [route, setRoute] = useState<Route>(parseRoute);
  const [branding, setBranding] = useState<Branding | null>(null);
  // Bumped after the brand is edited, to refetch it without a page reload.
  const [brandVersion, setBrandVersion] = useState(0);
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [policyError, setPolicyError] = useState<string | null>(null);
  const [lang, setLang] = useState<Lang>(() => storedLang() ?? browserLang() ?? "fr");
  const [theme, setTheme] = useState<Theme>(() => readTheme());
  const session = useSession();

  useEffect(() => {
    const onNavigate = () => setRoute(parseRoute());
    window.addEventListener("popstate", onNavigate);
    window.addEventListener("hashchange", onNavigate);
    return () => {
      window.removeEventListener("popstate", onNavigate);
      window.removeEventListener("hashchange", onNavigate);
    };
  }, []);

  useEffect(() => {
    api
      .branding()
      .then((b) => {
        setBranding(b);
        document.title = b.service_name;
        if (!storedLang() && (b.language === "fr" || b.language === "en")) {
          setLang(b.language);
        }
      })
      .catch(() => setBranding(null));
  }, [lang, brandVersion]);

  // The policy lives on the internal listener only: a 404 is how a public,
  // recipient-only instance tells us not to offer creation here.
  useEffect(() => {
    if (route.name !== "create") return;
    api
      .policy()
      .then((p) => {
        setPolicy(p);
        setPolicyError(null);
      })
      .catch((err) => {
        if (err instanceof ApiError && (err.status === 404 || err.status === 403)) {
          setPolicyError(
            lang === "fr"
              ? "La création de secrets n'est pas disponible depuis ce réseau. Utilisez l'adresse interne du service, ou contactez votre administrateur."
              : "Creating secrets is not available from this network. Use the internal address of the service, or ask your administrator.",
          );
          return;
        }
        setPolicyError(null);
      });
  }, [route.name, lang]);

  useEffect(() => {
    document.documentElement.lang = lang;
  }, [lang]);

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  // A fresh instance sends its administrator to the first-run page rather than
  // to a sign-in form nobody can pass.
  useEffect(() => {
    if (session.loading || !session.me) return;
    if (session.me.needs_bootstrap && route.name === "login") {
      replace("/bootstrap");
    }
    if (!session.me.needs_bootstrap && route.name === "bootstrap") {
      replace("/login");
    }
  }, [session.loading, session.me, route.name]);

  const t = useMemo(() => translator(lang), [lang]);
  const cryptoReady = useMemo(() => isCryptoAvailable() && isSecureContext(), []);
  const serviceName = branding?.service_name ?? "Peek";
  const me = session.me;
  const signedIn = !!me?.authenticated;

  return (
    <div className="flex min-h-screen flex-col">
      <header className="border-b" style={{ borderColor: "var(--peek-border)" }}>
        <div className="mx-auto flex w-full max-w-5xl flex-wrap items-center gap-3 px-4 py-4">
          <a href="/" className="flex items-center gap-2 font-semibold">
            <span
              aria-hidden="true"
              className="inline-block size-6 rounded-md"
              style={{ background: "var(--peek-primary)" }}
            />
            {serviceName}
          </a>

          {signedIn ? (
            <nav
              aria-label={t("app.dashboard")}
              className="flex flex-wrap items-center gap-1 text-sm"
            >
              <NavLink href="/" label={t("app.create")} active={route.name === "create"} />
              <NavLink
                href="/dashboard"
                label={t("app.dashboard")}
                active={route.name === "dashboard"}
              />
              <NavLink href="/account" label={t("app.account")} active={route.name === "account"} />
              {me?.can_manage || me?.can_audit ? (
                <NavLink href="/admin" label={t("app.admin")} active={route.name === "admin"} />
              ) : null}
            </nav>
          ) : (
            <span className="peek-muted hidden flex-1 text-xs sm:block">{t("app.tagline")}</span>
          )}

          <div className="ml-auto flex items-center gap-2">
            <label htmlFor="lang" className="sr-only">
              {t("app.language")}
            </label>
            <select
              id="lang"
              className="peek-input w-auto py-1 text-xs"
              value={lang}
              onChange={(e) => {
                const next = e.target.value as Lang;
                setLang(next);
                storeLang(next);
              }}
            >
              {LANGS.map((code) => (
                <option key={code} value={code}>
                  {code.toUpperCase()}
                </option>
              ))}
            </select>
            <button
              type="button"
              className="peek-btn peek-btn-ghost px-2 py-1 text-xs"
              onClick={() => {
                const next = effectiveTheme() === "dark" ? "light" : "dark";
                setTheme(next);
                writeTheme(next);
              }}
            >
              {effectiveTheme() === "dark" ? t("app.theme.light") : t("app.theme.dark")}
            </button>
            {signedIn ? (
              <button
                type="button"
                className="peek-btn peek-btn-ghost px-2 py-1 text-xs"
                onClick={() => void session.signOut()}
              >
                {t("app.signOut")}
              </button>
            ) : me && !me.needs_bootstrap && route.name !== "login" ? (
              <a href="/login" className="peek-btn peek-btn-ghost px-2 py-1 text-xs">
                {t("app.signIn")}
              </a>
            ) : null}
          </div>
        </div>
      </header>

      <main className="mx-auto w-full max-w-5xl flex-1 px-4 py-8">
        {cryptoReady ? null : (
          <Card className="mb-5">
            <Banner tone="danger" title={t("insecure.title")}>
              <p>{t("insecure.body")}</p>
              <p className="mt-2 text-xs">{t("insecure.admin")}</p>
            </Banner>
          </Card>
        )}

        {session.loading && route.name !== "reveal" ? (
          <Card>
            <Spinner label={t("app.loading")} />
          </Card>
        ) : (
          <Routes
            route={route}
            t={t}
            lang={lang}
            policy={policy}
            policyError={policyError}
            session={{ ...session, onBrandChanged: () => setBrandVersion((v) => v + 1) }}
          />
        )}
      </main>

      <footer className="border-t" style={{ borderColor: "var(--peek-border)" }}>
        <div className="peek-muted mx-auto flex w-full max-w-5xl flex-wrap items-center gap-x-4 gap-y-1 px-4 py-4 text-xs">
          {branding?.support_url ? (
            <a href={branding.support_url} className="underline">
              {t("app.support")}
            </a>
          ) : null}
          {branding?.legal_url ? (
            <a href={branding.legal_url} className="underline">
              {t("app.legal")}
            </a>
          ) : null}
          {branding?.privacy_url ? (
            <a href={branding.privacy_url} className="underline">
              {t("app.privacy")}
            </a>
          ) : null}
          {branding?.hide_powered_by ? null : <span className="ml-auto">{t("app.poweredBy")}</span>}
        </div>
      </footer>
    </div>
  );
}

function Routes({
  route,
  t,
  lang,
  policy,
  policyError,
  session,
}: {
  route: Route;
  t: ReturnType<typeof translator>;
  lang: Lang;
  policy: Policy | null;
  policyError: string | null;
  session: ReturnType<typeof useSession> & { onBrandChanged: () => void };
}) {
  const me = session.me;
  const signedIn = !!me?.authenticated;

  switch (route.name) {
    case "reveal":
      return <Reveal key={route.id} id={route.id} fragment={route.fragment} t={t} lang={lang} />;
    case "receipt":
      return <Receipt key={route.id} id={route.id} fragment={route.fragment} t={t} lang={lang} />;
    case "login":
      return (
        <Login
          t={t}
          onSignedIn={session.refresh}
          pending={me?.mfa_pending}
          passkeysEnabled={me?.passkeys}
        />
      );
    case "bootstrap":
      return <Bootstrap t={t} onSignedIn={session.refresh} />;
    case "invitation":
      return <AcceptInvitation t={t} onSignedIn={session.refresh} />;
    case "reset":
      return <ResetPassword t={t} />;
    case "dashboard":
      return signedIn ? <Dashboard t={t} lang={lang} /> : <SignInFirst t={t} />;
    case "account":
      return signedIn && me ? (
        <Account t={t} lang={lang} me={me} refresh={session.refresh} />
      ) : (
        <SignInFirst t={t} />
      );
    case "admin":
      return signedIn && me && (me.can_manage || me.can_audit) ? (
        <Admin t={t} lang={lang} me={me} onBrandChanged={session.onBrandChanged} />
      ) : (
        <SignInFirst t={t} />
      );
    default:
      return <Create t={t} policy={policy} policyError={policyError} />;
  }
}

function SignInFirst({ t }: { t: ReturnType<typeof translator> }) {
  return (
    <Card className="mx-auto max-w-md space-y-3">
      <h1 className="text-xl font-semibold">{t("login.title")}</h1>
      <p className="peek-muted text-sm leading-relaxed">{t("login.subtitle")}</p>
      <button
        type="button"
        className="peek-btn peek-btn-primary"
        onClick={() => navigate("/login")}
      >
        {t("app.signIn")}
      </button>
    </Card>
  );
}

function NavLink({ href, label, active }: { href: string; label: string; active: boolean }) {
  return (
    <a
      href={href}
      aria-current={active ? "page" : undefined}
      className="rounded-lg px-2.5 py-1.5 font-medium"
      style={
        active
          ? { background: "var(--peek-primary-soft)", color: "var(--peek-primary)" }
          : undefined
      }
      onClick={(event) => {
        if (event.metaKey || event.ctrlKey || event.shiftKey) return;
        event.preventDefault();
        navigate(href);
      }}
    >
      {label}
    </a>
  );
}

const THEME_KEY = "peek.theme";

function readTheme(): Theme {
  try {
    const v = localStorage.getItem(THEME_KEY);
    return v === "light" || v === "dark" ? v : "system";
  } catch {
    return "system";
  }
}

function writeTheme(theme: Theme): void {
  try {
    localStorage.setItem(THEME_KEY, theme);
  } catch {
    // Not remembering the theme is survivable.
  }
}

function applyTheme(theme: Theme): void {
  const root = document.documentElement;
  if (theme === "system") {
    root.removeAttribute("data-theme");
    return;
  }
  root.setAttribute("data-theme", theme);
}

function effectiveTheme(): "light" | "dark" {
  const attr = document.documentElement.getAttribute("data-theme");
  if (attr === "light" || attr === "dark") return attr;
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}
