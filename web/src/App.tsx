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
import { AskSecret, Deposit, RequestStatus } from "./pages/Requests";
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
  | { name: "ask" }
  | { name: "deposit"; id: string; fragment: string }
  | { name: "qstatus"; id: string; fragment: string }
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
  // Secret requests: /q is where you answer one, /qs is where the person who
  // asked follows it. "/r" already belongs to a sender's receipt.
  const deposit = /^\/q\/([A-Za-z0-9_-]{22})$/.exec(path);
  if (deposit) return { name: "deposit", id: deposit[1], fragment };
  const qstatus = /^\/qs\/([A-Za-z0-9_-]{22})$/.exec(path);
  if (qstatus) return { name: "qstatus", id: qstatus[1], fragment };

  switch (path) {
    case "/login":
      return { name: "login" };
    case "/bootstrap":
      return { name: "bootstrap" };
    case "/invitation":
      return { name: "invitation" };
    case "/reset":
      return { name: "reset" };
    case "/ask":
      return { name: "ask" };
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
  // What is actually painted, which is not the same thing as `theme`: that one
  // may say "system", and even an explicit choice only reaches the document in
  // the effect below. Reading the DOM during render gave the toggle the value
  // from before the click, so its label was always one click behind.
  const [painted, setPainted] = useState<"light" | "dark">("dark");
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
  //
  // Three pages need it: creating a secret, asking for one, and answering a
  // request — the deposit page uses the instance's KDF parameters and expiry
  // ceiling. On the public listener it 404s there too, and the page falls back
  // to the format defaults rather than refusing to work.
  const needsPolicy = route.name === "create" || route.name === "ask" || route.name === "deposit";
  useEffect(() => {
    if (!needsPolicy) return;
    api
      .policy()
      .then((p) => {
        setPolicy(p);
        setPolicyError(null);
      })
      .catch((err) => {
        if (
          route.name === "create" &&
          err instanceof ApiError &&
          (err.status === 404 || err.status === 403)
        ) {
          setPolicyError(
            lang === "fr"
              ? "La création de secrets n'est pas disponible depuis ce réseau. Utilisez l'adresse interne du service, ou contactez votre administrateur."
              : "Creating secrets is not available from this network. Use the internal address of the service, or ask your administrator.",
          );
          return;
        }
        setPolicyError(null);
      });
  }, [needsPolicy, route.name, lang]);

  useEffect(() => {
    document.documentElement.lang = lang;
  }, [lang]);

  useEffect(() => {
    applyTheme(theme);
    setPainted(effectiveTheme());
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
  // The two pages a stranger lands on get a page of their own rather than the
  // application's chrome: no navigation to somewhere they cannot go, the
  // customer's identity above the panel at a size worth uploading a logo for,
  // and the panel itself centred in the viewport instead of pinned under a
  // bar. Everything else keeps the dense, signed-in shell.
  const focused = route.name === "reveal" || route.name === "deposit";
  const logo = painted === "dark" ? brandLogo(branding, "dark") : brandLogo(branding, "light");

  return (
    <div className="flex min-h-screen flex-col">
      {/* WCAG 2.4.1: the header carries a navigation bar, so there has to be
          a way past it. Visible on focus only, which is the convention a
          keyboard user expects. */}
      <a href="#content" className="peek-skip">
        {t("app.skip")}
      </a>
      <header
        className={focused ? "" : "border-b"}
        style={focused ? undefined : { borderColor: "var(--peek-border)" }}
      >
        <div
          className={
            focused
              ? "mx-auto flex w-full max-w-5xl items-center justify-end gap-2 px-4 py-4"
              : "mx-auto flex w-full max-w-5xl flex-wrap items-center gap-3 px-4 py-4"
          }
        >
          {focused ? null : (
            <a href="/" className="flex items-center gap-2 font-semibold">
              <span
                aria-hidden="true"
                className="inline-block size-6 rounded-md"
                style={{ background: "var(--peek-primary)" }}
              />
              {serviceName}
            </a>
          )}

          {focused ? null : signedIn ? (
            <nav
              aria-label={t("app.dashboard")}
              className="flex flex-wrap items-center gap-1 text-sm"
            >
              <NavLink href="/" label={t("app.create")} active={route.name === "create"} />
              <NavLink href="/ask" label={t("nav.ask")} active={route.name === "ask"} />
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
              className="peek-input peek-select w-auto py-1 text-xs"
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
                const next = painted === "dark" ? "light" : "dark";
                setTheme(next);
                writeTheme(next);
              }}
            >
              {painted === "dark" ? t("app.theme.light") : t("app.theme.dark")}
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

      <main
        id="content"
        className={
          focused
            ? "relative mx-auto flex w-full max-w-lg flex-1 flex-col items-center justify-center gap-6 px-4 py-10"
            : "mx-auto w-full max-w-5xl flex-1 px-4 py-8"
        }
      >
        {focused ? (
          <>
            <div aria-hidden="true" className="peek-glow" />
            {logo ? (
              <img
                src={logo}
                alt={serviceName}
                className="relative max-h-10 w-auto max-w-[260px]"
              />
            ) : (
              <div className="relative flex items-center gap-3">
                <span
                  aria-hidden="true"
                  className="inline-block h-8 w-[5px] rounded-full"
                  style={{ background: "var(--peek-primary)" }}
                />
                <span className="text-lg font-bold tracking-tight">{serviceName}</span>
              </div>
            )}
          </>
        ) : null}

        {cryptoReady ? null : (
          <Card className="mb-5">
            <Banner tone="danger" title={t("insecure.title")}>
              <p>{t("insecure.body")}</p>
              <p className="mt-2 text-xs">{t("insecure.admin")}</p>
            </Banner>
          </Card>
        )}

        <div className={focused ? "relative w-full" : "contents"}>
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
        </div>
      </main>

      <footer
        className={focused ? "" : "border-t"}
        style={focused ? undefined : { borderColor: "var(--peek-border)" }}
      >
        <div
          className={
            focused
              ? "peek-muted mx-auto flex w-full max-w-5xl flex-wrap items-center justify-center gap-x-4 gap-y-1 px-4 pb-6 text-xs"
              : "peek-muted mx-auto flex w-full max-w-5xl flex-wrap items-center gap-x-4 gap-y-1 px-4 py-4 text-xs"
          }
        >
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
          {branding?.hide_powered_by ? null : (
            <span className={focused ? "" : "ml-auto"}>{t("app.poweredBy")}</span>
          )}
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
    case "ask":
      return <AskSecret t={t} policy={policy} />;
    case "deposit":
      return (
        <Deposit key={route.id} id={route.id} fragment={route.fragment} t={t} policy={policy} />
      );
    case "qstatus":
      return (
        <RequestStatus key={route.id} id={route.id} fragment={route.fragment} t={t} lang={lang} />
      );
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
      <h1 className="text-2xl leading-tight font-bold tracking-tight">{t("login.title")}</h1>
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
      className={
        "peek-toggle rounded-lg px-2.5 py-1.5 font-medium" + (active ? " peek-toggle-soft" : "")
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

/** brandLogo picks the uploaded logo for the theme being painted, if any. */
function brandLogo(branding: Branding | null, scheme: "light" | "dark"): string | undefined {
  const assets = branding?.assets;
  if (!assets) return undefined;
  // A dark page wants the light-on-dark logo. When a brand uploaded only one,
  // that one is used rather than nothing: a slightly wrong logo beats the
  // service name in text where a logo was provided.
  return scheme === "dark"
    ? (assets.logo_dark ?? assets.logo_light)
    : (assets.logo_light ?? assets.logo_dark);
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
  // No explicit choice: ask the stylesheet rather than re-deciding here. The
  // answer can come from three places — the base, the instance default the
  // server writes into /branding.css, or that default following the system —
  // and the toggle has to agree with whichever one won, or its label lies.
  const scheme = getComputedStyle(document.documentElement)
    .getPropertyValue("--peek-scheme")
    .trim();
  if (scheme === "light" || scheme === "dark") return scheme;
  return "dark";
}
