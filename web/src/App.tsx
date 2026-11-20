import { useEffect, useMemo, useState } from "react";
import { ApiError, api, type Branding, type Policy } from "./lib/api";
import { LANGS, browserLang, storeLang, storedLang, translator, type Lang } from "./lib/i18n";
import Create from "./pages/Create";
import Receipt from "./pages/Receipt";
import Reveal from "./pages/Reveal";

type Theme = "system" | "light" | "dark";

/**
 * Routing by hand. Three routes do not justify a router dependency, and the
 * recipient bundle stays small — which is a stated budget, not a preference.
 */
type Route =
  | { name: "create" }
  | { name: "reveal"; id: string; fragment: string }
  | { name: "receipt"; id: string; fragment: string };

function parseRoute(): Route {
  const path = window.location.pathname;
  const fragment = window.location.hash.replace(/^#/, "");
  const reveal = /^\/s\/([A-Za-z0-9_-]{22})\/?$/.exec(path);
  if (reveal) return { name: "reveal", id: reveal[1], fragment };
  const receipt = /^\/r\/([A-Za-z0-9_-]{22})\/?$/.exec(path);
  if (receipt) return { name: "receipt", id: receipt[1], fragment };
  return { name: "create" };
}

export default function App() {
  const [route, setRoute] = useState<Route>(parseRoute);
  const [branding, setBranding] = useState<Branding | null>(null);
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [policyError, setPolicyError] = useState<string | null>(null);
  const [lang, setLang] = useState<Lang>(() => storedLang() ?? browserLang() ?? "fr");
  const [theme, setTheme] = useState<Theme>(() => readTheme());

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
        document.documentElement.lang = lang;
        if (!storedLang() && (b.language === "fr" || b.language === "en")) {
          setLang(b.language);
        }
      })
      .catch(() => setBranding(null));
  }, [lang]);

  // The policy lives on the internal listener only: on a public listener it
  // answers 404, which is precisely how the page learns it must not offer
  // creation here.
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

  const t = useMemo(() => translator(lang), [lang]);
  const serviceName = branding?.service_name ?? "Peek";

  return (
    <div className="flex min-h-screen flex-col">
      <header className="border-b" style={{ borderColor: "var(--peek-border)" }}>
        <div className="mx-auto flex w-full max-w-3xl flex-wrap items-center gap-3 px-4 py-4">
          <a href="/" className="flex items-center gap-2 font-semibold">
            <span
              aria-hidden="true"
              className="inline-block size-6 rounded-md"
              style={{ background: "var(--peek-primary)" }}
            />
            {serviceName}
          </a>
          <span className="peek-muted hidden flex-1 text-xs sm:block">{t("app.tagline")}</span>

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
          </div>
        </div>
      </header>

      <main className="mx-auto w-full max-w-3xl flex-1 px-4 py-8">
        {route.name === "create" ? (
          <Create t={t} policy={policy} policyError={policyError} />
        ) : null}
        {route.name === "reveal" ? (
          <Reveal key={route.id} id={route.id} fragment={route.fragment} t={t} lang={lang} />
        ) : null}
        {route.name === "receipt" ? (
          <Receipt key={route.id} id={route.id} fragment={route.fragment} t={t} lang={lang} />
        ) : null}
      </main>

      <footer className="border-t" style={{ borderColor: "var(--peek-border)" }}>
        <div className="peek-muted mx-auto flex w-full max-w-3xl flex-wrap items-center gap-x-4 gap-y-1 px-4 py-4 text-xs">
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
