import { useCallback, useEffect, useRef, useState } from "react";
import {
  brandingAdmin,
  type BrandingAdminState,
  type BrandingPayload,
  type ResolvedTheme,
} from "../lib/api";
import type { Lang, Translate } from "../lib/i18n";
import { Banner, Card, Field, Spinner, Toggle } from "../ui";
import { describeError } from "./Create";

interface Props {
  t: Translate;
  lang: Lang;
  /** Called after a save, so the shell picks the new brand up immediately. */
  onChanged: () => void;
}

const ASSET_LABELS: Record<string, string> = {
  logo_light: "branding.asset.logoLight",
  logo_dark: "branding.asset.logoDark",
  favicon: "branding.asset.favicon",
  open_graph: "branding.asset.openGraph",
  background: "branding.asset.background",
};

/**
 * The customisation page.
 *
 * Everything on the left edits a draft; the preview on the right renders that
 * draft rather than the saved brand, so an administrator sees the result
 * before committing to it. Saving is what makes it live for everybody.
 */
export default function Branding({ t, lang, onChanged }: Props) {
  const [state, setState] = useState<BrandingAdminState | null>(null);
  const [draft, setDraft] = useState<BrandingPayload | null>(null);
  const [preview, setPreview] = useState<ResolvedTheme | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [testTo, setTestTo] = useState("");

  const load = useCallback(async () => {
    try {
      const res = await brandingAdmin.get();
      setState(res);
      setPreview(res.theme);
      setDraft({
        service_name: res.theme.service_name,
        primary_color: res.theme.primary_color,
        accent_color: res.theme.accent_color,
        background_color: res.theme.background_color ?? "",
        corner_radius: res.theme.corner_radius,
        font: res.theme.font,
        button_style: res.theme.button_style,
        hide_powered_by: res.theme.hide_powered_by,
        support_url: res.theme.support_url,
        legal_url: res.theme.legal_url,
        privacy_url: res.theme.privacy_url,
        contact_email: res.theme.contact_email ?? "",
        texts: res.texts ?? {},
        custom_css: res.custom_css ?? "",
      });
      setError(null);
    } catch (err) {
      setError(describeError(err, t));
    }
  }, [t]);

  useEffect(() => {
    void load();
  }, [load]);

  function update(changes: Partial<BrandingPayload>) {
    setDraft((current) => (current ? { ...current, ...changes } : current));
  }

  function updateText(language: string, key: string, value: string) {
    setDraft((current) => {
      if (!current) return current;
      const texts = { ...current.texts };
      texts[language] = { ...(texts[language] ?? {}), [key]: value };
      return { ...current, texts };
    });
  }

  async function save() {
    if (!draft) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const theme = await brandingAdmin.save(draft);
      setPreview(theme);
      setNotice(t("branding.saved"));
      onChanged();
      await load();
    } catch (err) {
      setError(describeError(err, t));
    } finally {
      setBusy(false);
    }
  }

  async function reset() {
    if (!window.confirm(t("branding.reset.confirm"))) return;
    setBusy(true);
    try {
      await brandingAdmin.reset();
      onChanged();
      await load();
      setNotice(t("branding.reset.done"));
    } catch (err) {
      setError(describeError(err, t));
    } finally {
      setBusy(false);
    }
  }

  async function sendTest() {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const res = await brandingAdmin.testEmail(testTo);
      setNotice(t("branding.email.sent", { to: res.to }));
    } catch (err) {
      setError(describeError(err, t));
    } finally {
      setBusy(false);
    }
  }

  if (!state || !draft) {
    return (
      <Card>
        <Spinner label={t("app.loading")} />
      </Card>
    );
  }

  return (
    <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_320px]">
      <div className="space-y-5">
        <Card className="space-y-4">
          <header className="flex flex-wrap items-start justify-between gap-3">
            <div className="space-y-1">
              <h1 className="text-2xl leading-tight font-bold tracking-tight">
                {t("branding.title")}
              </h1>
              <p className="peek-muted text-sm leading-relaxed">{t("branding.hint")}</p>
            </div>
            <div className="flex gap-2">
              <button
                type="button"
                className="peek-btn peek-btn-primary"
                onClick={save}
                disabled={busy}
              >
                {busy ? <Spinner label={t("app.loading")} /> : t("branding.save")}
              </button>
              {state.saved ? (
                <button
                  type="button"
                  className="peek-btn peek-btn-ghost"
                  onClick={reset}
                  disabled={busy}
                >
                  {t("branding.reset")}
                </button>
              ) : null}
            </div>
          </header>

          {notice ? <Banner tone="success">{notice}</Banner> : null}
          {error ? <Banner tone="danger">{error}</Banner> : null}
          {preview?.warnings?.length ? (
            <Banner tone="warning" title={t("branding.contrast")}>
              <ul className="list-disc space-y-1 pl-4">
                {preview.warnings.map((w) => (
                  <li key={w}>{w}</li>
                ))}
              </ul>
            </Banner>
          ) : null}
        </Card>

        <Card className="space-y-4">
          <h2 className="font-semibold">{t("branding.identity")}</h2>

          <Field label={t("branding.serviceName")} htmlFor="service-name">
            <input
              id="service-name"
              className="peek-input"
              value={draft.service_name}
              onChange={(e) => update({ service_name: e.target.value })}
              maxLength={60}
            />
          </Field>

          <div className="grid gap-4 sm:grid-cols-3">
            <ColorField
              id="primary"
              label={t("branding.primary")}
              value={draft.primary_color}
              onChange={(v) => update({ primary_color: v })}
            />
            <ColorField
              id="accent"
              label={t("branding.accent")}
              value={draft.accent_color}
              onChange={(v) => update({ accent_color: v })}
            />
            <ColorField
              id="background"
              label={t("branding.background")}
              value={draft.background_color}
              onChange={(v) => update({ background_color: v })}
              allowEmpty
            />
          </div>

          <div className="grid gap-4 sm:grid-cols-3">
            <Field label={t("branding.font")} htmlFor="font">
              <select
                id="font"
                className="peek-input peek-select"
                value={draft.font}
                onChange={(e) => update({ font: e.target.value })}
              >
                {state.options.fonts.map((f) => (
                  <option key={f.id} value={f.id}>
                    {f.label}
                  </option>
                ))}
              </select>
            </Field>
            <Field label={t("branding.corners")} htmlFor="radius">
              <select
                id="radius"
                className="peek-input peek-select"
                value={draft.corner_radius}
                onChange={(e) => update({ corner_radius: e.target.value })}
              >
                {state.options.radii.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.label}
                  </option>
                ))}
              </select>
            </Field>
            <Field label={t("branding.buttons")} htmlFor="button-style">
              <select
                id="button-style"
                className="peek-input peek-select"
                value={draft.button_style}
                onChange={(e) => update({ button_style: e.target.value })}
              >
                {state.options.button_styles.map((b) => (
                  <option key={b.id} value={b.id}>
                    {b.label}
                  </option>
                ))}
              </select>
            </Field>
          </div>

          <Toggle
            id="hide-powered-by"
            checked={draft.hide_powered_by}
            onChange={(v) => update({ hide_powered_by: v })}
            label={t("branding.hidePoweredBy")}
          />
        </Card>

        <Card className="space-y-4">
          <h2 className="font-semibold">{t("branding.images")}</h2>
          <p className="peek-muted text-sm leading-relaxed">{t("branding.images.hint")}</p>
          <div className="grid gap-4 sm:grid-cols-2">
            {state.options.asset_kinds.map((kind) => (
              <AssetField
                key={kind}
                kind={kind}
                label={t(ASSET_LABELS[kind] as Parameters<Translate>[0])}
                current={state.assets.find((a) => a.kind === kind)?.url}
                t={t}
                onDone={async (message) => {
                  setNotice(message);
                  onChanged();
                  await load();
                }}
                onError={setError}
              />
            ))}
          </div>
        </Card>

        <Card className="space-y-4">
          <h2 className="font-semibold">{t("branding.texts")}</h2>
          <p className="peek-muted text-sm leading-relaxed">{t("branding.texts.hint")}</p>
          {state.options.languages.map((language) => (
            <details
              key={language}
              open={language === lang}
              className="rounded-xl border p-3"
              style={{ borderColor: "var(--peek-border)" }}
            >
              <summary className="cursor-pointer text-sm font-medium">
                {language.toUpperCase()}
              </summary>
              <div className="mt-3 space-y-3">
                {state.options.text_keys.map((key) => (
                  <Field key={key} label={key} htmlFor={`text-${language}-${key}`}>
                    <input
                      id={`text-${language}-${key}`}
                      className="peek-input"
                      value={draft.texts[language]?.[key] ?? ""}
                      onChange={(e) => updateText(language, key, e.target.value)}
                      maxLength={500}
                    />
                  </Field>
                ))}
              </div>
            </details>
          ))}
        </Card>

        <Card className="space-y-4">
          <h2 className="font-semibold">{t("branding.links")}</h2>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label={t("app.support")} htmlFor="support-url">
              <input
                id="support-url"
                type="url"
                className="peek-input"
                value={draft.support_url}
                onChange={(e) => update({ support_url: e.target.value })}
              />
            </Field>
            <Field label={t("app.legal")} htmlFor="legal-url">
              <input
                id="legal-url"
                type="url"
                className="peek-input"
                value={draft.legal_url}
                onChange={(e) => update({ legal_url: e.target.value })}
              />
            </Field>
            <Field label={t("app.privacy")} htmlFor="privacy-url">
              <input
                id="privacy-url"
                type="url"
                className="peek-input"
                value={draft.privacy_url}
                onChange={(e) => update({ privacy_url: e.target.value })}
              />
            </Field>
            <Field label={t("branding.contact")} htmlFor="contact-email">
              <input
                id="contact-email"
                type="email"
                className="peek-input"
                value={draft.contact_email}
                onChange={(e) => update({ contact_email: e.target.value })}
              />
            </Field>
          </div>
        </Card>

        <Card className="space-y-4">
          <h2 className="font-semibold">{t("branding.css")}</h2>
          <p className="peek-muted text-sm leading-relaxed">{t("branding.css.hint")}</p>
          <Field label={t("branding.css")} htmlFor="custom-css">
            <textarea
              id="custom-css"
              rows={8}
              className="peek-input font-mono text-xs"
              value={draft.custom_css}
              onChange={(e) => update({ custom_css: e.target.value })}
              spellCheck={false}
            />
          </Field>
        </Card>

        <Card className="space-y-4">
          <h2 className="font-semibold">{t("branding.email")}</h2>
          <p className="peek-muted text-sm leading-relaxed">
            {state.mail_configured ? t("branding.email.hint") : t("branding.email.none")}
          </p>
          {state.mail_configured ? (
            <div className="flex flex-wrap items-end gap-3">
              <div className="grow">
                <Field label={t("branding.email.to")} htmlFor="test-to">
                  <input
                    id="test-to"
                    type="email"
                    className="peek-input"
                    value={testTo}
                    onChange={(e) => setTestTo(e.target.value)}
                    placeholder={t("branding.email.placeholder")}
                  />
                </Field>
              </div>
              <button
                type="button"
                className="peek-btn peek-btn-ghost"
                onClick={sendTest}
                disabled={busy}
              >
                {t("branding.email.send")}
              </button>
            </div>
          ) : null}
        </Card>
      </div>

      <Preview draft={draft} state={state} t={t} />
    </div>
  );
}

/** The live preview: the draft rendered as the recipient page would be. */
function Preview({
  draft,
  state,
  t,
}: {
  draft: BrandingPayload;
  state: BrandingAdminState;
  t: Translate;
}) {
  const font = state.options.fonts.find((f) => f.id === draft.font)?.stack;
  const radius = state.options.radii.find((r) => r.id === draft.corner_radius)?.value ?? "10px";
  const primary = draft.primary_color || "#4f46e5";
  const outline = draft.button_style === "outline";
  const logo = state.assets.find((a) => a.kind === "logo_light")?.url;

  return (
    <aside className="lg:sticky lg:top-6 lg:h-fit">
      <Card className="space-y-3">
        <h2 className="font-semibold">{t("branding.preview")}</h2>
        <div
          className="space-y-3 border p-4"
          style={{
            borderColor: "var(--peek-border)",
            borderRadius: radius,
            fontFamily: font,
            background: draft.background_color || "var(--peek-surface)",
          }}
        >
          <div className="flex items-center gap-2">
            {logo ? (
              <img src={logo} alt="" className="h-6 w-auto" />
            ) : (
              <span
                aria-hidden="true"
                className="inline-block size-5"
                style={{ background: primary, borderRadius: radius }}
              />
            )}
            <span className="text-sm font-semibold">{draft.service_name || "Peek"}</span>
          </div>

          <p className="text-sm font-medium">
            {draft.texts["fr"]?.["home.title"] || t("reveal.title")}
          </p>
          <p className="peek-muted text-xs leading-relaxed">{t("reveal.warning")}</p>

          <button
            type="button"
            className="w-full px-3 py-2 text-sm font-semibold"
            style={{
              borderRadius: radius,
              border: `1px solid ${primary}`,
              background: outline ? "transparent" : primary,
              color: outline ? primary : "#ffffff",
            }}
          >
            {t("reveal.button")}
          </button>

          <p className="peek-muted text-[11px]">
            {draft.hide_powered_by ? " " : t("app.poweredBy")}
          </p>
        </div>
        <p className="peek-muted text-xs leading-relaxed">{t("branding.preview.hint")}</p>
      </Card>
    </aside>
  );
}

function ColorField({
  id,
  label,
  value,
  onChange,
  allowEmpty,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  allowEmpty?: boolean;
}) {
  return (
    <Field label={label} htmlFor={id}>
      <div className="flex items-center gap-2">
        <input
          id={id}
          type="color"
          className="h-9 w-10 cursor-pointer rounded-lg border"
          style={{ borderColor: "var(--peek-border)" }}
          value={value || "#ffffff"}
          onChange={(e) => onChange(e.target.value)}
          aria-label={label}
        />
        <input
          className="peek-input font-mono text-xs"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={allowEmpty ? "—" : "#000000"}
          aria-label={`${label} (hex)`}
        />
      </div>
    </Field>
  );
}

function AssetField({
  kind,
  label,
  current,
  t,
  onDone,
  onError,
}: {
  kind: string;
  label: string;
  current?: string;
  t: Translate;
  onDone: (message: string) => void;
  onError: (message: string) => void;
}) {
  const input = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);

  async function upload(file: File) {
    setBusy(true);
    try {
      await brandingAdmin.uploadAsset(kind, file);
      onDone(t("branding.asset.uploaded"));
    } catch (err) {
      onError(describeError(err, t));
    } finally {
      setBusy(false);
      if (input.current) input.current.value = "";
    }
  }

  async function remove() {
    setBusy(true);
    try {
      await brandingAdmin.deleteAsset(kind);
      onDone(t("branding.asset.removed"));
    } catch (err) {
      onError(describeError(err, t));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-2 rounded-xl border p-3" style={{ borderColor: "var(--peek-border)" }}>
      <p className="text-sm font-medium">{label}</p>
      {current ? (
        <img src={current} alt="" className="h-10 w-auto max-w-full object-contain" />
      ) : (
        <p className="peek-muted text-xs">{t("branding.asset.none")}</p>
      )}
      <div className="flex flex-wrap gap-2">
        <label className="peek-btn peek-btn-ghost cursor-pointer px-3 py-1 text-xs">
          {busy ? t("app.loading") : t("branding.asset.choose")}
          <input
            ref={input}
            type="file"
            className="sr-only"
            accept="image/png,image/webp,image/svg+xml,image/x-icon,.ico"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) void upload(file);
            }}
          />
        </label>
        {current ? (
          <button
            type="button"
            className="peek-btn peek-btn-danger px-3 py-1 text-xs"
            onClick={remove}
            disabled={busy}
          >
            {t("app.remove")}
          </button>
        ) : null}
      </div>
    </div>
  );
}
