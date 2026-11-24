import type { ReactNode } from "react";
import { useEffect, useState } from "react";
import { copyToClipboard } from "./lib/format";

/** Small, accessible building blocks. No component library, nothing remote. */

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <section className={`peek-card p-5 sm:p-6 ${className}`}>{children}</section>;
}

export function Field({
  label,
  hint,
  htmlFor,
  children,
  error,
}: {
  label: string;
  hint?: string;
  htmlFor?: string;
  children: ReactNode;
  error?: string;
}) {
  const hintId = hint && htmlFor ? `${htmlFor}-hint` : undefined;
  return (
    <div className="space-y-1.5">
      <label htmlFor={htmlFor} className="block text-sm font-semibold">
        {label}
      </label>
      {children}
      {hint ? (
        <p id={hintId} className="peek-muted text-xs leading-relaxed">
          {hint}
        </p>
      ) : null}
      {error ? (
        <p role="alert" className="text-xs font-medium" style={{ color: "var(--peek-danger)" }}>
          {error}
        </p>
      ) : null}
    </div>
  );
}

export type BannerTone = "info" | "warning" | "danger" | "success";

const bannerColor: Record<BannerTone, string> = {
  info: "var(--peek-primary)",
  warning: "var(--peek-warning)",
  danger: "var(--peek-danger)",
  success: "var(--peek-success)",
};

export function Banner({
  tone = "info",
  title,
  children,
  role,
}: {
  tone?: BannerTone;
  title?: string;
  children?: ReactNode;
  role?: "alert" | "status";
}) {
  const color = bannerColor[tone];
  // The text takes the tone's colour, except for `info`: that one is the
  // brand's primary, which can be any colour a customer chose and only has to
  // carry white text on a button, not body text on a surface. The other three
  // are fixed tokens picked for AA against both surfaces, so they are safe.
  // Without this a warning with no title rendered in ordinary body grey and
  // read as a note rather than a warning.
  const toned = tone !== "info";
  return (
    <div
      role={role ?? (tone === "danger" ? "alert" : "status")}
      className="rounded-xl border px-4 py-3 text-sm"
      style={{
        borderColor: `color-mix(in srgb, ${color} 45%, transparent)`,
        background: `color-mix(in srgb, ${color} 10%, transparent)`,
        color: toned ? color : undefined,
      }}
    >
      {title ? (
        <p className="font-semibold" style={{ color }}>
          {title}
        </p>
      ) : null}
      {children ? <div className="mt-0.5 leading-relaxed">{children}</div> : null}
    </div>
  );
}

export function CopyButton({
  value,
  label,
  copiedLabel,
  className = "peek-btn peek-btn-ghost",
}: {
  value: string;
  label: string;
  copiedLabel: string;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!copied) return;
    const timer = window.setTimeout(() => setCopied(false), 2000);
    return () => window.clearTimeout(timer);
  }, [copied]);

  return (
    <button
      type="button"
      className={className}
      onClick={async () => {
        setCopied(await copyToClipboard(value));
      }}
    >
      {copied ? copiedLabel : label}
      <span aria-live="polite" className="sr-only">
        {copied ? copiedLabel : ""}
      </span>
    </button>
  );
}

export function Toggle({
  id,
  checked,
  onChange,
  label,
  hint,
  disabled,
}: {
  id: string;
  checked: boolean;
  onChange: (next: boolean) => void;
  label: string;
  hint?: string;
  disabled?: boolean;
}) {
  return (
    <div className="flex items-start gap-3">
      <input
        id={id}
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
        className="mt-0.5 size-4 shrink-0 accent-[var(--peek-primary)]"
        aria-describedby={hint ? `${id}-hint` : undefined}
      />
      <div className="space-y-0.5">
        <label htmlFor={id} className="block text-sm font-medium">
          {label}
        </label>
        {hint ? (
          <p id={`${id}-hint`} className="peek-muted text-xs leading-relaxed">
            {hint}
          </p>
        ) : null}
      </div>
    </div>
  );
}

export function Spinner({ label }: { label: string }) {
  return (
    <span className="inline-flex items-center gap-2" role="status">
      <span
        aria-hidden="true"
        className="size-4 animate-spin rounded-full border-2 border-current border-t-transparent"
      />
      <span className="text-sm">{label}</span>
    </span>
  );
}

export function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-4 py-2">
      <dt className="peek-muted text-sm">{label}</dt>
      <dd className="text-right text-sm font-medium">{children}</dd>
    </div>
  );
}
