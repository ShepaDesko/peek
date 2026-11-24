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
  icon,
  className = "peek-btn peek-btn-ghost",
}: {
  value: string;
  label: string;
  copiedLabel: string;
  /** Drawn before the label, for the one copy button that is a page's action. */
  icon?: ReactNode;
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
      {icon}
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

/**
 * One line of state, inside a `<dl className="peek-rows">`.
 *
 * The label, the rule and the alignment come from that class, so every table
 * of state in the product reads the same way; `figure` is for the value
 * somebody is actually scanning for — a count of reads, a quota — which the
 * stylesheet then sets larger and in tabular figures.
 */
export function Row({
  label,
  figure,
  mono,
  children,
}: {
  label: string;
  figure?: boolean;
  mono?: boolean;
  children: ReactNode;
}) {
  const classes = [figure ? "peek-figure" : "", mono ? "font-mono" : ""].join(" ").trim();
  return (
    <div>
      <dt>{label}</dt>
      <dd className={classes || undefined}>{children}</dd>
    </div>
  );
}

/* --- the marks ------------------------------------------------------------
 *
 * Four shapes, drawn at the trait rather than pulled from an icon set: a set
 * would be a dependency, a download and a house style that is not ours, for
 * four paths. They are decorative — every one of them sits next to its own
 * label — so they are hidden from the accessibility tree.
 */

/** A padlock being opened: the action on the recipient's panel. */
export function IconUnlock() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <rect
        x="4.5"
        y="10.5"
        width="15"
        height="10"
        rx="2.4"
        stroke="currentColor"
        strokeWidth="1.8"
      />
      <path
        d="M8.2 10.5V7.8a3.8 3.8 0 0 1 7.3-1.3"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
      />
    </svg>
  );
}

/** The same padlock, closed: sealing something — a deposit, a creation. */
export function IconLock() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <rect
        x="4.5"
        y="10.5"
        width="15"
        height="10"
        rx="2.4"
        stroke="currentColor"
        strokeWidth="1.8"
      />
      <path
        d="M8.2 10.5V7.6a3.8 3.8 0 0 1 7.6 0v2.9"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
      />
    </svg>
  );
}

/** A key, for the promise under a form: the key never leaves the browser. */
export function IconKey() {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
      className="mt-0.5 shrink-0"
    >
      <circle cx="8.5" cy="12" r="3.6" stroke="currentColor" strokeWidth="1.7" />
      <path
        d="M12.1 12H20M17 12v3.1M14.6 12v2.2"
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinecap="round"
      />
    </svg>
  );
}

/** Two sheets, the second offset: copying, when that is the page's action. */
export function IconCopy() {
  return (
    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <rect
        x="9"
        y="3.5"
        width="11.5"
        height="14"
        rx="2.2"
        stroke="currentColor"
        strokeWidth="1.8"
      />
      <path
        d="M15 20.5H6a2.5 2.5 0 0 1-2.5-2.5V7"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
      />
    </svg>
  );
}
