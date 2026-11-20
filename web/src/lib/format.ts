import type { Lang } from "./i18n";

/** Relative or absolute time, whichever reads better at that distance. */
export function formatWhen(iso: string | null | undefined, lang: Lang): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "—";

  const diffMs = date.getTime() - Date.now();
  const absMinutes = Math.abs(diffMs) / 60000;
  if (absMinutes < 60 * 24 * 2) {
    const rtf = new Intl.RelativeTimeFormat(lang, { numeric: "auto" });
    if (absMinutes < 1) return rtf.format(Math.round(diffMs / 1000), "second");
    if (absMinutes < 60) return rtf.format(Math.round(diffMs / 60000), "minute");
    return rtf.format(Math.round(diffMs / 3600000), "hour");
  }
  return new Intl.DateTimeFormat(lang, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

export function formatDateTime(iso: string | null | undefined, lang: Lang): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat(lang, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KiB", "MiB", "GiB"];
  let value = n;
  for (const unit of units) {
    value /= 1024;
    if (value < 1024) return `${value.toFixed(1)} ${unit}`;
  }
  return `${value.toFixed(1)} TiB`;
}

/** Copy to the clipboard, with a textarea fallback for older browsers. */
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // Fall through to the legacy path.
  }
  try {
    const area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(area);
    return ok;
  } catch {
    return false;
  }
}
