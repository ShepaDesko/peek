import { useCallback, useEffect, useMemo, useState } from "react";
import QRCode from "qrcode";
import { b64urlDecode } from "../crypto";
import { api, type Receipt as ReceiptData } from "../lib/api";
import { formatDateTime, formatWhen } from "../lib/format";
import type { Lang, Translate } from "../lib/i18n";
import { Banner, Card, CopyButton, Row, Spinner } from "../ui";
import { describeError } from "./Create";

interface Props {
  id: string;
  /** Fragment of the receipt URL: v1.<contentKey>~<receiptToken>. */
  fragment: string;
  t: Translate;
  lang: Lang;
}

const STATUS_KEY = {
  active: "receipt.status.active",
  viewed: "receipt.status.viewed",
  expired: "receipt.status.expired",
  burned: "receipt.status.burned",
  deleted: "receipt.status.deleted",
  locked: "receipt.status.locked",
} as const;

export default function Receipt({ id, fragment, t, lang }: Props) {
  const [receipt, setReceipt] = useState<ReceiptData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [qr, setQr] = useState<string | null>(null);
  const [burning, setBurning] = useState(false);
  const [burned, setBurned] = useState(false);

  // Memoised: a fresh object on every render would make refresh a new
  // callback each time, re-arm the effect, and poll the API in a tight loop.
  const parsed = useMemo(() => parseFragment(fragment), [fragment]);
  const shareURL = parsed ? `${window.location.origin}/s/${id}#v1.${parsed.contentKeyB64}` : "";

  const refresh = useCallback(async () => {
    if (!parsed) return;
    try {
      setReceipt(await api.receipt(id, parsed.receiptTokenB64));
      setError(null);
    } catch (err) {
      setError(describeError(err, t));
    }
  }, [id, parsed, t]);

  useEffect(() => {
    void refresh();
    // Light polling: the sender watches this page while the recipient opens
    // the link, and the status is the point of the page.
    const timer = window.setInterval(() => void refresh(), 10000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  useEffect(() => {
    if (!shareURL) return;
    let cancelled = false;
    // Rendered locally into a data URL: no QR service is contacted, which
    // would otherwise hand the key to a third party.
    QRCode.toDataURL(shareURL, { errorCorrectionLevel: "M", margin: 1, width: 220 })
      .then((url) => {
        if (!cancelled) setQr(url);
      })
      .catch(() => setQr(null));
    return () => {
      cancelled = true;
    };
  }, [shareURL]);

  if (!parsed) {
    return (
      <Card>
        <h1 className="text-xl font-semibold">{t("reveal.noKey.title")}</h1>
        <p className="peek-muted mt-2 text-sm leading-relaxed">{t("reveal.noKey.body")}</p>
      </Card>
    );
  }

  async function burn() {
    if (!window.confirm(t("receipt.burn.confirm"))) return;
    setBurning(true);
    try {
      await api.burn(id, parsed!.receiptTokenB64);
      setBurned(true);
      await refresh();
    } catch (err) {
      setError(describeError(err, t));
    } finally {
      setBurning(false);
    }
  }

  const status = receipt?.status ?? "active";
  const gone = status !== "active";

  return (
    <div className="space-y-5">
      <Card className="space-y-4">
        <header className="space-y-1">
          <h1 className="text-xl font-semibold">{t("receipt.title")}</h1>
          <p className="peek-muted text-sm leading-relaxed">{t("receipt.subtitle")}</p>
        </header>

        <div className="space-y-2">
          <p className="text-sm font-semibold">{t("receipt.link")}</p>
          <div className="flex flex-col gap-2 sm:flex-row">
            <input
              readOnly
              value={shareURL}
              onFocus={(e) => e.currentTarget.select()}
              className="peek-input font-mono text-xs"
              aria-label={t("receipt.link")}
            />
            <CopyButton
              value={shareURL}
              label={t("receipt.copy")}
              copiedLabel={t("receipt.copied")}
              className="peek-btn peek-btn-primary shrink-0"
            />
          </div>
          <p className="peek-muted text-xs leading-relaxed">{t("receipt.keepLink")}</p>
        </div>

        {receipt?.has_passphrase ? (
          <Banner tone="warning">{t("receipt.passphraseReminder")}</Banner>
        ) : null}

        {burned ? <Banner tone="success">{t("receipt.burned")}</Banner> : null}
        {error ? <Banner tone="danger">{error}</Banner> : null}
      </Card>

      <div className="grid gap-5 sm:grid-cols-2">
        <Card className="space-y-3">
          <h2 className="text-sm font-semibold">{t("receipt.status")}</h2>
          {receipt ? (
            <>
              <p
                className="peek-chip"
                style={{
                  color: gone ? "var(--peek-muted)" : "var(--peek-success)",
                  borderColor: "var(--peek-border)",
                }}
              >
                {t(STATUS_KEY[status])}
              </p>
              <dl className="divide-y" style={{ borderColor: "var(--peek-border)" }}>
                <Row label={t("receipt.views")}>
                  {receipt.views_used} / {receipt.views_max}
                </Row>
                <Row label={t("receipt.expires")}>{formatWhen(receipt.expires_at, lang)}</Row>
                <Row label={t("receipt.created")}>{formatDateTime(receipt.created_at, lang)}</Row>
              </dl>
              {!gone ? (
                <button
                  type="button"
                  className="peek-btn peek-btn-danger w-full"
                  onClick={burn}
                  disabled={burning}
                >
                  {burning ? <Spinner label={t("app.loading")} /> : t("receipt.burn")}
                </button>
              ) : null}
            </>
          ) : (
            <Spinner label={t("app.loading")} />
          )}
        </Card>

        <Card className="space-y-3">
          <h2 className="text-sm font-semibold">{t("receipt.qr")}</h2>
          {qr ? (
            <img
              src={qr}
              width={220}
              height={220}
              alt={t("receipt.qr")}
              className="mx-auto rounded-lg bg-white p-2"
            />
          ) : (
            <Spinner label={t("app.loading")} />
          )}
        </Card>
      </div>

      <a href="/" className="peek-btn peek-btn-ghost">
        {t("receipt.new")}
      </a>
    </div>
  );
}

/** parseFragment reads v1.<contentKey>~<receiptToken> without throwing. */
function parseFragment(fragment: string): { contentKeyB64: string; receiptTokenB64: string } | null {
  const raw = fragment.replace(/^#/, "");
  if (!raw.startsWith("v1.")) return null;
  const [contentKeyB64, receiptTokenB64] = raw.slice(3).split("~");
  if (!contentKeyB64 || !receiptTokenB64) return null;
  try {
    if (b64urlDecode(contentKeyB64).length !== 32) return null;
    if (b64urlDecode(receiptTokenB64).length !== 32) return null;
  } catch {
    return null;
  }
  return { contentKeyB64, receiptTokenB64 };
}
