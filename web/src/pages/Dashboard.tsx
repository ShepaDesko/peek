import { useCallback, useEffect, useState } from "react";
import { dashboardApi, type DashboardSecret } from "../lib/api";
import { formatBytes, formatWhen } from "../lib/format";
import type { Lang, Translate } from "../lib/i18n";
import { navigate } from "../lib/session";
import { Banner, Card, Spinner } from "../ui";
import { describeError } from "./Create";

interface Props {
  t: Translate;
  lang: Lang;
}

const STATUS_TONE: Record<string, string> = {
  active: "var(--peek-success)",
  viewed: "var(--peek-muted)",
  expired: "var(--peek-muted)",
  burned: "var(--peek-danger)",
  deleted: "var(--peek-danger)",
  locked: "var(--peek-warning)",
};

/**
 * The sender's own secrets.
 *
 * It shows what the server knows — status, counters, dates — and nothing
 * else: the label is encrypted in the browser, and the server returns it
 * without ever being able to read it. Decrypting it needs the key, which
 * lives in the receipt link, so the list shows an identifier until the sender
 * opens that link.
 */
export default function Dashboard({ t, lang }: Props) {
  const [items, setItems] = useState<DashboardSecret[]>([]);
  const [counts, setCounts] = useState({ live: 0, closed: 0 });
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await dashboardApi.secrets(status ? { status } : {});
      setItems(res.secrets);
      setCounts(res.counts);
      setError(null);
    } catch (err) {
      setError(describeError(err, t));
    } finally {
      setLoading(false);
    }
  }, [status, t]);

  useEffect(() => {
    void load();
  }, [load]);

  async function burn(id: string) {
    if (!window.confirm(t("dashboard.burn.confirm"))) return;
    try {
      await dashboardApi.burn(id);
      await load();
    } catch (err) {
      setError(describeError(err, t));
    }
  }

  return (
    <div className="space-y-5">
      <Card className="space-y-4">
        <header className="flex flex-wrap items-start justify-between gap-3">
          <div className="space-y-1">
            <h1 className="text-2xl leading-tight font-bold tracking-tight">
              {t("dashboard.title")}
            </h1>
            <p className="peek-muted text-sm">
              {t("dashboard.counts", { live: counts.live, closed: counts.closed })}
            </p>
          </div>
          <button type="button" className="peek-btn peek-btn-primary" onClick={() => navigate("/")}>
            {t("dashboard.new")}
          </button>
        </header>

        <div className="flex flex-wrap gap-2">
          {[
            { value: "", label: t("dashboard.filter.all") },
            { value: "active", label: t("receipt.status.active") },
            { value: "viewed", label: t("receipt.status.viewed") },
            { value: "expired", label: t("receipt.status.expired") },
            { value: "burned", label: t("receipt.status.burned") },
          ].map((option) => (
            <button
              key={option.value || "all"}
              type="button"
              aria-pressed={status === option.value}
              onClick={() => setStatus(option.value)}
              className={
                "peek-chip peek-toggle" + (status === option.value ? " peek-toggle-on" : "")
              }
            >
              {option.label}
            </button>
          ))}
        </div>

        {error ? <Banner tone="danger">{error}</Banner> : null}
      </Card>

      {loading ? (
        <Card>
          <Spinner label={t("app.loading")} />
        </Card>
      ) : items.length === 0 ? (
        <Card className="space-y-2">
          <p className="font-medium">{t("dashboard.empty.title")}</p>
          <p className="peek-muted text-sm leading-relaxed">{t("dashboard.empty.body")}</p>
        </Card>
      ) : (
        <Card className="overflow-x-auto p-0">
          <table className="peek-table">
            <caption className="sr-only">{t("dashboard.title")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("dashboard.col.secret")}</th>
                <th scope="col">{t("receipt.status")}</th>
                <th scope="col">{t("receipt.views")}</th>
                <th scope="col">{t("receipt.created")}</th>
                <th scope="col">
                  <span className="sr-only">{t("dashboard.col.actions")}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.id}>
                  <td>
                    <span className="font-mono text-xs">{item.id}</span>
                    <span className="peek-muted ml-2 text-xs">
                      {item.kind} · {formatBytes(item.size_bytes)}
                      {item.has_passphrase ? ` · ${t("dashboard.passphrase")}` : ""}
                    </span>
                  </td>
                  <td style={{ color: STATUS_TONE[item.status] ?? "var(--peek-muted)" }}>
                    {t(`receipt.status.${item.status}` as Parameters<Translate>[0])}
                  </td>
                  <td className="peek-num">
                    {item.views_used} / {item.views_max}
                  </td>
                  <td className="peek-muted whitespace-nowrap">
                    {formatWhen(item.created_at, lang)}
                  </td>
                  <td className="text-right">
                    {item.status === "active" ? (
                      <button
                        type="button"
                        className="peek-btn peek-btn-danger px-3 py-1 text-xs"
                        onClick={() => burn(item.id)}
                      >
                        {t("receipt.burn")}
                      </button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}
