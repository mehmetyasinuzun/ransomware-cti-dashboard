import type { Summary } from "../lib/api";
import { fmtDateTime } from "../lib/format";
import { NAV } from "./Sidebar";

const SUBTITLES: Record<string, string> = {
  overview: "Tehdit ortamının genel görünümü",
  groups: "Ransomware gruplarının aktivite dağılımı",
  geo: "Hedef ülke ve sektör analizi",
  timeline: "Saldırıların zaman içindeki seyri",
  ioc: "IP adresi veya dosya hash'i ile gösterge sorgulama",
  records: "Ham saldırı kayıtları ve filtreleme",
};

const RANGES: { id: string; label: string }[] = [
  { id: "all", label: "Tümü" },
  { id: "365d", label: "1 Yıl" },
  { id: "180d", label: "6 Ay" },
  { id: "30d", label: "30 Gün" },
];

const RANGE_VIEWS = new Set(["overview", "groups", "geo", "timeline"]);

export function Topbar({
  view,
  summary,
  range,
  onRange,
  onRefresh,
  refreshing,
  onMenu,
}: {
  view: string;
  summary: Summary | null;
  range: string;
  onRange: (r: string) => void;
  onRefresh: () => void;
  refreshing: boolean;
  onMenu: () => void;
}) {
  const item = NAV.find((n) => n.id === view);
  const updated = summary?.meta?.generated_at;
  const mode = summary?.meta?.ioc_mode;

  return (
    <div className="topbar">
      <div className="topbar-left">
        <button className="menu-btn" onClick={onMenu} aria-label="Menü">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round">
            <path d="M3 6h18M3 12h18M3 18h18" />
          </svg>
        </button>
        <div className="topbar-title">
          {item?.label ?? "Pano"}
          <small>{SUBTITLES[view]}</small>
        </div>
      </div>
      <div className="topbar-right">
        {RANGE_VIEWS.has(view) && (
          <div className="seg" role="group" aria-label="Zaman aralığı">
            {RANGES.map((r) => (
              <button key={r.id} className={range === r.id ? "on" : ""} onClick={() => onRange(r.id)}>
                {r.label}
              </button>
            ))}
          </div>
        )}
        {mode && (
          <span className="chip hide-sm" title="IOC veri modu">
            IOC: {mode}
          </span>
        )}
        <div className="freshness hide-sm" title="Verinin çekildiği an">
          <span className="pulse" />
          {fmtDateTime(updated)}
        </div>
        <button className="btn ghost refresh-btn" onClick={onRefresh} disabled={refreshing} title="Veriyi kaynaklardan yeniden çek">
          {refreshing ? <span className="spin" /> : <RefreshIcon />}
          <span className="hide-sm">{refreshing ? "Yenileniyor…" : "Yenile"}</span>
        </button>
      </div>
    </div>
  );
}

function RefreshIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 12a9 9 0 1 1-2.64-6.36" />
      <path d="M21 3v6h-6" />
    </svg>
  );
}
