import { Icon } from "./ui";

export interface NavEntry {
  id: string;
  label: string;
  icon: string;
}

export const NAV: NavEntry[] = [
  { id: "overview", label: "Genel Bakış", icon: "overview" },
  { id: "groups", label: "Tehdit Grupları", icon: "groups" },
  { id: "geo", label: "Coğrafya & Sektör", icon: "geo" },
  { id: "timeline", label: "Zaman Serisi", icon: "timeline" },
  { id: "ioc", label: "IOC Arama", icon: "ioc" },
  { id: "records", label: "Kayıtlar", icon: "records" },
];

export function Sidebar({ active, onChange }: { active: string; onChange: (id: string) => void }) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark">
          <span className="brand-dot" />
          RansomWatch
        </div>
        <div className="brand-sub">CTI / Tehdit İstihbaratı</div>
      </div>
      <nav className="nav">
        <div className="nav-section">Analiz</div>
        {NAV.map((n) => (
          <div
            key={n.id}
            data-view={n.id}
            className={"nav-item" + (active === n.id ? " active" : "")}
            onClick={() => onChange(n.id)}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => e.key === "Enter" && onChange(n.id)}
          >
            <Icon name={n.icon} />
            {n.label}
          </div>
        ))}
      </nav>
      <div className="nav-foot">
        <img
          className="brand-logo"
          src="/yildiz-logo.png"
          alt="Yıldız"
          onError={(e) => {
            e.currentTarget.style.display = "none";
          }}
        />
      </div>
    </aside>
  );
}
