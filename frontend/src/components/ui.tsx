import type { ReactNode, CSSProperties } from "react";
import { sevColor, sevLabel } from "../lib/echarts";

export function Panel({
  title,
  subtitle,
  meta,
  children,
  tight,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  meta?: ReactNode;
  children: ReactNode;
  tight?: boolean;
}) {
  return (
    <div className="panel">
      <div className="panel-head">
        <div className="panel-title">
          {title}
          {subtitle && <small>{subtitle}</small>}
        </div>
        {meta && <div className="panel-meta">{meta}</div>}
      </div>
      <div className={"panel-body" + (tight ? " tight" : "")}>{children}</div>
    </div>
  );
}

export function Kpi({
  label,
  value,
  sub,
  stripe,
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  stripe?: string;
}) {
  const style = stripe ? ({ ["--kpi-stripe" as string]: stripe } as CSSProperties) : undefined;
  return (
    <div className="kpi sev" style={style}>
      <div className="kpi-label">{label}</div>
      <div className="kpi-value num">{value}</div>
      {sub && <div className="kpi-sub">{sub}</div>}
    </div>
  );
}

export function SeverityBadge({ value, withLabel = false }: { value: number; withLabel?: boolean }) {
  return (
    <span className="sev-badge" style={{ color: sevColor(value) }} title={`Severity ${value}/10 - ${sevLabel(value)}`}>
      <span className="dot" />
      <span className="num">{value}</span>
      {withLabel && <span style={{ marginLeft: 2 }}>{sevLabel(value)}</span>}
    </span>
  );
}

export function Loading({ label = "Yükleniyor" }: { label?: string }) {
  return (
    <div className="state">
      <div className="spinner" />
      <span>{label}</span>
    </div>
  );
}

export function ErrorState({ msg }: { msg: string }) {
  return (
    <div className="state">
      <span style={{ color: "var(--sev-high)" }}>Veri alınamadı</span>
      <span style={{ fontSize: 12 }}>{msg}</span>
      <span style={{ fontSize: 11.5 }}>Backend çalışıyor mu? (varsayılan :8080)</span>
    </div>
  );
}

export function Empty({ label = "Gösterilecek kayıt yok" }: { label?: string }) {
  return <div className="state">{label}</div>;
}

const ICONS: Record<string, ReactNode> = {
  overview: (
    <>
      <rect x="3" y="3" width="7" height="9" rx="1" />
      <rect x="14" y="3" width="7" height="5" rx="1" />
      <rect x="14" y="12" width="7" height="9" rx="1" />
      <rect x="3" y="16" width="7" height="5" rx="1" />
    </>
  ),
  groups: (
    <>
      <circle cx="12" cy="12" r="8" />
      <circle cx="12" cy="12" r="3" />
      <path d="M12 2v3M12 19v3M2 12h3M19 12h3" />
    </>
  ),
  geo: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18M12 3c2.5 2.5 2.5 15 0 18M12 3c-2.5 2.5-2.5 15 0 18" />
    </>
  ),
  timeline: (
    <>
      <path d="M3 3v18h18" />
      <path d="M7 14l4-5 3 3 5-7" />
    </>
  ),
  ioc: (
    <>
      <circle cx="11" cy="11" r="7" />
      <path d="M21 21l-4.3-4.3" />
    </>
  ),
  records: (
    <>
      <rect x="3" y="4" width="18" height="16" rx="1.5" />
      <path d="M3 9h18M9 9v11" />
    </>
  ),
};

export function Icon({ name }: { name: string }) {
  return (
    <svg className="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
      {ICONS[name]}
    </svg>
  );
}
