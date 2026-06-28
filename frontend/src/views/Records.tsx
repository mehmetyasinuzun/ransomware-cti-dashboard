import { useEffect, useState } from "react";
import { Panel, Loading, ErrorState, Empty, SeverityBadge } from "../components/ui";
import { useFetch } from "../lib/useFetch";
import { api, type RecordsFilter } from "../lib/api";
import { fmt, fmtDate } from "../lib/format";
import { nameTR } from "../lib/countries";

const PAGE = 25;

const SEV_LABEL: Record<string, string> = { "8": "Kritik (8+)", "6": "Yüksek (6+)", "4": "Orta (4+)" };

export function Records({
  version,
  filter,
  onFilter,
}: {
  version: number;
  filter: RecordsFilter;
  onFilter: (f: RecordsFilter) => void;
}) {
  const groups = useFetch(() => api.groups(200), [version]);
  const sectors = useFetch(() => api.sectors(50), [version]);
  const countries = useFetch(() => api.countries(80), [version]);

  const [inputQ, setInputQ] = useState(filter.q ?? "");
  const [offset, setOffset] = useState(0);

  useEffect(() => {
    setInputQ(filter.q ?? "");
  }, [filter.q]);

  useEffect(() => {
    setOffset(0);
  }, [filter]);

  const params = { ...filter, limit: PAGE, offset } as Record<string, string | number>;
  const res = useFetch(
    () => api.victims(params),
    [filter.group, filter.country, filter.sector, filter.severity_min, filter.q, offset, version]
  );

  function set(field: keyof RecordsFilter, val: string) {
    onFilter({ ...filter, [field]: val || undefined });
  }

  const total = res.data?.total ?? 0;
  const items = res.data?.items ?? [];
  const pageStart = total === 0 ? 0 : offset + 1;
  const pageEnd = offset + items.length;

  const active = (Object.keys(filter) as (keyof RecordsFilter)[]).filter((k) => filter[k]);
  function chipText(k: keyof RecordsFilter): string {
    const v = filter[k] ?? "";
    if (k === "group") return `Grup: ${v}`;
    if (k === "country") return `Ülke: ${nameTR(v)}`;
    if (k === "sector") return `Sektör: ${v}`;
    if (k === "severity_min") return `Severity: ${SEV_LABEL[v] ?? v}`;
    return `Arama: ${v}`;
  }

  return (
    <>
      <Panel title="Filtreler" subtitle="Kayıtları daralt — grafiklerden de tıklayarak gelebilirsiniz">
        <form
          className="filters"
          onSubmit={(e) => {
            e.preventDefault();
            set("q", inputQ);
          }}
        >
          <input
            className="input"
            placeholder="Kurum / alan adı / grup ara…"
            value={inputQ}
            onChange={(e) => setInputQ(e.target.value)}
            style={{ minWidth: 220, flex: 1 }}
          />
          <select className="select" value={filter.group ?? ""} onChange={(e) => set("group", e.target.value)}>
            <option value="">Tüm gruplar</option>
            {(groups.data ?? []).map((g) => (
              <option key={g.ransomware_group} value={g.ransomware_group}>
                {g.ransomware_group} ({g.count})
              </option>
            ))}
          </select>
          <select className="select" value={filter.country ?? ""} onChange={(e) => set("country", e.target.value)}>
            <option value="">Tüm ülkeler</option>
            {(countries.data ?? []).map((c) => (
              <option key={c.country} value={c.country}>
                {nameTR(c.country)} ({c.count})
              </option>
            ))}
          </select>
          <select className="select" value={filter.sector ?? ""} onChange={(e) => set("sector", e.target.value)}>
            <option value="">Tüm sektörler</option>
            {(sectors.data ?? []).map((s) => (
              <option key={s.target_sector} value={s.target_sector}>
                {s.target_sector} ({s.count})
              </option>
            ))}
          </select>
          <select className="select" value={filter.severity_min ?? ""} onChange={(e) => set("severity_min", e.target.value)}>
            <option value="">Tüm severity</option>
            <option value="8">Kritik (8+)</option>
            <option value="6">Yüksek (6+)</option>
            <option value="4">Orta (4+)</option>
          </select>
          <button className="btn" type="submit">
            Ara
          </button>
        </form>

        {active.length > 0 && (
          <div className="active-filters">
            {active.map((k) => (
              <span key={k} className="chip removable" onClick={() => set(k, "")}>
                {chipText(k)}
                <span className="x" aria-label="kaldır">
                  ×
                </span>
              </span>
            ))}
            <button className="btn ghost xs" onClick={() => onFilter({})}>
              Tümünü temizle
            </button>
          </div>
        )}
      </Panel>

      <div style={{ marginTop: 16 }}>
        <Panel
          title="Saldırı Kayıtları"
          subtitle="ransomware.live kaynaklı, işlenmiş"
          meta={total > 0 ? `${fmt(pageStart)}-${fmt(pageEnd)} / ${fmt(total)}` : ""}
        >
          {res.loading ? (
            <Loading />
          ) : res.error ? (
            <ErrorState msg={res.error} />
          ) : items.length === 0 ? (
            <Empty label="Filtreye uyan kayıt yok" />
          ) : (
            <>
              <div className="tbl-wrap">
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>Tarih</th>
                      <th>Kurban</th>
                      <th>Grup</th>
                      <th>Ülke</th>
                      <th>Sektör</th>
                      <th>Saldırı Vektörü</th>
                      <th>Teknik</th>
                      <th>Severity</th>
                      <th>IOC (IP / Hash)</th>
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((v) => (
                      <tr key={v.id}>
                        <td className="num">{fmtDate(v.date)}</td>
                        <td className="hi truncate" title={v.victim}>
                          {v.victim || v.domain || "-"}
                        </td>
                        <td className="mono">{v.ransomware_group}</td>
                        <td>{nameTR(v.country)}</td>
                        <td>{v.target_sector}</td>
                        <td style={{ fontSize: 11.5 }}>{v.attack_vector}</td>
                        <td>{v.technique_id ? <span className="tag-mitre" title={v.technique}>{v.technique_id}</span> : "-"}</td>
                        <td>
                          <SeverityBadge value={v.severity} />
                        </td>
                        <td className="cell-mono">
                          {v.ioc_ip && <div title={v.ioc_ip}>{v.ioc_ip}</div>}
                          {v.ioc_hash && (
                            <div className="truncate" style={{ maxWidth: 160 }} title={v.ioc_hash}>
                              {v.ioc_hash}
                            </div>
                          )}
                          {!v.ioc_ip && !v.ioc_hash && <span style={{ color: "var(--text-lo)" }}>-</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 12 }}>
                <span style={{ fontSize: 12, color: "var(--text-lo)" }}>
                  Sayfa {Math.floor(offset / PAGE) + 1} / {Math.max(1, Math.ceil(total / PAGE))}
                </span>
                <div style={{ display: "flex", gap: 8 }}>
                  <button className="btn ghost" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>
                    Önceki
                  </button>
                  <button className="btn ghost" disabled={pageEnd >= total} onClick={() => setOffset(offset + PAGE)}>
                    Sonraki
                  </button>
                </div>
              </div>
            </>
          )}
        </Panel>
      </div>
    </>
  );
}
