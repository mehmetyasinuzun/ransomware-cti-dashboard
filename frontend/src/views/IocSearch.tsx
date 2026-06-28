import { useState } from "react";
import type { ReactNode } from "react";
import { Panel, Loading, Empty, ErrorState, SeverityBadge } from "../components/ui";
import { useFetch } from "../lib/useFetch";
import { api, type IOCResult } from "../lib/api";
import { fmt, fmt1, fmtDate } from "../lib/format";
import { nameTR } from "../lib/countries";

export function IocSearch() {
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<IOCResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function search(q: string) {
    const term = q.trim();
    if (!term) return;
    setLoading(true);
    setError(null);
    window.scrollTo({ top: 0, behavior: "smooth" });
    try {
      setResult(await api.ioc(term));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setResult(null);
    } finally {
      setLoading(false);
    }
  }

  function pick(v: string) {
    setQuery(v);
    search(v);
  }

  return (
    <>
      <Panel title="IOC Sorgulama" subtitle="Bir IP adresi veya dosya hash'i (MD5 / SHA-256) girin">
        <form
          className="filters"
          style={{ marginBottom: 0 }}
          onSubmit={(e) => {
            e.preventDefault();
            search(query);
          }}
        >
          <input
            className="input mono"
            style={{ flex: 1, minWidth: 280 }}
            placeholder="örn. 185.220.101.4  veya  e3b0c44298fc1c149afbf4c8996fb924..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            spellCheck={false}
          />
          <button className="btn" type="submit">
            Sorgula
          </button>
        </form>
      </Panel>

      {loading && (
        <div style={{ marginTop: 16 }}>
          <Panel title="Sonuç" subtitle="Sorgulanıyor">
            <Loading label="Gösterge sorgulanıyor" />
          </Panel>
        </div>
      )}
      {error && (
        <div style={{ marginTop: 16 }}>
          <Panel title="Hata" subtitle="">
            <div className="state" style={{ color: "var(--sev-high)" }}>
              {error}
            </div>
          </Panel>
        </div>
      )}
      {!loading && result && <Results r={result} />}

      <Catalog onPick={pick} />
    </>
  );
}

function Catalog({ onPick }: { onPick: (v: string) => void }) {
  const PAGE = 50;
  const groups = useFetch(() => api.iocGroups(), []);
  const [type, setType] = useState("");
  const [group, setGroup] = useState("");
  const [offset, setOffset] = useState(0);

  const res = useFetch(() => api.iocList({ type, group, limit: PAGE, offset }), [type, group, offset]);
  const total = res.data?.total ?? 0;
  const items = res.data?.items ?? [];

  function setFilter(setter: (v: string) => void, v: string) {
    setter(v);
    setOffset(0);
  }

  return (
    <div style={{ marginTop: 18 }}>
      <div className="section-title">Tüm Göstergeler</div>
      <Panel
        title="IOC Kataloğu"
        subtitle="abuse.ch ThreatFox kaynaklı gerçek göstergeler · en yeni önce · bir değere tıklayarak ilişkili kayıtları sorgula"
        meta={total > 0 ? `${fmt(offset + 1)}-${fmt(offset + items.length)} / ${fmt(total)}` : ""}
      >
        <div className="filters">
          <select className="select" value={type} onChange={(e) => setFilter(setType, e.target.value)}>
            <option value="">Tüm tipler</option>
            <option value="ip">IP adresi</option>
            <option value="hash">Dosya hash'i</option>
          </select>
          <select className="select" value={group} onChange={(e) => setFilter(setGroup, e.target.value)}>
            <option value="">Tüm gruplar</option>
            {(groups.data ?? []).map((g) => (
              <option key={g.ransomware_group} value={g.ransomware_group}>
                {g.ransomware_group} ({g.count})
              </option>
            ))}
          </select>
        </div>

        {res.loading ? (
          <Loading />
        ) : res.error ? (
          <ErrorState msg={res.error} />
        ) : items.length === 0 ? (
          <Empty label="Filtreye uyan gösterge yok" />
        ) : (
          <>
            <div className="tbl-wrap">
              <table className="tbl">
                <thead>
                  <tr>
                    <th>Değer</th>
                    <th>Tip</th>
                    <th>Grup</th>
                    <th>Aile</th>
                    <th>Güven</th>
                    <th>İlk Görülme</th>
                    <th>Kaynak</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((m, i) => (
                    <tr key={m.value + m.type + i}>
                      <td>
                        <span
                          className="ioc-link cell-mono"
                          role="button"
                          tabIndex={0}
                          onClick={() => onPick(m.value)}
                          onKeyDown={(e) => e.key === "Enter" && onPick(m.value)}
                          title="Bu göstergeyi sorgula"
                        >
                          {m.value}
                        </span>
                      </td>
                      <td>{m.type === "ip" ? "IP" : "hash"}</td>
                      <td className="mono hi">{m.ransomware_group}</td>
                      <td>{m.malware_family || "-"}</td>
                      <td className="num">{m.confidence || "-"}</td>
                      <td className="num">{fmtDate(m.first_seen)}</td>
                      <td style={{ fontSize: 11.5 }}>{m.source}</td>
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
                <button className="btn ghost" disabled={offset + items.length >= total} onClick={() => setOffset(offset + PAGE)}>
                  Sonraki
                </button>
              </div>
            </div>
          </>
        )}
      </Panel>
    </div>
  );
}

function Results({ r }: { r: IOCResult }) {
  const found = r.matches.length > 0 || r.groups.length > 0;
  if (!found) {
    return (
      <div style={{ marginTop: 16 }}>
        <Panel title="Sonuç bulunamadı" subtitle={`"${r.query}" için eşleşme yok`}>
          <div className="state">
            Bu gösterge veri setindeki hiçbir ransomware grubuyla ilişkilendirilemedi.
            <span style={{ fontSize: 11.5 }}>Tam IP veya hash değerini girdiğinizden emin olun.</span>
          </div>
        </Panel>
      </div>
    );
  }

  return (
    <div style={{ marginTop: 16 }}>
      <div className="kpi-grid">
        <Kpi label="Eşleşen Gösterge" value={fmt(r.matches.length)} />
        <Kpi label="İlişkili Grup" value={r.groups.length ? r.groups.join(", ") : "-"} mono />
        <Kpi label="İlişkili Kayıt" value={fmt(r.severity.count)} />
        <Kpi label="Severity (ort / maks)" value={`${fmt1(r.severity.avg)} / ${r.severity.max}`} />
      </div>

      {r.matches.length > 0 && (
        <Panel title="Eşleşen Göstergeler" subtitle="abuse.ch / veri seti kaynaklı" meta={`${fmt(r.matches.length)} kayıt`}>
          <div className="tbl-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>Değer</th>
                  <th>Tip</th>
                  <th>Grup</th>
                  <th>Aile</th>
                  <th>Güven</th>
                  <th>Kaynak</th>
                </tr>
              </thead>
              <tbody>
                {r.matches.map((m, i) => (
                  <tr key={i}>
                    <td className="cell-mono hi">{m.value}</td>
                    <td>{m.type === "ip" ? "IP" : "hash"}</td>
                    <td className="mono hi">{m.ransomware_group}</td>
                    <td>{m.malware_family || "-"}</td>
                    <td className="num">{m.confidence || "-"}</td>
                    <td style={{ fontSize: 11.5 }}>{m.source}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      <div className="section-title">İlişkili Saldırı Kayıtları</div>
      <Panel title="Kurban Kayıtları" subtitle={`Grup: ${r.groups.join(", ")}`} meta={`${fmt(r.victims.length)} kayıt gösteriliyor`}>
        <div className="tbl-wrap" style={{ maxHeight: 440, overflowY: "auto" }}>
          <table className="tbl">
            <thead>
              <tr>
                <th>Tarih</th>
                <th>Kurban</th>
                <th>Grup</th>
                <th>Ülke</th>
                <th>Sektör</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody>
              {r.victims.map((v) => (
                <tr key={v.id}>
                  <td className="num">{fmtDate(v.date)}</td>
                  <td className="hi truncate" title={v.victim}>
                    {v.victim || v.domain || "-"}
                  </td>
                  <td className="mono">{v.ransomware_group}</td>
                  <td>{nameTR(v.country)}</td>
                  <td>{v.target_sector}</td>
                  <td>
                    <SeverityBadge value={v.severity} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}

function Kpi({ label, value, mono }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <div className="kpi sev">
      <div className="kpi-label">{label}</div>
      <div className={"kpi-value" + (mono ? " mono" : " num")} style={mono ? { fontSize: 18 } : undefined}>
        {value}
      </div>
    </div>
  );
}
