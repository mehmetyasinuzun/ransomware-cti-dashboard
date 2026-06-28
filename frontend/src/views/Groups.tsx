import { useMemo } from "react";
import { Chart } from "../components/Chart";
import { Panel, Loading, ErrorState, Empty, SeverityBadge } from "../components/ui";
import { useFetch } from "../lib/useFetch";
import { api, type RecordsFilter } from "../lib/api";
import { T, axisCommon, tooltipStyle, SERIES, clickName } from "../lib/echarts";
import { fmt, fmt1 } from "../lib/format";

export function Groups({ range, version, onDrill }: { range: string; version: number; onDrill: (f: RecordsFilter) => void }) {
  const groups = useFetch(() => api.groups(200, range), [range, version]);
  const vectors = useFetch(() => api.vectors(range), [range, version]);
  const techniques = useFetch(() => api.techniques(12, range), [range, version]);
  const groupEvents = useMemo(() => clickName((n) => onDrill({ group: n })), [onDrill]);

  const total = useMemo(() => (groups.data ?? []).reduce((a, g) => a + g.count, 0), [groups.data]);

  const barOption = useMemo(() => {
    const d = [...(groups.data ?? []).slice(0, 15)].reverse();
    return {
      tooltip: { trigger: "axis", axisPointer: { type: "shadow" }, ...tooltipStyle },
      grid: { left: 8, right: 30, top: 6, bottom: 24, containLabel: true },
      xAxis: { type: "value", ...axisCommon },
      yAxis: {
        type: "category",
        data: d.map((g) => g.ransomware_group),
        axisLine: { lineStyle: { color: T.border } },
        axisTick: { show: false },
        axisLabel: { color: T.textMid, fontFamily: T.fontMono, fontSize: 11.5 },
      },
      series: [
        {
          type: "bar",
          barWidth: "62%",
          data: d.map((g) => g.count),
          itemStyle: { color: T.accent, borderRadius: [0, 3, 3, 0] },
          label: { show: true, position: "right", color: T.textLo, fontSize: 11 },
        },
      ],
    };
  }, [groups.data]);

  const vectorOption = useMemo(() => {
    const d = vectors.data ?? [];
    return {
      tooltip: { trigger: "item", ...tooltipStyle },
      legend: { type: "scroll", orient: "vertical", right: 4, top: "center", textStyle: { color: T.textMid, fontSize: 11 }, pageTextStyle: { color: T.textLo } },
      series: [
        {
          type: "pie",
          radius: ["42%", "68%"],
          center: ["34%", "50%"],
          avoidLabelOverlap: true,
          itemStyle: { borderColor: T.surface1, borderWidth: 2 },
          label: { show: false },
          data: d.map((v, i) => ({ name: v.attack_vector, value: v.count, itemStyle: { color: SERIES[i % SERIES.length] } })),
        },
      ],
    };
  }, [vectors.data]);

  const techOption = useMemo(() => {
    const d = [...(techniques.data ?? [])].reverse();
    return {
      tooltip: {
        trigger: "axis",
        axisPointer: { type: "shadow" },
        ...tooltipStyle,
        formatter: (p: { dataIndex: number }[]) => {
          const i = d[p[0].dataIndex];
          return `<b>${i.technique_id}</b> ${i.technique}<br/>${fmt(i.count)} kayıt`;
        },
      },
      grid: { left: 8, right: 30, top: 6, bottom: 24, containLabel: true },
      xAxis: { type: "value", ...axisCommon },
      yAxis: {
        type: "category",
        data: d.map((t) => t.technique_id),
        axisLine: { lineStyle: { color: T.border } },
        axisTick: { show: false },
        axisLabel: { color: T.accent, fontFamily: T.fontMono, fontSize: 11 },
      },
      series: [
        {
          type: "bar",
          barWidth: "60%",
          data: d.map((t) => t.count),
          itemStyle: { color: "#009e73", borderRadius: [0, 3, 3, 0] },
        },
      ],
    };
  }, [techniques.data]);

  if (groups.error) return <ErrorState msg={groups.error} />;

  return (
    <>
      <div className="grid">
        <div className="col-6">
          <Panel title="Grup Dağılımı" subtitle="Bir gruba tıklayarak kayıtlarını gör" tight>
            {groups.loading ? <Loading /> : <Chart option={barOption} height={360} onEvents={groupEvents} />}
          </Panel>
        </div>
        <div className="col-6">
          <Panel title="Saldırı Vektörleri" subtitle="Initial Access (MITRE TA0001) dağılımı" tight>
            {vectors.loading ? <Loading /> : <Chart option={vectorOption} height={360} />}
          </Panel>
        </div>
        <div className="col-12">
          <Panel title="En Sık Kullanılan Teknikler" subtitle="MITRE ATT&CK teknik kodlarına göre" tight>
            {techniques.loading ? <Loading /> : <Chart option={techOption} height={300} />}
          </Panel>
        </div>
      </div>

      <div className="section-title">Tüm Gruplar ({fmt((groups.data ?? []).length)})</div>
      <Panel title="Grup Listesi" subtitle="Aktiviteye göre sıralanmış" meta={`Toplam ${fmt(total)} saldırı`}>
        {groups.loading ? (
          <Loading />
        ) : (groups.data ?? []).length === 0 ? (
          <Empty />
        ) : (
          <div className="tbl-wrap" style={{ maxHeight: 460, overflowY: "auto" }}>
            <table className="tbl">
              <thead>
                <tr>
                  <th style={{ width: 40 }}>#</th>
                  <th>Grup</th>
                  <th>Saldırı</th>
                  <th>Pay</th>
                  <th>Ort. Severity</th>
                </tr>
              </thead>
              <tbody>
                {(groups.data ?? []).map((g, i) => (
                  <tr key={g.ransomware_group} className="row-link" onClick={() => onDrill({ group: g.ransomware_group })} title="Bu grubun kayıtlarına git">
                    <td className="num">{i + 1}</td>
                    <td className="hi mono">{g.ransomware_group}</td>
                    <td className="num">{fmt(g.count)}</td>
                    <td className="num">{total ? ((g.count / total) * 100).toFixed(1) : "0"}%</td>
                    <td>
                      <SeverityBadge value={Math.round(g.avg_severity)} withLabel />
                      <span className="num" style={{ marginLeft: 8, color: "var(--text-lo)" }}>
                        {fmt1(g.avg_severity)}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </>
  );
}
