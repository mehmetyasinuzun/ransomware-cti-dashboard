import { useMemo } from "react";
import { Chart } from "../components/Chart";
import { Kpi, Panel, Loading, ErrorState } from "../components/ui";
import { useFetch } from "../lib/useFetch";
import { api } from "../lib/api";
import { T, axisCommon, tooltipStyle, sevColor } from "../lib/echarts";
import { fmt, fmt1, periodLabel } from "../lib/format";

export function Timeline({ range, version }: { range: string; version: number }) {
  const ts = useFetch(() => api.timeseries(range), [range, version]);
  const daily = range === "30d";
  const unit = daily ? "gün" : "ay";

  const stats = useMemo(() => {
    const d = ts.data ?? [];
    if (d.length === 0) return null;
    const total = d.reduce((a, p) => a + p.count, 0);
    const peak = d.reduce((m, p) => (p.count > m.count ? p : m), d[0]);
    const avgSev = d.reduce((a, p) => a + p.avg_severity * p.count, 0) / (total || 1);
    const last = d[d.length - 1];
    const prev = d.length > 1 ? d[d.length - 2] : last;
    const delta = prev.count ? ((last.count - prev.count) / prev.count) * 100 : 0;
    return { total, peak, avgSev, last, delta, points: d.length };
  }, [ts.data]);

  const option = useMemo(() => {
    const d = ts.data ?? [];
    return {
      tooltip: { trigger: "axis", ...tooltipStyle },
      legend: { data: ["Saldırı sayısı", "Ort. severity"], textStyle: { color: T.textMid, fontSize: 11.5 }, top: 2, right: 10, icon: "roundRect" },
      grid: { left: 48, right: 48, top: 38, bottom: 30 },
      xAxis: { type: "category", data: d.map((p) => periodLabel(p.period)), ...axisCommon },
      yAxis: [
        { type: "value", name: "saldırı", nameTextStyle: { color: T.textLo, fontSize: 10 }, ...axisCommon, splitNumber: 4 },
        { type: "value", name: "severity", min: 0, max: 10, position: "right", nameTextStyle: { color: T.textLo, fontSize: 10 }, ...axisCommon, splitLine: { show: false } },
      ],
      series: [
        {
          name: "Saldırı sayısı",
          type: "bar",
          data: d.map((p) => p.count),
          itemStyle: { color: "rgba(90,160,230,0.55)", borderRadius: [3, 3, 0, 0] },
          barWidth: "56%",
        },
        {
          name: "Ort. severity",
          type: "line",
          yAxisIndex: 1,
          smooth: true,
          symbol: "circle",
          symbolSize: 5,
          data: d.map((p) => Number(p.avg_severity.toFixed(2))),
          lineStyle: { color: "#f08c2e", width: 2 },
          itemStyle: { color: "#f08c2e" },
        },
      ],
    };
  }, [ts.data]);

  if (ts.loading) return <Loading />;
  if (ts.error) return <ErrorState msg={ts.error} />;

  return (
    <>
      {stats && (
        <div className="kpi-grid">
          <Kpi label="Toplam Saldırı" value={fmt(stats.total)} sub={`${stats.points} ${unit}`} />
          <Kpi
            label={daily ? "En Yoğun Gün" : "En Yoğun Ay"}
            value={periodLabel(stats.peak.period)}
            sub={`${fmt(stats.peak.count)} saldırı`}
          />
          <Kpi label="Dönem Ort. Severity" value={fmt1(stats.avgSev)} sub="ağırlıklı ortalama" stripe={sevColor(stats.avgSev)} />
          <Kpi
            label={daily ? "Son Güne Göre" : "Son Aya Göre"}
            value={`${stats.delta >= 0 ? "+" : ""}${stats.delta.toFixed(0)}%`}
            sub={`son ${unit} ${fmt(stats.last.count)} saldırı`}
            stripe={stats.delta >= 0 ? "var(--sev-high)" : "var(--ok)"}
          />
        </div>
      )}
      <Panel
        title="Saldırı Trendi ve Severity Seyri"
        subtitle={daily ? "Günlük saldırı hacmi ve ortalama etki puanı" : "Aylık saldırı hacmi ve ortalama etki puanı"}
        tight
      >
        <Chart option={option} height={400} />
      </Panel>
    </>
  );
}
