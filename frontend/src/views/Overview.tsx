import { useMemo } from "react";
import { Chart } from "../components/Chart";
import { Kpi, Panel, Loading, ErrorState } from "../components/ui";
import { useFetch } from "../lib/useFetch";
import { api, type RecordsFilter } from "../lib/api";
import { T, axisCommon, tooltipStyle, sevColor, clickName } from "../lib/echarts";
import { fmt, fmt1, fmtDate, periodLabel } from "../lib/format";

export function Overview({ range, version, onDrill }: { range: string; version: number; onDrill: (f: RecordsFilter) => void }) {
  const summary = useFetch(() => api.summary(range), [range, version]);
  const ts = useFetch(() => api.timeseries(range), [range, version]);
  const sev = useFetch(() => api.severity(range), [range, version]);
  const groups = useFetch(() => api.groups(10, range), [range, version]);
  const sectors = useFetch(() => api.sectors(8, range), [range, version]);

  const tsOption = useMemo(() => {
    const d = ts.data ?? [];
    return {
      tooltip: { trigger: "axis", ...tooltipStyle },
      grid: { left: 46, right: 18, top: 16, bottom: 26 },
      xAxis: { type: "category", boundaryGap: false, data: d.map((p) => periodLabel(p.period)), ...axisCommon },
      yAxis: { type: "value", ...axisCommon, splitNumber: 4 },
      series: [
        {
          name: "Saldırı",
          type: "line",
          smooth: true,
          symbol: "circle",
          symbolSize: 5,
          showSymbol: false,
          data: d.map((p) => p.count),
          lineStyle: { color: T.accent, width: 2 },
          itemStyle: { color: T.accent },
          areaStyle: {
            color: {
              type: "linear",
              x: 0,
              y: 0,
              x2: 0,
              y2: 1,
              colorStops: [
                { offset: 0, color: "rgba(90,160,230,0.22)" },
                { offset: 1, color: "rgba(90,160,230,0.01)" },
              ],
            },
          },
        },
      ],
    };
  }, [ts.data]);

  const sevOption = useMemo(() => {
    const d = sev.data ?? [];
    return {
      tooltip: { trigger: "axis", axisPointer: { type: "shadow" }, ...tooltipStyle },
      grid: { left: 42, right: 16, top: 16, bottom: 26 },
      xAxis: { type: "category", data: d.map((b) => String(b.severity)), name: "severity", nameTextStyle: { color: T.textLo, fontSize: 10 }, ...axisCommon },
      yAxis: { type: "value", ...axisCommon, splitNumber: 4 },
      series: [
        {
          type: "bar",
          barWidth: "58%",
          data: d.map((b) => ({ value: b.count, itemStyle: { color: sevColor(b.severity), borderRadius: [3, 3, 0, 0] } })),
        },
      ],
    };
  }, [sev.data]);

  const groupsOption = useMemo(() => {
    const d = [...(groups.data ?? [])].reverse();
    return {
      tooltip: { trigger: "axis", axisPointer: { type: "shadow" }, ...tooltipStyle },
      grid: { left: 8, right: 26, top: 6, bottom: 22, containLabel: true },
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
          barWidth: "60%",
          data: d.map((g) => g.count),
          itemStyle: { color: T.accent, borderRadius: [0, 3, 3, 0] },
        },
      ],
    };
  }, [groups.data]);

  const sectorsOption = useMemo(() => {
    const d = [...(sectors.data ?? [])].reverse();
    return {
      tooltip: { trigger: "axis", axisPointer: { type: "shadow" }, ...tooltipStyle },
      grid: { left: 8, right: 26, top: 6, bottom: 22, containLabel: true },
      xAxis: { type: "value", ...axisCommon },
      yAxis: {
        type: "category",
        data: d.map((s) => s.target_sector),
        axisLine: { lineStyle: { color: T.border } },
        axisTick: { show: false },
        axisLabel: { color: T.textMid, fontSize: 11.5 },
      },
      series: [
        {
          type: "bar",
          barWidth: "60%",
          data: d.map((s) => ({ value: s.count, itemStyle: { color: sevColor(s.avg_severity), borderRadius: [0, 3, 3, 0] } })),
        },
      ],
    };
  }, [sectors.data]);

  const sevEvents = useMemo(() => clickName((n) => onDrill({ severity_min: n })), [onDrill]);
  const groupEvents = useMemo(() => clickName((n) => onDrill({ group: n })), [onDrill]);
  const sectorEvents = useMemo(() => clickName((n) => onDrill({ sector: n })), [onDrill]);

  const daily = range === "30d";

  if (summary.loading) return <Loading />;
  if (summary.error) return <ErrorState msg={summary.error} />;
  const s = summary.data!;

  return (
    <>
      <div className="kpi-grid">
        <Kpi label="Toplam Saldırı" value={fmt(s.victim_count)} sub={`${fmtDate(s.date_min)} – ${fmtDate(s.date_max)}`} />
        <Kpi label="Aktif Grup" value={fmt(s.group_count)} sub="benzersiz ransomware grubu" />
        <Kpi label="Hedef Ülke" value={fmt(s.country_count)} sub={`${fmt(s.sector_count)} farklı sektör`} />
        <Kpi label="Ort. Severity" value={fmt1(s.avg_severity)} sub="10 üzerinden" stripe={sevColor(s.avg_severity)} />
        <Kpi label="Kritik Saldırı" value={fmt(s.high_severity_count)} sub="severity ≥ 8" stripe={sevColor(8)} />
        <Kpi label="IOC Göstergesi" value={fmt(s.ioc_count)} sub="IP ve hash" />
      </div>

      <div className="grid">
        <div className="col-7">
          <Panel title={daily ? "Günlük Saldırı Trendi" : "Aylık Saldırı Trendi"} subtitle={daily ? "Güne göre yayımlanan kurban sayısı" : "Aya göre yayımlanan kurban sayısı"} tight>
            {ts.loading ? <Loading /> : <Chart option={tsOption} height={300} />}
          </Panel>
        </div>
        <div className="col-5">
          <Panel title="Severity Dağılımı" subtitle="Bir bara tıklayarak o severity'deki kayıtlara git" tight>
            {sev.loading ? <Loading /> : <Chart option={sevOption} height={300} onEvents={sevEvents} />}
          </Panel>
        </div>
        <div className="col-6">
          <Panel title="En Aktif Gruplar" subtitle="Bir gruba tıklayarak kayıtlarını gör" tight>
            {groups.loading ? <Loading /> : <Chart option={groupsOption} height={300} onEvents={groupEvents} />}
          </Panel>
        </div>
        <div className="col-6">
          <Panel title="Hedef Sektörler" subtitle="Renk = ortalama severity · tıkla ve filtrele" tight>
            {sectors.loading ? <Loading /> : <Chart option={sectorsOption} height={300} onEvents={sectorEvents} />}
          </Panel>
        </div>
      </div>
    </>
  );
}
