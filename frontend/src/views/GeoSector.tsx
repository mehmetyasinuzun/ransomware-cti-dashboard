import { useMemo } from "react";
import { Chart } from "../components/Chart";
import { Panel, Loading, ErrorState } from "../components/ui";
import { useFetch } from "../lib/useFetch";
import { api, type RecordsFilter } from "../lib/api";
import { echarts, T, axisCommon, tooltipStyle, sevColor, clickName } from "../lib/echarts";
import { fmt, fmt1 } from "../lib/format";
import { alpha2ToAlpha3, alpha3ToAlpha2, nameTR } from "../lib/countries";
import worldGeo from "../assets/world.geo.json";

let mapRegistered = false;
function ensureWorldMap() {
  if (mapRegistered) return;
  const geo = worldGeo as unknown as { features: { id: string; properties: Record<string, unknown> }[] };
  for (const f of geo.features) {
    f.properties = f.properties || {};
    f.properties.name = f.id;
  }
  echarts.registerMap("world", geo as unknown as Parameters<typeof echarts.registerMap>[1]);
  mapRegistered = true;
}

export function GeoSector({ range, version, onDrill }: { range: string; version: number; onDrill: (f: RecordsFilter) => void }) {
  ensureWorldMap();
  const countries = useFetch(() => api.countries(80, range), [range, version]);
  const sectors = useFetch(() => api.sectors(20, range), [range, version]);

  const topCountries = useMemo(() => [...(countries.data ?? []).slice(0, 12)].reverse(), [countries.data]);
  const mapEvents = useMemo(
    () => ({
      click: (p: unknown) => {
        const n = (p as { name?: string })?.name;
        const iso2 = n ? alpha3ToAlpha2(n) : "";
        if (iso2) onDrill({ country: iso2 });
      },
    }),
    [onDrill]
  );
  const countryBarEvents = useMemo(
    () => ({
      click: (p: unknown) => {
        const i = (p as { dataIndex?: number })?.dataIndex;
        if (i != null && topCountries[i]) onDrill({ country: topCountries[i].country });
      },
    }),
    [onDrill, topCountries]
  );
  const sectorEvents = useMemo(() => clickName((n) => onDrill({ sector: n })), [onDrill]);

  const mapOption = useMemo(() => {
    const d = countries.data ?? [];
    const max = d.reduce((m, c) => Math.max(m, c.count), 1);
    const data = d.map((c) => ({
      name: alpha2ToAlpha3(c.country),
      value: c.count,
      label2: nameTR(c.country),
    }));
    return {
      tooltip: {
        trigger: "item",
        ...tooltipStyle,
        formatter: (p: { data?: { label2?: string; value?: number }; name: string }) => {
          if (!p.data) return `${p.name}<br/>veri yok`;
          return `<b>${p.data.label2}</b><br/>${fmt(p.data.value ?? 0)} saldırı`;
        },
      },
      visualMap: {
        min: 0,
        max,
        left: 14,
        bottom: 18,
        calculable: true,
        itemHeight: 110,
        text: ["yüksek", "düşük"],
        textStyle: { color: T.textMid, fontSize: 11 },
        inRange: { color: ["#18313f", "#1f527a", "#2f7fc0", "#5aa0e6", "#9ec9f2"] },
      },
      series: [
        {
          type: "map",
          map: "world",
          roam: false,
          scaleLimit: { min: 1, max: 5 },
          itemStyle: { areaColor: T.surface2, borderColor: T.border, borderWidth: 0.5 },
          emphasis: { itemStyle: { areaColor: "#2f7fc0" }, label: { show: false } },
          select: { itemStyle: { areaColor: T.accent }, label: { show: false } },
          label: { show: false },
          data,
        },
      ],
    };
  }, [countries.data]);

  const countryBar = useMemo(() => {
    const d = topCountries;
    return {
      tooltip: { trigger: "axis", axisPointer: { type: "shadow" }, ...tooltipStyle },
      grid: { left: 8, right: 28, top: 6, bottom: 22, containLabel: true },
      xAxis: { type: "value", ...axisCommon },
      yAxis: {
        type: "category",
        data: d.map((c) => nameTR(c.country)),
        axisLine: { lineStyle: { color: T.border } },
        axisTick: { show: false },
        axisLabel: { color: T.textMid, fontSize: 11.5 },
      },
      series: [
        {
          type: "bar",
          barWidth: "62%",
          data: d.map((c) => c.count),
          itemStyle: { color: "#56b4e9", borderRadius: [0, 3, 3, 0] },
        },
      ],
    };
  }, [countries.data]);

  const sectorBar = useMemo(() => {
    const d = [...(sectors.data ?? [])].reverse();
    return {
      tooltip: {
        trigger: "axis",
        axisPointer: { type: "shadow" },
        ...tooltipStyle,
        formatter: (p: { dataIndex: number }[]) => {
          const i = d[p[0].dataIndex];
          return `<b>${i.target_sector}</b><br/>${fmt(i.count)} saldırı<br/>ort. severity ${fmt1(i.avg_severity)}`;
        },
      },
      grid: { left: 8, right: 30, top: 6, bottom: 24, containLabel: true },
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
          label: { show: true, position: "right", color: T.textLo, fontSize: 11 },
        },
      ],
    };
  }, [sectors.data]);

  if (countries.error) return <ErrorState msg={countries.error} />;

  return (
    <>
      <div className="grid">
        <div className="col-8">
          <Panel title="Coğrafi Dağılım" subtitle="Bir ülkeye tıklayarak kayıtlarına git" tight>
            {countries.loading ? <Loading /> : <Chart option={mapOption} height={420} onEvents={mapEvents} />}
          </Panel>
        </div>
        <div className="col-4">
          <Panel title="En Çok Hedeflenen Ülkeler" subtitle="İlk 12 · tıkla ve filtrele" tight>
            {countries.loading ? <Loading /> : <Chart option={countryBar} height={420} onEvents={countryBarEvents} />}
          </Panel>
        </div>
        <div className="col-12">
          <Panel title="Sektör Bazlı Dağılım" subtitle="Renk = ortalama severity · bir sektöre tıklayarak filtrele" tight>
            {sectors.loading ? <Loading /> : <Chart option={sectorBar} height={340} onEvents={sectorEvents} />}
          </Panel>
        </div>
      </div>
    </>
  );
}
