import * as echarts from "echarts/core";
import { BarChart, LineChart, MapChart, PieChart, HeatmapChart } from "echarts/charts";
import {
  GridComponent,
  TooltipComponent,
  LegendComponent,
  VisualMapComponent,
  TitleComponent,
  GraphicComponent,
  MarkLineComponent,
  DatasetComponent,
} from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";

echarts.use([
  BarChart,
  LineChart,
  MapChart,
  PieChart,
  HeatmapChart,
  GridComponent,
  TooltipComponent,
  LegendComponent,
  VisualMapComponent,
  TitleComponent,
  GraphicComponent,
  MarkLineComponent,
  DatasetComponent,
  CanvasRenderer,
]);

export { echarts };

export const T = {
  bg: "#0e1116",
  surface1: "#161b22",
  surface2: "#1f2630",
  surface3: "#283039",
  border: "#262c35",
  borderStrong: "#39424e",
  textHi: "#e6edf3",
  textMid: "#9da7b3",
  textLo: "#6b7480",
  accent: "#5aa0e6",
  fontMono: "'IBM Plex Mono', monospace",
  fontSans: "'IBM Plex Sans', sans-serif",
};

// Wong renk-koru-guvenli palet
export const SERIES = [
  "#648fff",
  "#e69f00",
  "#009e73",
  "#cc79a7",
  "#d55e00",
  "#56b4e9",
  "#b7950b",
  "#8e7cc3",
  "#7f8c8d",
  "#2fa968",
  "#c0507d",
  "#4f9de0",
];

export function sevColor(s: number): string {
  if (s >= 8) return "#f0503a";
  if (s >= 6) return "#f08c2e";
  if (s >= 4) return "#e3b341";
  return "#4f9de0";
}

export function sevLabel(s: number): string {
  if (s >= 8) return "Kritik";
  if (s >= 6) return "Yüksek";
  if (s >= 4) return "Orta";
  return "Düşük";
}

export const tooltipStyle = {
  backgroundColor: T.surface2,
  borderColor: T.borderStrong,
  borderWidth: 1,
  padding: [8, 11] as [number, number],
  textStyle: { color: T.textHi, fontSize: 12, fontFamily: T.fontSans },
  extraCssText: "box-shadow: 0 4px 14px rgba(0,0,0,0.5); border-radius:6px;",
};

// ECharts tiklama olayindan kategori adini alip bir callback'e geciren yardimci.
export function clickName(fn: (name: string) => void) {
  return {
    click: (p: unknown) => {
      const n = (p as { name?: string })?.name;
      if (n) fn(String(n));
    },
  };
}

export const axisCommon = {
  axisLine: { lineStyle: { color: T.border } },
  axisTick: { show: false },
  axisLabel: { color: T.textLo, fontSize: 11, fontFamily: T.fontSans },
  splitLine: { lineStyle: { color: T.border, type: "dashed" as const } },
};
