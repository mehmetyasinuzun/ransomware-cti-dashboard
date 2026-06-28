import { useEffect, useRef } from "react";
import { echarts } from "../lib/echarts";

type EChartsOption = Parameters<ReturnType<typeof echarts.init>["setOption"]>[0];
type EventHandler = (params: unknown) => void;

export function Chart({
  option,
  height = 300,
  onEvents,
}: {
  option: EChartsOption;
  height?: number | string;
  onEvents?: Record<string, EventHandler>;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const inst = useRef<ReturnType<typeof echarts.init> | null>(null);

  useEffect(() => {
    if (!ref.current) return;
    const chart = echarts.init(ref.current, undefined, { renderer: "canvas" });
    inst.current = chart;
    const ro = new ResizeObserver(() => chart.resize());
    ro.observe(ref.current);
    return () => {
      ro.disconnect();
      chart.dispose();
      inst.current = null;
    };
  }, []);

  useEffect(() => {
    inst.current?.setOption(option, true);
  }, [option]);

  useEffect(() => {
    const chart = inst.current;
    if (!chart || !onEvents) return;
    for (const [evt, fn] of Object.entries(onEvents)) chart.on(evt, fn);
    return () => {
      for (const evt of Object.keys(onEvents)) chart.off(evt);
    };
  }, [onEvents]);

  return <div ref={ref} style={{ width: "100%", height }} />;
}
