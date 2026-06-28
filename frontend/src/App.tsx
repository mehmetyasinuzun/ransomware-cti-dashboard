import { useCallback, useState } from "react";
import { Sidebar } from "./components/Sidebar";
import { Topbar } from "./components/Topbar";
import { useFetch } from "./lib/useFetch";
import { api, type RecordsFilter } from "./lib/api";
import { Overview } from "./views/Overview";
import { Groups } from "./views/Groups";
import { GeoSector } from "./views/GeoSector";
import { Timeline } from "./views/Timeline";
import { IocSearch } from "./views/IocSearch";
import { Records } from "./views/Records";

export function App() {
  const [view, setView] = useState("overview");
  const [range, setRange] = useState("all");
  const [version, setVersion] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [recordsFilter, setRecordsFilter] = useState<RecordsFilter>({});

  const summary = useFetch(() => api.summary(range), [range, version]);

  const doRefresh = useCallback(async () => {
    if (refreshing) return;
    setRefreshing(true);
    try {
      await api.refresh();
      for (let i = 0; i < 240; i++) {
        await new Promise((r) => setTimeout(r, 2500));
        const st = await api.refreshStatus();
        if (!st.running) break;
      }
      setVersion((v) => v + 1);
    } catch {
      // hata bir sonraki durum sorgusunda yansir
    } finally {
      setRefreshing(false);
    }
  }, [refreshing]);

  const navigate = useCallback((v: string) => {
    setView(v);
    setSidebarOpen(false);
  }, []);

  const drill = useCallback((f: RecordsFilter) => {
    setRecordsFilter(f);
    setView("records");
    setSidebarOpen(false);
    window.scrollTo({ top: 0 });
  }, []);

  const shared = { range, version };
  return (
    <div className={"app" + (sidebarOpen ? " sidebar-open" : "")}>
      <Sidebar active={view} onChange={navigate} />
      <div className="sidebar-backdrop" onClick={() => setSidebarOpen(false)} />
      <div className="main">
        <Topbar
          view={view}
          summary={summary.data}
          range={range}
          onRange={setRange}
          onRefresh={doRefresh}
          refreshing={refreshing}
          onMenu={() => setSidebarOpen((o) => !o)}
        />
        <div className="content">
          {view === "overview" && <Overview {...shared} onDrill={drill} />}
          {view === "groups" && <Groups {...shared} onDrill={drill} />}
          {view === "geo" && <GeoSector {...shared} onDrill={drill} />}
          {view === "timeline" && <Timeline {...shared} />}
          {view === "ioc" && <IocSearch />}
          {view === "records" && <Records version={version} filter={recordsFilter} onFilter={setRecordsFilter} />}
        </div>
      </div>
    </div>
  );
}
