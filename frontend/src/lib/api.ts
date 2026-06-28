const BASE = "/api";

async function get<T>(path: string): Promise<T> {
  const res = await fetch(BASE + path);
  if (!res.ok) {
    throw new Error(`Sunucu hatası (${res.status})`);
  }
  return res.json() as Promise<T>;
}

async function post<T>(path: string): Promise<T> {
  const res = await fetch(BASE + path, { method: "POST" });
  if (!res.ok) {
    throw new Error(`Sunucu hatası (${res.status})`);
  }
  return res.json() as Promise<T>;
}

function qs(params: Record<string, string | number | undefined>): string {
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== "" && v !== "all") u.set(k, String(v));
  }
  const s = u.toString();
  return s ? `?${s}` : "";
}

export interface Summary {
  victim_count: number;
  group_count: number;
  country_count: number;
  sector_count: number;
  ioc_count: number;
  avg_severity: number;
  high_severity_count: number;
  date_min: string;
  date_max: string;
  last30d_count: number;
  window?: string;
  meta: Record<string, string>;
}

export interface RefreshStatus {
  running: boolean;
  last_run: string;
  error: string;
  started?: boolean;
  victims?: number;
  iocs?: number;
  ioc_mode?: string;
}

export interface GroupStat {
  ransomware_group: string;
  count: number;
  avg_severity: number;
}
export interface CountryStat {
  country: string;
  country_name: string;
  count: number;
  avg_severity: number;
}
export interface SectorStat {
  target_sector: string;
  count: number;
  avg_severity: number;
}
export interface VectorStat {
  attack_vector: string;
  count: number;
}
export interface TechniqueStat {
  technique_id: string;
  technique: string;
  count: number;
}
export interface TimePoint {
  period: string;
  count: number;
  avg_severity: number;
}
export interface SeverityBin {
  severity: number;
  count: number;
}

export interface Victim {
  id: number;
  date: string;
  ransomware_group: string;
  country: string;
  country_name: string;
  target_sector: string;
  attack_vector: string;
  technique_id: string;
  technique: string;
  severity: number;
  ioc_ip: string;
  ioc_hash: string;
  victim: string;
  description: string;
  domain: string;
  claim_url: string;
  source_url: string;
}

export interface VictimsResponse {
  total: number;
  limit: number;
  offset: number;
  items: Victim[];
}

export interface IOC {
  value: string;
  type: string;
  ransomware_group: string;
  malware_family: string;
  confidence: number;
  first_seen: string;
  source: string;
}

export interface IOCResult {
  query: string;
  matches: IOC[];
  groups: string[];
  victims: Victim[];
  severity: { count: number; avg: number; min: number; max: number };
}

export interface IOCListResponse {
  total: number;
  limit: number;
  offset: number;
  items: IOC[];
}

export interface RecordsFilter {
  group?: string;
  country?: string;
  sector?: string;
  severity_min?: string;
  q?: string;
}

export const api = {
  summary: (window?: string) => get<Summary>(`/summary${qs({ window })}`),
  groups: (limit = 12, window?: string) => get<GroupStat[]>(`/groups${qs({ limit, window })}`),
  countries: (limit = 60, window?: string) => get<CountryStat[]>(`/countries${qs({ limit, window })}`),
  sectors: (limit = 20, window?: string) => get<SectorStat[]>(`/sectors${qs({ limit, window })}`),
  vectors: (window?: string) => get<VectorStat[]>(`/attack-vectors${qs({ window })}`),
  techniques: (limit = 12, window?: string) => get<TechniqueStat[]>(`/techniques${qs({ limit, window })}`),
  timeseries: (window?: string) => get<TimePoint[]>(`/timeseries${qs({ window })}`),
  severity: (window?: string) => get<SeverityBin[]>(`/severity${qs({ window })}`),
  victims: (params: Record<string, string | number>) => get<VictimsResponse>(`/victims${qs(params)}`),
  ioc: (q: string) => get<IOCResult>(`/ioc?q=${encodeURIComponent(q)}`),
  iocList: (params: Record<string, string | number>) => get<IOCListResponse>(`/iocs${qs(params)}`),
  iocGroups: () => get<GroupStat[]>("/ioc-groups"),
  refresh: () => post<RefreshStatus>("/refresh"),
  refreshStatus: () => get<RefreshStatus>("/refresh/status"),
};
