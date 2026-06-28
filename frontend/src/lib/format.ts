const nf = new Intl.NumberFormat("tr-TR");

export function fmt(n: number | undefined | null): string {
  if (n == null || isNaN(n)) return "-";
  return nf.format(n);
}

export function fmt1(n: number | undefined | null): string {
  if (n == null || isNaN(n)) return "-";
  return n.toFixed(1);
}

export function fmtDate(s: string | undefined | null): string {
  if (!s) return "-";
  const d = new Date(s);
  if (isNaN(d.getTime())) return s;
  return d.toLocaleDateString("tr-TR", { day: "2-digit", month: "short", year: "numeric" });
}

export function fmtDateTime(s: string | undefined | null): string {
  if (!s) return "-";
  const d = new Date(s);
  if (isNaN(d.getTime())) return s;
  return d.toLocaleString("tr-TR", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

const MONTHS_TR = ["Oca", "Şub", "Mar", "Nis", "May", "Haz", "Tem", "Ağu", "Eyl", "Eki", "Kas", "Ara"];

// "2025-03" -> "Mar 25" (aylik) | "2026-06-27" -> "27 Haz" (gunluk)
export function periodLabel(period: string): string {
  const parts = period.split("-");
  const mi = parseInt(parts[1], 10) - 1;
  if (mi < 0 || mi > 11) return period;
  if (parts.length >= 3) return `${parseInt(parts[2], 10)} ${MONTHS_TR[mi]}`;
  return `${MONTHS_TR[mi]} ${parts[0].slice(2)}`;
}
