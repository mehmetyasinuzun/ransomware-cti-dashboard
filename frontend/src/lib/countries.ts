import countries from "i18n-iso-countries";
import en from "i18n-iso-countries/langs/en.json";
import tr from "i18n-iso-countries/langs/tr.json";

countries.registerLocale(en);
countries.registerLocale(tr);

export function alpha2ToAlpha3(a2: string): string {
  if (!a2) return "";
  return countries.alpha2ToAlpha3(a2.toUpperCase()) ?? "";
}

export function alpha3ToAlpha2(a3: string): string {
  if (!a3) return "";
  return countries.alpha3ToAlpha2(a3.toUpperCase()) ?? "";
}

export function nameTR(a2: string): string {
  if (!a2) return "-";
  return countries.getName(a2.toUpperCase(), "tr") ?? a2;
}

export function nameEN(a2: string): string {
  if (!a2) return "-";
  return countries.getName(a2.toUpperCase(), "en") ?? a2;
}
