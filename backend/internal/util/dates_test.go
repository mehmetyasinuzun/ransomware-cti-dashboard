package util

import "testing"

func TestToDate(t *testing.T) {
	cases := map[string]string{
		"2026-06-27T18:28:12.666986+00:00": "2026-06-27", // recentvictims formati
		"2026-06-03 00:00:00.000000":       "2026-06-03", // victims/{y}/{m} formati
		"2024-01-15":                       "2024-01-15",
		"":                                 "",
		"gecersiz":                         "",
	}
	for in, want := range cases {
		if got := ToDate(in); got != want {
			t.Errorf("ToDate(%q) = %q, beklenen %q", in, got, want)
		}
	}
}

func TestPickDate(t *testing.T) {
	if got := PickDate("2026-06-27T00:00:00Z", "2025-01-01"); got != "2026-06-27" {
		t.Errorf("birincil tarih tercih edilmeli, %q aldim", got)
	}
	if got := PickDate("", "2025-01-01"); got != "2025-01-01" {
		t.Errorf("birincil bos ise yedek kullanilmali, %q aldim", got)
	}
}
