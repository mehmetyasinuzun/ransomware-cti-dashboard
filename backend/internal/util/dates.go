package util

import (
	"strings"
	"time"
)

var layouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.999999999",
	"2006-01-02 15:04:05.999999",
	"2006-01-02 15:04:05",
	"2006-01-02T15:04:05",
	"2006-01-02",
}

func ParseFlexible(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func ToDate(s string) string {
	if t, ok := ParseFlexible(s); ok {
		return t.Format("2006-01-02")
	}
	return ""
}

func PickDate(primary, fallback string) string {
	if d := ToDate(primary); d != "" {
		return d
	}
	return ToDate(fallback)
}
