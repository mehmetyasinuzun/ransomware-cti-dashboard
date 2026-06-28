package config

import (
	"os"
	"strconv"
)

type Config struct {
	RansomwareLiveBase string
	AbuseKey           string
	WindowFrom         string
	DBPath             string
	DataDir            string
	ThrottleMS         int
	MaxRetry           int
	UserAgent          string
	Refresh            bool
	APIAddr            string
	RefreshIntervalHrs int
	IOCPerGroup        int
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getint(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func FromEnv() Config {
	dataDir := getenv("DATA_DIR", "data")
	return Config{
		RansomwareLiveBase: getenv("RANSOMWARELIVE_BASE", "https://api.ransomware.live/v2"),
		AbuseKey:           os.Getenv("ABUSECH_AUTH_KEY"),
		WindowFrom:         getenv("WINDOW_FROM", "2024-07"),
		DBPath:             getenv("DB_PATH", dataDir+"/cti.db"),
		DataDir:            dataDir,
		ThrottleMS:         getint("THROTTLE_MS", 1200),
		MaxRetry:           getint("MAX_RETRY", 5),
		UserAgent:          getenv("USER_AGENT", "ransomware-cti-dashboard/1.0 (research; contact: local)"),
		Refresh:            getenv("REFRESH", "false") == "true",
		APIAddr:            getenv("API_ADDR", ":8080"),
		RefreshIntervalHrs: getint("REFRESH_INTERVAL_HOURS", 0),
		IOCPerGroup:        getint("IOC_PER_GROUP", 250),
	}
}
