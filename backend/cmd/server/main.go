package main

import (
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"ransomware-cti/internal/api"
	"ransomware-cti/internal/config"
	"ransomware-cti/internal/store"
)

func main() {
	healthFlag := flag.Bool("healthcheck", false, "HTTP saglik kontrolu yapip cik (Docker healthcheck icin)")
	flag.Parse()

	log.SetFlags(log.Ltime)
	cfg := config.FromEnv()

	if *healthFlag {
		os.Exit(runHealthcheck(cfg.APIAddr))
	}

	db, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("veritabani acilamadi (%s): %v", cfg.DBPath, err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		log.Fatalf("sema olusturulamadi: %v", err)
	}

	server := api.New(db, cfg)
	server.SeedIfEmpty()
	server.StartScheduler()

	srv := &http.Server{
		Addr:              cfg.APIAddr,
		Handler:           server.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("CTI API dinliyor %s (db=%s)", cfg.APIAddr, cfg.DBPath)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("sunucu hatasi: %v", err)
	}
}

func runHealthcheck(addr string) int {
	client := http.Client{Timeout: 4 * time.Second}
	resp, err := client.Get("http://127.0.0.1" + addr + "/api/health")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode == http.StatusOK {
		return 0
	}
	return 1
}
