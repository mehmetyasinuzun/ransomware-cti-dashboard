package main

import (
	"context"
	"log"
	"os"

	"ransomware-cti/internal/config"
	"ransomware-cti/internal/ingest"
)

func main() {
	log.SetFlags(log.Ltime)
	cfg := config.FromEnv()
	ctx := context.Background()

	var err error
	if os.Getenv("IOC_ONLY") == "true" {
		_, err = ingest.ReingestIOCs(ctx, cfg)
	} else {
		_, err = ingest.Run(ctx, cfg)
	}
	if err != nil {
		log.Fatalf("pipeline hatasi: %v", err)
	}
}
