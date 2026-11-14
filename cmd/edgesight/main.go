// Command edgesight is the integrated EdgeSight CLI: it wires the validated
// internal components (config, SQLite storage, behavioral detector, HTTP API +
// embedded dashboard) into a single binary.
//
// SAFE DEFAULTS: by default edgesight does NOT capture live traffic. It serves
// the read API and dashboard over an existing SQLite database on a loopback
// address. Live AF_PACKET capture is opt-in via -capture and requires elevated
// privileges (CAP_NET_RAW); it is intended only for an authorized local lab.
//
// The server fails closed: an empty api_key is permitted only on a loopback
// bind (see internal/api.bindGuard).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"edgesight/internal/analytics"
	"edgesight/internal/api"
	"edgesight/internal/capture"
	"edgesight/internal/config"
	"edgesight/internal/storage"
	"edgesight/pkg/protocol"
)

func main() {
	fs := flag.NewFlagSet("edgesight", flag.ExitOnError)
	var (
		configPath = fs.String("config", "", "path to JSON config (optional; defaults used if empty)")
		dbPath     = fs.String("db", "", "SQLite database path (overrides config)")
		listen     = fs.String("listen", "", "HTTP listen address (overrides config; default 127.0.0.1:8080)")
		doCapture  = fs.Bool("capture", false, "enable live AF_PACKET capture (opt-in; needs CAP_NET_RAW; authorized local lab only)")
	)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "EdgeSight — single-binary passive network detection (research prototype)\n\n")
		fmt.Fprintf(os.Stderr, "Usage: edgesight [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Default run serves the dashboard/API over an existing DB on loopback; no capture.\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(os.Args[1:])

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if *dbPath != "" {
		cfg.DatabasePath = *dbPath
	}
	if *listen != "" {
		cfg.ListenAddr = *listen
	}

	store, err := storage.Open(cfg.DatabasePath)
	if err != nil {
		log.Fatalf("open storage %q: %v", cfg.DatabasePath, err)
	}
	defer store.Close()

	// Events are already persisted by the detector/store; the emit hook is a
	// no-op here (plugin fan-out is configured separately).
	detector := analytics.NewDetector(cfg, store, func(*protocol.Event) {})

	if *doCapture {
		log.Printf("WARNING: live capture enabled on %q (requires CAP_NET_RAW; authorized local lab only)", cfg.Interface)
		eng := capture.NewEngine(cfg, capture.NewAFPacketSource())
		eng.Register(detector.ProcessPacket)
		go func() {
			if err := eng.Start(context.Background()); err != nil {
				log.Printf("capture stopped: %v", err)
			}
		}()
		defer eng.Stop()
	} else {
		log.Printf("serve-only mode (no live capture); serving existing DB %q", cfg.DatabasePath)
	}

	srv := api.NewServer(cfg, store, detector)
	if err := srv.Listen(); err != nil {
		log.Fatalf("server: %v", err)
	}
}
