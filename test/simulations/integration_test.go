package simulations

import (
	"context"
	"testing"
	"time"

	"edgesight/internal/analytics"
	"edgesight/internal/capture"
	"edgesight/internal/config"
	"edgesight/internal/storage"
)

func TestEngineToDetector(t *testing.T) {
	db, err := storage.Open(":memory:")
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	defer db.Close()

	cfg := config.Default()
	cfg.AnomalyZScore = 999
	d := analytics.NewDetector(cfg, db, nil)

	src := capture.NewTestSource()
	for i := 0; i < 120; i++ {
		src.InjectEthIPv4TCP("10.0.0.1", "10.0.0.2", 10000+uint16(i), 80, 0x02, nil)
	}

	eng := capture.NewEngine(cfg, src)
	eng.Register(d.ProcessPacket)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		_ = eng.Start(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("engine did not finish")
	}

	ev, _ := db.ListEvents(context.Background(), "", 1000, 0)
	var syn int
	for _, e := range ev {
		if e.Source == "syn_flood" {
			syn++
		}
	}
	if syn == 0 {
		t.Fatal("expected SYN flood events")
	}
}
