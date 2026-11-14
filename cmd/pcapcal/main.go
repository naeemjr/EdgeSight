// pcapcal is an offline calibration driver for the EdgeSight detection
// pipeline. It replays a committed pcap through the REAL detection code
// (capture.ParsePacket -> analytics.Detector) with pcap timestamps, flushing
// the detector on fixed window boundaries, and prints every emitted event as
// JSON. No packets are transmitted; nothing leaves the machine.
//
// Used by XDPLAB Track W2 (gap B4) to measure EdgeSight's detection floor
// against the committed GhostNIC MQTT covert-channel pcaps with known labels.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/gopacket/pcapgo"

	"edgesight/internal/analytics"
	"edgesight/internal/capture"
	"edgesight/internal/config"
	"edgesight/pkg/protocol"
)

type eventOut struct {
	Timestamp string `json:"timestamp"`
	UnixNano  int64  `json:"unix_nano"`
	Kind      string `json:"kind"`
	Source    string `json:"source"`
	Severity  int    `json:"severity"`
	Title     string `json:"title"`
	Message   string `json:"message"`
}

type result struct {
	Pcap             string     `json:"pcap"`
	Packets          int        `json:"packets"`
	FirstPacketNS    int64      `json:"first_packet_unix_nano"`
	LastPacketNS     int64      `json:"last_packet_unix_nano"`
	WindowCount      int        `json:"window_count"`
	FlushIntervalNS  int64      `json:"flush_interval_nano"`
	BaselineWindowNS int64      `json:"baseline_window_nano"`
	AnomalyZScore    float64    `json:"anomaly_z_score"`
	Events           []eventOut `json:"events"`
}

func main() {
	pcapPath := flag.String("pcap", "", "path to pcap file (required)")
	zscore := flag.Float64("z", 1.0, "anomaly z-score threshold")
	baselineWindow := flag.Duration("baseline-window", time.Second, "baseline window")
	flushInterval := flag.Duration("flush-interval", 5*time.Second, "detector flush interval in pcap time")
	flag.Parse()
	if *pcapPath == "" {
		fmt.Fprintln(os.Stderr, "pcapcal: -pcap is required")
		os.Exit(2)
	}

	f, err := os.Open(*pcapPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pcapcal:", err)
		os.Exit(1)
	}
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pcapcal:", err)
		os.Exit(1)
	}

	res := result{Pcap: *pcapPath, FlushIntervalNS: flushInterval.Nanoseconds(),
		BaselineWindowNS: baselineWindow.Nanoseconds(), AnomalyZScore: *zscore,
		Events: []eventOut{}}

	cfg := &config.Config{BaselineWindow: *baselineWindow, AnomalyZScore: *zscore}
	det := analytics.NewDetector(cfg, nil, func(e *protocol.Event) {
		res.Events = append(res.Events, eventOut{
			Timestamp: e.Timestamp.UTC().Format(time.RFC3339Nano),
			UnixNano:  e.Timestamp.UnixNano(),
			Kind:      string(e.Kind),
			Source:    e.Source,
			Severity:  e.Severity,
			Title:     e.Title,
			Message:   e.Message,
		})
	})

	ctx := context.Background()

	var nextFlush time.Time
	for {
		data, ci, err := r.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "pcapcal: read error:", err)
			os.Exit(1)
		}
		if res.Packets == 0 {
			res.FirstPacketNS = ci.Timestamp.UnixNano()
			// Align flush boundaries to the first packet, like the live
			// detector aligning its ticker to process start.
			nextFlush = ci.Timestamp.Add(*flushInterval)
		}
		res.Packets++
		res.LastPacketNS = ci.Timestamp.UnixNano()
		for !ci.Timestamp.Before(nextFlush) {
			det.FlushAt(ctx, nextFlush)
			res.WindowCount++
			nextFlush = nextFlush.Add(*flushInterval)
		}
		m := capture.ParsePacket(data, ci)
		det.ProcessPacket(m)
	}
	// Final flush at the last packet's time so trailing state is evaluated.
	det.FlushAt(ctx, nextFlush)
	res.WindowCount++

	out, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "pcapcal:", err)
		os.Exit(1)
	}
	fmt.Println(string(out))
}
