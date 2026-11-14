package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"edgesight/pkg/protocol"
	_ "modernc.org/sqlite"
)

// Store wraps SQLite access.
type Store struct {
	db *sql.DB
}

// Open opens (and bootstraps if necessary) the SQLite database.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(30000)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetConnMaxLifetime(0)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *Store) migrate() error {
	schema := `
CREATE TABLE IF NOT EXISTS events (
	id TEXT PRIMARY KEY,
	kind TEXT NOT NULL,
	severity INTEGER NOT NULL,
	timestamp INTEGER NOT NULL,
	source TEXT NOT NULL,
	title TEXT NOT NULL,
	message TEXT NOT NULL,
	mitre TEXT,
	packet TEXT,
	enrichment TEXT,
	raw TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);
CREATE INDEX IF NOT EXISTS idx_events_sev ON events(severity);

CREATE TABLE IF NOT EXISTS flows (
	id TEXT PRIMARY KEY,
	start_time INTEGER NOT NULL,
	end_time INTEGER NOT NULL,
	src_ip TEXT NOT NULL,
	dst_ip TEXT NOT NULL,
	src_port INTEGER,
	dst_port INTEGER,
	proto TEXT NOT NULL,
	bytes INTEGER NOT NULL,
	packets INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_flows_time ON flows(start_time, end_time);
CREATE INDEX IF NOT EXISTS idx_flows_src ON flows(src_ip);

CREATE TABLE IF NOT EXISTS baseline (
	key TEXT PRIMARY KEY,
	mean REAL NOT NULL,
	stddev REAL NOT NULL,
	count INTEGER NOT NULL,
	last_update INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS metrics (
	timestamp INTEGER PRIMARY KEY,
	flows_per_sec REAL NOT NULL,
	bytes_per_sec REAL NOT NULL,
	active_flows INTEGER NOT NULL,
	alerts INTEGER NOT NULL
);
`
	_, err := s.db.Exec(schema)
	return err
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// SaveEvent persists an event.
func (s *Store) SaveEvent(ctx context.Context, e *protocol.Event) error {
	mitreJSON, _ := json.Marshal(e.MITRE)
	packetJSON, _ := json.Marshal(e.Packet)
	enrichJSON, _ := json.Marshal(e.Enrich)
	rawJSON, _ := json.Marshal(e.Raw)

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO events(id, kind, severity, timestamp, source, title, message, mitre, packet, enrichment, raw)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			severity=excluded.severity, message=excluded.message, mitre=excluded.mitre,
			enrichment=excluded.enrichment, raw=excluded.raw`,
		e.ID, string(e.Kind), e.Severity, e.Timestamp.UnixMilli(), e.Source, e.Title, e.Message,
		string(mitreJSON), string(packetJSON), string(enrichJSON), string(rawJSON),
	)
	return err
}

// ListEvents returns paginated events with optional kind filter.
func (s *Store) ListEvents(ctx context.Context, kind string, limit, offset int) ([]*protocol.Event, error) {
	var rows *sql.Rows
	var err error
	if kind != "" {
		rows, err = s.db.QueryContext(ctx, `SELECT id, kind, severity, timestamp, source, title, message, mitre, packet, enrichment, raw
			FROM events WHERE kind=? ORDER BY timestamp DESC LIMIT ? OFFSET ?`, kind, limit, offset)
	} else {
		rows, err = s.db.QueryContext(ctx, `SELECT id, kind, severity, timestamp, source, title, message, mitre, packet, enrichment, raw
			FROM events ORDER BY timestamp DESC LIMIT ? OFFSET ?`, limit, offset)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

// CountEvents returns total event count optionally filtered by kind.
func (s *Store) CountEvents(ctx context.Context, kind string) (int64, error) {
	var q string
	var args []any
	if kind != "" {
		q = `SELECT COUNT(*) FROM events WHERE kind=?`
		args = append(args, kind)
	} else {
		q = `SELECT COUNT(*) FROM events`
	}
	var n int64
	err := s.db.QueryRowContext(ctx, q, args...).Scan(&n)
	return n, err
}

// SaveFlow persists a flow record.
func (s *Store) SaveFlow(ctx context.Context, f *protocol.FlowRecord) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO flows(id, start_time, end_time, src_ip, dst_ip, src_port, dst_port, proto, bytes, packets)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			end_time=excluded.end_time, bytes=bytes+excluded.bytes, packets=packets+excluded.packets`,
		f.ID, f.StartTime.UnixMilli(), f.EndTime.UnixMilli(), f.SrcIP, f.DstIP, f.SrcPort, f.DstPort, f.Proto, f.Bytes, f.Packets,
	)
	return err
}

// SaveMetric persists a metric snapshot.
func (s *Store) SaveMetric(ctx context.Context, m *protocol.MetricSnapshot) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO metrics(timestamp, flows_per_sec, bytes_per_sec, active_flows, alerts)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(timestamp) DO UPDATE SET
			flows_per_sec=excluded.flows_per_sec, bytes_per_sec=excluded.bytes_per_sec,
			active_flows=excluded.active_flows, alerts=excluded.alerts`,
		m.Timestamp.UnixMilli(), m.FlowsPerSec, m.BytesPerSec, m.ActiveFlows, m.Alerts,
	)
	return err
}

// GetBaseline retrieves a baseline statistic by key.
func (s *Store) GetBaseline(ctx context.Context, key string) (protocol.BaselineStat, error) {
	var st protocol.BaselineStat
	err := s.db.QueryRowContext(ctx, `SELECT key, mean, stddev, count, last_update FROM baseline WHERE key=?`, key).
		Scan(&st.Key, &st.Mean, &st.Stddev, &st.Count, &st.LastUpdate)
	if err == sql.ErrNoRows {
		return st, nil
	}
	return st, err
}

// SetBaseline updates a baseline statistic.
func (s *Store) SetBaseline(ctx context.Context, st protocol.BaselineStat) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO baseline(key, mean, stddev, count, last_update)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET
			mean=excluded.mean, stddev=excluded.stddev, count=excluded.count, last_update=excluded.last_update`,
		st.Key, st.Mean, st.Stddev, st.Count, st.LastUpdate,
	)
	return err
}

// Query executes an arbitrary read-only SQL query and returns rows as JSON-like maps.
func (s *Store) Query(ctx context.Context, q string, args ...any) ([]map[string]any, error) {
	if !strings.HasPrefix(strings.TrimSpace(strings.ToUpper(q)), "SELECT") {
		return nil, fmt.Errorf("only SELECT queries allowed")
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		m := make(map[string]any, len(cols))
		for i, c := range cols {
			m[c] = vals[i]
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func scanEvents(rows *sql.Rows) ([]*protocol.Event, error) {
	var out []*protocol.Event
	for rows.Next() {
		var e protocol.Event
		var ts int64
		var mitre, packet, enrich, raw string
		var kind string
		err := rows.Scan(&e.ID, &kind, &e.Severity, &ts, &e.Source, &e.Title, &e.Message, &mitre, &packet, &enrich, &raw)
		if err != nil {
			return nil, err
		}
		e.Kind = protocol.EventKind(kind)
		e.Timestamp = time.UnixMilli(ts)
		json.Unmarshal([]byte(mitre), &e.MITRE)
		json.Unmarshal([]byte(packet), &e.Packet)
		json.Unmarshal([]byte(enrich), &e.Enrich)
		json.Unmarshal([]byte(raw), &e.Raw)
		out = append(out, &e)
	}
	return out, rows.Err()
}
