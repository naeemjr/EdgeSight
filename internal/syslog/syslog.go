package syslog

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"edgesight/pkg/protocol"
)

// Severity mapping to RFC 5424 severity (0=Emergency ... 7=Debug).
func severity(level int) int {
	switch {
	case level >= 9:
		return 1 // Alert
	case level >= 7:
		return 2 // Critical
	case level >= 5:
		return 3 // Error
	case level >= 3:
		return 4 // Warning
	default:
		return 5 // Notice
	}
}

// Format renders an event as an RFC 5424 message.
func Format(hostname, appName string, e *protocol.Event) string {
	pri := 1*8 + severity(e.Severity) // facility 1 (user-level)
	timestamp := e.Timestamp.UTC().Format(time.RFC3339Nano)
	if hostname == "" {
		hostname = "-"
	}
	if appName == "" {
		appName = "edgesight"
	}
	msgID := e.ID
	if msgID == "" {
		msgID = "-"
	}
	structData := fmt.Sprintf("[edgesight@1 id=\"%s\" kind=\"%s\" severity=\"%d\" source=\"%s\"]",
		escapeSD(e.ID), escapeSD(string(e.Kind)), e.Severity, escapeSD(e.Source))
	jsonPayload, _ := json.Marshal(e)
	return fmt.Sprintf("<%d>1 %s %s %s - %s %s %s",
		pri, timestamp, hostname, appName, msgID, structData, string(jsonPayload))
}

func escapeSD(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, `]`, `\]`)
	return s
}

// Sender emits formatted syslog messages via UDP or TCP.
type Sender struct {
	target   string
	protocol string
	conn     net.Conn
}

// NewSender creates a syslog sender. target may be "udp://host:port" or "tcp://host:port".
func NewSender(target string) *Sender {
	return &Sender{target: target}
}

// Send transmits a single RFC 5424 message.
func (s *Sender) Send(hostname, appName string, e *protocol.Event) error {
	if s.conn == nil {
		proto := "udp"
		addr := s.target
		if strings.HasPrefix(s.target, "udp://") {
			addr = strings.TrimPrefix(s.target, "udp://")
		} else if strings.HasPrefix(s.target, "tcp://") {
			proto = "tcp"
			addr = strings.TrimPrefix(s.target, "tcp://")
		}
		conn, err := net.Dial(proto, addr)
		if err != nil {
			return err
		}
		s.conn = conn
	}
	msg := Format(hostname, appName, e) + "\n"
	_, err := s.conn.Write([]byte(msg))
	return err
}

// Close closes the underlying connection.
func (s *Sender) Close() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}
