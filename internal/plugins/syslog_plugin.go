package plugins

import (
	"context"
	"fmt"
	"os"

	"edgesight/internal/config"
	"edgesight/internal/syslog"
	"edgesight/pkg/protocol"
)

// SyslogPlugin emits events as RFC 5424 syslog messages.
type SyslogPlugin struct {
	sender   *syslog.Sender
	hostname string
}

func (s *SyslogPlugin) Name() string { return "syslog" }

func (s *SyslogPlugin) Init(cfg *config.Config) error {
	if cfg.SyslogTarget == "" {
		return fmt.Errorf("syslog plugin requires syslog_target")
	}
	s.sender = syslog.NewSender(cfg.SyslogTarget)
	s.hostname, _ = os.Hostname()
	return nil
}

func (s *SyslogPlugin) HandleEvent(ctx context.Context, e *protocol.Event) error {
	return s.sender.Send(s.hostname, "edgesight", e)
}

func (s *SyslogPlugin) Close() error {
	if s.sender != nil {
		return s.sender.Close()
	}
	return nil
}
