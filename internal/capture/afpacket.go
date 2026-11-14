//go:build linux

package capture

import (
	"fmt"
	"net"
	"time"

	"edgesight/internal/config"

	"github.com/google/gopacket"
	"github.com/mdlayher/packet"
)

// AFPacketSource wraps mdlayher/packet for pure-Go Linux AF_PACKET capture.
type AFPacketSource struct {
	conn *packet.Conn
	buf  []byte
}

// NewAFPacketSource creates a Linux AF_PACKET source.
func NewAFPacketSource() *AFPacketSource { return &AFPacketSource{} }

func (a *AFPacketSource) Init(cfg *config.Config) error {
	ifi, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return fmt.Errorf("interface %s: %w", cfg.Interface, err)
	}
	conn, err := packet.Listen(ifi, packet.Raw, int(htons(0x0003)), nil) // ETH_P_ALL
	if err != nil {
		return fmt.Errorf("packet listen: %w", err)
	}
	if cfg.Promiscuous {
		if err := conn.SetPromiscuous(true); err != nil {
			conn.Close()
			return fmt.Errorf("promiscuous: %w", err)
		}
	}
	a.conn = conn
	a.buf = make([]byte, cfg.MaxPacketSize)
	return nil
}

func htons(v uint16) uint16 {
	return v<<8 | v>>8
}

func (a *AFPacketSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	n, _, err := a.conn.ReadFrom(a.buf)
	if err != nil {
		return nil, gopacket.CaptureInfo{}, err
	}
	data := make([]byte, n)
	copy(data, a.buf[:n])
	return data, gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: n,
		Length:        n,
	}, nil
}

func (a *AFPacketSource) Close() {
	if a.conn != nil {
		a.conn.Close()
	}
}

func (a *AFPacketSource) SetBPFFilter(expr string) error {
	// Compiling pcap-style BPF expressions requires libpcap/CGO.
	return fmt.Errorf("BPF string compilation requires CGO/libpcap; use userspace filtering instead")
}
