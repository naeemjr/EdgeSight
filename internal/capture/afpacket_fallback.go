//go:build !linux

package capture

import (
	"fmt"

	"edgesight/internal/config"

	"github.com/google/gopacket"
)

// AFPacketSource is a stub on non-Linux platforms.
type AFPacketSource struct{}

// NewAFPacketSource creates a stub source.
func NewAFPacketSource() *AFPacketSource { return &AFPacketSource{} }

func (a *AFPacketSource) Init(cfg *config.Config) error {
	return fmt.Errorf("AF_PACKET only supported on Linux")
}
func (a *AFPacketSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return nil, gopacket.CaptureInfo{}, fmt.Errorf("AF_PACKET only supported on Linux")
}
func (a *AFPacketSource) Close() {}
func (a *AFPacketSource) SetBPFFilter(expr string) error {
	return fmt.Errorf("AF_PACKET only supported on Linux")
}
