package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/mdlayher/packet"
)

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func main() {
	ifi, err := net.InterfaceByName(os.Args[1])
	if err != nil {
		panic(err)
	}
	conn, err := packet.Listen(ifi, packet.Raw, 0x0003, nil)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	if os.Getenv("PROMISC") == "1" {
		if err := conn.SetPromiscuous(true); err != nil {
			panic(err)
		}
	}
	buf := make([]byte, 65535)
	deadline := time.Now().Add(8 * time.Second)
	n := 0
	for time.Now().Before(deadline) {
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		nb, _, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		if nb > 0 {
			n++
		}
	}
	fmt.Printf("packets_seen=%d\n", n)
}
