package urltest

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	N "github.com/sagernet/sing/common/network"
)

// stunServer answers binding requests, ignoring the first drop of them.
func stunServer(t *testing.T, drop int) string {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		b := make([]byte, 1500)
		for {
			n, from, err := c.ReadFromUDP(b)
			if err != nil {
				return
			}
			if n < 20 {
				continue
			}
			if drop > 0 {
				drop--
				continue
			}
			resp := make([]byte, 20)
			binary.BigEndian.PutUint16(resp, 0x0101)
			copy(resp[4:], b[4:20])
			_, _ = c.WriteToUDP(resp, from)
		}
	}()
	return c.LocalAddr().String()
}

func TestURLTestOverSTUN(t *testing.T) {
	addr := stunServer(t, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := URLTest(ctx, "stun://"+addr, N.SystemDialer); err != nil {
		t.Fatalf("live STUN: %v", err)
	}
	// A lost request is sent again within the probe's time.
	if _, err := URLTest(ctx, "stun://"+stunServer(t, 1), N.SystemDialer); err != nil {
		t.Fatalf("one lost request: %v", err)
	}
}

func TestURLTestOverSTUNSilent(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}) // answers nothing
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := URLTest(ctx, "stun://"+c.LocalAddr().String(), N.SystemDialer); err == nil {
		t.Fatal("a silent path passed")
	}
	if time.Since(start) > 4*time.Second {
		t.Fatalf("probe outlived its context: %v", time.Since(start))
	}
}

func TestSTUNAnswerMatchesTransaction(t *testing.T) {
	id := [12]byte{1, 2, 3}
	resp := make([]byte, 20)
	binary.BigEndian.PutUint16(resp, 0x0101)
	binary.BigEndian.PutUint32(resp[4:], stunMagic)
	copy(resp[8:], id[:])
	if !isSTUNAnswer(resp, id) {
		t.Fatal("answer not matched")
	}
	if isSTUNAnswer(resp, [12]byte{9}) {
		t.Fatal("another transaction matched")
	}
	binary.BigEndian.PutUint16(resp, 0x0001) // a request
	if isSTUNAnswer(resp, id) {
		t.Fatal("a request matched")
	}
}
