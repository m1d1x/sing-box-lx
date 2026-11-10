package urltest

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// A urltest group whose url is stun://host:port probes its members over UDP:
// one STUN binding request (RFC 5389) through the member's ListenPacket, the
// delay being the round trip of the first matching answer. An HTTP probe rides
// TCP, and a member whose TCP works says nothing about its UDP: VLESS and
// Naive carry UDP inside TCP, a datagram channel can be down while the stream
// channel is up. A group that carries calls has to be chosen by what calls use.
//
// The host is best given as an address: a name is passed to the member as it
// is, and a member that cannot carry a name in a datagram drops the probe.

const (
	stunMagic   = 0x2112A442
	stunAttempt = time.Second // a lost request is retried, as a call would not wait longer
)

func stunTest(ctx context.Context, host, port string, detour N.Dialer) (uint16, error) {
	if port == "" {
		port = "3478"
	}
	destination := M.ParseSocksaddrHostPortStr(host, port)
	conn, err := detour.ListenPacket(ctx, destination)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	var id [12]byte
	_, _ = rand.Read(id[:])
	request := make([]byte, 20)
	binary.BigEndian.PutUint16(request[0:], 0x0001)
	binary.BigEndian.PutUint32(request[4:], stunMagic)
	copy(request[8:], id[:])
	buffer := make([]byte, 1500)
	// A plain *net.UDPConn takes only a *net.UDPAddr; the members' packet
	// connections take either.
	var to net.Addr = destination
	if destination.IsIP() {
		to = destination.UDPAddr()
	}
	for ctx.Err() == nil {
		start := time.Now()
		if _, err = conn.WriteTo(request, to); err != nil {
			return 0, err
		}
		attemptEnd := start.Add(stunAttempt)
		if deadline, ok := ctx.Deadline(); ok && deadline.Before(attemptEnd) {
			attemptEnd = deadline
		}
		_ = conn.SetReadDeadline(attemptEnd)
		for {
			n, _, readErr := conn.ReadFrom(buffer)
			if readErr != nil {
				if E.IsTimeout(readErr) {
					break
				}
				return 0, readErr
			}
			if isSTUNAnswer(buffer[:n], id) {
				return uint16(time.Since(start) / time.Millisecond), nil
			}
		}
	}
	return 0, E.Cause(ctx.Err(), "stun probe to ", destination)
}

// isSTUNAnswer reports whether b answers the request with transaction id: a
// success or error response (class bits set) with the magic cookie.
func isSTUNAnswer(b []byte, id [12]byte) bool {
	if len(b) < 20 || binary.BigEndian.Uint16(b)&0x0100 == 0 || binary.BigEndian.Uint32(b[4:]) != stunMagic {
		return false
	}
	return string(b[8:20]) == string(id[:])
}
