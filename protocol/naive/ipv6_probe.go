//go:build with_naive_outbound

package naive

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

// Chromium asks whether IPv6 is reachable before it resolves a name: a UDP
// socket connected, never written to, toward Google DNS on port 443
// (net/dns/host_resolver_manager.cc, StartGloballyReachableCheck, result kept
// for a second). cronet-go dials that socket through the outbound's dialer and
// logs a failed dial as an error, so on a network without IPv6 every
// resolution of the server's name read
//
//	ERROR outbound/naive[…]: open UDP connection to [2001:4860:4860::8888]:443: … unreachable network
//
// It is not QUIC (the engine runs with QUIC off unless `quic` is set) and not
// a fault: the failed connect is Chromium's answer "no IPv6 here", which it
// acts on by asking for IPv4 only. ipv6ProbeLogger says that line at debug and
// passes every other line through unchanged.
var ipv6ProbeAddr = netip.AddrFrom16([16]byte{0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 14: 0x88, 15: 0x88})

type ipv6ProbeLogger struct {
	logger.ContextLogger
}

func (l ipv6ProbeLogger) ErrorContext(ctx context.Context, args ...any) {
	if isIPv6ProbeFailure(args) {
		l.ContextLogger.DebugContext(ctx, args...)
		return
	}
	l.ContextLogger.ErrorContext(ctx, args...)
}

// isIPv6ProbeFailure matches cronet-go's line for a UDP dial that failed:
// "open UDP connection to ", destination, ": ", err.
func isIPv6ProbeFailure(args []any) bool {
	if len(args) < 2 {
		return false
	}
	if prefix, ok := args[0].(string); !ok || prefix != "open UDP connection to " {
		return false
	}
	destination, ok := args[1].(M.Socksaddr)
	return ok && destination.Addr == ipv6ProbeAddr
}
