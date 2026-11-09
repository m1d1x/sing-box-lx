//go:build with_naive_outbound

package naive

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

type levelLogger struct {
	logger.ContextLogger
	lines []string
}

func (l *levelLogger) ErrorContext(_ context.Context, args ...any) {
	l.lines = append(l.lines, "ERROR "+fmt.Sprint(args...))
}

func (l *levelLogger) DebugContext(_ context.Context, args ...any) {
	l.lines = append(l.lines, "DEBUG "+fmt.Sprint(args...))
}

func TestIPv6ProbeFailureIsDebug(t *testing.T) {
	if ipv6ProbeAddr.String() != "2001:4860:4860::8888" {
		t.Fatalf("probe address %s", ipv6ProbeAddr)
	}
	base := &levelLogger{ContextLogger: logger.NOP()}
	l := ipv6ProbeLogger{base}
	unreachable := errors.New("connect: A socket operation was attempted to an unreachable network")
	l.ErrorContext(context.Background(), "open UDP connection to ", M.ParseSocksaddr("[2001:4860:4860::8888]:443"), ": ", unreachable)
	// The relay, another IPv6 host, and any other error stay errors.
	l.ErrorContext(context.Background(), "open UDP connection to ", M.ParseSocksaddr("203.0.113.5:443"), ": ", unreachable)
	l.ErrorContext(context.Background(), "open UDP connection to ", M.ParseSocksaddr("[2001:db8::1]:443"), ": ", unreachable)
	l.ErrorContext(context.Background(), "socket pair failed: ", unreachable)
	want := []string{"DEBUG", "ERROR", "ERROR", "ERROR"}
	if len(base.lines) != len(want) {
		t.Fatalf("lines %q", base.lines)
	}
	for i, w := range want {
		if !strings.HasPrefix(base.lines[i], w+" ") {
			t.Fatalf("line %d: %q, want %s", i, base.lines[i], w)
		}
	}
}
