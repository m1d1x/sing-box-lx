package dnsdiag

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestAddrTagNeverPrintsPublicAddress(t *testing.T) {
	for in, want := range map[string]string{
		"172.19.0.2:53": "172-19-0-2",
		"192.168.1.1":   "192-168-1-1",
		"77.88.8.8:53":  "public",
		"[fc00::1]:53":  "v6-private",
		"[2a00::1]:53":  "v6-public",
		"nonsense":      "unparsed",
	} {
		if got := AddrTag(in); got != want {
			t.Errorf("AddrTag(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClassifyReadsWrappedErrors(t *testing.T) {
	err := fmt.Errorf("yandex.ru.: %w", errors.New("write udp 1.2.3.4:5->6.7.8.9:53: write: no buffer space available"))
	if got := Classify(err); got != "enobufs" {
		t.Fatalf("got %q", got)
	}
	if got := Classify(errors.New("strange")); got != "other" {
		t.Fatalf("got %q", got)
	}
}

func TestCompactStackKeepsThePath(t *testing.T) {
	stack := "goroutine 7 [running]:\n" +
		"github.com/sagernet/sing-box/dns/transport/local.(*Transport).Exchange.func1(0x0?)\n" +
		"\t/w/dns/transport/local/local.go:151 +0x58\n" +
		"created by context.(*afterFuncCtx).cancel.func1 in goroutine 256411\n" +
		"\t/go/src/context/context.go:358 +0x24\n"
	want := "dns/transport/local.(*Transport).Exchange.func1@local/local.go:151 < created-by:context.(*afterFuncCtx).cancel.func1@context/context.go:358"
	if got := CompactStack(stack); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestWindowNamesAskersSocketsAndErrors(t *testing.T) {
	s := &stats{lastLine: time.Now()}
	s.reset()
	saved := global
	global = s
	defer func() { global = saved }()

	Hijack("sing-box", "yandex.ru.", "A")
	Hijack("sing-box", "yandex.ru.", "A")
	Hijack("", "dns-shop.ru.", "AAAA")
	Dialed("172.19.0.2:53", &net.UDPAddr{IP: net.IPv4(172, 19, 0, 1), Port: 5})
	Wrote("172.19.0.2:53", errors.New("write: no buffer space available"))
	HijackDone(errors.New("write: no buffer space available"), 6*time.Second)

	lines := strings.Join(s.window(time.Now()), "\n")
	for _, want := range []string{
		"hijack=3", "err={enobufs x1}", "max=6s", "sing-box yandex.ru. A x2; ? dns-shop.ru. AAAA x1",
		"server=172-19-0-2", "local=172-19-0-1/", "dials=1 writes=1 write_err={enobufs x1}",
	} {
		if !strings.Contains(lines, want) {
			t.Errorf("no %q in:\n%s", want, lines)
		}
	}
	if again := s.window(time.Now()); again != nil {
		t.Errorf("an emptied window still reports: %v", again)
	}
}

func TestQuietWindowWaitsForTheMinute(t *testing.T) {
	s := &stats{lastLine: time.Now()}
	s.reset()
	s.hijacks = 1
	s.askers["a b A"] = 1
	if lines := s.window(time.Now()); lines != nil {
		t.Fatalf("a quiet window logged: %v", lines)
	}
	if lines := s.window(s.lastLine.Add(quietEvery)); len(lines) == 0 {
		t.Fatal("a quiet minute logged nothing")
	}
}
