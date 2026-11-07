// Package dnsdiag is Hikkari's temporary instrument for the DNS flood on a
// tester's Mac (tester-004, 04.11): thousands of "no buffer space available"
// per minute on direct names, then "panic: close of closed channel" in the
// local transport. It answers four questions from the log alone: who asks,
// where the local transport really sends the query, from which socket, and
// which path calls an exchange's callback twice.
//
// It only counts and logs. Remove it with the fix.
package dnsdiag

import (
	"fmt"
	"net"
	"net/netip"
	"path"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing/common/logger"
)

const (
	// flushEvery is one window. A quiet window waits for quietEvery.
	flushEvery = 10 * time.Second
	quietEvery = time.Minute
	// busyHijacks makes a window worth a line even with no errors.
	busyHijacks = 20
	topAskers   = 10
	// stackedDoubles is how many double callbacks carry both stacks. Later
	// ones only count: the path is what matters, and it is in the first ones.
	stackedDoubles = 5
	stackBufSize   = 16 << 10
)

type socketStat struct {
	dials, writes, replies int
	writeErrs              map[string]int
	local                  string
}

type stats struct {
	mu       sync.Mutex
	log      logger.Logger
	started  bool
	lastLine time.Time

	hijacks, drops, oks int
	errs                map[string]int
	maxLatency          time.Duration
	askers              map[string]int
	sockets             map[string]*socketStat
	doubles             int
}

var global = &stats{}

// Start begins flushing windows to log. The first call wins: one core process
// has one router.
func Start(log logger.Logger) {
	global.mu.Lock()
	defer global.mu.Unlock()
	if global.started || log == nil {
		return
	}
	global.started = true
	global.log = log
	global.reset()
	global.lastLine = time.Now()
	go func() {
		for range time.Tick(flushEvery) {
			global.flush(time.Now())
		}
	}()
}

// reset must be called with mu held.
func (s *stats) reset() {
	s.hijacks, s.drops, s.oks, s.doubles = 0, 0, 0, 0
	s.maxLatency = 0
	s.errs = make(map[string]int)
	s.askers = make(map[string]int)
	s.sockets = make(map[string]*socketStat)
}

func (s *stats) flush(now time.Time) {
	lines := s.window(now)
	if len(lines) == 0 {
		return
	}
	s.mu.Lock()
	log := s.log
	s.mu.Unlock()
	for _, line := range lines {
		log.Warn(line)
	}
}

// window closes the current window and returns its lines, none when it is not
// worth a line yet.
func (s *stats) window(now time.Time) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.errs == nil {
		return nil
	}
	socketTrouble := false
	for _, sk := range s.sockets {
		if len(sk.writeErrs) > 0 {
			socketTrouble = true
		}
	}
	trouble := len(s.errs) > 0 || s.drops > 0 || s.doubles > 0 || socketTrouble || s.hijacks >= busyHijacks
	active := s.hijacks > 0 || len(s.sockets) > 0
	if !trouble && !(active && now.Sub(s.lastLine) >= quietEvery) {
		return nil
	}
	lines := []string{fmt.Sprintf("[dns-diag] window hijack=%d drop=%d ok=%d err=%s max=%s double=%d top=[%s]",
		s.hijacks, s.drops, s.oks, formatCounts(s.errs), s.maxLatency.Round(time.Millisecond), s.doubles, formatTop(s.askers, topAskers))}
	servers := make([]string, 0, len(s.sockets))
	for server := range s.sockets {
		servers = append(servers, server)
	}
	sort.Strings(servers)
	for _, server := range servers {
		sk := s.sockets[server]
		lines = append(lines, fmt.Sprintf("[dns-diag] socket server=%s local=%s dials=%d writes=%d write_err=%s replies=%d",
			server, sk.local, sk.dials, sk.writes, formatCounts(sk.writeErrs), sk.replies))
	}
	s.reset()
	s.lastLine = now
	return lines
}

// Hijack counts a query the TUN handed to the router.
func Hijack(process, name, qtype string) {
	if process == "" {
		process = "?"
	}
	global.mu.Lock()
	defer global.mu.Unlock()
	if global.errs == nil {
		return
	}
	global.hijacks++
	global.askers[process+" "+name+" "+qtype]++
}

// HijackDropped counts a query lost to the hijack concurrency limit.
func HijackDropped() {
	global.mu.Lock()
	defer global.mu.Unlock()
	if global.errs != nil {
		global.drops++
	}
}

// HijackDone records how a hijacked query ended.
func HijackDone(err error, latency time.Duration) {
	global.mu.Lock()
	defer global.mu.Unlock()
	if global.errs == nil {
		return
	}
	if latency > global.maxLatency {
		global.maxLatency = latency
	}
	if err == nil {
		global.oks++
		return
	}
	global.errs[Classify(err)]++
}

func (s *stats) socket(server string) *socketStat {
	sk := s.sockets[server]
	if sk == nil {
		sk = &socketStat{writeErrs: make(map[string]int)}
		s.sockets[server] = sk
	}
	return sk
}

// Dialed records a new socket of a plain DNS transport: where it sends and the
// address and interface the system chose for it. A local address on a utun
// means the query goes back into a tunnel.
func Dialed(server string, local net.Addr) {
	global.mu.Lock()
	defer global.mu.Unlock()
	if global.errs == nil {
		return
	}
	sk := global.socket(AddrTag(server))
	sk.dials++
	sk.local = LocalTag(local)
}

// Wrote records one write of a query.
func Wrote(server string, err error) {
	global.mu.Lock()
	defer global.mu.Unlock()
	if global.errs == nil {
		return
	}
	sk := global.socket(AddrTag(server))
	sk.writes++
	if err != nil {
		sk.writeErrs[Classify(err)]++
	}
}

// Replied records one datagram read from a resolver.
func Replied(server string) {
	global.mu.Lock()
	defer global.mu.Unlock()
	if global.errs != nil {
		global.socket(AddrTag(server)).replies++
	}
}

// LocalConfig logs the system resolver setting the local transport works from.
func LocalConfig(log logger.Logger, servers []string, attempts int, timeout time.Duration, useTCP bool) {
	tags := make([]string, 0, len(servers))
	for _, server := range servers {
		tags = append(tags, AddrTag(server))
	}
	log.Warn(fmt.Sprintf("[dns-diag] local config servers=[%s] attempts=%d timeout=%s tcp=%v", strings.Join(tags, " "), attempts, timeout, useTCP))
}

// Stack is the calling goroutine's stack, compact enough for one log line.
func Stack() string {
	buffer := make([]byte, stackBufSize)
	return CompactStack(string(buffer[:runtime.Stack(buffer, false)]))
}

// DoubleCallback reports an exchange whose callback ran again, with the stack
// of each call.
func DoubleCallback(log logger.Logger, name string, ctxErr, firstErr, secondErr error, gap time.Duration, firstStack string) {
	global.mu.Lock()
	var nth int
	if global.errs != nil {
		global.doubles++
	}
	doubleCount++
	nth = doubleCount
	global.mu.Unlock()
	if nth > stackedDoubles {
		return
	}
	log.Error(fmt.Sprintf("[dns-diag] double callback #%d name=%s ctx=%v gap=%s first_err=%v second_err=%v first_stack=%s second_stack=%s",
		nth, name, ctxErr, gap.Round(time.Microsecond), firstErr, secondErr, firstStack, Stack()))
}

var doubleCount int

// AddrTag names a resolver without the form the client's log sanitizer erases.
// Private addresses are this machine's and its router's and say what the check
// needs: 172-19-0-2 is the core's own TUN. A public one stays a class.
func AddrTag(hostPort string) string {
	host := hostPort
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		host = h
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return "unparsed"
	}
	address = address.Unmap()
	if address.IsLoopback() || address.IsPrivate() || address.IsLinkLocalUnicast() || address.IsUnspecified() {
		if address.Is4() {
			return strings.ReplaceAll(address.String(), ".", "-")
		}
		return "v6-private"
	}
	if address.Is4() {
		return "public"
	}
	return "v6-public"
}

// LocalTag is a socket's local address and the interface that holds it.
func LocalTag(local net.Addr) string {
	if local == nil {
		return "none"
	}
	tag := AddrTag(local.String())
	host, _, err := net.SplitHostPort(local.String())
	if err != nil {
		return tag
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return tag
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return tag
	}
	for _, iface := range interfaces {
		addresses, addrErr := iface.Addrs()
		if addrErr != nil {
			continue
		}
		for _, candidate := range addresses {
			if prefix, parseErr := netip.ParsePrefix(candidate.String()); parseErr == nil && prefix.Addr().Unmap() == address.Unmap() {
				return tag + "/" + iface.Name
			}
		}
	}
	return tag + "/?"
}

// Classify reduces an error to a stable word. It reads the text: the errnos it
// names do not all exist on every platform, and wrapped DNS errors keep them
// only in the message.
func Classify(err error) string {
	message := strings.ToLower(err.Error())
	for _, known := range []struct{ needle, word string }{
		{"no buffer space", "enobufs"},
		{"no route to host", "no_route"},
		{"network is unreachable", "net_unreach"},
		{"network is down", "net_down"},
		{"can't assign requested address", "addr_not_avail"},
		{"connection refused", "refused"},
		{"operation not permitted", "eperm"},
		{"use of closed network connection", "closed"},
		{"deadline exceeded", "deadline"},
		{"i/o timeout", "timeout"},
		{"query timeout", "timeout"},
		{"context canceled", "canceled"},
		{"rejected", "rejected"},
	} {
		if strings.Contains(message, known.needle) {
			return known.word
		}
	}
	return "other"
}

// CompactStack turns runtime.Stack output into "func@file:line < ..." with the
// innermost call first and the spawning goroutine kept as "created-by".
func CompactStack(stack string) string {
	lines := strings.Split(strings.TrimSpace(stack), "\n")
	frames := make([]string, 0, len(lines)/2)
	for i := 1; i+1 < len(lines); i += 2 {
		function := lines[i]
		if strings.HasPrefix(function, "created by ") {
			function = "created-by:" + strings.Fields(strings.TrimPrefix(function, "created by "))[0]
		} else if open := strings.LastIndex(function, "("); open > 0 {
			function = function[:open]
		}
		function = strings.TrimPrefix(function, "github.com/sagernet/sing-box/")
		location := strings.Fields(strings.TrimSpace(lines[i+1]))[0]
		frames = append(frames, function+"@"+path.Base(path.Dir(location))+"/"+path.Base(location))
	}
	return strings.Join(frames, " < ")
}

func formatCounts(counts map[string]int) string {
	if len(counts) == 0 {
		return "{}"
	}
	return "{" + formatTop(counts, len(counts)) + "}"
}

// formatTop lists the largest counts first, ties by name.
func formatTop(counts map[string]int, limit int) string {
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	if len(keys) > limit {
		keys = keys[:limit]
	}
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s x%d", key, counts[key]))
	}
	return strings.Join(parts, "; ")
}
