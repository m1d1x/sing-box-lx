package trafficcontrol

// hikkari: tunnel stalls in milliseconds (hikkari-client plans/ROADMAP.md, 3.3).
//
// The client's downtime meter looks at the connection list every 5 seconds,
// so a pause shorter than that is invisible to it. The core sees every byte
// as it moves, so it times the pauses itself: a stall is the time from the
// first byte an app sent through the tunnel after the last byte that came back
// from it, on any connection, to the next byte back. One byte back on any
// tunnel connection ends it. So a stall is the tunnel as a whole asked and
// silent, not one slow site among others that answer.
//
// Only connections through a proxy outbound count: direct, block and DNS
// traffic says nothing about the tunnel. What is kept is counts and sums per
// threshold, nothing about the connection, its destination or its bytes.
//
// A stall also holds the far server's own thinking time and the round trip,
// which a tunnel cannot take away, so the thresholds start above an ordinary
// answer and the counts are read against their own baseline, not as zero.

import (
	"sync/atomic"
	"time"

	C "github.com/sagernet/sing-box/constant"
)

// StallBoundsMS are the thresholds a stall is counted against, in ms.
var StallBoundsMS = [...]int64{300, 1000, 3000}

// stallMinAsk is the least an app must have sent for the silence after it to
// count: a lone keepalive is not a question (as the client's meter).
const stallMinAsk = 200

// StallTotals are the stalls since the core started, one value per bound:
// how many stalls lasted at least the bound, and their whole length in ms.
type StallTotals struct {
	BoundsMS []int64 `json:"bounds_ms"`
	Count    []int64 `json:"count"`
	MS       []int64 `json:"ms"`
}

type stallMeter struct {
	// askedAt is the unix nanoseconds of the first byte up since the last
	// byte down, 0 while nothing waits.
	askedAt atomic.Int64
	// asked is the bytes up since the last byte down.
	asked atomic.Int64
	count [len(StallBoundsMS)]atomic.Int64
	ms    [len(StallBoundsMS)]atomic.Int64
}

// up notes bytes an app sent through the tunnel. The common case, a wait
// already open and large enough, only reads, so a busy tunnel does not fight
// over one cache line.
func (s *stallMeter) up(n int64) {
	if n <= 0 {
		return
	}
	if s.askedAt.Load() != 0 && s.asked.Load() >= stallMinAsk {
		return
	}
	s.askedAt.CompareAndSwap(0, time.Now().UnixNano())
	s.asked.Add(n)
}

// down notes bytes that came back through the tunnel and closes the wait.
func (s *stallMeter) down(n int64) {
	if n <= 0 || s.askedAt.Load() == 0 {
		return
	}
	at := s.askedAt.Swap(0)
	asked := s.asked.Swap(0)
	if at == 0 || asked < stallMinAsk {
		return
	}
	s.record((time.Now().UnixNano() - at) / int64(time.Millisecond))
}

func (s *stallMeter) record(waitMS int64) {
	for i, bound := range StallBoundsMS {
		if waitMS < bound {
			return
		}
		s.count[i].Add(1)
		s.ms[i].Add(waitMS)
	}
}

func (s *stallMeter) totals() StallTotals {
	t := StallTotals{
		BoundsMS: StallBoundsMS[:],
		Count:    make([]int64, len(StallBoundsMS)),
		MS:       make([]int64, len(StallBoundsMS)),
	}
	for i := range StallBoundsMS {
		t.Count[i] = s.count[i].Load()
		t.MS[i] = s.ms[i].Load()
	}
	return t
}

// Stalls are the tunnel's stalls since the core started.
func (m *Manager) Stalls() StallTotals { return m.stalls.totals() }

// throughTunnel reports whether a connection's final outbound is a proxy.
func throughTunnel(outboundType string) bool {
	switch outboundType {
	case "", C.TypeDirect, C.TypeBlock, C.TypeDNS:
		return false
	}
	return true
}

// stallCounters are the read and write counters of a connection: its own
// byte totals, and the stall meter when it goes through the tunnel.
func (m *Manager) stallCounters(metadata *TrackerMetadata) (read, write func(int64)) {
	upload, download := metadata.Upload, metadata.Download
	if !throughTunnel(metadata.OutboundType) {
		return func(n int64) { download.Add(n) }, func(n int64) { upload.Add(n) }
	}
	return func(n int64) {
			download.Add(n)
			m.stalls.down(n)
		}, func(n int64) {
			upload.Add(n)
			m.stalls.up(n)
		}
}
