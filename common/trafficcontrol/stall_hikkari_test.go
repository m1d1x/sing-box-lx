package trafficcontrol

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestAStallIsTheTunnelAskedAndSilentUntilAnyByteComesBack(t *testing.T) {
	var s stallMeter
	s.up(500)
	time.Sleep(350 * time.Millisecond)
	s.down(1)
	got := s.totals()
	if got.Count[0] != 1 || got.Count[1] != 0 {
		t.Fatalf("one stall past 300 ms and none past 1 s, got %+v", got)
	}
	if got.MS[0] < 350 || got.MS[0] > 1000 {
		t.Fatalf("the stall's length in ms, got %d", got.MS[0])
	}

	// The wait is closed: more bytes back are not another stall.
	s.down(100)
	if s.totals().Count[0] != 1 {
		t.Fatal("bytes back with nothing asked counted a stall")
	}
}

func TestAKeepaliveIsNotAQuestion(t *testing.T) {
	var s stallMeter
	s.up(stallMinAsk - 1)
	time.Sleep(320 * time.Millisecond)
	s.down(1)
	if got := s.totals(); got.Count[0] != 0 {
		t.Fatalf("a wait after %d bytes counted, got %+v", stallMinAsk-1, got)
	}
}

func TestAStallStartsAtTheFirstByteUp(t *testing.T) {
	var s stallMeter
	s.up(100)
	time.Sleep(200 * time.Millisecond)
	s.up(300)
	time.Sleep(150 * time.Millisecond)
	s.down(1)
	if got := s.totals(); got.Count[0] != 1 || got.MS[0] < 350 {
		t.Fatalf("the stall runs from the first byte up, got %+v", got)
	}
}

func TestALongStallCountsUnderEveryBoundItPassed(t *testing.T) {
	var s stallMeter
	s.record(3500)
	s.record(1200)
	got := s.totals()
	want := []int64{2, 2, 1}
	for i := range want {
		if got.Count[i] != want[i] {
			t.Fatalf("counts per bound %v, got %v", want, got.Count)
		}
	}
	if got.MS[0] != 4700 || got.MS[2] != 3500 {
		t.Fatalf("ms per bound, got %v", got.MS)
	}
}

func TestOnlyTheTunnelIsTimed(t *testing.T) {
	m := &Manager{}
	for _, kind := range []string{"direct", "block", "dns", ""} {
		md := &TrackerMetadata{Upload: new(atomic.Int64), Download: new(atomic.Int64), OutboundType: kind}
		read, write := m.stallCounters(md)
		write(500)
		time.Sleep(310 * time.Millisecond)
		read(10)
		if md.Upload.Load() != 500 || md.Download.Load() != 10 {
			t.Fatalf("%q: byte totals not kept", kind)
		}
	}
	if got := m.Stalls(); got.Count[0] != 0 {
		t.Fatalf("traffic outside the tunnel counted, got %+v", got)
	}
	md := &TrackerMetadata{Upload: new(atomic.Int64), Download: new(atomic.Int64), OutboundType: "hikkari"}
	read, write := m.stallCounters(md)
	write(500)
	time.Sleep(310 * time.Millisecond)
	read(10)
	if got := m.Stalls(); got.Count[0] != 1 {
		t.Fatalf("a tunnel stall not counted, got %+v", got)
	}
}
