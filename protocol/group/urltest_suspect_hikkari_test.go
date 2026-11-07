package group

import (
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
)

func newSuspectGroup(t *testing.T) (g *URLTestGroup, held, spare *penaltyDialNode) {
	t.Helper()
	held = &penaltyDialNode{tag: "held", addr: "server"}
	spare = &penaltyDialNode{tag: "spare", addr: "server"}
	g = newPenaltyTestGroup(t, []*penaltyDialNode{held, spare}, map[string]uint16{"held": 10, "spare": 50})
	g.failover = true
	g.selectedOutboundTCP = held
	g.selectedOutboundUDP = held
	return g, held, spare
}

func waitSuspect(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for ", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestSuspectThatDoesNotAnswerLosesTheSelection(t *testing.T) {
	g, held, spare := newSuspectGroup(t)
	held.err = syscall.ECONNRESET
	g.suspect(held)
	waitSuspect(t, "the move", func() bool { return g.heldTCP() == adapter.Outbound(spare) })
	waitSuspect(t, "the check after the move", func() bool { return !g.suspectRunning.Load() })
	if g.selectedOutboundUDP != adapter.Outbound(spare) {
		t.Fatal("UDP held on the same node must move too")
	}
	if g.history.LoadURLTestHistory("held") != nil {
		t.Fatal("the dead node keeps no history")
	}
}

// A dead site looks exactly like a dead node from one connection. The probe decides.
func TestSuspectThatAnswersStays(t *testing.T) {
	g, held, _ := newSuspectGroup(t)
	g.suspect(held)
	waitSuspect(t, "the probe", func() bool { return g.suspectEnd.Load() != 0 })
	waitSuspect(t, "the probe to finish", func() bool { return !g.suspectRunning.Load() })
	if g.heldTCP() != adapter.Outbound(held) {
		t.Fatal("a node that answers must keep the selection")
	}
	dials := held.dials
	g.suspect(held)
	time.Sleep(50 * time.Millisecond)
	if held.dials != dials {
		t.Fatal("a second suspicion inside suspectGap must not probe")
	}
}

func TestSuspectIgnoresNodeNoLongerHeld(t *testing.T) {
	g, held, spare := newSuspectGroup(t)
	g.selectedOutboundTCP = spare
	g.suspect(held)
	time.Sleep(50 * time.Millisecond)
	if held.dials != 0 {
		t.Fatal("old connections must not trigger probes of a node already left")
	}
}

type suspectRecorder struct {
	net.Conn
	readErr error
	reads   chan []byte
}

func (c *suspectRecorder) Read(p []byte) (int, error) {
	data, ok := <-c.reads
	if !ok {
		return 0, c.readErr
	}
	return copy(p, data), nil
}
func (c *suspectRecorder) Write(p []byte) (int, error) { return len(p), nil }
func (c *suspectRecorder) Close() error                { return nil }

func watched(g *URLTestGroup, node adapter.Outbound, readErr error) (*firstResponseConn, *suspectRecorder) {
	inner := &suspectRecorder{readErr: readErr, reads: make(chan []byte, 1)}
	return g.watchFirstResponse(N.NetworkTCP, node, inner).(*firstResponseConn), inner
}

func TestFailureBeforeFirstByteIsSuspicious(t *testing.T) {
	g, held, spare := newSuspectGroup(t)
	held.err = syscall.ECONNRESET
	conn, inner := watched(g, held, io.EOF)
	close(inner.reads)
	_, _ = conn.Read(make([]byte, 8))
	waitSuspect(t, "the move", func() bool { return g.heldTCP() == adapter.Outbound(spare) })
}

func TestFailureAfterFirstByteIsNot(t *testing.T) {
	g, held, _ := newSuspectGroup(t)
	held.err = syscall.ECONNRESET
	conn, inner := watched(g, held, io.EOF)
	inner.reads <- []byte("x")
	_, _ = conn.Read(make([]byte, 8))
	close(inner.reads)
	_, _ = conn.Read(make([]byte, 8))
	time.Sleep(50 * time.Millisecond)
	if held.dials != 0 {
		t.Fatal("a connection that was answered ended normally for the node")
	}
}

func TestSilenceAfterWriteIsSuspiciousButNotBeforeIt(t *testing.T) {
	old := suspectResponseBudget
	suspectResponseBudget = 20 * time.Millisecond
	defer func() { suspectResponseBudget = old }()
	g, held, spare := newSuspectGroup(t)
	held.err = syscall.ECONNRESET
	conn, _ := watched(g, held, io.EOF)
	time.Sleep(60 * time.Millisecond)
	if held.dials != 0 {
		t.Fatal("nothing was sent, silence means nothing yet")
	}
	_, _ = conn.Write([]byte("request"))
	waitSuspect(t, "the move", func() bool { return g.heldTCP() == adapter.Outbound(spare) })
}

func TestClosingBeforeAnswerIsNotSuspicious(t *testing.T) {
	old := suspectResponseBudget
	suspectResponseBudget = 20 * time.Millisecond
	defer func() { suspectResponseBudget = old }()
	g, held, _ := newSuspectGroup(t)
	held.err = syscall.ECONNRESET
	conn, _ := watched(g, held, io.EOF)
	_, _ = conn.Write([]byte("request"))
	_ = conn.Close()
	time.Sleep(60 * time.Millisecond)
	if held.dials != 0 {
		t.Fatal("the client walked away, the node did nothing wrong")
	}
}

func TestLeastTestIsNotWatched(t *testing.T) {
	g, held, _ := newSuspectGroup(t)
	g.failover = false
	inner := &suspectRecorder{}
	if g.watchFirstResponse(N.NetworkTCP, held, inner) != net.Conn(inner) {
		t.Fatal("only failover groups are watched")
	}
}
