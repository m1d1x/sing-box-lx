package group

// hikkari: suspicion probe for mode: failover.
//
// A failure does not always surface as a dial error. XHTTP dials lazily, so a dead
// node hands back a working-looking connection and the error shows up on read;
// Hysteria2 parks the dial on a QUIC connection that lost its path; a node that
// went silent after the handshake gives no error at all. SPEC 054 sees none of
// these, and the group would sit on the node until the next tick while every new
// connection fails.
//
// So a connection that gets no first byte (it failed, or stayed silent past
// suspectResponseBudget) makes the held node a suspect, and the suspect gets one
// immediate probe. Only the probe decides. A dead site or a slow long-poll looks
// the same from here, and must not move anyone: the node answers and stays. If it
// does not answer, its history goes and the selection moves as after a failed tick.
// Connections on the node are left to end by themselves, as on any move.

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

var (
	// suspectResponseBudget is how long a connection may wait for its first byte
	// before its node gets probed. Cheap to be wrong about: it costs one probe.
	suspectResponseBudget = 3 * time.Second
	// suspectProbeBudget is how long the probe itself may take.
	suspectProbeBudget = 5 * time.Second
	// suspectGap limits probes after a suspect turned out fine, so a page full of
	// dead ad hosts costs at most two extra requests a minute through the tunnel.
	suspectGap = 30 * time.Second
)

// suspectTimer starts counting for a dial that may park. The returned stop must be
// called when the dial returns.
func (g *URLTestGroup) suspectTimer(network string, node adapter.Outbound) func() {
	if !g.failover || network != N.NetworkTCP {
		return func() {}
	}
	timer := time.AfterFunc(suspectResponseBudget, func() { g.suspect(node) })
	return func() { timer.Stop() }
}

// watchFirstResponse wraps a dialed connection until its first byte.
func (g *URLTestGroup) watchFirstResponse(network string, node adapter.Outbound, conn net.Conn) net.Conn {
	if !g.failover || network != N.NetworkTCP {
		return conn
	}
	return &firstResponseConn{Conn: conn, group: g, node: node}
}

// suspect probes the node if it is still the one held for TCP.
func (g *URLTestGroup) suspect(node adapter.Outbound) {
	if g.heldTCP() != node {
		return
	}
	if end := g.suspectEnd.Load(); end != 0 && time.Since(time.Unix(0, end)) < suspectGap {
		return
	}
	if !g.suspectRunning.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer g.suspectRunning.Store(false)
		tag := RealTag(g.outbound, node)
		delay, err := g.suspectProbe(node)
		if g.ctx.Err() != nil {
			return
		}
		if err == nil {
			g.logger.Debug("suspect ", tag, " answered: ", delay, "ms")
			g.penaltyReset(tag)
			g.history.StoreURLTestHistory(tag, &adapter.URLTestHistory{Time: time.Now(), Delay: delay})
			g.suspectEnd.Store(time.Now().UnixNano())
			return
		}
		g.logger.Info("suspect ", tag, " did not answer, moving: ", E.Cause(err, "probe"))
		g.history.DeleteURLTestHistory(tag)
		// Move to the fastest known node now, then let the usual check confirm it:
		// a stale neighbour that is dead too is replaced by the full run it escalates to.
		g.performSelectionUpdate(false)
		if !g.checking.Swap(true) {
			defer g.checking.Store(false)
			g.failoverCheck(g.ctx)
		}
	}()
}

// heldTCP reads the TCP selection under the lock performSelectionUpdate writes it
// with: this runs from timers, next to a move in progress.
func (g *URLTestGroup) heldTCP() adapter.Outbound {
	g.updateAccess.Lock()
	defer g.updateAccess.Unlock()
	return g.selectedOutboundTCP
}

func (g *URLTestGroup) suspectProbe(node adapter.Outbound) (uint16, error) {
	ctx, cancel := context.WithTimeout(g.ctx, suspectProbeBudget)
	defer cancel()
	// The test may outlive its context on a parked dial, as in urlTestBatch.
	result := make(chan urlTestResult, 1)
	go func() {
		delay, err := urltest.URLTest(ctx, g.link, node)
		result <- urlTestResult{delay, err}
	}()
	select {
	case got := <-result:
		return got.delay, got.err
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

// firstResponseConn reports a connection that ends or stays silent before its first
// byte. Afterwards it only passes calls through. It exposes the upstream so a lazy
// protocol stays discoverable (N.NeedHandshakeForWrite), but is not replaceable:
// the copy loop has to call its Read and Write.
type firstResponseConn struct {
	net.Conn
	group   *URLTestGroup
	node    adapter.Outbound
	settled atomic.Bool
	arm     sync.Once
	timer   atomic.Pointer[time.Timer]
}

func (c *firstResponseConn) settle() bool {
	if !c.settled.CompareAndSwap(false, true) {
		return false
	}
	if timer := c.timer.Load(); timer != nil {
		timer.Stop()
	}
	return true
}

func (c *firstResponseConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if c.settled.Load() {
		return n, err
	}
	if n > 0 {
		c.settle()
	} else if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) && c.settle() {
		c.group.suspect(c.node)
	}
	return n, err
}

// Write starts the wait: until something is sent, silence is not suspicious.
func (c *firstResponseConn) Write(p []byte) (int, error) {
	if !c.settled.Load() {
		c.arm.Do(func() {
			c.timer.Store(time.AfterFunc(suspectResponseBudget, func() {
				if c.settle() {
					c.group.suspect(c.node)
				}
			}))
			if c.settled.Load() {
				c.timer.Load().Stop()
			}
		})
	}
	return c.Conn.Write(p)
}

func (c *firstResponseConn) Close() error {
	c.settle()
	return c.Conn.Close()
}

func (c *firstResponseConn) Upstream() any           { return c.Conn }
func (c *firstResponseConn) ReaderReplaceable() bool { return false }
func (c *firstResponseConn) WriterReplaceable() bool { return false }
