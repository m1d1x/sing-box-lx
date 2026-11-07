package group

import (
	"context"
	"encoding/binary"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// voiceNode is a node whose UDP leads to its own STUN server. silent drops every
// request; refused fails every new socket at once, as a reset does; staleFirst
// makes only the first socket silent, as a flow stuck on a connection that broke
// while the node itself is fine.
type voiceNode struct {
	*penaltyDialNode
	server     *net.UDPConn
	silent     atomic.Bool
	refused    atomic.Bool
	staleFirst bool
	listens    atomic.Int32
}

func newVoiceNode(t *testing.T, tag string) *voiceNode {
	t.Helper()
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	n := &voiceNode{penaltyDialNode: &penaltyDialNode{tag: tag, addr: "server"}, server: server}
	go func() {
		buffer := make([]byte, 1500)
		for {
			size, from, err := server.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			if n.silent.Load() || size < 20 {
				continue
			}
			response := make([]byte, 20)
			binary.BigEndian.PutUint16(response[0:], 0x0101)
			binary.BigEndian.PutUint32(response[4:], stunMagicCookie)
			copy(response[8:], buffer[8:20])
			_, _ = server.WriteToUDP(response, from)
		}
	}()
	return n
}

func (n *voiceNode) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if n.refused.Load() {
		return nil, syscall.ECONNRESET
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	stale := n.listens.Add(1) == 1 && n.staleFirst
	return &voiceNodeConn{UDPConn: conn, node: n, stale: stale}, nil
}

// voiceNodeConn sends everything to the node's server, whatever the address.
type voiceNodeConn struct {
	*net.UDPConn
	node  *voiceNode
	stale bool
}

func (c *voiceNodeConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if c.stale {
		return len(p), nil
	}
	return c.UDPConn.WriteTo(p, c.node.server.LocalAddr())
}

func fastVoiceTimers(t *testing.T) {
	t.Helper()
	interval, timeout, verify, active := voicePingInterval, voicePingTimeout, voiceVerifyWindow, voiceActiveWindow
	voicePingInterval, voicePingTimeout, voiceVerifyWindow = 20*time.Millisecond, 40*time.Millisecond, 100*time.Millisecond
	voiceActiveWindow = 200 * time.Millisecond
	t.Cleanup(func() {
		voicePingInterval, voicePingTimeout, voiceVerifyWindow, voiceActiveWindow = interval, timeout, verify, active
	})
}

func newVoiceGroup(t *testing.T) (g *URLTestGroup, held, spare, third *voiceNode) {
	t.Helper()
	fastVoiceTimers(t)
	held, spare, third = newVoiceNode(t, "held"), newVoiceNode(t, "spare"), newVoiceNode(t, "third")
	g = newPenaltyTestGroup(t, []*penaltyDialNode{held.penaltyDialNode, spare.penaltyDialNode, third.penaltyDialNode},
		map[string]uint16{"held": 10, "spare": 50, "third": 30})
	g.outbounds = []adapter.Outbound{held, spare, third}
	g.outbound = &fakeManager{byTag: map[string]adapter.Outbound{"held": held, "spare": spare, "third": third}}
	g.failover = true
	g.selectedOutboundTCP = held
	g.selectedOutboundUDP = held
	ctx, cancel := context.WithCancel(context.Background())
	g.ctx = ctx
	// The watchdog must be gone before the timers are restored.
	t.Cleanup(func() {
		cancel()
		waitSuspect(t, "the watchdog to stop", func() bool { return !g.voiceRunning.Load() })
	})
	return g, held, spare, third
}

// call keeps a flow active the way voiceFlowConn does, until the test ends.
func call(t *testing.T, g *URLTestGroup) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		for ctx.Err() == nil {
			g.voiceFlow()
			time.Sleep(10 * time.Millisecond)
		}
	}()
}

func heldUDPTag(g *URLTestGroup) string {
	g.access.Lock()
	defer g.access.Unlock()
	return g.selectedOutboundUDP.Tag()
}

func TestVoiceSilentNodeLosesUDPToFastestCandidate(t *testing.T) {
	g, held, _, _ := newVoiceGroup(t)
	call(t, g)
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	held.silent.Store(true)
	waitSuspect(t, "the UDP move", func() bool { return heldUDPTag(g) != "held" })
	if tag := heldUDPTag(g); tag != "third" {
		t.Fatalf("UDP must move to the fastest candidate, got %s", tag)
	}
	if elapsed := time.Since(start); elapsed > 20*voicePingInterval {
		t.Fatalf("move took %s", elapsed)
	}
	// TCP has its own probe: the node still answers HTTP, so TCP stays.
	waitSuspect(t, "the TCP probe", func() bool { return g.suspectEnd.Load() != 0 })
	if g.heldTCP() != adapter.Outbound(held) {
		t.Fatal("TCP must stay on a node that answers its own probe")
	}
}

// A reset fails the suspect's fresh socket at once; that must not cut short the
// wait for the candidates. Whichever answers first takes over.
func TestVoiceResetNodeLosesUDP(t *testing.T) {
	g, held, _, _ := newVoiceGroup(t)
	call(t, g)
	time.Sleep(100 * time.Millisecond)
	held.refused.Store(true)
	held.silent.Store(true)
	waitSuspect(t, "the UDP move", func() bool { return heldUDPTag(g) != "held" })
}

func TestVoiceStaysWhenNoNodeAnswers(t *testing.T) {
	g, held, spare, third := newVoiceGroup(t)
	call(t, g)
	time.Sleep(100 * time.Millisecond)
	held.silent.Store(true)
	spare.silent.Store(true)
	third.silent.Store(true)
	waitSuspect(t, "the verdict", func() bool { return g.voiceSilent.Load() })
	time.Sleep(10 * voicePingInterval)
	if tag := heldUDPTag(g); tag != "held" {
		t.Fatalf("with every node silent the group must stay, moved to %s", tag)
	}
}

func TestVoiceStaleSocketOnLiveNodeDoesNotMove(t *testing.T) {
	g, held, _, _ := newVoiceGroup(t)
	held.staleFirst = true
	call(t, g)
	waitSuspect(t, "a fresh socket", func() bool { return held.listens.Load() >= 2 })
	time.Sleep(20 * voicePingInterval)
	if tag := heldUDPTag(g); tag != "held" {
		t.Fatalf("a node that answers on a fresh socket must stay, moved to %s", tag)
	}
	if g.voiceSilent.Load() {
		t.Fatal("a node that answers is not an outage")
	}
}

func TestVoiceNoSecondMoveInsideGap(t *testing.T) {
	g, held, _, third := newVoiceGroup(t)
	call(t, g)
	time.Sleep(100 * time.Millisecond)
	held.silent.Store(true)
	waitSuspect(t, "the first move", func() bool { return heldUDPTag(g) == "third" })
	third.silent.Store(true)
	held.silent.Store(false)
	time.Sleep(20 * voicePingInterval)
	if tag := heldUDPTag(g); tag != "third" {
		t.Fatalf("a second move inside voiceMoveGap must wait, moved to %s", tag)
	}
	g.voiceMoved.Store(0)
	waitSuspect(t, "the move after the gap", func() bool { return heldUDPTag(g) != "third" })
}

// Nothing is sent without a call, and a DNS-sized exchange is not a call.
func TestVoiceQuietWithoutAFlow(t *testing.T) {
	g, held, _, _ := newVoiceGroup(t)
	flow := &voiceFlowConn{NetPacketConn: &discardPacketConn{}, group: g}
	for i := int64(1); i < voiceFlowPackets; i++ {
		_ = flow.WritePacket(buf.As([]byte("query")), M.ParseSocksaddr("1.1.1.1:53"))
	}
	time.Sleep(10 * voicePingInterval)
	if held.listens.Load() != 0 || g.voiceRunning.Load() {
		t.Fatal("a short exchange must not start the watchdog")
	}
	_ = flow.WritePacket(buf.As([]byte("voice")), M.ParseSocksaddr("1.1.1.1:50000"))
	waitSuspect(t, "the watchdog", func() bool { return held.listens.Load() > 0 })
	waitSuspect(t, "the watchdog to stop", func() bool { return !g.voiceRunning.Load() })
	listens := held.listens.Load()
	time.Sleep(10 * voicePingInterval)
	if held.listens.Load() != listens {
		t.Fatal("an ended flow must leave no pings behind")
	}
}

func TestVoiceOnlyInFailover(t *testing.T) {
	g, _, _, _ := newVoiceGroup(t)
	g.failover = false
	conn := &discardPacketConn{}
	if g.watchVoice(conn) != net.PacketConn(conn) {
		t.Fatal("other modes keep the flow unwrapped")
	}
}

type discardPacketConn struct{ N.NetPacketConn }

func (c *discardPacketConn) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	buffer.Release()
	return nil
}
