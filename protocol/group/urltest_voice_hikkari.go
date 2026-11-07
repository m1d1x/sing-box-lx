package group

// hikkari: voice watchdog for mode: failover.
//
// UDP gives the group nothing to react to. A datagram has no dial error and no
// first byte to wait for, and the suspicion probe watches TCP only. With only a
// call up, a dead node is noticed by the next planned tick, two minutes later,
// and every new call socket lands on the dead node until then.
//
// So while a UDP flow is active, the group pings a STUN server through the node
// held for UDP every voicePingInterval. voiceMisses pings in a row without an
// answer within voicePingTimeout make the node a suspect. A fresh socket through
// it and sockets through the best candidates are then pinged side by side. Only
// a candidate that answers while the held node stays silent takes the UDP
// selection; if nobody answers, the user's own network is down and the group
// stays. After a move the old node gets the TCP suspicion probe, and TCP moves by
// its own rules. Flows already open stay on the node they started on, as on any
// move. Without an active flow nothing is sent.

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"slices"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var (
	// voiceTarget answers STUN binding requests. A public STUN server works for any
	// node, ours or not.
	voiceTarget = M.ParseSocksaddr("stun.l.google.com:19302")
	// voicePingInterval is the ping rate while a flow is active: 4 packets a second.
	voicePingInterval = 250 * time.Millisecond
	// voicePingTimeout: an answer later than this is a miss. For a call a reply after
	// a second and a half is as bad as none.
	voicePingTimeout = 500 * time.Millisecond
	// voiceMisses in a row, under a second, make the held node a suspect. The fresh
	// socket of the verification is the fourth strike.
	voiceMisses = 3
	// voiceVerifyWindow is how long the suspect and the candidates get to answer.
	voiceVerifyWindow = 750 * time.Millisecond
	// voiceCandidates is how many other nodes are tried, fastest first.
	voiceCandidates = 2
	// voiceActiveWindow: a flow with no packet out for this long is over.
	voiceActiveWindow = 2 * time.Second
	// voiceFlowPackets out make a flow active. A DNS or NTP exchange never gets there.
	voiceFlowPackets = int64(10)
	// voiceMoveGap is the quiet time after a move, against hopping between nodes.
	voiceMoveGap = 30 * time.Second
)

// watchVoice wraps a UDP flow of a failover group to report its activity.
func (g *URLTestGroup) watchVoice(conn net.PacketConn) net.PacketConn {
	if !g.failover {
		return conn
	}
	return &voiceFlowConn{NetPacketConn: bufio.NewPacketConn(conn), group: g}
}

// voiceFlow marks a packet out of an active flow and starts the watchdog if it is
// not running.
func (g *URLTestGroup) voiceFlow() {
	g.voiceLast.Store(time.Now().UnixNano())
	if g.ctx.Err() != nil || !g.voiceRunning.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer g.voiceRunning.Store(false)
		g.voiceWatch()
	}()
}

func (g *URLTestGroup) voiceActive() bool {
	return time.Since(time.Unix(0, g.voiceLast.Load())) < voiceActiveWindow
}

// heldUDP reads the UDP selection under the lock moveSelection writes it with.
func (g *URLTestGroup) heldUDP() adapter.Outbound {
	g.access.Lock()
	held := g.selectedOutboundUDP
	g.access.Unlock()
	if held == nil {
		held, _ = g.Select(N.NetworkUDP)
	}
	return held
}

// voiceWatch pings through the held node while a flow is active.
func (g *URLTestGroup) voiceWatch() {
	var pinger *voicePinger
	defer func() {
		if pinger != nil {
			pinger.close()
		}
	}()
	ticker := time.NewTicker(voicePingInterval)
	defer ticker.Stop()
	misses := 0
	for g.voiceActive() {
		held := g.heldUDP()
		if held == nil {
			return
		}
		if pinger != nil && pinger.node != held {
			pinger.close()
			pinger, misses = nil, 0
		}
		if pinger == nil {
			pinger = g.openVoicePinger(held)
		}
		if pinger != nil {
			answered, missed := pinger.collect()
			if answered {
				misses = 0
			}
			misses += missed
			pinger.send()
		}
		// A socket that broke is a stronger sign than a lost ping: verify now.
		if pinger == nil || pinger.broken() || misses >= voiceMisses {
			fresh := g.voiceVerify(held, misses)
			if pinger != nil {
				pinger.close()
			}
			pinger, misses = fresh, 0
		}
		select {
		case <-g.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// voiceVerify pings the suspect through a fresh socket and the candidates side by
// side, and moves the UDP selection to a candidate that answers if the suspect
// does not. All the sockets are fresh, so a live suspect answers about as fast as
// a candidate: once one answered, the suspect gets voicePingInterval more, at
// least voicePingTimeout in all and never more than voiceVerifyWindow. It returns
// the suspect's fresh pinger when the suspect answered, for the watchdog to keep.
func (g *URLTestGroup) voiceVerify(held adapter.Outbound, misses int) *voicePinger {
	start := time.Now()
	tag := RealTag(g.outbound, held)
	moveAllowed := time.Since(time.Unix(0, g.voiceMoved.Load())) >= voiceMoveGap
	nodes := []adapter.Outbound{held}
	if moveAllowed {
		nodes = append(nodes, g.voiceCandidateList(held)...)
	}
	type verdict struct {
		index  int
		ok     bool
		pinger *voicePinger // the suspect's, when it answered
	}
	verdicts := make(chan verdict, len(nodes))
	stop := make(chan struct{})
	for i, node := range nodes {
		go func() {
			pinger := g.openVoicePinger(node)
			ok := pinger != nil && pinger.answers(voiceVerifyWindow, stop)
			if pinger != nil && (i != 0 || !ok) {
				pinger.close()
				pinger = nil
			}
			verdicts <- verdict{i, ok, pinger}
		}()
	}
	// Once decided, the rest stop pinging, and their sockets are closed before
	// this returns: a late suspect hands over one nobody takes.
	pending := len(nodes)
	defer func() {
		close(stop)
		for ; pending > 0; pending-- {
			if v := <-verdicts; v.pinger != nil {
				v.pinger.close()
			}
		}
	}()
	// The suspect is out once it failed or its time ran out; then the first
	// candidate in rank order that answered takes over, or, once every candidate
	// gave its verdict, nobody does.
	deadline := time.NewTimer(voiceVerifyWindow)
	defer deadline.Stop()
	answered := make([]bool, len(nodes))
	heldOut, candidatesLeft := false, len(nodes)-1
	for !heldOut || (candidatesLeft > 0 && !slices.Contains(answered, true)) {
		select {
		case v := <-verdicts:
			pending--
			switch {
			case v.index == 0 && v.ok:
				g.logger.Debug("voice: ", tag, " answered on a fresh socket after ", misses, " misses")
				g.voiceSilent.Store(false)
				return v.pinger
			case v.index == 0:
				heldOut = true
			default:
				candidatesLeft--
				if v.ok && !slices.Contains(answered, true) && !heldOut {
					wait := max(voicePingTimeout, time.Since(start)+voicePingInterval)
					deadline.Reset(min(voiceVerifyWindow, wait) - time.Since(start))
				}
				answered[v.index] = v.ok
			}
		case <-deadline.C:
			heldOut = true
		}
	}
	for i := 1; i < len(nodes); i++ {
		if !answered[i] {
			continue
		}
		g.voiceMoved.Store(time.Now().UnixNano())
		g.voiceSilent.Store(false)
		g.moveSelection(N.NetworkUDP, nodes[i], nil)
		g.logger.Warn("[voice] ", tag, " silent after ", misses, " misses, UDP moved to ", RealTag(g.outbound, nodes[i]),
			" in ", time.Since(start).Milliseconds(), "ms")
		// TCP decides by its own probe whether the node is dead for it too.
		g.suspect(held)
		return nil
	}
	if !g.voiceSilent.Swap(true) {
		if moveAllowed {
			g.logger.Warn("[voice] ", tag, " silent after ", misses, " misses, no other node answered, staying")
		} else {
			g.logger.Warn("[voice] ", tag, " silent after ", misses, " misses, staying: moved less than ", voiceMoveGap, " ago")
		}
	}
	return nil
}

// voiceCandidateList is the fastest other UDP nodes with history.
func (g *URLTestGroup) voiceCandidateList(held adapter.Outbound) []adapter.Outbound {
	type ranked struct {
		node  adapter.Outbound
		delay uint16
	}
	var list []ranked
	for _, detour := range g.outbounds {
		if detour == held || !supportsNetwork(detour, N.NetworkUDP) {
			continue
		}
		if history := g.history.LoadURLTestHistory(RealTag(g.outbound, detour)); history != nil {
			list = append(list, ranked{detour, history.Delay})
		}
	}
	for i := 1; i < len(list); i++ {
		for j := i; j > 0 && list[j].delay < list[j-1].delay; j-- {
			list[j], list[j-1] = list[j-1], list[j]
		}
	}
	candidates := make([]adapter.Outbound, 0, voiceCandidates)
	for _, r := range list {
		if len(candidates) == voiceCandidates {
			break
		}
		candidates = append(candidates, r.node)
	}
	return candidates
}

// voicePinger is one UDP socket through a node to voiceTarget.
type voicePinger struct {
	node    adapter.Outbound
	conn    net.PacketConn
	replies chan [12]byte
	dead    atomic.Bool
	// sent counts the pings; pending holds the ones not answered yet, by number.
	// The watchdog sends one per tick, so a ping's age is counted in ticks: a
	// wall-clock age would land a hair under the timeout one tick in two and
	// count the miss a whole interval late.
	sent    int
	pending map[[12]byte]int
}

func (g *URLTestGroup) openVoicePinger(node adapter.Outbound) *voicePinger {
	ctx, cancel := context.WithTimeout(g.ctx, voiceVerifyWindow)
	defer cancel()
	conn, err := node.ListenPacket(ctx, voiceTarget)
	if err != nil {
		return nil
	}
	p := &voicePinger{node: node, conn: conn, replies: make(chan [12]byte, 16), pending: make(map[[12]byte]int)}
	go p.read()
	return p
}

func (p *voicePinger) read() {
	buffer := make([]byte, 1500)
	for {
		n, _, err := p.conn.ReadFrom(buffer)
		if err != nil {
			p.dead.Store(true)
			close(p.replies)
			return
		}
		if id, ok := stunBindingSuccess(buffer[:n]); ok {
			select {
			case p.replies <- id:
			default:
			}
		}
	}
}

func (p *voicePinger) close() { _ = p.conn.Close() }

func (p *voicePinger) broken() bool { return p.dead.Load() }

func (p *voicePinger) send() {
	var id [12]byte
	_, _ = rand.Read(id[:])
	request := make([]byte, 20)
	binary.BigEndian.PutUint16(request[0:], 0x0001) // Binding Request, no attributes
	binary.BigEndian.PutUint32(request[4:], stunMagicCookie)
	copy(request[8:], id[:])
	if _, err := p.conn.WriteTo(request, voiceTarget); err != nil {
		p.dead.Store(true)
		return
	}
	p.sent++
	p.pending[id] = p.sent
}

// collect, called once a tick before the next send, takes the answers that
// arrived and returns whether one came in time and how many pings ran out of
// time without one.
func (p *voicePinger) collect() (answered bool, missed int) {
	age := func(number int) time.Duration { return time.Duration(p.sent-number+1) * voicePingInterval }
	for drained := false; !drained; {
		select {
		case id, ok := <-p.replies:
			if !ok {
				drained = true
				break
			}
			if sent, known := p.pending[id]; known {
				delete(p.pending, id)
				answered = answered || age(sent) <= voicePingTimeout
			}
		default:
			drained = true
		}
	}
	for id, sent := range p.pending {
		if age(sent) >= voicePingTimeout {
			delete(p.pending, id)
			missed++
		}
	}
	return answered, missed
}

// answers pings every voicePingInterval until one is answered, window ends or stop
// is closed.
func (p *voicePinger) answers(window time.Duration, stop <-chan struct{}) bool {
	deadline := time.NewTimer(window)
	defer deadline.Stop()
	ticker := time.NewTicker(voicePingInterval)
	defer ticker.Stop()
	p.send()
	for {
		select {
		case id, ok := <-p.replies:
			if !ok {
				return false
			}
			if _, known := p.pending[id]; known {
				// The pings still out are not misses of the watch that takes this socket over.
				clear(p.pending)
				return true
			}
		case <-ticker.C:
			p.send()
		case <-deadline.C:
			return false
		case <-stop:
			return false
		}
	}
}

const stunMagicCookie = 0x2112A442

// stunBindingSuccess returns the transaction id of a STUN Binding Success Response.
func stunBindingSuccess(packet []byte) ([12]byte, bool) {
	var id [12]byte
	if len(packet) < 20 || binary.BigEndian.Uint16(packet[0:]) != 0x0101 || binary.BigEndian.Uint32(packet[4:]) != stunMagicCookie {
		return id, false
	}
	copy(id[:], packet[8:20])
	return id, true
}

// voiceFlowConn counts packets out of one UDP flow. Writes must go through it, so
// it is not writer-replaceable; reads pass straight to the upstream.
type voiceFlowConn struct {
	N.NetPacketConn
	group *URLTestGroup
	sent  atomic.Int64
}

func (c *voiceFlowConn) mark() {
	if c.sent.Add(1) >= voiceFlowPackets {
		c.group.voiceFlow()
	}
}

func (c *voiceFlowConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	c.mark()
	return c.NetPacketConn.WritePacket(buffer, destination)
}

func (c *voiceFlowConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mark()
	return c.NetPacketConn.WriteTo(p, addr)
}

func (c *voiceFlowConn) Upstream() any           { return c.NetPacketConn }
func (c *voiceFlowConn) ReaderReplaceable() bool { return true }
func (c *voiceFlowConn) WriterReplaceable() bool { return false }
