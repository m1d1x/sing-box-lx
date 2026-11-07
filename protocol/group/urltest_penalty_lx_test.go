// lx:begin SPEC 054 penalty failover tests

package group

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// penaltyDialNode — outbound с управляемым исходом дайла: err != nil → ошибка,
// иначе соединение к addr.
type penaltyDialNode struct {
	adapter.Outbound
	tag   string
	addr  string
	err   error
	dials int
}

func (n *penaltyDialNode) Type() string           { return C.TypeDirect }
func (n *penaltyDialNode) Tag() string            { return n.tag }
func (n *penaltyDialNode) Network() []string      { return []string{N.NetworkTCP, N.NetworkUDP} }
func (n *penaltyDialNode) Dependencies() []string { return nil }
func (n *penaltyDialNode) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	n.dials++
	if n.err != nil {
		return nil, n.err
	}
	return net.Dial("tcp", n.addr)
}

func newPenaltyTestGroup(t *testing.T, nodes []*penaltyDialNode, delays map[string]uint16) *URLTestGroup {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	byTag := make(map[string]adapter.Outbound, len(nodes))
	outbounds := make([]adapter.Outbound, 0, len(nodes))
	for _, node := range nodes {
		if node.addr == "server" {
			node.addr = server.Listener.Addr().String()
		}
		byTag[node.tag] = node
		outbounds = append(outbounds, node)
	}
	g := &URLTestGroup{
		ctx:            context.Background(),
		outbound:       &fakeManager{byTag: byTag},
		logger:         logger.NOP(),
		outbounds:      outbounds,
		link:           server.URL,
		interval:       time.Minute,
		history:        urltest.NewHistoryStorage(),
		interruptGroup: interrupt.NewGroup(),
	}
	for tag, delay := range delays {
		g.history.StoreURLTestHistory(tag, &adapter.URLTestHistory{Time: time.Now(), Delay: delay})
	}
	return g
}

// TestIsPathDeadDialError pins the error classification: transport errors of
// the dial count as "path dead"; caller cancellation never does.
func TestIsPathDeadDialError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"ctx deadline (SPEC 052)", context.DeadlineExceeded, true},
		{"wrapped ctx deadline", E.Cause(context.DeadlineExceeded, "dial"), true},
		{"os deadline", &net.OpError{Op: "connect", Err: syscall.ETIMEDOUT}, true},
		{"host unreachable", syscall.EHOSTUNREACH, true},
		{"refused (node)", syscall.ECONNREFUSED, true},
		{"reset (node)", &net.OpError{Op: "read", Err: syscall.ECONNRESET}, true},
		{"broken pipe (node)", &net.OpError{Op: "write", Err: syscall.EPIPE}, true},
		{"windows reset", &net.OpError{Op: "read", Err: syscall.Errno(10054)}, true},
		{"windows refused", &net.OpError{Op: "dial", Err: syscall.Errno(10061)}, true},
		{"eof in tls handshake", E.Cause(io.EOF, "tls handshake"), true},
		{"canceled (caller)", context.Canceled, false},
		{"plain error", E.New("dead node"), false},
		{"nil", nil, false},
	}
	for _, c := range cases {
		if got := isPathDeadDialError(c.err); got != c.want {
			t.Fatalf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// TestPenaltyEmergencyRanking: аварийный режим включается порогом у
// лучшего-по-скорости и ранжирует двумя уровнями — штрафы ↑, затем задержка ↑
// (победители по штрафам соревнуются по скорости).
func TestPenaltyEmergencyRanking(t *testing.T) {
	a := &penaltyDialNode{tag: "a"}
	b := &penaltyDialNode{tag: "b"}
	c := &penaltyDialNode{tag: "c"}
	g := newPenaltyTestGroup(t, []*penaltyDialNode{a, b, c}, map[string]uint16{"a": 10, "b": 50, "c": 100})

	if g.penaltyEmergency(N.NetworkTCP) {
		t.Fatal("no penalties → no emergency")
	}
	g.penaltyAdd("a")
	g.penaltyAdd("a")
	if g.penaltyEmergency(N.NetworkTCP) {
		t.Fatal("fastest below threshold → no emergency")
	}
	g.penaltyAdd("a") // a=3 → аварийный режим
	if !g.penaltyEmergency(N.NetworkTCP) {
		t.Fatal("fastest at threshold → emergency")
	}
	// b и c без штрафов — победители по штрафам; из них выбирается быстрый (b).
	best, _ := g.selectPenaltyAware(N.NetworkTCP)
	if best.Tag() != "b" {
		t.Fatalf("two-level ranking must pick b (0 penalties, fastest of them), got %s", best.Tag())
	}
	g.penaltyAdd("b") // b=1, c=0 → побеждает c несмотря на большую задержку
	best, _ = g.selectPenaltyAware(N.NetworkTCP)
	if best.Tag() != "c" {
		t.Fatalf("fewer penalties must beat delay, got %s", best.Tag())
	}
	// Успех b (доказательство жизни) сбрасывает его штраф → снова b.
	g.penaltyReset("b")
	best, _ = g.selectPenaltyAware(N.NetworkTCP)
	if best.Tag() != "b" {
		t.Fatalf("after reset b must win again, got %s", best.Tag())
	}
}

// TestPenaltyFailoverDial: «путь мёртв» → штраф отказавшему, fallback-дайл через
// следующего кандидата, успех переносит выбор группы на fallback без Interrupt.
func TestPenaltyFailoverDial(t *testing.T) {
	dead := &penaltyDialNode{tag: "dead", err: context.DeadlineExceeded}
	alive := &penaltyDialNode{tag: "alive", addr: "server"}
	g := newPenaltyTestGroup(t, []*penaltyDialNode{dead, alive}, map[string]uint16{"dead": 10, "alive": 50})
	g.selectedOutboundTCP = dead

	conn, fallback, ok := g.penaltyFailoverDial(context.Background(), N.NetworkTCP, M.Socksaddr{}, dead, context.DeadlineExceeded)
	if !ok {
		t.Fatal("failover must succeed via the alive node")
	}
	defer conn.Close()
	if fallback.Tag() != "alive" {
		t.Fatalf("fallback must be the alive node, got %s", fallback.Tag())
	}
	if g.penaltyOf("dead") != 1 {
		t.Fatalf("failed node must get +1 penalty, got %d", g.penaltyOf("dead"))
	}
	if g.penaltyOf("alive") != 0 {
		t.Fatalf("successful fallback must hold 0 penalties, got %d", g.penaltyOf("alive"))
	}
	if g.selectedOutboundTCP != adapter.Outbound(alive) {
		t.Fatal("selection must move to the fallback")
	}
	if alive.dials != 1 {
		t.Fatalf("exactly one fallback attempt (cap 2 total), got %d", alive.dials)
	}
}

// TestPenaltyFailoverDial_nodeRefusal: hikkari — RST/refused на дайле приходит от
// самого узла: штраф, fallback, и UDP, державшийся на том же узле, едет вместе с TCP.
func TestPenaltyFailoverDial_nodeRefusal(t *testing.T) {
	dead := &penaltyDialNode{tag: "dead", err: syscall.ECONNREFUSED}
	alive := &penaltyDialNode{tag: "alive", addr: "server"}
	g := newPenaltyTestGroup(t, []*penaltyDialNode{dead, alive}, map[string]uint16{"dead": 10, "alive": 50})
	g.selectedOutboundTCP = dead
	g.selectedOutboundUDP = dead

	conn, fallback, ok := g.penaltyFailoverDial(context.Background(), N.NetworkTCP, M.Socksaddr{}, dead, syscall.ECONNREFUSED)
	if !ok {
		t.Fatal("a refusal from the node must fail over")
	}
	conn.Close()
	if fallback != adapter.Outbound(alive) || g.penaltyOf("dead") != 1 {
		t.Fatalf("fallback %v, penalties %d", fallback, g.penaltyOf("dead"))
	}
	if g.selectedOutboundTCP != adapter.Outbound(alive) || g.selectedOutboundUDP != adapter.Outbound(alive) {
		t.Fatal("both networks held on the dead node must move")
	}
}

// TestPenaltyFailoverDial_keepsOtherNetwork: сеть, державшаяся на другом узле,
// остаётся на нём.
func TestPenaltyFailoverDial_keepsOtherNetwork(t *testing.T) {
	dead := &penaltyDialNode{tag: "dead", err: syscall.ECONNRESET}
	alive := &penaltyDialNode{tag: "alive", addr: "server"}
	other := &penaltyDialNode{tag: "other", addr: "server"}
	g := newPenaltyTestGroup(t, []*penaltyDialNode{dead, alive, other}, map[string]uint16{"dead": 10, "alive": 50, "other": 60})
	g.selectedOutboundTCP = dead
	g.selectedOutboundUDP = other

	conn, _, ok := g.penaltyFailoverDial(context.Background(), N.NetworkTCP, M.Socksaddr{}, dead, syscall.ECONNRESET)
	if !ok {
		t.Fatal("must fail over")
	}
	conn.Close()
	if g.selectedOutboundUDP != adapter.Outbound(other) {
		t.Fatal("UDP held on a live node must stay")
	}
}

// TestMaybeForceRetest_levelTriggerWithGap: тотальные штрафы запускают force-прогон;
// повторный запуск не раньше penaltyForcedRetestGap от КОНЦА прошлого прогона;
// частичное здоровье (кандидат ниже порога) не запускает вовсе.
func TestMaybeForceRetest_levelTriggerWithGap(t *testing.T) {
	a := &penaltyDialNode{tag: "a"}
	b := &penaltyDialNode{tag: "b"}
	g := newPenaltyTestGroup(t, []*penaltyDialNode{a, b}, map[string]uint16{"a": 10, "b": 50})
	// Глушим реальный прогон: checking=true → CheckOutbounds(force) — мгновенный no-op.
	g.checking.Store(true)

	for i := 0; i < 3; i++ {
		g.penaltyAdd("a")
	}
	g.maybeForceRetest()
	if !g.forcedRetestRunning.Load() {
		// b без штрафов → не тотально → не должен был стрелять.
	} else {
		t.Fatal("partial health (b at 0) must not force a retest")
	}

	for i := 0; i < 3; i++ {
		g.penaltyAdd("b")
	}
	g.maybeForceRetest() // теперь тотально → стреляет
	waitUntil(t, func() bool { return !g.forcedRetestRunning.Load() && !g.lastForcedRetest.Load().IsZero() })
	firstRun := g.lastForcedRetest.Load()

	g.maybeForceRetest() // сразу же — дельта-лимит должен удержать
	if g.forcedRetestRunning.Load() {
		t.Fatal("gap not elapsed → no second forced retest")
	}
	if !g.lastForcedRetest.Load().Equal(firstRun) {
		t.Fatal("gap not elapsed → timestamp must be unchanged")
	}

	// Отматываем «конец прошлого прогона» за пределы паузы → уровень-триггер стреляет снова.
	g.lastForcedRetest.Store(time.Now().Add(-penaltyForcedRetestGap - time.Second))
	g.maybeForceRetest()
	waitUntil(t, func() bool { return !g.forcedRetestRunning.Load() })
	if g.lastForcedRetest.Load().Equal(firstRun) || g.lastForcedRetest.Load().Add(penaltyForcedRetestGap).Before(time.Now()) {
		t.Fatal("after the gap the level trigger must fire again and restamp from run end")
	}
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

// lx:end SPEC 054
