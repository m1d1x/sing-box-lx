package box_test

// hikkari: hot reload — a running box takes new outbounds and group members
// without a restart, and the connections it already carries survive.

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"

	"github.com/stretchr/testify/require"
)

var globalCtx = include.Context(context.Background())

// connectProxy is an HTTP CONNECT proxy that counts the tunnels it opened
// and how many of them are still open.
type connectProxy struct {
	listener net.Listener
	opened   atomic.Int32
	open     atomic.Int32
	wg       sync.WaitGroup
}

func newConnectProxy(t *testing.T) *connectProxy {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	proxy := &connectProxy{listener: listener}
	proxy.wg.Add(1)
	go func() {
		defer proxy.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			proxy.wg.Add(1)
			go func() {
				defer proxy.wg.Done()
				proxy.serve(conn)
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		proxy.wg.Wait()
	})
	return proxy
}

func (p *connectProxy) port() uint16 { return uint16(p.listener.Addr().(*net.TCPAddr).Port) }

func (p *connectProxy) serve(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	request, err := http.ReadRequest(reader)
	if err != nil || request.Method != http.MethodConnect {
		return
	}
	upstream, err := net.Dial("tcp", request.Host)
	if err != nil {
		_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer upstream.Close()
	p.opened.Add(1)
	p.open.Add(1)
	defer p.open.Add(-1)
	_, _ = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, reader); _ = upstream.(*net.TCPConn).CloseWrite(); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, upstream); done <- struct{}{} }()
	<-done
	<-done
}

// echoServer answers every line with the same line.
func echoServer(t *testing.T) uint16 {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		wg.Wait()
	})
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

func freePort(t *testing.T) uint16 {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

type hotNode struct {
	tag  string
	port uint16
}

// hotConfig is the shape Hikkari runs: profile outbounds, a `proxy` selector
// over them, optionally the `auto` urltest, route.final at the head.
func hotConfig(mixedPort, clashPort uint16, nodes []hotNode, active string, auto string) string {
	var outbounds, tags []string
	for _, node := range nodes {
		outbounds = append(outbounds, fmt.Sprintf(`{"type":"http","tag":%q,"server":"127.0.0.1","server_port":%d}`, node.tag, node.port))
		tags = append(tags, fmt.Sprintf("%q", node.tag))
	}
	outbounds = append(outbounds, `{"type":"direct","tag":"direct"}`)
	outbounds = append(outbounds, fmt.Sprintf(`{"type":"selector","tag":"proxy","outbounds":[%s],"default":%q}`, strings.Join(tags, ","), active))
	final := "proxy"
	if auto != "" {
		outbounds = append(outbounds, fmt.Sprintf(`{"type":"urltest","tag":"auto","mode":"failover","outbounds":[%s],"url":%q,"interval":"1m"}`, strings.Join(tags, ","), auto))
		final = "auto"
	}
	return fmt.Sprintf(`{
  "log": {"level": "warning"},
  "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": %d}],
  "outbounds": [%s],
  "route": {"final": %q},
  "experimental": {"clash_api": {"external_controller": "127.0.0.1:%d"}}
}`, mixedPort, strings.Join(outbounds, ","), final, clashPort)
}

func parseHotConfig(t *testing.T, content string) option.Options {
	options, err := json.UnmarshalExtendedContext[option.Options](globalCtx, []byte(content))
	require.NoError(t, err)
	return options
}

func startHotInstance(t *testing.T, content string) *box.Box {
	ctx, cancel := context.WithCancel(globalCtx)
	instance, err := box.New(box.Options{Context: ctx, Options: parseHotConfig(t, content)})
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	t.Cleanup(func() {
		instance.Close()
		cancel()
	})
	return instance
}

func hotReload(t *testing.T, instance *box.Box, previous, next string) box.HotReloadResult {
	result, err := instance.HotReload([]byte(previous), []byte(next), parseHotConfig(t, next))
	require.NoError(t, err)
	return result
}

// openEcho opens a connection through the box and checks one round trip.
func openEcho(t *testing.T, mixedPort, echoPort uint16) net.Conn {
	dialer := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", mixedPort), socks.Version5, "", "")
	conn, err := dialer.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddrHostPort("127.0.0.1", echoPort))
	require.NoError(t, err)
	requireEcho(t, conn, "hello")
	return conn
}

func requireEcho(t *testing.T, conn net.Conn, message string) {
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err := conn.Write([]byte(message + "\n"))
	require.NoError(t, err)
	line, err := bufio.NewReader(conn).ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, message+"\n", line)
}

func TestHotReloadReplaceKeepsConnections(t *testing.T) {
	proxyA, proxyB := newConnectProxy(t), newConnectProxy(t)
	echoPort := echoServer(t)
	mixedPort, clashPort := freePort(t), freePort(t)
	before := hotConfig(mixedPort, clashPort, []hotNode{{"p-1", proxyA.port()}}, "p-1", "")
	after := hotConfig(mixedPort, clashPort, []hotNode{{"p-1", proxyB.port()}}, "p-1", "")
	instance := startHotInstance(t, before)

	long := openEcho(t, mixedPort, echoPort)
	defer long.Close()
	require.EqualValues(t, 1, proxyA.opened.Load())

	result := hotReload(t, instance, before, after)
	require.True(t, result.Applied, result.Declined)
	require.Equal(t, []string{"p-1"}, result.Replaced)
	require.Equal(t, []string{"proxy"}, result.Groups)

	// The connection opened before the reload still works over the old node.
	requireEcho(t, long, "still here")
	// A new connection goes over the replaced node.
	fresh := openEcho(t, mixedPort, echoPort)
	defer fresh.Close()
	require.EqualValues(t, 1, proxyA.opened.Load())
	require.EqualValues(t, 1, proxyB.opened.Load())
	require.EqualValues(t, 1, proxyA.open.Load())

	outbound, loaded := instance.Outbound().Outbound("p-1")
	require.True(t, loaded)
	group, _ := instance.Outbound().Outbound("proxy")
	require.Equal(t, "p-1", group.(adapter.OutboundGroup).Now())
	require.NotNil(t, outbound)
}

func TestHotReloadAddRemoveMembers(t *testing.T) {
	proxyA, proxyB := newConnectProxy(t), newConnectProxy(t)
	echoPort := echoServer(t)
	mixedPort, clashPort := freePort(t), freePort(t)
	one := hotConfig(mixedPort, clashPort, []hotNode{{"p-1", proxyA.port()}}, "p-1", "")
	two := hotConfig(mixedPort, clashPort, []hotNode{{"p-1", proxyA.port()}, {"p-2", proxyB.port()}}, "p-1", "")
	onlySecond := hotConfig(mixedPort, clashPort, []hotNode{{"p-2", proxyB.port()}}, "p-2", "")
	instance := startHotInstance(t, one)

	result := hotReload(t, instance, one, two)
	require.True(t, result.Applied, result.Declined)
	require.Equal(t, []string{"p-2"}, result.Added)
	group, _ := instance.Outbound().Outbound("proxy")
	require.Equal(t, []string{"p-1", "p-2"}, group.(adapter.OutboundGroup).All())
	require.Equal(t, "p-1", group.(adapter.OutboundGroup).Now())

	// Removing the selected member moves the selection to the new default.
	result = hotReload(t, instance, two, onlySecond)
	require.True(t, result.Applied, result.Declined)
	require.Equal(t, []string{"p-1"}, result.Removed)
	require.Equal(t, "p-2", group.(adapter.OutboundGroup).Now())
	_, loaded := instance.Outbound().Outbound("p-1")
	require.False(t, loaded)

	conn := openEcho(t, mixedPort, echoPort)
	defer conn.Close()
	require.EqualValues(t, 0, proxyA.opened.Load())
	require.EqualValues(t, 1, proxyB.opened.Load())
}

func TestHotReloadURLTestKeepsHeldNode(t *testing.T) {
	proxyA, proxyB, proxyC := newConnectProxy(t), newConnectProxy(t), newConnectProxy(t)
	probe := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })}
	probeListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = probe.Serve(probeListener) }()
	t.Cleanup(func() { _ = probe.Close() })
	probeURL := fmt.Sprintf("http://127.0.0.1:%d/generate_204", probeListener.Addr().(*net.TCPAddr).Port)

	mixedPort, clashPort := freePort(t), freePort(t)
	before := hotConfig(mixedPort, clashPort, []hotNode{{"p-1", proxyA.port()}, {"p-2", proxyB.port()}}, "p-1", probeURL)
	instance := startHotInstance(t, before)
	group, _ := instance.Outbound().Outbound("auto")
	// A synchronous run selects the held node (the background one may race it;
	// upstream reads the selection unlocked, see the plan).
	_, err = group.(adapter.URLTestGroup).URLTest(context.Background())
	require.NoError(t, err)
	held := group.(adapter.OutboundGroup).Now()

	// The held node gets new options (as when the hub turns a knob) and a
	// third node joins: the exit stays on the held tag.
	nodes := []hotNode{{"p-1", proxyA.port()}, {"p-2", proxyB.port()}, {"p-3", proxyC.port()}}
	for i := range nodes {
		if nodes[i].tag == held {
			nodes[i].port = proxyC.port()
		}
	}
	after := hotConfig(mixedPort, clashPort, nodes, "p-1", probeURL)
	result := hotReload(t, instance, before, after)
	require.True(t, result.Applied, result.Declined)
	require.Equal(t, []string{"auto", "proxy"}, result.Groups)
	require.Equal(t, []string{held}, result.Replaced)
	require.Equal(t, []string{"p-1", "p-2", "p-3"}, group.(adapter.OutboundGroup).All())
	require.Equal(t, held, group.(adapter.OutboundGroup).Now())
}

func TestHotReloadDeclinesWhatNeedsRestart(t *testing.T) {
	proxyA := newConnectProxy(t)
	mixedPort, clashPort := freePort(t), freePort(t)
	before := hotConfig(mixedPort, clashPort, []hotNode{{"p-1", proxyA.port()}}, "p-1", "")
	instance := startHotInstance(t, before)

	for name, after := range map[string]string{
		"inbound port":  hotConfig(freePort(t), clashPort, []hotNode{{"p-1", proxyA.port()}}, "p-1", ""),
		"auto mode on":  hotConfig(mixedPort, clashPort, []hotNode{{"p-1", proxyA.port()}}, "p-1", "http://127.0.0.1:1/"),
		"detour":        strings.Replace(before, `"server_port":`, `"detour":"direct","server_port":`, 1),
		"direct option": strings.Replace(before, `{"type":"direct","tag":"direct"}`, `{"type":"direct","tag":"direct","tcp_fast_open":true}`, 1),
	} {
		result := hotReload(t, instance, before, after)
		require.False(t, result.Applied, name)
		require.NotEmpty(t, result.Declined, name)
	}
	// Declined reloads left the box as it was.
	outbound, loaded := instance.Outbound().Outbound("p-1")
	require.True(t, loaded)
	require.Equal(t, "http", outbound.Type())
}

func TestHotReloadFailedStartLeavesBox(t *testing.T) {
	proxyA := newConnectProxy(t)
	echoPort := echoServer(t)
	mixedPort, clashPort := freePort(t), freePort(t)
	before := hotConfig(mixedPort, clashPort, []hotNode{{"p-1", proxyA.port()}}, "p-1", "")
	instance := startHotInstance(t, before)
	// An outbound the registry refuses: the reload fails, nothing is published.
	after := strings.Replace(before, `{"type":"http","tag":"p-1"`, `{"type":"http","tag":"p-1","tls":{"enabled":true,"certificate_path":"/nonexistent/cert.pem"}`, 1)
	_, err := instance.HotReload([]byte(before), []byte(after), parseHotConfig(t, after))
	require.Error(t, err)
	conn := openEcho(t, mixedPort, echoPort)
	defer conn.Close()
	require.EqualValues(t, 1, proxyA.opened.Load())
}
