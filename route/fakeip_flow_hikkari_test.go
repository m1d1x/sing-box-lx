package route

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	N "github.com/sagernet/sing/common/network"

	M "github.com/sagernet/sing/common/metadata"
)

// flowEndpoint stands for a WireGuard endpoint: it takes flows from the TUN by
// address. Only what preMatchFlow calls is implemented.
type flowEndpoint struct{ adapter.FlowOutbound }

func (flowEndpoint) Type() string      { return C.TypeWireGuard }
func (flowEndpoint) Tag() string       { return "p-awg" }
func (flowEndpoint) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }
func (flowEndpoint) PreMatchFlow(string, netip.Addr) adapter.PreMatchAction {
	return adapter.PreMatchFlow
}

type defaultOutbound struct {
	adapter.OutboundManager
	outbound adapter.Outbound
}

func (m defaultOutbound) Default() adapter.Outbound { return m.outbound }

func fakeFlowRouter() *Router {
	return &Router{logger: log.NewNOPFactory().NewLogger("test"), outbound: defaultOutbound{outbound: flowEndpoint{}}}
}

// A fake destination no resolve action filled in used to be rejected on its
// way to a WireGuard endpoint (tester-002, 04.11: Discord's voice host). It goes
// the connection path now, where the endpoint resolves the name itself.
func TestUnresolvedFakeDestinationFallsBackToTheConnectionPath(t *testing.T) {
	packet := M.SocksaddrFrom(netip.MustParseAddr("198.18.0.7"), 50001)
	metadata := adapter.InboundContext{
		Network:     N.NetworkTCP,
		Source:      M.SocksaddrFrom(netip.MustParseAddr("172.19.0.1"), 50000),
		Destination: M.Socksaddr{Fqdn: "c-ord02-8fd81e95.discord.media", Port: 50001},
		FakeIP:      true,
	}
	result := fakeFlowRouter().preMatchFlow(context.Background(), &metadata, packet, nil, "")
	if result.Action != adapter.PreMatchContinue {
		t.Fatalf("action %v, want continue", result.Action)
	}
}

// A resolved fake destination still goes straight to the endpoint as a flow.
func TestResolvedFakeDestinationStillFlows(t *testing.T) {
	packet := M.SocksaddrFrom(netip.MustParseAddr("198.18.0.7"), 50001)
	metadata := adapter.InboundContext{
		Network:              N.NetworkTCP,
		Source:               M.SocksaddrFrom(netip.MustParseAddr("172.19.0.1"), 50000),
		Destination:          M.Socksaddr{Fqdn: "c-ord02-8fd81e95.discord.media", Port: 50001},
		FakeIP:               true,
		DestinationAddresses: []netip.Addr{netip.MustParseAddr("162.159.130.234")},
	}
	result := fakeFlowRouter().preMatchFlow(context.Background(), &metadata, packet, nil, "")
	if result.Action != adapter.PreMatchFlow || result.Destination.Addr() != netip.MustParseAddr("162.159.130.234") {
		t.Fatalf("action %v destination %v", result.Action, result.Destination)
	}
}
