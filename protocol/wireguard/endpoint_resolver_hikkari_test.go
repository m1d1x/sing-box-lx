package wireguard

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/wireguard"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type resolverTestTransport struct {
	adapter.DNSTransport
	tag string
}

func (t resolverTestTransport) Tag() string { return t.tag }

type resolverTestTransports struct {
	adapter.DNSTransportManager
	transports map[string]adapter.DNSTransport
}

func (m resolverTestTransports) Transport(tag string) (adapter.DNSTransport, bool) {
	transport, loaded := m.transports[tag]
	return transport, loaded
}

// lookupRecorder is a DNS router that refuses every lookup and keeps the
// options it was asked with, so the dial stops before touching the device.
type lookupRecorder struct {
	adapter.DNSRouter
	asked []adapter.DNSQueryOptions
}

var errLookupRecorded = E.New("lookup recorded")

func (r *lookupRecorder) Lookup(_ context.Context, _ string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	r.asked = append(r.asked, options)
	return nil, errLookupRecorded
}

func resolverTestContext() (context.Context, adapter.DNSTransport) {
	tunnelled := resolverTestTransport{tag: "dns-p-awg"}
	ctx := service.ContextWith[adapter.DNSTransportManager](context.Background(), resolverTestTransports{
		transports: map[string]adapter.DNSTransport{"dns-p-awg": tunnelled},
	})
	return ctx, tunnelled
}

func newResolverTestEndpoint(t *testing.T, ctx context.Context, resolver *option.DomainResolveOptions) (*Endpoint, *lookupRecorder) {
	t.Helper()
	query, err := destinationQueryOptions(ctx, resolver)
	if err != nil {
		t.Fatal(err)
	}
	router := &lookupRecorder{}
	w := &Endpoint{
		Adapter:          endpoint.NewAdapter(C.TypeWireGuard, "p-awg", []string{N.NetworkTCP, N.NetworkUDP}, nil),
		logger:           logger.NOP(),
		dnsRouter:        router,
		endpoint:         &wireguard.Endpoint{},
		destinationQuery: query,
	}
	w.started.Store(true)
	return w, router
}

// The names a WireGuard endpoint dials are resolved by destination_resolver's
// server, on the TCP path and on the UDP path alike.
func TestDestinationResolverResolvesDialedNames(t *testing.T) {
	ctx, tunnelled := resolverTestContext()
	w, router := newResolverTestEndpoint(t, ctx, &option.DomainResolveOptions{
		Server:   "dns-p-awg",
		Strategy: option.DomainStrategy(C.DomainStrategyIPv4Only),
	})
	destination := M.ParseSocksaddrHostPort("discord.com", 443)
	if _, err := w.DialContext(context.Background(), N.NetworkTCP, destination); err == nil || !E.IsMulti(err, errLookupRecorded) {
		t.Fatalf("dial: want the recorded lookup error, got %v", err)
	}
	if _, _, err := w.ListenPacketWithDestination(context.Background(), destination); err == nil || !E.IsMulti(err, errLookupRecorded) {
		t.Fatalf("listen: want the recorded lookup error, got %v", err)
	}
	if len(router.asked) != 2 {
		t.Fatalf("want 2 lookups, got %d", len(router.asked))
	}
	for i, asked := range router.asked {
		if asked.Transport != tunnelled {
			t.Fatalf("lookup %d went to %v, want the tunnelled server", i, asked.Transport)
		}
		if asked.Strategy != C.DomainStrategyIPv4Only {
			t.Fatalf("lookup %d strategy %v, want ipv4_only", i, asked.Strategy)
		}
	}
}

// Without the option the endpoint keeps upstream behaviour: no transport, the
// DNS rules decide.
func TestDestinationResolverUnsetLeavesRules(t *testing.T) {
	ctx, _ := resolverTestContext()
	w, router := newResolverTestEndpoint(t, ctx, nil)
	_, _ = w.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddrHostPort("discord.com", 443))
	if len(router.asked) != 1 || router.asked[0].Transport != nil {
		t.Fatalf("want one lookup with no transport, got %+v", router.asked)
	}
}

// A tag that names no DNS server fails the endpoint at construction instead of
// silently resolving outside the tunnel.
func TestDestinationResolverUnknownServer(t *testing.T) {
	ctx, _ := resolverTestContext()
	if _, err := destinationQueryOptions(ctx, &option.DomainResolveOptions{Server: "dns-missing"}); err == nil {
		t.Fatal("want an error for an unknown server")
	}
}
