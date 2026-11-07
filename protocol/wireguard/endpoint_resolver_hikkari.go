package wireguard

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
)

// destinationQueryOptions turns destination_resolver into the query options the
// endpoint passes when it resolves a connection's destination name. Without
// the option the endpoint asks the DNS router with no transport, so the DNS
// rules pick the server: for the core's own lookups that is dns.final, a
// resolver outside the tunnel, and the provider sees (and may forge) every name
// that then travels inside it. DNS servers are created before endpoints, so the
// transport is looked up here and a wrong tag fails the config at start.
func destinationQueryOptions(ctx context.Context, resolver *option.DomainResolveOptions) (adapter.DNSQueryOptions, error) {
	if resolver == nil || resolver.Server == "" {
		return adapter.DNSQueryOptions{}, nil
	}
	return dialer.NewDNSQueryOptions(ctx, resolver, false)
}
