package fakeip

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

// hikkari: a v6 fake address is handed out only to names with no A record.
//
// Dual-stack fake addresses for every name made Discord voice ICE spike to
// 1000 ms (the v6 candidate is tried first and the v6 UDP path through the
// tunnel is not equivalent to v4), which is why the config used ipv4_only.
// That left IPv6-only sites (ntc.party has AAAA and no A) unreachable. A name
// that has an A record keeps behaving exactly as under ipv4_only; only a name
// the v4 stack cannot reach at all gets an inet6_range address.
//
// The probe asks inet6_only_without_a_via for the A record. Anything but a
// clean NOERROR with no A address (timeout, SERVFAIL, NXDOMAIN, an A present)
// answers the AAAA query with an empty NOERROR, the ipv4_only behaviour.

// aaaaAllowed reports whether an AAAA query for domain may get a fake address.
func (t *Transport) aaaaAllowed(ctx context.Context, domain string) bool {
	if t.aProbeTag == "" {
		return true
	}
	router := service.FromContext[adapter.DNSRouter](t.ctx)
	manager := service.FromContext[adapter.DNSTransportManager](t.ctx)
	if router == nil || manager == nil {
		return false
	}
	probe, loaded := manager.Transport(t.aProbeTag)
	if !loaded {
		return false
	}
	request := &mDNS.Msg{
		MsgHdr:   mDNS.MsgHdr{RecursionDesired: true},
		Question: []mDNS.Question{{Name: mDNS.Fqdn(domain), Qtype: mDNS.TypeA, Qclass: mDNS.ClassINET}},
	}
	response, err := router.Exchange(ctx, request, adapter.DNSQueryOptions{
		Transport: probe,
		Strategy:  C.DomainStrategyIPv4Only,
	})
	if err != nil || response == nil || response.Rcode != mDNS.RcodeSuccess {
		return false
	}
	return len(dns.MessageToAddresses(response)) == 0
}
