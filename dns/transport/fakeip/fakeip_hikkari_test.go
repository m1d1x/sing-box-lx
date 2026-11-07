package fakeip

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

type probeRouter struct {
	adapter.DNSRouter
	respond func(domain string) (*mDNS.Msg, error)
}

func (r probeRouter) Exchange(_ context.Context, message *mDNS.Msg, _ adapter.DNSQueryOptions) (*mDNS.Msg, error) {
	return r.respond(dns.FqdnToDomain(message.Question[0].Name))
}

type probeManager struct {
	adapter.DNSTransportManager
	tags map[string]bool
}

func (m probeManager) Transport(tag string) (adapter.DNSTransport, bool) {
	return nil, m.tags[tag]
}

func newProbedTransport(t *testing.T, tag string, respond func(string) (*mDNS.Msg, error)) *Transport {
	t.Helper()
	ctx := service.ContextWith[adapter.DNSRouter](context.Background(), probeRouter{respond: respond})
	ctx = service.ContextWith[adapter.DNSTransportManager](ctx, probeManager{tags: map[string]bool{"dns-direct": true}})
	v4 := badoption.Prefix(netip.MustParsePrefix("198.18.0.0/15"))
	v6 := badoption.Prefix(netip.MustParsePrefix("fc00::/18"))
	transport, err := NewTransport(ctx, nil, "fakeip-dns", option.FakeIPDNSServerOptions{
		Inet4Range:           &v4,
		Inet6Range:           &v6,
		Inet6OnlyWithoutAVia: tag,
	})
	if err != nil {
		t.Fatal(err)
	}
	tr := transport.(*Transport)
	if err := tr.store.Start(); err != nil {
		t.Fatal(err)
	}
	return tr
}

func aMessage(domain string, rcode int, addrs ...string) *mDNS.Msg {
	m := &mDNS.Msg{MsgHdr: mDNS.MsgHdr{Response: true, Rcode: rcode}}
	m.Question = []mDNS.Question{{Name: mDNS.Fqdn(domain), Qtype: mDNS.TypeA, Qclass: mDNS.ClassINET}}
	for _, a := range addrs {
		m.Answer = append(m.Answer, &mDNS.A{
			Hdr: mDNS.RR_Header{Name: mDNS.Fqdn(domain), Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 60},
			A:   netip.MustParseAddr(a).AsSlice(),
		})
	}
	return m
}

func TestAAAAOnlyWithoutA(t *testing.T) {
	cases := []struct {
		name    string
		tag     string
		respond func(string) (*mDNS.Msg, error)
		wantV6  bool
	}{
		{"has A record keeps ipv4 behaviour", "dns-direct", func(d string) (*mDNS.Msg, error) {
			return aMessage(d, mDNS.RcodeSuccess, "203.0.113.7"), nil
		}, false},
		{"no A record gets a v6 fake address", "dns-direct", func(d string) (*mDNS.Msg, error) {
			return aMessage(d, mDNS.RcodeSuccess), nil
		}, true},
		{"NXDOMAIN gets no address", "dns-direct", func(d string) (*mDNS.Msg, error) {
			return aMessage(d, mDNS.RcodeNameError), nil
		}, false},
		{"probe failure gets no address", "dns-direct", func(string) (*mDNS.Msg, error) {
			return nil, errors.New("timeout")
		}, false},
		{"unknown probe server gets no address", "missing", func(d string) (*mDNS.Msg, error) {
			return aMessage(d, mDNS.RcodeSuccess), nil
		}, false},
		{"option unset keeps upstream dual-stack", "", func(d string) (*mDNS.Msg, error) {
			return aMessage(d, mDNS.RcodeSuccess, "203.0.113.7"), nil
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := newProbedTransport(t, tc.tag, tc.respond)
			defer tr.store.Close()
			q := &mDNS.Msg{Question: []mDNS.Question{{Name: "ntc.party.", Qtype: mDNS.TypeAAAA, Qclass: mDNS.ClassINET}}}
			resp, err := tr.Exchange(context.Background(), q)
			if err != nil {
				t.Fatal(err)
			}
			got := len(resp.Answer) == 1
			if got != tc.wantV6 {
				t.Fatalf("v6 answer = %v, want %v (resp %v)", got, tc.wantV6, resp)
			}
			if resp.Rcode != mDNS.RcodeSuccess {
				t.Fatalf("rcode = %d, want NOERROR", resp.Rcode)
			}
		})
	}
}

func TestAQueryUnaffected(t *testing.T) {
	tr := newProbedTransport(t, "dns-direct", func(d string) (*mDNS.Msg, error) {
		t.Fatal("A query must not trigger a probe")
		return nil, nil
	})
	defer tr.store.Close()
	q := &mDNS.Msg{Question: []mDNS.Question{{Name: "discord.com.", Qtype: mDNS.TypeA, Qclass: mDNS.ClassINET}}}
	resp, err := tr.Exchange(context.Background(), q)
	if err != nil || len(resp.Answer) != 1 {
		t.Fatalf("A answer: %v %v", resp, err)
	}
}
