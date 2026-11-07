package rule

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"

	C "github.com/sagernet/sing-box/constant"
)

// The rule itself turns the override on: the inbound field that used to is gone
// from the configs we write.
func TestSniffRuleCarriesTheOverride(t *testing.T) {
	for _, want := range []bool{true, false} {
		action, err := NewRuleAction(context.Background(), log.NewNOPFactory().Logger(), option.RuleAction{
			Action:       C.RuleActionTypeSniff,
			SniffOptions: option.RouteActionSniff{OverrideDestination: want},
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := action.(*RuleActionSniff).OverrideDestination; got != want {
			t.Fatalf("override = %v, want %v", got, want)
		}
	}
}

// A rule about a range follows a flow that chose an address in it, under the name
// that replaced the address. The address itself must not reach the list a dial
// reads: a direct dial on a machine without IPv6 would fail on it.
func TestOverrideKeepsTheAddressForRulesOnly(t *testing.T) {
	russian, err := NewIPCIDRItem(false, []string{"2a02:6b8::/29"})
	if err != nil {
		t.Fatal(err)
	}
	flow := func(address string) *adapter.InboundContext {
		return &adapter.InboundContext{
			Domain:      "not-in-the-list.example",
			Destination: M.SocksaddrFrom(netip.MustParseAddr(address), 443),
		}
	}

	inside := flow("2a02:6b8::2:242")
	inside.OverrideDestinationWithDomain()
	if inside.Destination.Fqdn != "not-in-the-list.example" || inside.Destination.Port != 443 {
		t.Fatalf("destination %s", inside.Destination)
	}
	if len(inside.DestinationAddresses) != 0 {
		t.Fatalf("a dial would read %v", inside.DestinationAddresses)
	}
	if !russian.Match(inside) {
		t.Fatal("the rule lost the flow to its name")
	}

	outside := flow("2a00:1450:4001::1")
	outside.OverrideDestinationWithDomain()
	if russian.Match(outside) {
		t.Fatal("matched an address outside the range")
	}

	// A resolved name keeps matching what it resolved to.
	outside.DestinationAddresses = []netip.Addr{netip.MustParseAddr("2a02:6b8::1")}
	if !russian.Match(outside) {
		t.Fatal("a resolved address stopped matching")
	}

	// A flow that came by name has no address to keep.
	named := &adapter.InboundContext{Domain: "a.example", Destination: M.ParseSocksaddrHostPort("a.example", 443)}
	named.OverrideDestinationWithDomain()
	if named.OverriddenDestinationAddr.IsValid() || russian.Match(named) {
		t.Fatal("a flow by name matched a range")
	}
}
