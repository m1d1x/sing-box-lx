package dns

// hikkari: hot reload of the DNS rules — the box swaps dns.rules while it runs
// (box_hot_hikkari.go), as the route rules. An exchange reads the rule list
// once under rulesAccess and walks that list to the end; the replaced rules
// are closed only after hotRulesRetireAfter, so no walk meets a closed rule.

import (
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	E "github.com/sagernet/sing/common/exceptions"
)

// hotRulesRetireAfter is how long replaced rules stay open for the exchanges
// that took them before the swap.
const hotRulesRetireAfter = time.Minute

// HotRules are DNS rules built and started by PrepareHotRules, not yet
// answering anything.
type HotRules struct {
	raw   []option.DNSRule
	rules []adapter.DNSRule
}

// Close releases rules that were never committed.
func (h *HotRules) Close() error {
	if h == nil {
		return nil
	}
	closeRules(h.rules)
	return nil
}

// PrepareHotRules builds and starts rules the way the router builds them at
// start. A declined reason means the rules need a restart: the router is not
// running, or they would switch the legacy DNS mode, which the running rules
// and the transports were set up for.
func (r *Router) PrepareHotRules(raw []option.DNSRule) (*HotRules, string, error) {
	r.rulesAccess.RLock()
	running := r.started && !r.closing
	legacyDNSMode := r.legacyDNSMode
	r.rulesAccess.RUnlock()
	if !running {
		return nil, "dns router is not running", nil
	}
	rules, newLegacyDNSMode, _, err := r.buildRulesFrom(raw, true)
	if err != nil {
		return nil, "", err
	}
	prepared := &HotRules{raw: append([]option.DNSRule(nil), raw...), rules: rules}
	if newLegacyDNSMode != legacyDNSMode {
		_ = prepared.Close()
		return nil, "new dns rules change the legacy dns mode", nil
	}
	for i, rule := range rules {
		route, isRoute := rule.Action().(*R.RuleActionDNSRoute)
		if !isRoute || route.Server == "" {
			continue
		}
		if _, loaded := r.transport.Transport(route.Server); !loaded {
			_ = prepared.Close()
			return nil, "", E.New("dns rule[", i, "] routes to unknown server ", route.Server)
		}
	}
	return prepared, "", nil
}

// CommitHotRules publishes prepared rules to every exchange from now on.
func (r *Router) CommitHotRules(prepared *HotRules) {
	r.rulesAccess.Lock()
	if r.closing {
		r.rulesAccess.Unlock()
		_ = prepared.Close()
		return
	}
	previous := r.rules
	r.rules = prepared.rules
	r.rawRules = prepared.raw
	r.rulesAccess.Unlock()
	prepared.rules = nil
	time.AfterFunc(hotRulesRetireAfter, func() { closeRules(previous) })
}
