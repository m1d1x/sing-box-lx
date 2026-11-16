package route

// hikkari: hot reload of the route rules — the box swaps route.rules (and, in
// box_hot_hikkari.go, route.final and dns.rules) while it runs, so a change of
// the routing mode or of the preset list does not restart the core and the TUN
// with it.
//
// The new rules are built and started aside, then published in one swap. A
// connection being matched keeps the list it started with: the match loops
// read the list once. The replaced rules are closed only after
// hotRulesRetireAfter, so a match that is still walking them (a sniff waits
// for the first bytes) never sees a closed rule, whose rule-set items drop
// their sets on Close.

import (
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	E "github.com/sagernet/sing/common/exceptions"
)

// hotRulesRetireAfter is how long replaced rules stay open for the matches
// that took them before the swap.
const hotRulesRetireAfter = time.Minute

type routerHot struct {
	access sync.RWMutex
	closed bool
}

// liveRules is the rule list new matches use.
func (r *Router) liveRules() []adapter.Rule {
	r.hot.access.RLock()
	defer r.hot.access.RUnlock()
	return r.rules
}

// closeLiveRules runs when the box closes.
func (r *Router) closeLiveRules() error {
	r.hot.access.Lock()
	r.hot.closed = true
	rules := r.rules
	r.rules = nil
	r.hot.access.Unlock()
	return closeRouteRules(rules)
}

// HotRules are route rules built and started by PrepareHotRules, not yet
// routing anything.
type HotRules struct {
	rules []adapter.Rule
}

// Close releases rules that were never committed.
func (h *HotRules) Close() error {
	if h == nil {
		return nil
	}
	return closeRouteRules(h.rules)
}

// HotRulesDeclined names what keeps new rules from going live without a
// restart: matching a process or a neighbour when the router was started
// without the searcher for it.
func (r *Router) HotRulesDeclined(rules []option.Rule, dnsRules []option.DNSRule) string {
	if r.processSearcher == nil && (hasRule(rules, isProcessRule) || hasDNSRule(dnsRules, isProcessDNSRule)) {
		return "new rules match processes, the router runs without process search"
	}
	if !r.needFindNeighbor && (hasRule(rules, isNeighborRule) || hasDNSRule(dnsRules, isNeighborDNSRule)) {
		return "new rules match neighbours, the router runs without a neighbour resolver"
	}
	return ""
}

// PrepareHotRules builds and starts rules the way the box builds them at
// start. A rule routing to a tag hasOutbound does not know is refused: cold,
// such a rule fails every connection it matches.
func (r *Router) PrepareHotRules(options []option.Rule, hasOutbound func(tag string) bool) (*HotRules, error) {
	prepared := &HotRules{rules: make([]adapter.Rule, 0, len(options))}
	for i, ruleOptions := range options {
		if err := R.ValidateNoNestedRuleActions(ruleOptions); err != nil {
			_ = prepared.Close()
			return nil, E.Cause(err, "parse rule[", i, "]")
		}
		rule, err := R.NewRule(r.ctx, r.logger, ruleOptions, false)
		if err != nil {
			_ = prepared.Close()
			return nil, E.Cause(err, "parse rule[", i, "]")
		}
		prepared.rules = append(prepared.rules, rule)
		for _, tag := range hotRuleOutbounds(rule) {
			if !hasOutbound(tag) {
				_ = prepared.Close()
				return nil, E.New("rule[", i, "] routes to unknown outbound ", tag)
			}
		}
	}
	for i, rule := range prepared.rules {
		if err := rule.Start(); err != nil {
			_ = prepared.Close()
			return nil, E.Cause(err, "initialize rule[", i, "]")
		}
	}
	return prepared, nil
}

// CommitHotRules publishes prepared rules to every match from now on.
func (r *Router) CommitHotRules(prepared *HotRules) {
	r.hot.access.Lock()
	if r.hot.closed {
		r.hot.access.Unlock()
		_ = prepared.Close()
		return
	}
	previous := r.rules
	r.rules = prepared.rules
	r.hot.access.Unlock()
	prepared.rules = nil
	time.AfterFunc(hotRulesRetireAfter, func() {
		if err := closeRouteRules(previous); err != nil {
			r.logger.Warn("hot reload: close replaced route rules: ", err)
		}
	})
}

func closeRouteRules(rules []adapter.Rule) error {
	var errs []error
	for _, rule := range rules {
		if err := rule.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return E.Errors(errs...)
}

// hotRuleOutbounds is the tag a rule's action routes to, if any.
func hotRuleOutbounds(rule adapter.Rule) []string {
	switch action := rule.Action().(type) {
	case *R.RuleActionRoute:
		if action.Outbound != "" {
			return []string{action.Outbound}
		}
	case *R.RuleActionBypass:
		if action.Outbound != "" {
			return []string{action.Outbound}
		}
	}
	return nil
}
