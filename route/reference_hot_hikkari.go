package route

// hikkari: hot reload of the rules — the reference manager keeps what the
// rules route to referenced (idle connections kept, DNS transports not reset),
// so it follows the rules the box swaps in.

import "github.com/sagernet/sing-box/option"

func (m *ReferenceManager) currentRules() ([]option.Rule, []option.DNSRule) {
	m.rulesAccess.Lock()
	defer m.rulesAccess.Unlock()
	return m.rules, m.dnsRules
}

// UpdateRules takes the rules a hot reload published and recomputes the
// references on the manager's own loop.
func (m *ReferenceManager) UpdateRules(rules []option.Rule, dnsRules []option.DNSRule) {
	m.rulesAccess.Lock()
	m.rules, m.dnsRules = rules, dnsRules
	subscriber := m.subscriber
	m.rulesAccess.Unlock()
	if subscriber != nil {
		subscriber.Emit(struct{}{})
	}
}
