package group

// hikkari: hot reload — the urltest group takes a new member list without a
// restart. The probing state lives in URLTestGroup, which holds its members as
// objects, so a member change builds a new URLTestGroup over the current
// objects and swaps it in: the held node, the penalties of unchanged members and
// the interrupt group carry over, the shared history (keyed by tag) stays.

import (
	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ adapter.HotMemberGroup = (*URLTest)(nil)

// CanUpdateMembers: the round_robin pool keeps slot state of its own that a
// rebuild would have to carry; it is not supported, and a reload that touches
// such a group restarts the core instead.
func (s *URLTest) CanUpdateMembers() error {
	if s.balancer != nil {
		return E.New("urltest[", s.Tag(), "]: member change in round_robin mode needs a restart")
	}
	if s.group.Load() == nil {
		return E.New("urltest[", s.Tag(), "] is not started")
	}
	return nil
}

func (s *URLTest) UpdateMembers(tags []string, _ string) error {
	if err := s.CanUpdateMembers(); err != nil {
		return err
	}
	if len(tags) == 0 {
		return E.New("missing tags")
	}
	outbounds := make([]adapter.Outbound, 0, len(tags))
	for i, tag := range tags {
		detour, loaded := s.outbound.Outbound(tag)
		if !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
		outbounds = append(outbounds, detour)
	}
	next, err := NewURLTestGroup(s.ctx, s.outbound, s.logger, outbounds, s.link, s.interval, s.tolerance, s.idleTimeout, s.interruptExternalConnections)
	if err != nil {
		return err
	}
	next.groupTag = s.Tag()
	next.failover = s.failover

	previous := s.group.Load()
	previous.updateAccess.Lock()
	byTag := make(map[string]adapter.Outbound, len(outbounds))
	for _, detour := range outbounds {
		byTag[detour.Tag()] = detour
	}
	unchanged := make(map[string]bool, len(outbounds))
	for _, detour := range previous.outbounds {
		if byTag[detour.Tag()] == detour {
			unchanged[detour.Tag()] = true
		}
	}
	// The held node stays held under its tag, as the new object when it was
	// replaced: a knob change on the node in use must not move the exit.
	if previous.selectedOutboundTCP != nil {
		next.selectedOutboundTCP = byTag[previous.selectedOutboundTCP.Tag()]
	}
	if previous.selectedOutboundUDP != nil {
		next.selectedOutboundUDP = byTag[previous.selectedOutboundUDP.Tag()]
	}
	next.lastSelected.Store(previous.lastSelected.Load())
	// Connections the old group handed out stay reachable for interrupts.
	next.interruptGroup = previous.interruptGroup
	// Penalties are evidence about one object; a replaced node starts clean.
	previous.penalties.Range(func(key, value any) bool {
		if tag, isTag := key.(string); isTag && unchanged[tag] {
			next.penalties.Store(key, value)
		}
		return true
	})
	previous.updateAccess.Unlock()

	for tag := range removedTags(previous.outbounds, byTag) {
		previous.history.DeleteURLTestHistory(tag)
	}
	s.members.Lock()
	s.tags = append([]string(nil), tags...)
	s.members.Unlock()
	s.group.Store(next)
	// PostStart probes the held nodes at once (failover) or all of them: the
	// replaced node is checked with its new options right away.
	next.PostStart()
	if err := previous.Close(); err != nil {
		s.logger.Warn("close previous group: ", err)
	}
	invalidateReachability(s.ctx)
	next.history.NotifyUpdated()
	return nil
}

func removedTags(previous []adapter.Outbound, current map[string]adapter.Outbound) map[string]bool {
	removed := make(map[string]bool)
	for _, detour := range previous {
		if _, kept := current[detour.Tag()]; !kept {
			removed[detour.Tag()] = true
		}
	}
	return removed
}
