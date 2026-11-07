package group

// hikkari: hot reload — the selector takes a new member list without a restart.

import (
	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"
)

var _ adapter.HotMemberGroup = (*Selector)(nil)

func (s *Selector) CanUpdateMembers() error { return nil }

// UpdateMembers re-resolves the members. The selection keeps its tag when the
// tag stays a member (now pointing at that tag's current object); otherwise it
// moves to defaultTag, or to the first member, and the move is stored like a
// manual switch so a restart does not bring the removed member back.
func (s *Selector) UpdateMembers(tags []string, defaultTag string) error {
	if len(tags) == 0 {
		return E.New("missing tags")
	}
	outbounds := make(map[string]adapter.Outbound, len(tags))
	for i, tag := range tags {
		detour, loaded := s.outbound.Outbound(tag)
		if !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
		outbounds[tag] = detour
	}
	if defaultTag != "" {
		if _, loaded := outbounds[defaultTag]; !loaded {
			return E.New("default outbound not found: ", defaultTag)
		}
	}
	s.members.Lock()
	s.tags = append([]string(nil), tags...)
	s.outbounds = outbounds
	s.defaultTag = defaultTag
	s.members.Unlock()

	next, kept := s.keptSelection(outbounds)
	if !kept {
		if defaultTag != "" {
			next = outbounds[defaultTag]
		} else {
			next = outbounds[tags[0]]
		}
	}
	previous := s.selected.Load()
	if previous == next {
		return nil
	}
	s.selected.Store(next)
	invalidateReachability(s.ctx)
	if !kept && s.Tag() != "" {
		if cacheFile := service.FromContext[adapter.CacheFile](s.ctx); cacheFile != nil {
			if err := cacheFile.StoreSelected(s.Tag(), next.Tag()); err != nil {
				s.logger.Error("store selected: ", err)
			}
		}
	}
	if !kept {
		// The selected member is gone: its connections are not interrupted here,
		// they drain with the retired outbound like any other.
		s.logger.Info("selected member removed, now ", next.Tag())
	}
	if s.history != nil {
		s.history.NotifyUpdated()
	}
	return nil
}

func (s *Selector) keptSelection(outbounds map[string]adapter.Outbound) (adapter.Outbound, bool) {
	selected := s.selected.Load()
	if selected == nil {
		return nil, false
	}
	next, loaded := outbounds[selected.Tag()]
	return next, loaded
}
