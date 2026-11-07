package outbound

// hikkari: hot reload — profile outbounds are replaced, added and removed while
// the box runs, so a config change on the hub does not restart the core and the
// TUN with it. The box (box_hot_hikkari.go) decides what may change in place;
// the manager only owns the objects and their lifecycle scopes.

import (
	"context"
	"os"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

type hotState struct {
	// scope is the manager's own scope (the one Start receives): the outbounds
	// created from the config at boot are started as its children.
	scope *adapter.Scope
	// detached holds the scope of every outbound started by StartDetached. They
	// are not children of scope, so the manager closes them itself.
	detached map[adapter.Outbound]*adapter.Scope
}

// rememberScope runs on every Start stage; the scope is the same each time.
func (m *Manager) rememberScope(scope *adapter.Scope) {
	if m.hot.scope != nil {
		return
	}
	m.hot.scope = scope
	scope.Add(m.closeDetached)
}

// CreateDetached builds an outbound from options without registering it: it is
// invisible to routing until Swap publishes it.
func (m *Manager) CreateDetached(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, outboundType string, options any) (adapter.Outbound, error) {
	if tag == "" {
		return nil, os.ErrInvalid
	}
	return m.registry.CreateOutbound(ctx, router, logger, tag, outboundType, options)
}

// StartDetached runs every start stage of an outbound from CreateDetached in a
// scope of its own. On failure everything it started is closed again.
func (m *Manager) StartDetached(ctx context.Context, logger log.ContextLogger, outbound adapter.Outbound) error {
	m.access.Lock()
	parent := m.hot.scope
	m.access.Unlock()
	if parent == nil {
		return E.New("outbound manager is not started")
	}
	scope := adapter.NewScope(ctx, logger)
	if lifecycle, isLifecycle := outbound.(adapter.Lifecycle); isLifecycle {
		name := "outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
		for _, stage := range adapter.ListStartStages {
			if err := scope.Start(name, lifecycle, stage); err != nil {
				return E.Errors(err, scope.Close())
			}
		}
	}
	m.access.Lock()
	if m.hot.detached == nil {
		m.hot.detached = make(map[adapter.Outbound]*adapter.Scope)
	}
	m.hot.detached[outbound] = scope
	m.access.Unlock()
	return nil
}

// CloseDetached closes an outbound that StartDetached started but Swap never
// published (the reload failed half way).
func (m *Manager) CloseDetached(outbound adapter.Outbound) error {
	return m.Retire(outbound)
}

// HotOutbound is one outbound published by Swap: a new tag, or a new object
// under a tag that already exists.
type HotOutbound struct {
	Outbound     adapter.Outbound
	OutboundType string
	Options      any
}

// Swap publishes outbounds and drops the tags in remove, atomically for
// routing: a lookup sees either the old set or the new one. The previous object
// of every replaced or removed tag is returned and keeps running; the caller
// retires it once its connections are gone. Outbounds() returns a fresh slice
// after a swap, so a caller still ranging over the old one is not disturbed.
func (m *Manager) Swap(publish []HotOutbound, remove []string) ([]adapter.Outbound, error) {
	m.access.Lock()
	defer m.access.Unlock()
	removing := make(map[string]bool, len(remove))
	for _, tag := range remove {
		if _, loaded := m.outboundByTag[tag]; !loaded {
			return nil, E.New("remove outbound: not found: ", tag)
		}
		removing[tag] = true
	}
	publishing := make(map[string]HotOutbound, len(publish))
	for _, item := range publish {
		tag := item.Outbound.Tag()
		if removing[tag] {
			return nil, E.New("outbound both published and removed: ", tag)
		}
		if _, internal := m.internalByTag[tag]; internal {
			return nil, E.New("outbound tag collides with an internal outbound: ", tag)
		}
		if m.endpoint != nil {
			if _, exists := m.endpoint.Get(tag); exists {
				return nil, E.New("outbound tag collides with endpoint: ", tag)
			}
		}
		publishing[tag] = item
	}
	if m.defaultOutbound != nil && removing[m.defaultOutbound.Tag()] {
		return nil, E.New("remove outbound: the default outbound cannot be removed: ", m.defaultOutbound.Tag())
	}
	var retired []adapter.Outbound
	outbounds := make([]adapter.Outbound, 0, len(m.outbounds)+len(publish))
	for _, current := range m.outbounds {
		tag := current.Tag()
		if removing[tag] {
			retired = append(retired, current)
			continue
		}
		if item, replaced := publishing[tag]; replaced {
			retired = append(retired, current)
			outbounds = append(outbounds, item.Outbound)
			delete(publishing, tag)
			continue
		}
		outbounds = append(outbounds, current)
	}
	for _, item := range publish {
		if _, pending := publishing[item.Outbound.Tag()]; pending {
			outbounds = append(outbounds, item.Outbound)
		}
	}
	outboundByTag := make(map[string]adapter.Outbound, len(outbounds))
	for _, outbound := range outbounds {
		outboundByTag[outbound.Tag()] = outbound
	}
	for _, item := range publish {
		m.optionsByTag[item.Outbound.Tag()] = managedOptions{outboundType: item.OutboundType, options: item.Options}
	}
	for tag := range removing {
		delete(m.optionsByTag, tag)
	}
	if m.defaultOutbound != nil {
		if replacement, loaded := outboundByTag[m.defaultOutbound.Tag()]; loaded {
			m.defaultOutbound = replacement
		}
	}
	m.outbounds = outbounds
	m.outboundByTag = outboundByTag
	return retired, nil
}

// Retire closes an outbound that is no longer published: its own scope when
// StartDetached started it, otherwise its child scope under the manager.
func (m *Manager) Retire(outbound adapter.Outbound) error {
	m.access.Lock()
	scope, detached := m.hot.detached[outbound]
	if detached {
		delete(m.hot.detached, outbound)
	}
	parent := m.hot.scope
	m.access.Unlock()
	if detached {
		return scope.Close()
	}
	lifecycle, isLifecycle := outbound.(adapter.Lifecycle)
	if !isLifecycle || parent == nil {
		return nil
	}
	return parent.CloseChild(lifecycle)
}

// closeDetached is the manager scope's cleanup: at shutdown the outbounds of
// hot reloads close together with the boot ones.
func (m *Manager) closeDetached() error {
	m.access.Lock()
	scopes := make([]*adapter.Scope, 0, len(m.hot.detached))
	for _, scope := range m.hot.detached {
		scopes = append(scopes, scope)
	}
	m.hot.detached = nil
	m.access.Unlock()
	return E.Errors(common.Map(scopes, func(scope *adapter.Scope) error { return scope.Close() })...)
}
