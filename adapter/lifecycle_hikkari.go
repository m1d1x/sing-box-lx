package adapter

// hikkari: hot reload — closing one component's scope without closing its parent.

// CloseChild closes the scope that Start created for component and forgets it,
// leaving the rest of s running. The parent's own cleanup for that child still
// runs at s.Close and finds an already closed scope, which is a no-op. A
// component that was never started under s, or a scope already closed, is not an
// error.
func (s *Scope) CloseChild(component Lifecycle) error {
	s.access.Lock()
	child, loaded := s.children[component]
	if loaded {
		delete(s.children, component)
	}
	s.access.Unlock()
	if !loaded {
		return nil
	}
	return child.Close()
}
