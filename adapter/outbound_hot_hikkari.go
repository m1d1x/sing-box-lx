package adapter

// hikkari: hot reload.

// HotMemberGroup is an outbound group whose members can be changed while it
// runs. tags are resolved through the outbound manager at the time of the call,
// so a member replaced under the same tag is picked up as the new object.
// defaultTag is the selector's `default` and is ignored by groups without one.
// On error the group is left as it was.
//
// CanUpdateMembers says up front whether the group supports it at all, so a
// reload can be declined before anything is published.
type HotMemberGroup interface {
	OutboundGroup
	CanUpdateMembers() error
	UpdateMembers(tags []string, defaultTag string) error
}
