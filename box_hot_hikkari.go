package box

// hikkari: hot reload — apply a new config to the running box when it differs
// only in what can change without a restart: the proxy outbounds and the
// members of the selector / urltest groups over them. Anything else (TUN,
// inbounds, DNS, rules, endpoints, groups themselves) is declined with the
// reason, and the caller restarts the core as before.
//
// A replaced outbound keeps serving the connections it already carries: it is
// retired (closed) only when the connection tracker shows none of them left,
// or after hotDrainLimit. New connections go to the new object at once, since
// routing looks outbounds up by tag for every connection.

import (
	stdjson "encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/service"
)

const (
	// hotDrainLimit bounds how long a replaced outbound keeps its connections.
	hotDrainLimit = 30 * time.Minute
	// hotDrainPoll is how often the tracker is asked whether they are gone.
	hotDrainPoll = 2 * time.Second
	// hotDrainUntracked is the wait when the box has no connection tracker.
	hotDrainUntracked = 5 * time.Minute
)

// HotReloadResult is what a reload did. Applied=false with Declined set means
// nothing was touched and the config needs a restart.
type HotReloadResult struct {
	Applied  bool     `json:"applied"`
	Declined string   `json:"declined,omitempty"`
	Added    []string `json:"added,omitempty"`
	Removed  []string `json:"removed,omitempty"`
	Replaced []string `json:"replaced,omitempty"`
	Groups   []string `json:"groups,omitempty"`
}

// hotPlan is the difference between two configs, checked to be hot-applicable.
type hotPlan struct {
	added    []string
	removed  []string
	replaced []string
	groups   []hotGroupChange
}

type hotGroupChange struct {
	tag        string
	members    []string
	defaultTag string
}

func (p *hotPlan) empty() bool {
	return len(p.added) == 0 && len(p.removed) == 0 && len(p.replaced) == 0 && len(p.groups) == 0
}

func (p *hotPlan) result() HotReloadResult {
	return HotReloadResult{
		Applied:  true,
		Added:    p.added,
		Removed:  p.removed,
		Replaced: p.replaced,
		Groups:   common.Map(p.groups, func(it hotGroupChange) string { return it.tag }),
	}
}

// HotReload applies next (parsed from nextContent) over the running box, which
// was built from previousContent. It is not safe to call concurrently with
// itself; the run loop serialises reloads.
func (s *Box) HotReload(previousContent, nextContent []byte, next option.Options) (HotReloadResult, error) {
	plan, declined, err := planHotReload(previousContent, nextContent)
	if err != nil {
		return HotReloadResult{}, err
	}
	if declined != "" {
		return HotReloadResult{Declined: declined}, nil
	}
	if plan.empty() {
		return HotReloadResult{Applied: true}, nil
	}
	if declined = s.checkHotGroups(plan); declined != "" {
		return HotReloadResult{Declined: declined}, nil
	}
	// The same option pre-pass New runs (lx: SPEC 098/120), so a hot outbound
	// is built from the options a cold start would build it from.
	resolved, _, err := option.ResolveLX(&next)
	if err != nil {
		return HotReloadResult{}, err
	}
	if err = alignPathMTU(&next, resolved.MTUAlignOrDefault(), s.logFactory.NewLogger("lx")); err != nil {
		return HotReloadResult{}, err
	}
	byTag := make(map[string]option.Outbound, len(next.Outbounds))
	for _, item := range next.Outbounds {
		byTag[item.Tag] = item
	}

	var publish []outbound.HotOutbound
	abort := func(cause error) (HotReloadResult, error) {
		for _, item := range publish {
			if closeErr := s.outbound.CloseDetached(item.Outbound); closeErr != nil {
				s.logger.Warn("hot reload: close unpublished outbound[", item.Outbound.Tag(), "]: ", closeErr)
			}
		}
		return HotReloadResult{}, cause
	}
	for _, tag := range append(append([]string(nil), plan.added...), plan.replaced...) {
		item := byTag[tag]
		logger := s.logFactory.NewLogger(F.ToString("outbound/", item.Type, "[", tag, "]"))
		outboundCtx := adapter.WithContext(s.ctx, &adapter.InboundContext{Outbound: tag})
		created, createErr := s.outbound.CreateDetached(outboundCtx, s.router, logger, tag, item.Type, item.Options)
		if createErr != nil {
			return abort(E.Cause(createErr, "hot reload: initialize outbound ", item.Type, "[", tag, "]"))
		}
		if startErr := s.outbound.StartDetached(s.ctx, logger, created); startErr != nil {
			common.Close(created)
			return abort(E.Cause(startErr, "hot reload: start outbound ", item.Type, "[", tag, "]"))
		}
		publish = append(publish, outbound.HotOutbound{Outbound: created, OutboundType: item.Type, Options: item.Options})
	}
	swappedAt := time.Now()
	retired, err := s.outbound.Swap(publish, plan.removed)
	if err != nil {
		return abort(E.Cause(err, "hot reload"))
	}
	// Groups re-resolve every member by tag: a replaced member becomes its new
	// object, a removed one leaves. checkHotGroups made sure each group can.
	for _, change := range plan.groups {
		group, _ := s.outbound.Outbound(change.tag)
		if updateErr := group.(adapter.HotMemberGroup).UpdateMembers(change.members, change.defaultTag); updateErr != nil {
			// Not reachable after checkHotGroups; the box keeps running on the
			// published outbounds and the caller restarts to get a clean state.
			return HotReloadResult{}, E.Cause(updateErr, "hot reload: group[", change.tag, "]")
		}
	}
	s.router.InvalidateReachability()
	for _, old := range retired {
		go s.drainRetired(old, swappedAt)
	}
	result := plan.result()
	s.logger.Info("hot reload: applied, outbounds +", len(plan.added), " -", len(plan.removed), " ~", len(plan.replaced), ", groups ", strings.Join(result.Groups, ","))
	return result, nil
}

// checkHotGroups verifies, before anything is published, that every group
// the plan changes supports a member change.
func (s *Box) checkHotGroups(plan *hotPlan) string {
	for _, change := range plan.groups {
		group, loaded := s.outbound.Outbound(change.tag)
		if !loaded {
			return "group " + change.tag + " is not running"
		}
		hot, isHot := group.(adapter.HotMemberGroup)
		if !isHot {
			return "group " + change.tag + " (" + group.Type() + ") cannot change members"
		}
		if err := hot.CanUpdateMembers(); err != nil {
			return err.Error()
		}
	}
	return ""
}

// drainRetired closes a replaced or removed outbound once the connections it
// carried are gone. A connection belongs to it when the tracker saw it routed
// through the tag before the swap; later ones went to the new object.
func (s *Box) drainRetired(old adapter.Outbound, swappedAt time.Time) {
	tag := old.Tag()
	tracker := service.PtrFromContext[trafficcontrol.Manager](s.ctx)
	limit := hotDrainLimit
	if tracker == nil {
		limit = hotDrainUntracked
	}
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	poll := time.NewTicker(hotDrainPoll)
	defer poll.Stop()
	reason := "drained"
wait:
	for {
		if tracker != nil && carriedBefore(tracker, tag, swappedAt) == 0 {
			break
		}
		select {
		case <-s.ctx.Done():
			// The box is closing; its scopes close this outbound anyway.
			return
		case <-deadline.C:
			reason = "drain limit reached"
			if tracker != nil {
				reason += F.ToString(", ", carriedBefore(tracker, tag, swappedAt), " connections cut")
			}
			break wait
		case <-poll.C:
		}
	}
	if err := s.outbound.Retire(old); err != nil {
		s.logger.Warn("hot reload: retire outbound[", tag, "]: ", err)
		return
	}
	s.logger.Info("hot reload: retired previous outbound[", tag, "] after ", F.Seconds(time.Since(swappedAt).Seconds()), "s, ", reason)
}

func carriedBefore(tracker *trafficcontrol.Manager, tag string, swappedAt time.Time) int {
	count := 0
	for _, connection := range tracker.Connections() {
		if !connection.CreatedAt.Before(swappedAt) {
			continue
		}
		if slices.Contains(connection.Chain, tag) || slices.Contains(connection.Detour, tag) {
			count++
		}
	}
	return count
}

// planHotReload compares two configs as plain JSON. It returns a non-empty
// declined reason when the difference needs a restart; err only for configs
// that do not parse.
func planHotReload(previousContent, nextContent []byte) (*hotPlan, string, error) {
	var previous, next map[string]any
	if err := stdjson.Unmarshal(previousContent, &previous); err != nil {
		return nil, "", E.Cause(err, "hot reload: decode running config")
	}
	if err := stdjson.Unmarshal(nextContent, &next); err != nil {
		return nil, "", E.Cause(err, "hot reload: decode new config")
	}
	previousOutbounds, declined := outboundsByTag(previous["outbounds"])
	if declined != "" {
		return nil, "running config: " + declined, nil
	}
	nextOutbounds, declined := outboundsByTag(next["outbounds"])
	if declined != "" {
		return nil, "new config: " + declined, nil
	}
	delete(previous, "outbounds")
	delete(next, "outbounds")
	if differing := differingKeys(previous, next); len(differing) > 0 {
		return nil, "changed outside outbounds: " + strings.Join(differing, ", "), nil
	}

	plan := &hotPlan{}
	for _, tag := range sortedKeys(previousOutbounds) {
		before := previousOutbounds[tag]
		after, kept := nextOutbounds[tag]
		if isHotGroup(before) || (kept && isHotGroup(after)) {
			if !kept || !isHotGroup(before) || !isHotGroup(after) {
				return nil, "group " + tag + " added, removed or retyped", nil
			}
			change, changed, reason := groupChange(tag, before, after)
			if reason != "" {
				return nil, reason, nil
			}
			if changed {
				plan.groups = append(plan.groups, change)
			}
			continue
		}
		if !kept {
			plan.removed = append(plan.removed, tag)
		} else if !reflect.DeepEqual(before, after) {
			plan.replaced = append(plan.replaced, tag)
		}
	}
	for _, tag := range sortedKeys(nextOutbounds) {
		if _, existed := previousOutbounds[tag]; existed {
			continue
		}
		if isHotGroup(nextOutbounds[tag]) {
			return nil, "group " + tag + " added", nil
		}
		plan.added = append(plan.added, tag)
	}
	touched := make(map[string]bool)
	for _, tag := range slices.Concat(plan.added, plan.removed, plan.replaced) {
		touched[tag] = true
		item := nextOutbounds[tag]
		if item == nil {
			item = previousOutbounds[tag]
		}
		if reason := hotOutboundRefused(tag, item); reason != "" {
			return nil, reason, nil
		}
	}
	// A touched tag may be used through a cached reference (a dialer's detour,
	// a DNS server's detour, an endpoint) only by the groups this reload
	// re-resolves. Routing rules and route.final look tags up per connection,
	// but are part of the rest of the config, which must stay unchanged, so a
	// rule naming a removed tag is refused below as well.
	for tag := range touched {
		if path := findReference(next, tag, ""); path != "" {
			return nil, "outbound " + tag + " is referenced at " + path, nil
		}
		for otherTag, other := range nextOutbounds {
			if otherTag == tag || isHotGroup(other) {
				continue
			}
			if path := findReference(other, tag, "outbounds["+otherTag+"]"); path != "" {
				return nil, "outbound " + tag + " is referenced at " + path, nil
			}
		}
	}
	// Groups whose member list is the same still re-resolve when a member was
	// replaced, so they stop handing out the retired object.
	planned := make(map[string]bool, len(plan.groups))
	for _, change := range plan.groups {
		planned[change.tag] = true
	}
	for _, tag := range sortedKeys(nextOutbounds) {
		item := nextOutbounds[tag]
		if !isHotGroup(item) || planned[tag] {
			continue
		}
		members := stringList(item["outbounds"])
		if slices.ContainsFunc(members, func(member string) bool { return touched[member] }) {
			defaultTag, _ := item["default"].(string)
			plan.groups = append(plan.groups, hotGroupChange{tag: tag, members: members, defaultTag: defaultTag})
		}
	}
	sort.Slice(plan.groups, func(i, j int) bool { return plan.groups[i].tag < plan.groups[j].tag })
	return plan, "", nil
}

func outboundsByTag(raw any) (map[string]map[string]any, string) {
	list, _ := raw.([]any)
	if raw != nil && list == nil {
		return nil, "outbounds is not a list"
	}
	result := make(map[string]map[string]any, len(list))
	for i, item := range list {
		block, _ := item.(map[string]any)
		tag, _ := block["tag"].(string)
		if tag == "" {
			return nil, F.ToString("outbound ", i, " has no tag")
		}
		if _, duplicate := result[tag]; duplicate {
			return nil, "duplicate outbound tag " + tag
		}
		result[tag] = block
	}
	return result, ""
}

func isHotGroup(block map[string]any) bool {
	kind, _ := block["type"].(string)
	return kind == C.TypeSelector || kind == C.TypeURLTest
}

// groupChange: a group may change its members (and a selector its default);
// any other option needs a restart.
func groupChange(tag string, before, after map[string]any) (hotGroupChange, bool, string) {
	strip := func(block map[string]any) map[string]any {
		copied := make(map[string]any, len(block))
		for key, value := range block {
			if key != "outbounds" && key != "default" {
				copied[key] = value
			}
		}
		return copied
	}
	if !reflect.DeepEqual(strip(before), strip(after)) {
		return hotGroupChange{}, false, "group " + tag + " changed options other than its members"
	}
	members := stringList(after["outbounds"])
	if len(members) == 0 {
		return hotGroupChange{}, false, "group " + tag + " has no members"
	}
	defaultTag, _ := after["default"].(string)
	if defaultTag != "" && !slices.Contains(members, defaultTag) {
		return hotGroupChange{}, false, "group " + tag + " default " + defaultTag + " is not a member"
	}
	changed := !reflect.DeepEqual(before["outbounds"], after["outbounds"]) || before["default"] != after["default"]
	return hotGroupChange{tag: tag, members: members, defaultTag: defaultTag}, changed, ""
}

// hotOutboundRefused names what keeps an outbound from changing in place:
// ones that other outbounds are built over, or that are built over another.
func hotOutboundRefused(tag string, block map[string]any) string {
	kind, _ := block["type"].(string)
	switch kind {
	case C.TypeDirect, C.TypeBlock, C.TypeDNS, C.TypeChain:
		return "outbound " + tag + " (" + kind + ") changes only with a restart"
	}
	if detour, _ := block["detour"].(string); detour != "" {
		return "outbound " + tag + " dials through detour " + detour
	}
	return ""
}

// findReference returns the path of the first string equal to tag in value.
func findReference(value any, tag string, path string) string {
	switch typed := value.(type) {
	case string:
		if typed == tag {
			if path == "" {
				return "."
			}
			return path
		}
	case map[string]any:
		for _, key := range sortedKeys(typed) {
			if found := findReference(typed[key], tag, joinPath(path, key)); found != "" {
				return found
			}
		}
	case []any:
		for i, item := range typed {
			if found := findReference(item, tag, fmt.Sprintf("%s[%d]", path, i)); found != "" {
				return found
			}
		}
	}
	return ""
}

func joinPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// differingKeys lists the top-level keys that differ, one level deeper for
// objects, so the decline reason says what changed.
func differingKeys(previous, next map[string]any) []string {
	var differing []string
	for _, key := range sortedKeys(unionKeys(previous, next)) {
		before, after := previous[key], next[key]
		if reflect.DeepEqual(before, after) {
			continue
		}
		beforeMap, beforeIsMap := before.(map[string]any)
		afterMap, afterIsMap := after.(map[string]any)
		if !beforeIsMap || !afterIsMap {
			differing = append(differing, key)
			continue
		}
		for _, sub := range sortedKeys(unionKeys(beforeMap, afterMap)) {
			if !reflect.DeepEqual(beforeMap[sub], afterMap[sub]) {
				differing = append(differing, key+"."+sub)
			}
		}
	}
	return differing
}

func unionKeys(a, b map[string]any) map[string]any {
	union := make(map[string]any, len(a)+len(b))
	for key := range a {
		union[key] = nil
	}
	for key := range b {
		union[key] = nil
	}
	return union
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func stringList(raw any) []string {
	list, _ := raw.([]any)
	result := make([]string, 0, len(list))
	for _, item := range list {
		if text, isText := item.(string); isText {
			result = append(result, text)
		}
	}
	return result
}
