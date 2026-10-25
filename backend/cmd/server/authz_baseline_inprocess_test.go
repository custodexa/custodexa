package main

import (
	"reflect"
	"time"
	"unsafe"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/sshproxy"
)

// Authorization decision baseline: per-scenario reset of in-process state.
//
// Caches, ticket stores, throttles and counters that survive a request and
// must not leak between scenarios are listed in inProcessResetFields and
// reset here, by reflection over the live service
// graph so that no product code gains a reset hook. Map fields are emptied in
// place (several of these maps are captured by closures, so the map value
// itself must not be replaced); value fields are restored from the copy taken
// when the template was snapshotted.

// inProcessResetFields type name (as printed by reflect) -> fields to reset.
var inProcessResetFields = map[string][]string{
	"*policy.SecurityPolicyService":            {"cache", "lastGood"},
	"*proxy.ConnectTokenManager":               {"grants"},
	"*proxy.ObserverTicketManager":             {"tickets"},
	"*api.RecordingTokenManager":               {"grants", "observed", "unconfirmed"},
	"*sshproxy.ShareManager":                   {"byCode", "bySess"},
	"*api.sourceAbuseGuard":                    {"sources", "agg", "overflow", "global", "inFlight"},
	"*identity.externalLoginAttemptAggregator": {"entries"},
	"*identity.OIDCDiscoveryService":           {"cache"},
	"*audit.AuditFailureService":               {"failing", "pendingClose"},
	"*audit.RoleStateReconciler":               {"lastKeys"},
	"*offsite.OffsiteProfileService":           {"clients"},
}

// inProcessLazy types created on first use; their fields are all maps, so
// they can be picked up after the template without a saved value.
var inProcessLazy = map[string]bool{"*identity.externalLoginAttemptAggregator": true}

type inProcessSlot struct {
	field reflect.Value // settable alias of the field
	saved reflect.Value // value copy for non-map fields
}

// collectInProcessSlots walks the graph once (at template time).
func (e *baselineEnv) collectInProcessSlots() []inProcessSlot {
	found := map[string][]reflect.Value{}
	walkByTypeName(reflect.ValueOf(e.graph), found, map[serviceVisitKey]bool{}, 0)
	// Package-level singletons reachable through getters.
	if f := audit.GetSyslogForwarder(); f != nil {
		walkByTypeName(reflect.ValueOf(f), found, map[serviceVisitKey]bool{}, 0)
	}
	var slots []inProcessSlot
	for typ, fields := range inProcessResetFields {
		for _, inst := range found[typ] {
			elem := inst.Elem()
			for _, name := range fields {
				f := elem.FieldByName(name)
				if !f.IsValid() {
					e.t.Fatalf("baseline in-process reset: %s has no field %s (inventory out of date)", typ, name)
				}
				alias := reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem()
				slot := inProcessSlot{field: alias}
				if alias.Kind() != reflect.Map {
					saved := reflect.New(alias.Type()).Elem()
					saved.Set(alias)
					slot.saved = saved
				}
				slots = append(slots, slot)
			}
		}
	}
	return slots
}

// inProcessTypeCounts instances found per watched type (for the progress log).
func (e *baselineEnv) inProcessTypeCounts() map[string]int {
	found := map[string][]reflect.Value{}
	walkByTypeName(reflect.ValueOf(e.graph), found, map[serviceVisitKey]bool{}, 0)
	out := map[string]int{}
	for typ := range inProcessResetFields {
		out[typ] = len(found[typ])
	}
	return out
}

func walkByTypeName(v reflect.Value, found map[string][]reflect.Value, seen map[serviceVisitKey]bool, depth int) {
	if !v.IsValid() || depth > serviceGraphWalkDepth {
		return
	}
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			return
		}
		key := serviceVisitKey{typ: v.Type(), ptr: v.Pointer()}
		if seen[key] {
			return
		}
		seen[key] = true
		found[v.Type().String()] = append(found[v.Type().String()], v)
		if !inBackendModule(v.Type()) {
			return
		}
		walkByTypeName(v.Elem(), found, seen, depth+1)
	case reflect.Interface:
		if !v.IsNil() {
			walkByTypeName(v.Elem(), found, seen, depth+1)
		}
	case reflect.Struct:
		if !inBackendModule(v.Type()) {
			return
		}
		for i := 0; i < v.NumField(); i++ {
			walkByTypeName(v.Field(i), found, seen, depth+1)
		}
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.IsNil() || !inBackendModule(v.Type()) {
			return
		}
		for i := 0; i < v.Len(); i++ {
			walkByTypeName(v.Index(i), found, seen, depth+1)
		}
	case reflect.Map:
		if v.IsNil() || !inBackendModule(v.Type()) {
			return
		}
		for _, k := range v.MapKeys() {
			walkByTypeName(v.MapIndex(k), found, seen, depth+1)
		}
	}
}

// resetInProcess restores in-process state after a scenario.
func (e *baselineEnv) resetInProcess(touched []string) {
	if !e.lazyCollected {
		counts := e.inProcessTypeCounts()
		ready := true
		for typ := range inProcessLazy {
			ready = ready && counts[typ] > 0
		}
		if ready {
			e.inProcess = e.collectInProcessSlots()
			e.lazyCollected = true
		}
	}
	for _, s := range e.inProcess {
		if s.field.Kind() == reflect.Map {
			if s.field.IsNil() {
				continue
			}
			for _, k := range s.field.MapKeys() {
				s.field.SetMapIndex(k, reflect.Value{})
			}
			continue
		}
		s.field.Set(s.saved)
	}
	tset := map[string]bool{}
	for _, t := range touched {
		tset[t] = true
	}
	if tset["alert_rules"] {
		audit.ReloadAlertMatcher()
	}
	if tset["notification_channels"] {
		audit.ReloadAlertNotifier()
	}
	if tset["syslog_settings"] {
		if f := audit.GetSyslogForwarder(); f != nil {
			f.Reload()
		}
	}
	if tset["users"] || tset["security_policies"] || tset["user_roles"] {
		identity.EvaluateSourcePolicyHealth(database.DB)
	}
}

func unsafePointer(f reflect.Value) unsafe.Pointer { return unsafe.Pointer(f.UnsafeAddr()) }

// issueShare creates a live share code for a session (owner S02).
func (e *baselineEnv) issueShare(sessionID uint) string {
	found := map[string][]reflect.Value{}
	walkByTypeName(reflect.ValueOf(e.graph), found, map[serviceVisitKey]bool{}, 0)
	sm := firstOf[*sshproxy.ShareManager](found, "*sshproxy.ShareManager")
	if sm == nil {
		e.t.Fatalf("share manager not found on the service graph")
	}
	code, _, err := sm.Create(sessionID, e.subjects["S02"].UserID, time.Hour)
	if err != nil {
		e.t.Fatalf("share code: %v", err)
	}
	return code
}

// disableOffsiteHotStart replaces the offsite uploader hot-start callback
// with a no-op. The baseline gates every background worker; the hot start is
// the one path that would otherwise launch the uploader when a fixture saves
// offsite settings, after which it would race the scenarios.
func (e *baselineEnv) disableOffsiteHotStart() {
	found := map[string][]reflect.Value{}
	walkByTypeName(reflect.ValueOf(e.graph), found, map[serviceVisitKey]bool{}, 0)
	insts := found["*offsite.OffsiteProfileService"]
	if len(insts) == 0 {
		e.t.Fatalf("offsite profile service not found on the service graph")
	}
	for _, inst := range insts {
		f := inst.Elem().FieldByName("uploaderStarter")
		reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().Set(reflect.ValueOf(func() {}))
	}
}

// requireInProcessCoverage fails when a watched type has no instance on the
// graph (a rename would otherwise make its reset silently disappear).
func (e *baselineEnv) requireInProcessCoverage() {
	for typ, n := range e.inProcessTypeCounts() {
		if n == 0 && !inProcessLazy[typ] {
			e.t.Fatalf("in-process reset: no %s on the service graph (type renamed or no longer wired)", typ)
		}
	}
}
