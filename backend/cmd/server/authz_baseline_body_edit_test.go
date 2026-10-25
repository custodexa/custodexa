package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// bodyEditKey is an opt-in expectation for the body field. It lists what
// the change added to the golden body; the comparator takes exactly those
// additions back out of the fresh body and requires the result to equal the
// golden body (or, where the golden holds a summary, to summarize to it).
// Anything else that changed leaves the difference unapproved.
//
//	"body_edit": {
//	  "added_items":  [{"path": "data", "match": {"key": "k"}, "count": 1}],
//	  "added_values": [{"path": "data.unmapped_keys", "value": "k"}],
//	  "incremented":  [{"path": "data.key_count", "by": 1},
//	                   {"path": "summaries[].unmapped", "by": 1}],
//	  "item_edits":   [{"path": "data", "match": {"key": "k"}, "count": 1,
//	                    "added": {"min": 7},
//	                    "changed": {"username": {"from": "system", "to": "u"}}}]
//	}
//
// Paths are dotted object keys; "name[]" applies the rest of the path to
// every element of that array. added_items removes exactly count elements
// whose fields equal match from the array at path; added_values removes
// exactly one string element equal to value; incremented subtracts by from
// every number the path reaches. item_edits takes the elements of the array
// at path whose fields equal match (there must be exactly count of them) and
// undoes the declared edits on each: every added field must be present with
// the declared value and is removed, every changed field must hold its "to"
// value and is set back to "from". Match fields may not be edited fields.
// Each edit must apply, otherwise the expectation fails.
const bodyEditKey = "body_edit"

type bodyEdit struct {
	Items       []bodyEditItems
	Values      []bodyEditValue
	Incremented []bodyEditCount
	ItemEdits   []bodyEditItemFields
}

// bodyEditItemFields is one item_edits entry.
type bodyEditItemFields struct {
	Path    string
	Match   map[string]any
	Count   int
	Added   map[string]any
	Changed map[string][2]any // field -> {from, to}
}

func parseItemEdit(path string, m map[string]any) (bodyEditItemFields, error) {
	out := bodyEditItemFields{Path: path, Changed: map[string][2]any{}}
	match, _ := m["match"].(map[string]any)
	cnt, _ := m["count"].(float64)
	if len(match) == 0 || cnt < 1 {
		return out, fmt.Errorf("item_edits needs path, a non-empty match and count >= 1")
	}
	out.Match, out.Count = match, int(cnt)
	known := 3
	if a, ok := m["added"]; ok {
		am, _ := a.(map[string]any)
		if len(am) == 0 {
			return out, fmt.Errorf("item_edits added must be a non-empty object")
		}
		out.Added = am
		known++
	}
	if c, ok := m["changed"]; ok {
		cm, _ := c.(map[string]any)
		if len(cm) == 0 {
			return out, fmt.Errorf("item_edits changed must be a non-empty object")
		}
		for k, v := range cm {
			ft, _ := v.(map[string]any)
			from, okF := ft["from"]
			to, okT := ft["to"]
			if !okF || !okT || len(ft) != 2 || canon(from) == canon(to) {
				return out, fmt.Errorf("item_edits changed %q needs distinct from and to", k)
			}
			out.Changed[k] = [2]any{from, to}
		}
		known++
	}
	if known == 3 || len(m) != known {
		return out, fmt.Errorf("item_edits needs added or changed and only the documented keys")
	}
	for k := range match {
		_, inAdded := out.Added[k]
		_, inChanged := out.Changed[k]
		if inAdded || inChanged {
			return out, fmt.Errorf("item_edits match field %q must not be an edited field", k)
		}
	}
	for k := range out.Added {
		if _, ok := out.Changed[k]; ok {
			return out, fmt.Errorf("item_edits field %q is both added and changed", k)
		}
	}
	return out, nil
}

type bodyEditItems struct {
	Path  string
	Match map[string]any
	Count int
}

type bodyEditValue struct{ Path, Value string }

type bodyEditCount struct {
	Path string
	By   float64
}

func parseBodyEdit(expect map[string]any) (bodyEdit, error) {
	var out bodyEdit
	raw, ok := expect[bodyEditKey].(map[string]any)
	if !ok || len(raw) == 0 {
		return out, fmt.Errorf("%s must hold at least one edit", bodyEditKey)
	}
	if len(expect) != 1 {
		return out, fmt.Errorf("an entry with %s must not carry other expectations", bodyEditKey)
	}
	for k, v := range raw {
		list, ok := v.([]any)
		if !ok || len(list) == 0 {
			return out, fmt.Errorf("%s.%s must be a non-empty list", bodyEditKey, k)
		}
		for _, x := range list {
			m, ok := x.(map[string]any)
			if !ok {
				return out, fmt.Errorf("%s.%s entries must be objects", bodyEditKey, k)
			}
			path, _ := m["path"].(string)
			if path == "" {
				return out, fmt.Errorf("%s.%s entries need a path", bodyEditKey, k)
			}
			switch k {
			case "added_items":
				match, _ := m["match"].(map[string]any)
				cnt, _ := m["count"].(float64)
				if len(match) == 0 || cnt < 1 || len(m) != 3 {
					return out, fmt.Errorf("added_items needs path, a non-empty match and count >= 1")
				}
				out.Items = append(out.Items, bodyEditItems{Path: path, Match: match, Count: int(cnt)})
			case "added_values":
				val, _ := m["value"].(string)
				if val == "" || len(m) != 2 {
					return out, fmt.Errorf("added_values needs path and a non-empty string value")
				}
				out.Values = append(out.Values, bodyEditValue{Path: path, Value: val})
			case "incremented":
				by, ok := m["by"].(float64)
				if !ok || by == 0 || len(m) != 2 {
					return out, fmt.Errorf("incremented needs path and a non-zero by")
				}
				out.Incremented = append(out.Incremented, bodyEditCount{Path: path, By: by})
			case "item_edits":
				ie, err := parseItemEdit(path, m)
				if err != nil {
					return out, err
				}
				out.ItemEdits = append(out.ItemEdits, ie)
			default:
				return out, fmt.Errorf("unknown %s edit %q", bodyEditKey, k)
			}
		}
	}
	return out, nil
}

// validateBodyEdit is called from approvedDiffs.validate.
func validateBodyEdit(e approvedEntry) error {
	if _, ok := e.Expect[bodyEditKey]; !ok {
		return nil
	}
	if _, err := parseBodyEdit(e.Expect); err != nil {
		return fmt.Errorf("%s: %w", e.ID, err)
	}
	if len(e.Selector.Fields) != 1 || e.Selector.Fields[0] != "body" {
		return fmt.Errorf("%s: a %s entry must select the body field only", e.ID, bodyEditKey)
	}
	return nil
}

// bodyEditHolds reports whether taking the declared additions out of the
// fresh body gives back the golden body.
func bodyEditHolds(expect map[string]any, old, new map[string]any) bool {
	ed, err := parseBodyEdit(expect)
	if err != nil || new["body"] == nil || old["body"] == nil {
		return false
	}
	body := deepCopyJSON(new["body"])
	for _, it := range ed.Items {
		removed := 0
		ok := applyAtPath(body, it.Path, func(parent map[string]any, key string) bool {
			arr, ok := parent[key].([]any)
			if !ok {
				return false
			}
			var kept []any
			for _, x := range arr {
				m, isMap := x.(map[string]any)
				if isMap && removed < it.Count && fieldsMatch(m, it.Match) {
					removed++
					continue
				}
				kept = append(kept, x)
			}
			if kept == nil {
				kept = []any{}
			}
			parent[key] = kept
			return true
		})
		if !ok || removed != it.Count {
			return false
		}
	}
	for _, v := range ed.Values {
		removed := 0
		ok := applyAtPath(body, v.Path, func(parent map[string]any, key string) bool {
			arr, ok := parent[key].([]any)
			if !ok {
				return false
			}
			var kept []any
			for _, x := range arr {
				if s, isStr := x.(string); isStr && s == v.Value && removed == 0 {
					removed++
					continue
				}
				kept = append(kept, x)
			}
			if kept == nil {
				kept = []any{}
			}
			parent[key] = kept
			return true
		})
		if !ok || removed != 1 {
			return false
		}
	}
	for _, ie := range ed.ItemEdits {
		ok := applyAtPath(body, ie.Path, func(parent map[string]any, key string) bool {
			arr, ok := parent[key].([]any)
			if !ok {
				return false
			}
			n := 0
			for _, x := range arr {
				m, isMap := x.(map[string]any)
				if !isMap || !fieldsMatch(m, ie.Match) {
					continue
				}
				n++
				for k, want := range ie.Added {
					v, has := m[k]
					if !has || canon(v) != canon(want) {
						return false
					}
					delete(m, k)
				}
				for k, ft := range ie.Changed {
					v, has := m[k]
					if !has || canon(v) != canon(ft[1]) {
						return false
					}
					m[k] = ft[0]
				}
			}
			return n == ie.Count
		})
		if !ok {
			return false
		}
	}
	for _, c := range ed.Incremented {
		ok := applyAtPath(body, c.Path, func(parent map[string]any, key string) bool {
			f, ok := parent[key].(float64)
			if !ok {
				return false
			}
			parent[key] = f - c.By
			return true
		})
		if !ok {
			return false
		}
	}
	return fieldEqual("body", old["body"], body)
}

// applyAtPath calls fn on every (parent object, key) the dotted path reaches.
// It reports false when the path does not resolve, or fn fails, anywhere.
func applyAtPath(root any, path string, fn func(parent map[string]any, key string) bool) bool {
	segs := strings.Split(path, ".")
	var walk func(node any, i int) bool
	walk = func(node any, i int) bool {
		m, ok := node.(map[string]any)
		if !ok {
			return false
		}
		seg := segs[i]
		each := strings.HasSuffix(seg, "[]")
		key := strings.TrimSuffix(seg, "[]")
		if i == len(segs)-1 {
			if each {
				return false
			}
			if _, ok := m[key]; !ok {
				return false
			}
			return fn(m, key)
		}
		next, ok := m[key]
		if !ok {
			return false
		}
		if !each {
			return walk(next, i+1)
		}
		arr, ok := next.([]any)
		if !ok || len(arr) == 0 {
			return false
		}
		for _, el := range arr {
			if !walk(el, i+1) {
				return false
			}
		}
		return true
	}
	return walk(root, 0)
}

func fieldsMatch(m map[string]any, match map[string]any) bool {
	for k, want := range match {
		if canon(m[k]) != canon(want) {
			return false
		}
	}
	return true
}

func deepCopyJSON(v any) any {
	raw, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(raw, &out)
	return out
}
