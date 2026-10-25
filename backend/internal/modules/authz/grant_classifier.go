package authz

import (
	"sort"

	"github.com/custodexa/backend/internal/model"
)

// 授權變更分類器。
//
// 輸入是同一主體寫入前後的授權摘要。判定一律以集合比較，不追「有效等級是否真的變高」：
// 寧可多報，不漏報（例：已有個人連線授權又經群組取得仍算增加）。分級可由告警目錄調整。

// GrantDirection 自我授權的方向。
type GrantDirection string

const (
	GrantNone     GrantDirection = ""
	GrantIncrease GrantDirection = "increase" // 增加（含有增有減的互換）
	GrantDecrease GrantDirection = "decrease" // 純減少
)

// 審計 details 欄 grant_marks 的值。
const (
	GrantMarkSelfAuthorization = "self_authorization"
	GrantMarkManagementGrant   = "management_grant"
)

// GrantClassification 一個主體一次變更的分類結果。
type GrantClassification struct {
	// SelfDirection 對象是操作者本人時的方向；對他人恆為 GrantNone。
	SelfDirection GrantDirection
	// AddedEntries／RemovedEntries 變更前後的差（角色指派）。
	AddedEntries, RemovedEntries []GrantEntry
	// RulesBefore／RulesAfter 經群組帶來的授權規則數量。
	RulesBefore, RulesAfter int
	// ManagementGranted 對象不是操作者時，新取得的管理類指派。
	ManagementGranted []GrantEntry
	// Marks 審計標記，值域 GrantMarkSelfAuthorization／GrantMarkManagementGrant。
	Marks []string
}

// ClassifyGrantChange 比對同一主體的前後摘要。self 為該主體是否就是操作者本人。
func ClassifyGrantChange(before, after GrantSummary, self bool) GrantClassification {
	bk, ak := entryKeys(before.Entries), entryKeys(after.Entries)
	added, removed := map[string]GrantEntry{}, map[string]GrantEntry{}
	for k, e := range ak {
		// 同鍵（來源、群組、角色）前後都在：範圍以涵蓋比較，後者涵蓋前者未涵蓋的節點即新增
		if b, ok := bk[k]; !ok || widens(b, e) {
			added[k] = e
		}
	}
	for k, e := range bk {
		if a, ok := ak[k]; !ok || widens(a, e) {
			removed[k] = e
		}
	}
	rulesAdded, rulesRemoved := idDiff(after.RuleIDs, before.RuleIDs), idDiff(before.RuleIDs, after.RuleIDs)
	out := GrantClassification{
		AddedEntries: sortedEntries(added), RemovedEntries: sortedEntries(removed),
		RulesBefore: len(before.RuleIDs), RulesAfter: len(after.RuleIDs),
	}
	increased := len(added) > 0 || rulesAdded > 0
	decreased := len(removed) > 0 || rulesRemoved > 0
	if self {
		switch {
		case increased:
			out.SelfDirection = GrantIncrease
		case decreased:
			out.SelfDirection = GrantDecrease
		}
		if out.SelfDirection != GrantNone {
			out.Marks = append(out.Marks, GrantMarkSelfAuthorization)
		}
		return out
	}
	for _, e := range out.AddedEntries {
		if e.Management {
			out.ManagementGranted = append(out.ManagementGranted, e)
		}
	}
	if len(out.ManagementGranted) > 0 {
		out.Marks = append(out.Marks, GrantMarkManagementGrant)
	}
	return out
}

// ClassifyGroupManagementGrant 群組新增的角色指派是否含管理類（對群組的管理類發放）。
func ClassifyGroupManagementGrant(added []GrantEntry) []GrantEntry {
	var out []GrantEntry
	for _, e := range added {
		if e.Management {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}

// idDiff a 中不在 b 的個數。
func idDiff(a, b []uint) int {
	in := make(map[uint]bool, len(b))
	for _, id := range b {
		in[id] = true
	}
	n := 0
	for _, id := range a {
		if !in[id] {
			n++
		}
	}
	return n
}

// GrantEntriesAdded after 中角色不在 before 的指派（依角色編號比對），或範圍擴大的指派
// （後範圍涵蓋前範圍未涵蓋的節點）；群組角色指派新增判定的單一實作。
func GrantEntriesAdded(before, after []GrantEntry) []GrantEntry {
	in := map[uint]GrantEntry{}
	for _, e := range before {
		in[e.RoleID] = e
	}
	var out []GrantEntry
	for _, e := range after {
		if b, ok := in[e.RoleID]; !ok || widens(b, e) {
			out = append(out, e)
		}
	}
	return out
}

func (e GrantEntry) isGlobal() bool { return e.Scope != model.ScopeKindNodes }

func (e GrantEntry) coverOf(node uint) []uint {
	if c, ok := e.Cover[node]; ok {
		return c
	}
	return []uint{node}
}

// coversCover 本筆指派是否涵蓋「涵蓋集合為 cover 的節點」：全域涵蓋全部；節點範圍時，
// 該節點自身或其任一未刪除祖先是指派的節點即涵蓋。
func (e GrantEntry) coversCover(cover []uint) bool {
	if e.isGlobal() {
		return true
	}
	for _, n := range e.Nodes {
		for _, c := range cover {
			if n == c {
				return true
			}
		}
	}
	return false
}

// widens 後範圍是否涵蓋前範圍未涵蓋的節點（範圍的新增項）。全域涵蓋所有節點；
// 已刪除節點不在 Nodes 內，不計。
func widens(before, after GrantEntry) bool {
	if before.isGlobal() {
		return false
	}
	if after.isGlobal() {
		return true
	}
	for _, r := range after.Nodes {
		if !before.coversCover(after.coverOf(r)) {
			return true
		}
	}
	return false
}
