package api

import (
	"errors"
	"testing"

	"github.com/custodexa/backend/internal/modules/audit"
)

type fakeReasonNames struct {
	users, roles, groups map[uint64]string
	calls                map[string]int
	fail                 bool
}

func (f *fakeReasonNames) RoleAssignmentUsernames(ids []uint64) (map[uint64]string, error) {
	f.calls["users"]++
	return f.users, nil
}

func (f *fakeReasonNames) RoleAssignmentRoleNames(ids []uint64) (map[uint64]string, error) {
	f.calls["roles"]++
	if f.fail {
		return nil, errors.New("boom")
	}
	return f.roles, nil
}

func (f *fakeReasonNames) RoleAssignmentGroupNames(ids []uint64) (map[uint64]string, error) {
	f.calls["groups"]++
	return f.groups, nil
}

func newFakeNamer(f *fakeReasonNames, paths map[uint]string) (*AuditReasonNamer, *int) {
	nodeCalls := 0
	f.calls = map[string]int{}
	n := NewAuditReasonNamer(f, f)
	n.nodePaths = func() (map[uint]string, error) { nodeCalls++; return paths, nil }
	return n, &nodeCalls
}

func TestAuditReasonNamerRenames(t *testing.T) {
	f := &fakeReasonNames{
		users:  map[uint64]string{9: "ops-lee"},
		roles:  map[uint64]string{3: "asset_admin", 4: "custom-reader~del4"},
		groups: map[uint64]string{7: "prod-assets"},
	}
	n, nodeCalls := newFakeNamer(f, map[uint]string{167: "SIT / ELK"})
	views := []audit.AuditLogView{
		{ReasonCode: "user_role_assign_nodes", ReasonParams: map[string]string{
			"role": "#3", "target": "#9", "nodes": "#167,#999", "nodes_count": "2", "origin": "api"}},
		{ReasonCode: "event.role_binding_range_changed", ReasonParams: map[string]string{
			"role": "#4", "target": "#7", "target_kind": "user_group", "before": "#167", "after": "global", "before_count": "1"}},
		{ReasonCode: "user_role_revoke", ReasonParams: map[string]string{"role": "#55", "target": "#66"}},
		{ReasonCode: "user_group_role_assign", ReasonParams: map[string]string{"role": "#3", "target": "#7"}},
		{ReasonCode: "event.grant_change_graded", ReasonParams: map[string]string{"marks": "management_grant"}},
		{ReasonCode: "", ReasonParams: nil},
	}
	n.RenameViews(views)

	p := views[0].ReasonParams
	if p["role"] != "asset_admin" || p["target"] != "ops-lee" || p["nodes"] != "SIT / ELK,#999" {
		t.Errorf("指派列換名結果 = %v", p)
	}
	if p["nodes_count"] != "2" || p["origin"] != "api" {
		t.Errorf("非名稱參數不得被改動: %v", p)
	}
	q := views[1].ReasonParams
	if q["role"] != "custom-reader" || q["target"] != "prod-assets" || q["before"] != "SIT / ELK" || q["after"] != "global" {
		t.Errorf("範圍列換名結果（已刪角色去字尾、群組目標、global 不換）= %v", q)
	}
	if r := views[2].ReasonParams; r["role"] != "#55" || r["target"] != "#66" {
		t.Errorf("查無的物件保留識別碼: %v", r)
	}
	if g := views[3].ReasonParams; g["role"] != "asset_admin" || g["target"] != "prod-assets" {
		t.Errorf("群組指派列的對象查群組名: %v", g)
	}
	if m := views[4].ReasonParams["marks"]; m != "management_grant" {
		t.Errorf("非角色指派碼不換名: %v", m)
	}
	// 一次呼叫各類名稱至多查一次，節點路徑至多一次
	if f.calls["roles"] != 1 || f.calls["users"] != 1 || f.calls["groups"] != 1 || *nodeCalls != 1 {
		t.Errorf("查詢次數 = %v 節點 %d", f.calls, *nodeCalls)
	}
}

func TestAuditReasonNamerLookupFailureKeepsIdentifiers(t *testing.T) {
	f := &fakeReasonNames{users: map[uint64]string{9: "ops-lee"}, fail: true}
	n, _ := newFakeNamer(f, nil)
	views := []audit.AuditLogView{{ReasonCode: "user_role_revoke", ReasonParams: map[string]string{"role": "#3", "target": "#9"}}}
	n.RenameViews(views)
	if p := views[0].ReasonParams; p["role"] != "#3" || p["target"] != "ops-lee" {
		t.Errorf("角色查詢失敗時角色保留識別碼、其餘照換: %v", p)
	}
}

func TestAuditReasonNamerNilIsNoop(t *testing.T) {
	var n *AuditReasonNamer
	views := []audit.AuditLogView{{ReasonCode: "user_role_revoke", ReasonParams: map[string]string{"role": "#3"}}}
	n.RenameViews(views)
	if views[0].ReasonParams["role"] != "#3" {
		t.Error("nil 換算器不得改動")
	}
}

func TestAuditReasonNamerNoQueriesWhenNothingToRename(t *testing.T) {
	f := &fakeReasonNames{}
	n, nodeCalls := newFakeNamer(f, nil)
	n.RenameViews([]audit.AuditLogView{{ReasonCode: "retention_purge", ReasonParams: map[string]string{"target": "audit_logs"}}})
	if len(f.calls) != 0 && (f.calls["roles"]+f.calls["users"]+f.calls["groups"]+*nodeCalls) != 0 {
		t.Errorf("沒有角色指派列時不應查任何名稱: %v %d", f.calls, *nodeCalls)
	}
}
