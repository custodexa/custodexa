package api

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

type permStateEvents struct{ ev *model.AuditFailureEvent }

func (p permStateEvents) LatestByMechanism(string) (*model.AuditFailureEvent, error) { return nil, nil }
func (p permStateEvents) LatestByStateTable(table string) (*model.AuditFailureEvent, error) {
	if table != audit.StateTablePermission {
		return nil, nil
	}
	return p.ev, nil
}

// 權限狀態比對無法完成時才出現在驗證結果；正常回應（相符、尚未涵蓋）與不符的欄位不變。
func TestProjectPermissionState(t *testing.T) {
	ev := &model.AuditFailureEvent{ID: 42, Mechanism: model.MechanismPrincipalStateIntegrity,
		CauseCode: model.CausePrincipalStateMismatch, StartedAt: time.Now().UTC()}
	lookup := &roleStateLookup{events: permStateEvents{ev: ev}}
	for _, state := range []string{"match", "mismatch", "not_covered"} {
		if v := projectPermissionState(&audit.PermissionReport{State: state}, lookup); v != nil {
			t.Fatalf("%s 不應附帶權限狀態欄", state)
		}
	}
	if projectPermissionState(nil, lookup) != nil {
		t.Fatal("未注入來源時不附帶")
	}
	v := projectPermissionState(&audit.PermissionReport{State: "unknown", Error: "權限狀態事件鏈不完整或被竄改: 內部細節"}, lookup)
	if v == nil || v.State != "unknown" || v.LastEvent == nil || v.LastEvent.ID != 42 {
		t.Fatalf("無法判定時要附帶狀態與失效事件連結: %+v", v)
	}
	raw, _ := json.Marshal(v)
	if string(raw) == "" || json.Valid(raw) == false {
		t.Fatal("出站形狀須可序列化")
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	if _, leaked := m["error"]; leaked {
		t.Fatal("不帶錯誤原文")
	}
}
