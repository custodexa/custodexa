package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 資產列表的每頁筆數上限 1000（端到端）：三條查詢路徑（全量、授權集合、範圍化檢視者）都套用同一個上限，
// 超過時套用 1000 並在回應回報，資料至多 1000 筆、總數為全部符合條件的筆數；上限以內的請求不變；
// 不合法的值照舊套用預設 20。改前 page_size=5000 原樣套用，三條路徑會回出全部資料。
func TestAssetListPageSizeCapAcrossPaths(t *testing.T) {
	apiTokenBaselineGate(t)
	e := newBaselineEnv(t)
	ag1 := e.object("assetGroup.1").(uint)
	s01 := e.subjects["S01"]
	s02 := e.subjects["S02"]

	// 1005 台資產掛在節點一：一般使用者經節點授權看得到，節點範圍管理者在範圍內看得到
	const extra = 1005
	assets := make([]model.Asset, 0, extra)
	for i := 0; i < extra; i++ {
		assets = append(assets, model.Asset{Name: fmt.Sprintf("cap-asset-%04d", i), Protocol: model.ProtocolSSH,
			Host: "127.0.0.1", Port: 22, Active: true})
	}
	if err := e.db.CreateInBatches(&assets, 200).Error; err != nil {
		t.Fatalf("建立資產：%v", err)
	}
	nodes := make([]model.AssetNode, 0, extra)
	for _, a := range assets {
		nodes = append(nodes, model.AssetNode{AssetID: a.ID, NodeID: ag1})
	}
	if err := e.db.CreateInBatches(&nodes, 200).Error; err != nil {
		t.Fatalf("掛節點：%v", err)
	}
	uid := s02.UserID
	if err := e.db.Create(&model.AssetAuthorization{UserID: &uid, AssetGroupID: &ag1, Permission: model.PermissionConnect,
		Source: model.AuthorizationSourceManual, GrantedBy: s01.UserID, Accounts: model.AccountScope{model.AccountScopeAll}}).Error; err != nil {
		t.Fatalf("節點授權：%v", err)
	}
	mgr := e.apiTokenUser("cap-node-manager")
	e.srGrantNodes(mgr.userID, e.apiTokenCustomRole("cap-node-role", authz.PermAssetView), ag1)
	scoped := e.srSession("H-cap-node-manager", mgr)
	e.apiTokenRetemplate()

	type page struct {
		Data     []json.RawMessage `json:"data"`
		Total    int               `json:"total"`
		Page     int               `json:"page"`
		PageSize int               `json:"page_size"`
	}
	get := func(subj *baselineSubject, q string) page {
		t.Helper()
		r := e.srGet(subj, "/api/v1/assets"+q)
		if r.code != http.StatusOK {
			t.Fatalf("[%s] /api/v1/assets%s 回 %s", subj.ID, q, srShow(r))
		}
		var out page
		if err := json.Unmarshal(r.body, &out); err != nil {
			t.Fatalf("解析：%v", err)
		}
		return out
	}

	for _, c := range []struct {
		label string
		subj  *baselineSubject
	}{
		{"全量（超級管理者）", s01},
		{"授權集合（一般使用者）", s02},
		{"範圍化檢視者（節點範圍管理者）", scoped},
	} {
		t.Run(c.label, func(t *testing.T) {
			e.apiTokenRuleRestore()
			defer e.apiTokenRuleRestore()
			over := get(c.subj, "?page=1&page_size=5000")
			if over.Total < extra {
				t.Fatalf("前提：總數 %d 應至少 %d（三條路徑都要看得到超過上限的資料）", over.Total, extra)
			}
			if over.PageSize != 1000 || len(over.Data) != 1000 || over.Page != 1 {
				t.Errorf("page_size=5000：回報 %d、資料 %d 筆、頁碼 %d，應為 1000／1000／1", over.PageSize, len(over.Data), over.Page)
			}
			second := get(c.subj, "?page=2&page_size=5000")
			if second.PageSize != 1000 || len(second.Data) != over.Total-1000 || second.Total != over.Total {
				t.Errorf("第 2 頁：回報 %d、資料 %d 筆、總數 %d（應以 1000 為每頁筆數接續，餘 %d 筆）",
					second.PageSize, len(second.Data), second.Total, over.Total-1000)
			}
			at := get(c.subj, "?page=1&page_size=1000")
			if at.PageSize != 1000 || len(at.Data) != 1000 || at.Total != over.Total {
				t.Errorf("page_size=1000：回報 %d、資料 %d 筆、總數 %d", at.PageSize, len(at.Data), at.Total)
			}
			for _, bad := range []string{"?page_size=abc", "?page_size=0", "?page_size=-5"} {
				got := get(c.subj, bad)
				if got.PageSize != 20 || len(got.Data) != 20 {
					t.Errorf("%s：不合法的值應套用預設 20，得回報 %d、資料 %d 筆", bad, got.PageSize, len(got.Data))
				}
			}
		})
	}
}
