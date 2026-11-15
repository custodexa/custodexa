package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
)

// 會讓平台立刻以保存的秘密對外連線的動作對 API token 不開放（端到端）：脫離共用、資產連線測試、整組改密、
// 改密計劃立即執行、專用帳號的設定或更換與登入測試。每一項以存在且可成功的目標驗證——同一請求由
// 持有相同角色的人類送出時會走到授權之後的分支（不以雙方同回 400 或 404 當成結果相同），token 則回 403、
// 不寫入、不對外連線。專用帳號的清除照舊對 token 開放並成功。

func (e *baselineEnv) dialOutRequest(method, path string, body any, settle time.Duration) baselineRequest {
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	return baselineRequest{Method: method, Path: path, Body: raw, ContentType: "application/json", Settle: settle}
}

// executorCount 現存（未刪除）的專用帳號數。
func (e *baselineEnv) executorCount(assetID uint) int64 {
	e.t.Helper()
	var n int64
	if err := e.db.Model(&model.AssetAccount{}).Where("asset_id = ? AND purpose = ?", assetID, model.AccountPurposeExecutor).
		Count(&n).Error; err != nil {
		e.t.Fatalf("計數專用帳號：%v", err)
	}
	return n
}

// TestAPITokenDialOutActionsStayClosed 見檔頭。
func TestAPITokenDialOutActionsStayClosed(t *testing.T) {
	apiTokenBaselineGate(t)
	e := newBaselineEnv(t)
	pairs := seedAPITokenPairs(e)
	super := pairs[0]
	ssh := e.object("asset.ssh").(uint)
	shared := e.object("credential.shared").(uint)
	sharedAccount := e.object("account.sshShared").(uint)
	plan := e.object("changeSecretPlan.1").(uint)
	forbidden := string(apierror.CodeAuthAPITokenForbiddenRoute)
	executorBody := map[string]any{"source": "inline", "username": "cmp-exec", "password": "Cmp-Exec-Known-1", "expected_account_id": 0}

	cases := []struct {
		name string
		req  baselineRequest
		// dials 人類送出時會對外連線（以接收端被打到為證）
		dials bool
	}{
		{"脫離共用", e.dialOutRequest(http.MethodPost, fmt.Sprintf("/api/v1/credentials/%d/bindings/%d/detach", shared, sharedAccount),
			map[string]any{"source": "custom", "password": "Cmp-Detach-Known-1"}, 0), true},
		{"資產連線測試", e.dialOutRequest(http.MethodPost, fmt.Sprintf("/api/v1/assets/%d/test-connection", ssh),
			map[string]any{"timeout": 2}, 0), true},
		{"整組改密", e.dialOutRequest(http.MethodPost, fmt.Sprintf("/api/v1/credentials/%d/rotations", shared),
			map[string]any{"mode": "group", "policy": map[string]any{"length": 16, "include_symbol": true, "exclude_ambiguous": true}},
			300*time.Millisecond), false},
		{"改密計劃立即執行", e.dialOutRequest(http.MethodPost, fmt.Sprintf("/api/v1/change-secret-plans/%d/run", plan), nil,
			300*time.Millisecond), false},
		{"專用帳號的設定", e.dialOutRequest(http.MethodPut, fmt.Sprintf("/api/v1/assets/%d/executor", ssh), executorBody, 0), false},
	}
	for _, c := range cases {
		t.Run("APIToken DialOut "+c.name, func(t *testing.T) {
			hr := e.cmpRun(super.human, c.req, super.humanSelf, super.tokenSelf)
			if hr.Status == http.StatusBadRequest || hr.Status == http.StatusForbidden || hr.Status == http.StatusNotFound {
				t.Fatalf("同一請求由人類送出應走到授權之後的分支，得到 %d %v", hr.Status, hr.Body)
			}
			if c.dials && len(hr.Remote) == 0 {
				t.Fatalf("人類送出應對外連線（接收端未被打到），得到 %d %v", hr.Status, hr.Body)
			}
			if !c.dials && !is2xx(hr.Status) {
				t.Fatalf("人類送出應成功，得到 %d %v", hr.Status, hr.Body)
			}
			tr := e.cmpRun(super.token, c.req, super.tokenSelf, super.humanSelf)
			if tr.Status != http.StatusForbidden || cmpErrorCode(tr) != forbidden {
				t.Errorf("token 應回 403 %s，得到 %d %v", forbidden, tr.Status, tr.Body)
			}
			if len(tr.DB) > 0 || len(tr.Remote) > 0 || len(tr.Alerts) > 0 || len(tr.FS) > 0 {
				t.Errorf("token 被拒卻有變更或對外連線 db=%v remote=%v alerts=%v fs=%v", tr.DB, tr.Remote, tr.Alerts, tr.FS)
			}
		})
	}

	// 專用帳號的登入測試與清除：先由人類設定一個專用帳號（存在且可測試的目標）
	t.Run("APIToken DialOut 專用帳號的登入測試被拒、清除照舊成功", func(t *testing.T) {
		defer e.apiTokenRuleRestore()
		if code, body := e.apiTokenRuleCall(super.human, http.MethodPut, fmt.Sprintf("/api/v1/assets/%d/executor", ssh), executorBody); !is2xx(code) {
			t.Fatalf("人類設定專用帳號應成功，得到 %d %v", code, body)
		}
		var before model.AssetAccount
		if err := e.db.Where("asset_id = ? AND purpose = ?", ssh, model.AccountPurposeExecutor).First(&before).Error; err != nil {
			t.Fatalf("讀取專用帳號：%v", err)
		}
		loginCheck := fmt.Sprintf("/api/v1/assets/%d/executor/login-check", ssh)
		e.recv.take()
		code, body := e.apiTokenRuleCall(super.token, http.MethodPost, loginCheck, nil)
		if code != http.StatusForbidden || apiTokenRuleCode(body) != forbidden {
			t.Errorf("token 登入測試應回 403 %s，得到 %d %v", forbidden, code, body)
		}
		if hits := e.recv.take(); len(hits) > 0 {
			t.Errorf("token 被拒卻對外連線：%v", hits)
		}
		var after model.AssetAccount
		if err := e.db.Where("id = ?", before.ID).First(&after).Error; err != nil || after.CredentialID != before.CredentialID {
			t.Errorf("token 被拒後專用帳號應不變：%v %+v", err, after)
		}
		code, body = e.apiTokenRuleCall(super.human, http.MethodPost, loginCheck, nil)
		if code == http.StatusBadRequest || code == http.StatusForbidden || code == http.StatusNotFound {
			t.Errorf("人類的登入測試應走到授權之後的分支，得到 %d %v", code, body)
		}
		if hits := e.recv.take(); len(hits) == 0 {
			t.Errorf("人類的登入測試應對外連線（接收端未被打到），得到 %d %v", code, body)
		}
		code, body = e.apiTokenRuleCall(super.token, http.MethodDelete, fmt.Sprintf("/api/v1/assets/%d/executor", ssh), nil)
		if !is2xx(code) || e.executorCount(ssh) != 0 {
			t.Errorf("token 清除專用帳號應成功並移除，得到 %d %v（剩 %d）", code, body, e.executorCount(ssh))
		}
	})
}
