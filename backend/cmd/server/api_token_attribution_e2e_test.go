package main

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// 稽核歸因（端到端）：以正式組裝的服務圖（含授權變更分級與稽核寫入面）經真的路由呼叫，
// 對「該次請求落地的所有稽核列」逐列斷言帶 token 標示；同一請求改以人類工作階段送出時兩欄為空。
// 涵蓋操作者結構在服務層內轉手的途徑：外部身分的綁定、解除、解除並停用、改為只允許外部登入
// （成功與被拒都寫服務列），以及會授予管理類角色的角色映射與群組映射（分級寫交易內稽核）。

func (e *baselineEnv) maxAuditID() uint {
	e.t.Helper()
	var id uint
	if err := e.db.Raw("SELECT COALESCE(MAX(id), 0) FROM audit_logs").Scan(&id).Error; err != nil {
		e.t.Fatalf("讀取稽核最大識別：%v", err)
	}
	return id
}

func (e *baselineEnv) auditRowsAfter(id uint) []model.AuditLog {
	e.t.Helper()
	var rows []model.AuditLog
	if err := e.db.Where("id > ?", id).Order("id").Find(&rows).Error; err != nil {
		e.t.Fatalf("讀取稽核列：%v", err)
	}
	return rows
}

// auditRowsHave 列中是否有細節含 marker 的一筆。
func auditRowsHave(rows []model.AuditLog, marker string) bool {
	for _, r := range rows {
		if strings.Contains(r.Details, marker) {
			return true
		}
	}
	return false
}

// auditRowsHaveStatus 列中是否有細節含 marker、且狀態為 status 的一筆（status 為空時不看狀態）。
func auditRowsHaveStatus(rows []model.AuditLog, marker string, status model.AuditStatus) bool {
	for _, r := range rows {
		if strings.Contains(r.Details, marker) && (status == "" || r.Status == status) {
			return true
		}
	}
	return false
}

func describeAuditRows(rows []model.AuditLog) string {
	var b strings.Builder
	for _, r := range rows {
		tok := "-"
		if r.APITokenID != nil {
			tok = fmt.Sprint(*r.APITokenID)
		}
		fmt.Fprintf(&b, "\n  #%d %s %s %s token=%s %s", r.ID, r.Action, r.Resource, r.Status, tok, clipCmp(r.Details))
	}
	return b.String()
}

// TestAPITokenActorConversionRowsAttributed 操作者結構在服務層轉手後落地的稽核列帶 token 標示。
func TestAPITokenActorConversionRowsAttributed(t *testing.T) {
	apiTokenBaselineGate(t)
	e := newBaselineEnv(t)
	pairs := seedAPITokenPairs(e)
	super := pairs[0]
	var tokenName string
	if err := e.db.Model(&model.APIToken{}).Select("name").Where("id = ?", super.tokenID).Scan(&tokenName).Error; err != nil || tokenName == "" {
		t.Fatalf("讀取 token 名稱：%v", err)
	}

	ext := e.object("user.extTarget").(uint)
	ei := e.object("externalIdentity.extTarget").(uint)
	prov := e.object("oidcProvider.1").(uint)
	spare := e.object("oidcProvider.spare").(uint)
	ug := e.object("userGroup.1").(uint)
	// 群組帶管理類角色：群組映射寫入時，分級把它判為授予管理類角色
	if err := e.db.Create(&model.UserGroupRole{UserGroupID: ug, RoleID: e.roleID(model.RoleAdmin)}).Error; err != nil {
		t.Fatalf("群組角色：%v", err)
	}
	e.apiTokenRetemplate()
	src := fmt.Sprintf("/api/v1/identity-sources/oidc/%d", prov)

	ok, failure := model.StatusSuccess, model.StatusFailure
	cases := []struct {
		name, method, path string
		body               any
		// wantOK 預期 HTTP 結果為成功（否則預期被拒）；成功流程若退化成拒絕，這裡先擋下
		wantOK bool
		// marker 該次請求必有一筆細節含此字樣、且狀態為 status 的服務列（證明會漏的那種列確實產生了，
		// 而且是預期的那一種事件：成功流程退化成拒絕時，失敗列帶的鍵相同，只看鍵會放過）
		marker string
		status model.AuditStatus
	}{
		{"替他人綁定外部身分", http.MethodPost, fmt.Sprintf("/api/v1/users/%d/external-identities", ext),
			map[string]any{"provider_id": spare, "subject": "cmp-attr-subject"}, true, `"event":"external_identity_bound"`, ok},
		{"解除不屬於該帳號的外部身分（被拒）", http.MethodDelete, fmt.Sprintf("/api/v1/users/%d/external-identities/%d", super.humanSelf.userID, ei),
			nil, false, `"event":"external_identity_unbind_rejected"`, failure},
		{"解除他人的外部身分", http.MethodDelete, fmt.Sprintf("/api/v1/users/%d/external-identities/%d", ext, ei), nil,
			true, `"event":"external_identity_unbound"`, ok},
		{"解除並停用他人", http.MethodPost, fmt.Sprintf("/api/v1/users/%d/external-identities/%d/unbind-and-disable", ext, ei), nil,
			true, `"event":"external_identity_unbound_and_account_disabled"`, ok},
		{"把他人改為只允許外部登入", http.MethodPost, fmt.Sprintf("/api/v1/users/%d/external-only", ext), nil,
			true, `"event":"user_converted_to_external_only"`, ok},
		{"建立授予管理類角色的角色映射", http.MethodPost, src + "/role-mappings",
			map[string]any{"match_value": "cmp-attr-admins", "role": model.RoleAdmin, "enabled": true, "risk_acknowledged": true},
			true, `"grant_change_graded"`, ""},
		{"建立指向帶管理類角色群組的群組映射", http.MethodPost, src + "/user-group-mappings",
			map[string]any{"match_value": "cmp-attr-ug", "user_group_id": ug, "enabled": true,
				"risk_acknowledged": true, "source_config_acknowledged": true},
			true, `"grant_change_graded"`, ""},
	}
	// check 該次請求的 HTTP 結果與預期一致，且產生了預期的服務列
	check := func(t *testing.T, who string, code int, body any, rows []model.AuditLog, wantOK bool, marker string, status model.AuditStatus) {
		t.Helper()
		if is2xx(code) != wantOK {
			t.Fatalf("%s：HTTP 結果與預期不符（預期成功=%v），得到 %d %v%s", who, wantOK, code, body, describeAuditRows(rows))
		}
		if !auditRowsHaveStatus(rows, marker, status) {
			t.Fatalf("%s：沒有產生含 %s、狀態 %q 的服務列（情境沒有走到被測的寫入面，或事件不是預期的那一種）：%s",
				who, marker, status, describeAuditRows(rows))
		}
	}
	for _, c := range cases {
		t.Run("APIToken "+c.name, func(t *testing.T) {
			before := e.maxAuditID()
			code, body := e.apiTokenRuleCall(super.token, c.method, c.path, c.body)
			rows := e.auditRowsAfter(before)
			t.Logf("token：%d %v，稽核列 %d 筆", code, body, len(rows))
			check(t, "token 請求", code, body, rows, c.wantOK, c.marker, c.status)
			for _, r := range rows {
				if r.APITokenID == nil || *r.APITokenID != super.tokenID || r.APITokenName == nil || *r.APITokenName != tokenName {
					t.Errorf("列不帶（或帶錯）token 標示：%s", describeAuditRows([]model.AuditLog{r}))
				}
			}
			e.apiTokenRuleRestore()

			before = e.maxAuditID()
			code, body = e.apiTokenRuleCall(super.human, c.method, c.path, c.body)
			rows = e.auditRowsAfter(before)
			check(t, "人類工作階段", code, body, rows, c.wantOK, c.marker, c.status)
			for _, r := range rows {
				if r.APITokenID != nil || r.APITokenName != nil {
					t.Errorf("親自操作的列不應帶 token 標示：%s", describeAuditRows([]model.AuditLog{r}))
				}
			}
			e.apiTokenRuleRestore()
		})
	}
}

// TestAPITokenSelfUnlockViaToken 解除帳號鎖定不在本人保護之列：token 經真的路由解除所屬帳號本人的鎖定成功，
// 鎖定確實解除，該次請求落地的稽核列帶 token 標示。
func TestAPITokenSelfUnlockViaToken(t *testing.T) {
	apiTokenBaselineGate(t)
	e := newBaselineEnv(t)
	super := seedAPITokenPairs(e)[0]
	owner := super.tokenSelf.userID
	until := time.Now().Add(time.Hour)
	if err := e.db.Model(&model.User{}).Where("id = ?", owner).
		Updates(map[string]any{"failed_login_attempts": 12, "locked_until": until}).Error; err != nil {
		t.Fatalf("鎖定所屬帳號：%v", err)
	}
	before := e.maxAuditID()
	code, body := e.apiTokenRuleCall(super.token, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/unlock", owner), nil)
	if code != http.StatusOK {
		t.Fatalf("token 解除本人鎖定應成功，得到 %d %v", code, body)
	}
	var u model.User
	if err := e.db.First(&u, owner).Error; err != nil {
		t.Fatalf("讀取帳號：%v", err)
	}
	if u.LockedUntil != nil || u.FailedLoginAttempts != 0 {
		t.Errorf("鎖定應已解除：locked_until=%v failed=%d", u.LockedUntil, u.FailedLoginAttempts)
	}
	rows := e.auditRowsAfter(before)
	if len(rows) == 0 {
		t.Fatal("解除鎖定應留下稽核列")
	}
	for _, r := range rows {
		if r.APITokenID == nil || *r.APITokenID != super.tokenID {
			t.Errorf("列不帶 token 標示：%s", describeAuditRows([]model.AuditLog{r}))
		}
	}
	e.apiTokenRuleRestore()
}
