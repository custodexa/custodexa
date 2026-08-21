package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// uptrScope 審核方個人指標 helper（approver_id 改 nullable 後測試字面值用）
// strPtr 測試用字串指標助手。
// 原宣告於 access_policy_service_test.go，該檔隨 W3 遷入 internal/modules/policy；
// 本包多個測試檔仍在用，故在此保留同名同義的宣告（policy 包側亦有一份）。
func strPtr(s string) *string { return &s }

func uptrScope(v uint) *uint { return &v }

// recordingSessionTerminator SessionTerminator 的測試替身（W7 §4.6 介面反轉後的必然形態）。
//
// **為何不是用真的 SessionService**：authz 不得 import session（矩陣 authz→session ✗），
// 而 `internal/service` 於 W7 起 import authz（`auth_service.go` 的 IsEffectiveApprover），
// 故 authz 的**同包**測試 import service 會構成 `import cycle not allowed in test`。
// 收線的**行為本體**（CAS 冪等、終態不被自然清理覆寫）改由 session 側
// `TestRevoke_ForceTerminatePreservesTerminalState` 直接對 SessionService 斷言；
// 此處負責的是 authz 的契約：政策開時**以正確引數**呼叫終斷器、政策關時**不呼叫**。
// 引數精確斷言（含 assetID）取代原本的「其他資產會話不得被誤傷」DB 斷言——
// 誤傷的唯一成因就是傳錯 assetID，直接斷言引數比觀察副作用更precise。
type recordingSessionTerminator struct {
	calls []terminateCall
}

type terminateCall struct {
	UserID  uint
	AssetID uint
	Reason  string
}

func (r *recordingSessionTerminator) TerminateByUserAsset(userID, assetID uint, reason string) (int, error) {
	r.calls = append(r.calls, terminateCall{UserID: userID, AssetID: assetID, Reason: reason})
	return len(r.calls), nil
}

// setupAccessRequestEnv 真 SQLite 全鏈環境：狀態機 CAS、同交易建授權、
// 去重唯一索引都必須實際執行驗證。
// 手動補 pending 去重 partial 唯一索引（production 由 migration 原生 SQL 建立，
// AutoMigrate 建不出帶 status 條件的索引）
func setupAccessRequestEnv(t *testing.T) (*AccessRequestService, *policy.SecurityPolicyService, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.UserGroup{}, &model.Asset{}, &model.AssetGroup{}, &model.AssetNode{},
		&model.AssetAuthorization{}, &model.AccessRequest{}, &model.AccessRequestApproval{}, &model.ApproverScope{},
		&model.SecurityPolicy{}, &model.AuditLog{}, &model.NotificationChannel{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_access_request_pending_dedup
		ON access_requests (requester_id, asset_id) WHERE status = 'pending' AND deleted_at IS NULL AND kind = 'normal'`).Error; err != nil {
		t.Fatalf("dedup index: %v", err)
	}

	policies := policy.NewSecurityPolicyService(db)
	accessPolicy := policy.NewAccessPolicyService(db, policies, NewAssetAuthorizationService(db))
	svc := NewAccessRequestService(db, policies, accessPolicy, nil, nil)
	return svc, policies, db
}

// seedRequestFixture user 1（requester）、user 2（approver）、user 3（admin）、
// user 4（另一 requester）；asset 1 ∈ group 1（approval）、asset 2 ∈ group 2（reason）、
// asset 3 未分組（全域 open）。user 1/4 對三資產皆有常設 view（可視）
func seedRequestFixture(t *testing.T, db *gorm.DB) {
	t.Helper()
	users := []model.User{
		{Username: "requester", Email: strPtr("r@x"), Active: true},
		{Username: "approver", Email: strPtr("a@x"), Active: true},
		{Username: "boss", Email: strPtr("b@x"), Active: true},
		{Username: "requester2", Email: strPtr("r2@x"), Active: true},
	}
	for i := range users {
		if err := db.Create(&users[i]).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
	}
	approval := model.AccessPolicyApproval
	reason := model.AccessPolicyReason
	// 政策掛資產（asset-level-access-policy）；組保留供 approver 範圍測試沿用
	db.Create(&model.AssetGroup{Name: "g-approval"}) // id 1
	db.Create(&model.AssetGroup{Name: "g-reason"})   // id 2
	db.Create(&model.Asset{Name: "a-approval", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 3, AccessPolicy: &approval})
	db.Create(&model.Asset{Name: "a-reason", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 3, AccessPolicy: &reason})
	db.Create(&model.AssetNode{AssetID: 1, NodeID: 1})
	db.Create(&model.AssetNode{AssetID: 2, NodeID: 2})
	db.Create(&model.Asset{Name: "a-open", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 3})
	for _, uid := range []uint{1, 4} {
		for aid := uint(1); aid <= 3; aid++ {
			u, a := uid, aid
			if err := db.Create(&model.AssetAuthorization{
				UserID: &u, AssetID: &a, Permission: model.PermissionView, GrantedBy: 3,
			}).Error; err != nil {
				t.Fatalf("seed view grant: %v", err)
			}
		}
	}
	// approver（user 2）範圍：直配 asset 1
	a1 := uint(1)
	if err := db.Create(&model.ApproverScope{ApproverID: uptrScope(2), AssetID: &a1, GrantedBy: 3}).Error; err != nil {
		t.Fatalf("seed scope: %v", err)
	}
}

func submitBasic(t *testing.T, svc *AccessRequestService, requesterID, assetID uint) *model.AccessRequest {
	t.Helper()
	req, err := svc.Submit(requesterID, "requester", model.RoleUser, SubmitAccessRequestInput{
		AssetID: assetID, Reason: "維護作業", DurationMinutes: 60,
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	return req
}

// TestAccessRequest_Submit 提出驗證：事由/時長上限/預約起始/open 拒建/角色豁免/可視守門
func TestAccessRequest_Submit(t *testing.T) {
	t.Run("正常提出為 pending", func(t *testing.T) {
		svc, _, _ := setupAccessRequestEnv(t)
		seedRequestFixture(t, testDBOf(svc))
		req := submitBasic(t, svc, 1, 1)
		if req.Status != model.AccessRequestPending || req.PendingExpiresAt.IsZero() {
			t.Fatalf("應為 pending 且帶超時時限: %+v", req)
		}
	})

	t.Run("超過政策上限 400", func(t *testing.T) {
		svc, policies, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		if _, err := policies.Update(policy.PolicyAccessRequestMaxDurationMinutes, "240", "admin"); err != nil {
			t.Fatalf("update policy: %v", err)
		}
		_, err := svc.Submit(1, "requester", model.RoleUser, SubmitAccessRequestInput{
			AssetID: 1, Reason: "r", DurationMinutes: 480,
		})
		if !errors.Is(err, ErrDurationExceedsPolicy) {
			t.Fatalf("應拒超上限: %v", err)
		}
	})

	t.Run("open 段位拒建單", func(t *testing.T) {
		svc, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		_, err := svc.Submit(1, "requester", model.RoleUser, SubmitAccessRequestInput{
			AssetID: 3, Reason: "r", DurationMinutes: 60,
		})
		if !errors.Is(err, ErrPolicyOpenNoRequest) {
			t.Fatalf("open 段應拒建單: %v", err)
		}
	})

	t.Run("admin 與 auditor 不受理", func(t *testing.T) {
		svc, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		for _, role := range []string{model.RoleAdmin, model.RoleAuditor} {
			_, err := svc.Submit(3, "boss", role, SubmitAccessRequestInput{
				AssetID: 1, Reason: "r", DurationMinutes: 60,
			})
			if !errors.Is(err, ErrRequesterExempt) {
				t.Fatalf("%s 不應受理申請: %v", role, err)
			}
		}
	})

	t.Run("不可視資產回不存在", func(t *testing.T) {
		svc, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		// user 2（approver）對 asset 2 無授權亦無範圍
		_, err := svc.Submit(2, "approver", model.RoleUser, SubmitAccessRequestInput{
			AssetID: 2, Reason: "r", DurationMinutes: 60,
		})
		if !errors.Is(err, ErrAccessRequestNotFound) {
			t.Fatalf("不可視應回不存在: %v", err)
		}
	})

	t.Run("預約起始早於現在 400", func(t *testing.T) {
		svc, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		past := time.Now().Add(-time.Hour)
		_, err := svc.Submit(1, "requester", model.RoleUser, SubmitAccessRequestInput{
			AssetID: 1, Reason: "r", DurationMinutes: 60, DateStart: &past,
		})
		if !errors.Is(err, ErrStartInPast) {
			t.Fatalf("過去起始應拒: %v", err)
		}
	})

	t.Run("重複申請 409 帶在途單號", func(t *testing.T) {
		svc, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		first := submitBasic(t, svc, 1, 1)
		_, err := svc.Submit(1, "requester", model.RoleUser, SubmitAccessRequestInput{
			AssetID: 1, Reason: "again", DurationMinutes: 30,
		})
		if !errors.Is(err, ErrDuplicatePendingRequest) {
			t.Fatalf("重複申請應 409: %v", err)
		}
		// 終態後可重新申請（去重僅擋 pending）
		if _, err := svc.Cancel(1, first.ID); err != nil {
			t.Fatalf("cancel: %v", err)
		}
		if _, err := svc.Submit(1, "requester", model.RoleUser, SubmitAccessRequestInput{
			AssetID: 1, Reason: "retry", DurationMinutes: 30,
		}); err != nil {
			t.Fatalf("撤回後應可重新申請: %v", err)
		}
	})
}

// testDBOf 從 service 取測試 DB（僅測試包內使用）
func testDBOf(svc *AccessRequestService) *gorm.DB { return svc.db }

// TestApproverScopeService_CRUD 範圍分配：XOR/角色驗證/去重/軟刪
func TestApproverScopeService_CRUD(t *testing.T) {
	_, _, db := setupAccessRequestEnv(t)
	seedRequestFixture(t, db)
	if err := db.AutoMigrate(&model.Role{}); err != nil {
		t.Fatalf("migrate roles: %v", err)
	}
	db.Create(&model.Role{Name: model.RoleApprover})
	var approverRole model.Role
	db.Where("name = ?", model.RoleApprover).First(&approverRole)
	db.Exec("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", 2, approverRole.ID)

	svc := NewApproverScopeService(db)
	a2 := uint(2)

	t.Run("客體 XOR 驗證", func(t *testing.T) {
		if _, err := svc.Create(ApproverScopeSpec{ApproverID: uptrScope(2), GrantedBy: 3}); !errors.Is(err, ErrScopeTargetInvalid) {
			t.Fatalf("雙空應拒: %v", err)
		}
		g1 := uint(1)
		if _, err := svc.Create(ApproverScopeSpec{ApproverID: uptrScope(2), AssetID: &a2, AssetGroupID: &g1, GrantedBy: 3}); !errors.Is(err, ErrScopeTargetInvalid) {
			t.Fatalf("雙填應拒: %v", err)
		}
	})

	t.Run("非 approver 角色拒分配", func(t *testing.T) {
		if _, err := svc.Create(ApproverScopeSpec{ApproverID: uptrScope(1), AssetID: &a2, GrantedBy: 3}); !errors.Is(err, ErrNotApproverRole) {
			t.Fatalf("非 approver 應拒: %v", err)
		}
	})

	t.Run("建立與去重", func(t *testing.T) {
		scope, err := svc.Create(ApproverScopeSpec{ApproverID: uptrScope(2), AssetID: &a2, GrantedBy: 3})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if _, err := svc.Create(ApproverScopeSpec{ApproverID: uptrScope(2), AssetID: &a2, GrantedBy: 3}); !errors.Is(err, ErrScopeExists) {
			t.Fatalf("活躍重複應拒: %v", err)
		}
		if err := svc.Delete(scope.ID); err != nil {
			t.Fatalf("delete: %v", err)
		}
		// 軟刪後可重新分配（partial 唯一索引語義）
		if _, err := svc.Create(ApproverScopeSpec{ApproverID: uptrScope(2), AssetID: &a2, GrantedBy: 3}); err != nil {
			t.Fatalf("軟刪後重新分配應成功: %v", err)
		}
	})

	t.Run("刪除不存在 404", func(t *testing.T) {
		if err := svc.Delete(9999); !errors.Is(err, ErrScopeNotFound) {
			t.Fatalf("不存在應回 NotFound: %v", err)
		}
	})
}

// TestCheckPermission_ScopeThirdSource service 解析入口的可視第三來源（D5）：
// 範圍內 view 命中、connect 不受影響（真 SQLite，走完整 CheckPermission 路徑）
func TestCheckPermission_ScopeThirdSource(t *testing.T) {
	_, _, db := setupAccessRequestEnv(t)
	seedRequestFixture(t, db)
	authz := NewAssetAuthorizationService(db)
	ctx := contextWithRole(model.RoleUser)

	// user 2（approver）對 asset 1 僅有審核範圍、無任何授權
	ok, err := authz.CheckPermission(ctx, 2, 1, model.PermissionView)
	if err != nil || !ok {
		t.Fatalf("範圍內 view 應命中: ok=%v err=%v", ok, err)
	}
	ok, err = authz.CheckPermission(ctx, 2, 1, model.PermissionConnect)
	if err != nil || ok {
		t.Fatalf("範圍不得隱含 connect: ok=%v err=%v", ok, err)
	}

	// 資產清單含範圍資產（view 等級）
	assets, err := authz.GetAuthorizedAssets(ctx, 2, model.PermissionView)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	found := false
	for _, a := range assets {
		if a.ID == 1 {
			found = true
			if a.Permission != model.PermissionView {
				t.Fatalf("範圍資產等級應為 view: %s", a.Permission)
			}
		}
	}
	if !found {
		t.Fatal("範圍資產應出現在可視清單")
	}

	// 移除範圍即失效
	db.Where("approver_id = ?", 2).Delete(&model.ApproverScope{})
	if ok, _ := authz.CheckPermission(ctx, 2, 1, model.PermissionView); ok {
		t.Fatal("移除範圍後 view 應失效")
	}
}

// contextWithRole 帶角色的 context（沿 CheckPermission string key 慣例）
func contextWithRole(role string) context.Context {
	return context.WithValue(context.Background(), "role", role) //nolint:staticcheck
}

// TestAccessRequest_AutoApprove reason 段即時自動核准（決議 B）：
// 同一資料軌、決定者 system、auto 標記、當場產生臨時授權
func TestAccessRequest_AutoApprove(t *testing.T) {
	svc, _, db := setupAccessRequestEnv(t)
	seedRequestFixture(t, db)

	req, err := svc.Submit(1, "requester", model.RoleUser, SubmitAccessRequestInput{
		AssetID: 2, Reason: "臨時查修", DurationMinutes: 120,
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if req.Status != model.AccessRequestApproved || !req.AutoApproved {
		t.Fatalf("reason 段應即時自動核准: %+v", req)
	}
	if req.ApproverID != nil || req.DecisionNote != "system" {
		t.Fatalf("自動核准決定者應記 system: %+v", req)
	}
	if req.AuthorizationID == nil {
		t.Fatal("應回填臨時授權關聯")
	}

	var auth model.AssetAuthorization
	if err := db.First(&auth, *req.AuthorizationID).Error; err != nil {
		t.Fatalf("load auth: %v", err)
	}
	if auth.Source != model.AuthorizationSourceTicket || auth.Permission != model.PermissionConnect {
		t.Fatalf("臨時授權應為 ticket/connect: %+v", auth)
	}
	if auth.DateStart == nil || auth.DateExpired == nil ||
		auth.DateExpired.Sub(*auth.DateStart) != 120*time.Minute {
		t.Fatalf("時效窗應等於申請時長: %+v", auth)
	}
}

// TestAccessRequest_ApproveFlow 人工核准：資格/禁自核/下修/推遲/上調拒/同交易建授權
func TestAccessRequest_ApproveFlow(t *testing.T) {
	t.Run("範圍命中 approver 可核准（含下修時長）", func(t *testing.T) {
		svc, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		req := submitBasic(t, svc, 1, 1)

		short := 30
		decided, err := svc.Approve(2, false, req.ID, DecideInput{DurationMinutes: &short, Note: "縮短"})
		if err != nil {
			t.Fatalf("approve: %v", err)
		}
		if decided.Status != model.AccessRequestApproved || decided.ApprovedDurationMinutes == nil ||
			*decided.ApprovedDurationMinutes != 30 {
			t.Fatalf("核准值應記下修後時長: %+v", decided)
		}
		if decided.RequestedDurationMinutes != 60 {
			t.Fatal("原申請值必須留存")
		}
		var auth model.AssetAuthorization
		if err := db.First(&auth, *decided.AuthorizationID).Error; err != nil {
			t.Fatalf("load auth: %v", err)
		}
		if auth.DateExpired.Sub(*auth.DateStart) != 30*time.Minute {
			t.Fatalf("授權時窗應為下修後 30 分: %+v", auth)
		}
		if auth.GrantedBy != 2 {
			t.Fatalf("granted_by 應為核准人: %d", auth.GrantedBy)
		}
	})

	t.Run("上調時長 400", func(t *testing.T) {
		svc, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		req := submitBasic(t, svc, 1, 1)

		longer := 120
		_, err := svc.Approve(2, false, req.ID, DecideInput{DurationMinutes: &longer})
		if !errors.Is(err, ErrDecisionIncrease) {
			t.Fatalf("上調應拒: %v", err)
		}
	})

	t.Run("推遲起始合法、提前拒", func(t *testing.T) {
		svc, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		start := time.Now().Add(2 * time.Hour).Truncate(time.Second)
		req, err := svc.Submit(1, "requester", model.RoleUser, SubmitAccessRequestInput{
			AssetID: 1, Reason: "維護窗", DurationMinutes: 60, DateStart: &start,
		})
		if err != nil {
			t.Fatalf("submit: %v", err)
		}

		earlier := start.Add(-time.Hour)
		if _, err := svc.Approve(2, false, req.ID, DecideInput{DateStart: &earlier}); !errors.Is(err, ErrDecisionIncrease) {
			t.Fatalf("提前起始應拒: %v", err)
		}
		later := start.Add(time.Hour)
		decided, err := svc.Approve(2, false, req.ID, DecideInput{DateStart: &later})
		if err != nil {
			t.Fatalf("推遲應合法: %v", err)
		}
		if !decided.ApprovedDateStart.Equal(later) {
			t.Fatalf("核准起始應為推遲值: %+v", decided.ApprovedDateStart)
		}
	})

	t.Run("範圍外 approver 403", func(t *testing.T) {
		svc, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		// asset 2 不在 user 2 的範圍
		db.Model(&model.Asset{}).Where("id = 2").Update("access_policy", model.AccessPolicyApproval)
		req := submitBasic(t, svc, 1, 2)

		if _, err := svc.Approve(2, false, req.ID, DecideInput{}); !errors.Is(err, ErrNotEligibleApprover) {
			t.Fatalf("範圍外應 403: %v", err)
		}
		// admin 兜底可核
		if _, err := svc.Approve(3, true, req.ID, DecideInput{}); err != nil {
			t.Fatalf("admin 兜底應可核: %v", err)
		}
	})

	t.Run("禁自核硬擋（含 admin）", func(t *testing.T) {
		svc, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		// user 2（approver、範圍含 asset 1）自己提申請
		u2, a1 := uint(2), uint(1)
		db.Create(&model.AssetAuthorization{UserID: &u2, AssetID: &a1, Permission: model.PermissionView, GrantedBy: 3})
		req, err := svc.Submit(2, "approver", model.RoleUser, SubmitAccessRequestInput{
			AssetID: 1, Reason: "自己的單", DurationMinutes: 60,
		})
		if err != nil {
			t.Fatalf("submit: %v", err)
		}

		if _, err := svc.Approve(2, false, req.ID, DecideInput{}); !errors.Is(err, ErrSelfApproval) {
			t.Fatalf("自核應硬擋: %v", err)
		}
		if _, err := svc.Reject(2, false, req.ID, "自己拒自己"); !errors.Is(err, ErrSelfApproval) {
			t.Fatalf("自拒同樣硬擋: %v", err)
		}
		// 防禦性：admin 也不得決定自己的單（若 admin 有單的異常情境）
		if _, err := svc.Approve(3, true, req.ID, DecideInput{}); err != nil {
			t.Fatalf("其他 admin 應可核該單: %v", err)
		}
	})

	t.Run("拒絕須記事由", func(t *testing.T) {
		svc, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		req := submitBasic(t, svc, 1, 1)

		if _, err := svc.Reject(2, false, req.ID, ""); !errors.Is(err, ErrDecisionNoteRequired) {
			t.Fatalf("空事由應拒: %v", err)
		}
		decided, err := svc.Reject(2, false, req.ID, "不符變更窗")
		if err != nil {
			t.Fatalf("reject: %v", err)
		}
		if decided.Status != model.AccessRequestRejected || decided.DecisionNote != "不符變更窗" {
			t.Fatalf("拒絕應留痕: %+v", decided)
		}
		if decided.AuthorizationID != nil {
			t.Fatal("拒絕不得產生授權")
		}
	})
}

// TestAccessRequest_CASTerminal 狀態轉移 CAS：終態不可復活、併發僅一方成立
func TestAccessRequest_CASTerminal(t *testing.T) {
	t.Run("核准後撤回 409", func(t *testing.T) {
		svc, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		req := submitBasic(t, svc, 1, 1)
		if _, err := svc.Approve(2, false, req.ID, DecideInput{}); err != nil {
			t.Fatalf("approve: %v", err)
		}
		if _, err := svc.Cancel(1, req.ID); !errors.Is(err, ErrAccessRequestConflict) {
			t.Fatalf("終態撤回應 409: %v", err)
		}
	})

	t.Run("逾期 pending 不可被核准（codex #2）", func(t *testing.T) {
		svc, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		req := submitBasic(t, svc, 1, 1)

		// 撥逾時但不跑 scheduler（模擬掃描間隙）
		db.Model(&model.AccessRequest{}).Where("id = ?", req.ID).
			Update("pending_expires_at", time.Now().Add(-time.Hour))

		// 逾期單雖仍是 pending，approve 須落敗（CAS 帶 expires_at 守衛）
		if _, err := svc.Approve(2, false, req.ID, DecideInput{}); !errors.Is(err, ErrAccessRequestConflict) {
			t.Fatalf("逾期單核准應 409: %v", err)
		}
		var count int64
		db.Model(&model.AssetAuthorization{}).Where("source = ?", model.AuthorizationSourceTicket).Count(&count)
		if count != 0 {
			t.Fatal("逾期單核准落敗不得產生臨時授權")
		}
	})

	t.Run("撤回後核准 409 且不產生授權", func(t *testing.T) {
		svc, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		req := submitBasic(t, svc, 1, 1)
		if _, err := svc.Cancel(1, req.ID); err != nil {
			t.Fatalf("cancel: %v", err)
		}
		if _, err := svc.Approve(2, false, req.ID, DecideInput{}); !errors.Is(err, ErrAccessRequestConflict) {
			t.Fatalf("撤回後核准應 409: %v", err)
		}
		var count int64
		db.Model(&model.AssetAuthorization{}).Where("source = ?", model.AuthorizationSourceTicket).Count(&count)
		if count != 0 {
			t.Fatal("CAS 落敗不得產生「已撤回卻有授權」分裂狀態")
		}
	})

	t.Run("併發決定僅一方成立（CAS 交錯模擬）", func(t *testing.T) {
		svc, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		req := submitBasic(t, svc, 1, 1)

		// GORM callback 交錯（Change 1 招式）：Approve 讀到 pending 之後、
		// CAS UPDATE 落地之前插入撤回競態。經同交易連線執行（SQLite 單寫鎖，
		// 跨連線會死鎖）——CAS 的 WHERE status='pending' 於同一快照可見競態寫入，
		// RowsAffected=0 即輸家讓行；競態寫與 tx 同批回滾，故終態斷言授權不存在
		raced := false
		err := db.Callback().Update().Before("gorm:update").Register("test:race", func(op *gorm.DB) {
			if raced {
				return
			}
			raced = true
			op.Session(&gorm.Session{NewDB: true, SkipHooks: true}).
				Exec("UPDATE access_requests SET status = 'cancelled' WHERE id = ? AND status = 'pending'", req.ID)
		})
		if err != nil {
			t.Fatalf("register callback: %v", err)
		}
		defer db.Callback().Update().Remove("test:race")

		_, aerr := svc.Approve(2, false, req.ID, DecideInput{})
		if !raced {
			t.Fatal("競態 callback 未觸發，測試無效")
		}
		if !errors.Is(aerr, ErrAccessRequestConflict) {
			t.Fatalf("被搶先的核准應 409: %v", aerr)
		}
		var count int64
		db.Model(&model.AssetAuthorization{}).Where("source = ?", model.AuthorizationSourceTicket).Count(&count)
		if count != 0 {
			t.Fatal("CAS 輸家不得產生臨時授權")
		}
	})
}

// TestAccessRequest_ExpireAndLazyFilter 超時作廢＋讀取惰性過濾雙保險
func TestAccessRequest_ExpireAndLazyFilter(t *testing.T) {
	svc, _, db := setupAccessRequestEnv(t)
	seedRequestFixture(t, db)
	req := submitBasic(t, svc, 1, 1)

	// 手動把時限撥到過去（模擬逾期）
	db.Model(&model.AccessRequest{}).Where("id = ?", req.ID).
		Update("pending_expires_at", time.Now().Add(-time.Hour))

	// 惰性過濾：掃描前待審列表/計數即不見逾期單
	pending, err := svc.ListPending(2, false, time.Now())
	if err != nil || len(pending) != 0 {
		t.Fatalf("逾期單不應出現在待審: %d err=%v", len(pending), err)
	}
	if n, _ := svc.PendingCount(2, false, time.Now()); n != 0 {
		t.Fatalf("badge 計數不應含逾期單: %d", n)
	}

	// 掃描轉 expired
	n, err := svc.ExpireOverdue(time.Now())
	if err != nil || n != 1 {
		t.Fatalf("應作廢 1 筆: n=%d err=%v", n, err)
	}
	var fresh model.AccessRequest
	db.First(&fresh, req.ID)
	if fresh.Status != model.AccessRequestExpired {
		t.Fatalf("狀態應為 expired: %s", fresh.Status)
	}

	// 過期後可重新申請
	if _, err := svc.Submit(1, "requester", model.RoleUser, SubmitAccessRequestInput{
		AssetID: 1, Reason: "重新申請", DurationMinutes: 60,
	}); err != nil {
		t.Fatalf("過期後應可重新申請: %v", err)
	}

	// 已決定的單不受掃描影響（CAS 終態）
	if n, _ := svc.ExpireOverdue(time.Now()); n != 0 {
		t.Fatalf("終態單不應重複作廢: %d", n)
	}
}

// TestAccessRequest_ResubmitExpiresOverduePending 逾期未掃的 pending 不卡重新申請
// （UI 走查實測發現）：撞去重時就地作廢逾期單並重試——寫路徑補全惰性過濾
func TestAccessRequest_ResubmitExpiresOverduePending(t *testing.T) {
	svc, _, db := setupAccessRequestEnv(t)
	seedRequestFixture(t, db)
	old := submitBasic(t, svc, 1, 1)

	// 撥逾時但不跑 scheduler（模擬掃描間隙）
	db.Model(&model.AccessRequest{}).Where("id = ?", old.ID).
		Update("pending_expires_at", time.Now().Add(-time.Hour))

	fresh, err := svc.Submit(1, "requester", model.RoleUser, SubmitAccessRequestInput{
		AssetID: 1, Reason: "逾期後重申請", DurationMinutes: 30,
	})
	if err != nil {
		t.Fatalf("逾期單應就地作廢、重申請成功: %v", err)
	}
	if fresh.Status != model.AccessRequestPending {
		t.Fatalf("新單應為 pending: %s", fresh.Status)
	}
	var stale model.AccessRequest
	db.First(&stale, old.ID)
	if stale.Status != model.AccessRequestExpired {
		t.Fatalf("逾期舊單應轉 expired: %s", stale.Status)
	}
}

// TestAccessRequest_NotifyPayloadMinimized 通知 payload 最小化（決議 F）：
// 出站僅單號/資產名/事件/導引文字，不含事由全文（出站去識別紅線）；
// 通道未配置時不阻斷（全套件其餘測試皆以 nil notifier 通過即為佐證）
func TestAccessRequest_NotifyPayloadMinimized(t *testing.T) {
	svc, _, db := setupAccessRequestEnv(t)
	seedRequestFixture(t, db)

	received := make(chan []byte, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := db.Create(&model.NotificationChannel{
		Name: "test-hook", Type: model.NotificationChannelTypeWebhook, URL: srv.URL, Enabled: true,
	}).Error; err != nil {
		t.Fatalf("seed channel: %v", err)
	}
	notifier := audit.NewAlertNotifier(db, nil)
	if err := notifier.LoadChannels(); err != nil {
		t.Fatalf("load channels: %v", err)
	}
	svc.notifier = notifier

	const secretReason = "極機密事由不得出站"
	req, err := svc.Submit(1, "requester", model.RoleUser, SubmitAccessRequestInput{
		AssetID: 1, Reason: secretReason, DurationMinutes: 60,
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	select {
	case body := <-received:
		payload := string(body)
		if strings.Contains(payload, secretReason) {
			t.Fatalf("出站 payload 不得含事由全文: %s", payload)
		}
		// M4 形狀：{event, params, sent_at}，散文零出站
		var got struct {
			Event    string            `json:"event"`
			Params   map[string]string `json:"params"`
			Degraded bool              `json:"degraded"`
			SentAt   string            `json:"sent_at"`
		}
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("payload 應為結構化 JSON: %s (%v)", payload, err)
		}
		if got.Event != string(notifycat.EventAccessRequestCreated) {
			t.Fatalf("event 應為機器識別字, got %q", got.Event)
		}
		if got.Degraded {
			t.Fatalf("已註冊事件不應降級投遞: %s", payload)
		}
		if got.SentAt == "" {
			t.Fatalf("payload 應含 sent_at: %s", payload)
		}
		if got.Params["request_id"] != strconv.FormatUint(uint64(req.ID), 10) {
			t.Fatalf("params 應含單號: %s", payload)
		}
		if got.Params["asset_name"] != "a-approval" {
			t.Fatalf("params 應含資產名: %s", payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("通知未送達 webhook")
	}
}

// TestAnnotateConnectStates 連線入口三態 bulk 標註（D7 補充二）：
// open+connect=connectable、open+view=空、非 open：ticket>pending>reason/approval
func TestAnnotateConnectStates(t *testing.T) {
	svc, _, db := setupAccessRequestEnv(t)
	seedRequestFixture(t, db)
	// W3 §4.8(a)：三態標註已改掛 AccessRequestService（authz 側）
	ap := svc

	// user 1 夾具現況：asset 1（approval 組）view、asset 2（reason 組）view、asset 3（未分組=open）view
	// 補：asset 3 connect（open 段可連）、asset 1 pending 單、asset 2 時窗內 ticket
	u1, a3 := uint(1), uint(3)
	db.Create(&model.AssetAuthorization{UserID: &u1, AssetID: &a3, Permission: model.PermissionConnect, GrantedBy: 3})
	req := submitBasic(t, svc, 1, 1) // approval 段 pending
	start := time.Now().Add(-time.Minute)
	exp := time.Now().Add(time.Hour)
	a2 := uint(2)
	db.Create(&model.AssetAuthorization{
		UserID: &u1, AssetID: &a2, Permission: model.PermissionConnect, GrantedBy: 3,
		Source: model.AuthorizationSourceTicket, DateStart: &start, DateExpired: &exp,
	})

	dtos := []*AuthorizedAssetDTO{}
	for aid := uint(1); aid <= 3; aid++ {
		var asset model.Asset
		db.First(&asset, aid)
		perm := model.PermissionView
		if aid == 3 {
			perm = model.PermissionConnect
		}
		dtos = append(dtos, &AuthorizedAssetDTO{Asset: asset, Permission: perm})
	}
	if err := ap.AnnotateConnectStates(1, dtos); err != nil {
		t.Fatalf("annotate: %v", err)
	}

	if dtos[0].AccessState != policy.AccessStatePending || dtos[0].PendingRequestID == nil || *dtos[0].PendingRequestID != req.ID {
		t.Fatalf("asset 1 應為 pending＋單號: %+v", dtos[0])
	}
	if dtos[1].AccessState != policy.AccessStateConnectable || dtos[1].TicketDateExpired == nil {
		t.Fatalf("asset 2 應為 connectable＋ticket 到期: %+v", dtos[1])
	}
	if dtos[2].AccessState != policy.AccessStateConnectable {
		t.Fatalf("asset 3（open+connect）應為 connectable: %+v", dtos[2])
	}

	// open 段 view-only 留空（沿既有 permission 欄渲染）
	var openAsset model.Asset
	db.First(&openAsset, 3)
	viewOnly := []*AuthorizedAssetDTO{{Asset: openAsset, Permission: model.PermissionView}}
	if err := ap.AnnotateConnectStates(4, viewOnly); err != nil {
		t.Fatalf("annotate: %v", err)
	}
	if viewOnly[0].AccessState != "" {
		t.Fatalf("open 段 view-only 應留空: %+v", viewOnly[0])
	}

	// 無 ticket 無 pending：approval 段=approval_required、reason 段=reason_required（user 4）
	var asset1, asset2 model.Asset
	db.First(&asset1, 1)
	db.First(&asset2, 2)
	fresh := []*AuthorizedAssetDTO{
		{Asset: asset1, Permission: model.PermissionView},
		{Asset: asset2, Permission: model.PermissionView},
	}
	if err := ap.AnnotateConnectStates(4, fresh); err != nil {
		t.Fatalf("annotate: %v", err)
	}
	if fresh[0].AccessState != policy.AccessGateApprovalRequired || fresh[1].AccessState != policy.AccessGateReasonRequired {
		t.Fatalf("段位提示錯誤: %s / %s", fresh[0].AccessState, fresh[1].AccessState)
	}
}

// TestAccessRequest_Views 視圖：owner-scoped 我的申請、範圍過濾待審、歷史、有效臨時授權
func TestAccessRequest_Views(t *testing.T) {
	svc, _, db := setupAccessRequestEnv(t)
	seedRequestFixture(t, db)

	// user 1 對 asset 1 pending；user 4 對 asset 1 pending 後被核准
	req1 := submitBasic(t, svc, 1, 1)
	req4, err := svc.Submit(4, "requester2", model.RoleUser, SubmitAccessRequestInput{
		AssetID: 1, Reason: "另一人", DurationMinutes: 60,
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if _, err := svc.Approve(2, false, req4.ID, DecideInput{}); err != nil {
		t.Fatalf("approve: %v", err)
	}

	// owner-scoped：user 1 只見自己的單
	mine, err := svc.ListMine(1)
	if err != nil || len(mine) != 1 || mine[0].ID != req1.ID {
		t.Fatalf("我的申請應僅含本人單: %d err=%v", len(mine), err)
	}

	// 待審依範圍過濾：user 2 範圍含 asset 1 → 見 req1（req4 已終態）
	pending, err := svc.ListPending(2, false, time.Now())
	if err != nil || len(pending) != 1 || pending[0].ID != req1.ID {
		t.Fatalf("待審應含範圍內 pending 單: %d err=%v", len(pending), err)
	}

	// 歷史含終態單、自動核准可辨識欄位存在
	history, total, err := svc.ListHistory(2, false, 1, 20)
	if err != nil || total != 1 || history[0].ID != req4.ID {
		t.Fatalf("歷史應含已決定單: total=%d err=%v", total, err)
	}

	// 有效臨時授權：user 4 一筆
	tickets, err := svc.MyActiveTickets(4, time.Now())
	if err != nil || len(tickets) != 1 {
		t.Fatalf("user 4 應有一筆有效臨時授權: %d err=%v", len(tickets), err)
	}
	all, err := svc.ActiveTickets(2, false, time.Now())
	if err != nil || len(all) != 1 {
		t.Fatalf("審核中心應見範圍內有效臨時授權: %d err=%v", len(all), err)
	}
}

// TestAccessRequest_PendingExcludesOwn approver 自己的申請不出現在自己待審
// （對抗驗收 UX 修正）：自己不能核自己，放待審只會誤導＋核准鈕必 403
func TestAccessRequest_PendingExcludesOwn(t *testing.T) {
	svc, _, db := setupAccessRequestEnv(t)
	seedRequestFixture(t, db)
	// user 2（approver、範圍含 asset1）自己申請 asset1（先補可視）
	u2, a1 := uint(2), uint(1)
	db.Create(&model.AssetAuthorization{UserID: &u2, AssetID: &a1, Permission: model.PermissionView, GrantedBy: 3})
	own, err := svc.Submit(2, "approver", model.RoleUser, SubmitAccessRequestInput{
		AssetID: 1, Reason: "自己的單", DurationMinutes: 60,
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	// user 2 的待審不含自己的單；計數亦不含
	pending, err := svc.ListPending(2, false, time.Now())
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	for _, r := range pending {
		if r.ID == own.ID {
			t.Fatal("approver 自己的單不應出現在自己待審")
		}
	}
	if n, _ := svc.PendingCount(2, false, time.Now()); n != 0 {
		t.Fatalf("badge 計數不應含本人單: %d", n)
	}
	// admin 待審仍見得到（兜底可核）
	adminPending, _ := svc.ListPending(3, true, time.Now())
	found := false
	for _, r := range adminPending {
		if r.ID == own.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("admin 待審應見 approver 本人單（兜底）")
	}
}

// TestAccessRequest_HistoryScopeFiltered approver 歷史依範圍過濾（對抗驗收修正）：
// 範圍外資產的決定紀錄不進 approver 歷史，admin 全量
func TestAccessRequest_HistoryScopeFiltered(t *testing.T) {
	svc, _, db := setupAccessRequestEnv(t)
	seedRequestFixture(t, db)

	// asset2（reason 段，不在 user2 範圍——範圍僅 asset1）：user1 申請即自動核准（終態）
	inScope, err := svc.Submit(1, "requester", model.RoleUser, SubmitAccessRequestInput{
		AssetID: 1, Reason: "範圍內", DurationMinutes: 30,
	})
	if err != nil {
		t.Fatalf("submit in-scope: %v", err)
	}
	if _, err := svc.Approve(2, false, inScope.ID, DecideInput{}); err != nil {
		t.Fatalf("approve in-scope: %v", err)
	}
	outScope, err := svc.Submit(1, "requester", model.RoleUser, SubmitAccessRequestInput{
		AssetID: 2, Reason: "範圍外（reason 自動核准）", DurationMinutes: 30,
	})
	if err != nil {
		t.Fatalf("submit out-scope: %v", err)
	}

	// approver（範圍=asset1）歷史只含 asset1 的決定，不含 asset2
	hist, _, err := svc.ListHistory(2, false, 1, 50)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	for _, r := range hist {
		if r.ID == outScope.ID {
			t.Fatal("approver 歷史不應含範圍外決定")
		}
	}
	foundIn := false
	for _, r := range hist {
		if r.ID == inScope.ID {
			foundIn = true
		}
	}
	if !foundIn {
		t.Fatal("approver 歷史應含範圍內決定")
	}
	// admin 全量含兩者
	adminHist, adminTotal, _ := svc.ListHistory(3, true, 1, 50)
	if adminTotal < 2 {
		t.Fatalf("admin 歷史應含全部決定: total=%d", adminTotal)
	}
	_ = adminHist
}

// ---- break-glass-revocation：破窗、提前撤銷、補審 ----

// grantConnect 常設 connect 授權（破窗資格 seed 用）
func grantConnect(t *testing.T, db *gorm.DB, userID, assetID uint) {
	t.Helper()
	u, a := userID, assetID
	if err := db.Create(&model.AssetAuthorization{
		UserID: &u, AssetID: &a, Permission: model.PermissionConnect, GrantedBy: 3,
	}).Error; err != nil {
		t.Fatalf("seed connect grant: %v", err)
	}
}

// enableBreakGlass 開破窗政策開關
func enableBreakGlass(t *testing.T, policies *policy.SecurityPolicyService) {
	t.Helper()
	if _, err := policies.Update(policy.PolicyBreakGlassEnabled, "true", "admin"); err != nil {
		t.Fatalf("enable break glass: %v", err)
	}
}

func TestAccessRequest_BreakGlass(t *testing.T) {
	t.Run("開關關閉一律拒", func(t *testing.T) {
		svc, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		grantConnect(t, db, 1, 1)
		if _, err := svc.BreakGlass(1, "requester", model.RoleUser, 1, "緊急"); !errors.Is(err, ErrBreakGlassDisabled) {
			t.Fatalf("want ErrBreakGlassDisabled, got %v", err)
		}
	})

	t.Run("常設 connect 者破窗成功（固定短窗政策鍵）", func(t *testing.T) {
		svc, policies, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		grantConnect(t, db, 1, 1)
		enableBreakGlass(t, policies)
		if _, err := policies.Update(policy.PolicyBreakGlassDurationMinutes, "30", "admin"); err != nil {
			t.Fatalf("set duration: %v", err)
		}

		req, err := svc.BreakGlass(1, "requester", model.RoleUser, 1, "半夜事故")
		if err != nil {
			t.Fatalf("break glass: %v", err)
		}
		if req.Kind != model.AccessRequestKindBreakGlass || req.Status != model.AccessRequestApproved {
			t.Fatalf("kind/status = %s/%s", req.Kind, req.Status)
		}
		if !req.AutoApproved || req.ReviewStatus != model.BreakGlassReviewPending {
			t.Fatalf("auto=%v review=%s", req.AutoApproved, req.ReviewStatus)
		}
		if req.AuthorizationID == nil {
			t.Fatal("破窗應同交易建票證並回鏈")
		}
		var ticket model.AssetAuthorization
		if err := db.First(&ticket, *req.AuthorizationID).Error; err != nil {
			t.Fatalf("load ticket: %v", err)
		}
		if ticket.Source != model.AuthorizationSourceTicket {
			t.Fatalf("source = %s", ticket.Source)
		}
		window := ticket.DateExpired.Sub(*ticket.DateStart)
		if window != 30*time.Minute {
			t.Fatalf("票證時窗 = %v, want 30m（政策鍵，client 值不進入）", window)
		}
	})

	t.Run("view-only 無資格", func(t *testing.T) {
		svc, policies, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		enableBreakGlass(t, policies)
		if _, err := svc.BreakGlass(1, "requester", model.RoleUser, 1, "緊急"); !errors.Is(err, ErrBreakGlassNotEligible) {
			t.Fatalf("want ErrBreakGlassNotEligible, got %v", err)
		}
	})

	t.Run("票證不構成資格", func(t *testing.T) {
		svc, policies, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		enableBreakGlass(t, policies)
		u, a := uint(1), uint(1)
		start := time.Now().Add(-10 * time.Minute)
		exp := time.Now().Add(10 * time.Minute)
		db.Create(&model.AssetAuthorization{
			UserID: &u, AssetID: &a, Permission: model.PermissionConnect,
			GrantedBy: 3, Source: model.AuthorizationSourceTicket, DateStart: &start, DateExpired: &exp,
		})
		if _, err := svc.BreakGlass(1, "requester", model.RoleUser, 1, "緊急"); !errors.Is(err, ErrBreakGlassNotEligible) {
			t.Fatalf("want ErrBreakGlassNotEligible（ticket 不算常設）, got %v", err)
		}
	})

	t.Run("open 段位不需破窗", func(t *testing.T) {
		svc, policies, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		grantConnect(t, db, 1, 3)
		enableBreakGlass(t, policies)
		if _, err := svc.BreakGlass(1, "requester", model.RoleUser, 3, "緊急"); !errors.Is(err, ErrPolicyOpenNoRequest) {
			t.Fatalf("want ErrPolicyOpenNoRequest, got %v", err)
		}
	})

	t.Run("admin/auditor 不受理", func(t *testing.T) {
		svc, policies, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		enableBreakGlass(t, policies)
		if _, err := svc.BreakGlass(3, "boss", model.RoleAdmin, 1, "緊急"); !errors.Is(err, ErrRequesterExempt) {
			t.Fatalf("admin want ErrRequesterExempt, got %v", err)
		}
		if _, err := svc.BreakGlass(3, "aud", model.RoleAuditor, 1, "緊急"); !errors.Is(err, ErrRequesterExempt) {
			t.Fatalf("auditor want ErrRequesterExempt, got %v", err)
		}
	})

	t.Run("重複破窗擋 409（帶單號＋到期，codex #4）", func(t *testing.T) {
		svc, policies, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		grantConnect(t, db, 1, 1)
		enableBreakGlass(t, policies)
		first, err := svc.BreakGlass(1, "requester", model.RoleUser, 1, "第一次")
		if err != nil {
			t.Fatalf("first: %v", err)
		}
		_, err = svc.BreakGlass(1, "requester", model.RoleUser, 1, "第二次")
		if !errors.Is(err, ErrDuplicateBreakGlass) {
			t.Fatalf("want ErrDuplicateBreakGlass, got %v", err)
		}
		// 訊息帶現有票證資訊（單號＋可用至；規格要求，防日後格式回歸）
		if msg := err.Error(); !strings.Contains(msg, fmt.Sprintf("單號 %d", first.ID)) || !strings.Contains(msg, "可用至") {
			t.Fatalf("409 訊息應帶單號與到期: %q", msg)
		}
	})

	t.Run("與在途一般申請並存", func(t *testing.T) {
		svc, policies, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		grantConnect(t, db, 1, 1)
		enableBreakGlass(t, policies)

		pending := submitBasic(t, svc, 1, 1) // 一般在途單
		bg, err := svc.BreakGlass(1, "requester", model.RoleUser, 1, "緊急優先")
		if err != nil {
			t.Fatalf("在途單不得阻擋破窗: %v", err)
		}
		if bg.Status != model.AccessRequestApproved {
			t.Fatalf("bg status = %s", bg.Status)
		}
		var orig model.AccessRequest
		if err := db.First(&orig, pending.ID).Error; err != nil {
			t.Fatalf("reload pending: %v", err)
		}
		if orig.Status != model.AccessRequestPending {
			t.Fatalf("破窗不得動在途單: status = %s", orig.Status)
		}
	})
}

func TestAccessRequest_Revoke(t *testing.T) {
	// approveByScope 建單→approver(2) 核准，回傳核准後單
	approveByScope := func(t *testing.T, svc *AccessRequestService) *model.AccessRequest {
		t.Helper()
		req := submitBasic(t, svc, 1, 1)
		approved, err := svc.Approve(2, false, req.ID, DecideInput{})
		if err != nil {
			t.Fatalf("approve: %v", err)
		}
		return approved
	}

	t.Run("原核准人撤銷成功＋票證失效＋單附註", func(t *testing.T) {
		svc, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		approved := approveByScope(t, svc)

		revoked, err := svc.Revoke(2, false, "approver", approved.ID, "核錯人")
		if err != nil {
			t.Fatalf("revoke: %v", err)
		}
		if revoked.Status != model.AccessRequestApproved {
			t.Fatalf("撤銷不得動狀態機終態: %s", revoked.Status)
		}
		if revoked.RevokedAt == nil || revoked.RevokedBy == nil || *revoked.RevokedBy != 2 || revoked.RevokeNote != "核錯人" {
			t.Fatalf("撤銷附註缺漏: %+v", revoked)
		}
		var ticket model.AssetAuthorization
		err = db.First(&ticket, *approved.AuthorizationID).Error
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("票證應軟刪: %v", err)
		}
		// 政策閘擋新連線（approval 段、無票證）
		var asset model.Asset
		db.First(&asset, 1)
		decision, derr := svc.accessPolicy.CheckConnect(1, model.RoleUser, &asset)
		if derr != nil || decision.Allowed {
			t.Fatalf("撤銷後政策閘應攔截: %+v err=%v", decision, derr)
		}
	})

	t.Run("事由必填", func(t *testing.T) {
		svc, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		approved := approveByScope(t, svc)
		if _, err := svc.Revoke(2, false, "approver", approved.ID, ""); !errors.Is(err, ErrDecisionNoteRequired) {
			t.Fatalf("want ErrDecisionNoteRequired, got %v", err)
		}
	})

	t.Run("admin 可撤任何單", func(t *testing.T) {
		svc, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		approved := approveByScope(t, svc)
		if _, err := svc.Revoke(3, true, "boss", approved.ID, "人員異動"); err != nil {
			t.Fatalf("admin revoke: %v", err)
		}
	})

	t.Run("非原核准人 approver 不可撤一般單", func(t *testing.T) {
		svc, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		approved := approveByScope(t, svc)
		// user 4 也給範圍（範圍命中但非原核准人）
		a1 := uint(1)
		db.Create(&model.ApproverScope{ApproverID: uptrScope(4), AssetID: &a1, GrantedBy: 3})
		if _, err := svc.Revoke(4, false, "requester2", approved.ID, "越權嘗試"); !errors.Is(err, ErrNotRevokeEligible) {
			t.Fatalf("want ErrNotRevokeEligible, got %v", err)
		}
	})

	t.Run("auto 單範圍 approver 可撤、範圍外不可", func(t *testing.T) {
		svc, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		// reason 段自動核准單（asset 2）
		req, err := svc.Submit(1, "requester", model.RoleUser, SubmitAccessRequestInput{
			AssetID: 2, Reason: "填理由即連", DurationMinutes: 30,
		})
		if err != nil {
			t.Fatalf("submit reason: %v", err)
		}
		if !req.AutoApproved {
			t.Fatal("reason 段應自動核准")
		}
		// approver 2 範圍僅 asset 1 → 範圍外 403
		if _, err := svc.Revoke(2, false, "approver", req.ID, "範圍外"); !errors.Is(err, ErrNotRevokeEligible) {
			t.Fatalf("want ErrNotRevokeEligible, got %v", err)
		}
		// 補範圍後可撤（六題 4：auto 單放寬範圍命中 approver）
		a2 := uint(2)
		db.Create(&model.ApproverScope{ApproverID: uptrScope(2), AssetID: &a2, GrantedBy: 3})
		if _, err := svc.Revoke(2, false, "approver", req.ID, "事由消失"); err != nil {
			t.Fatalf("scope approver revoke auto: %v", err)
		}
	})

	t.Run("已到期票證不可撤（語義分離）", func(t *testing.T) {
		svc, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		approved := approveByScope(t, svc)
		past := time.Now().Add(-time.Minute)
		db.Model(&model.AssetAuthorization{}).Where("id = ?", *approved.AuthorizationID).
			Update("date_expired", past)
		if _, err := svc.Revoke(2, false, "approver", approved.ID, "太遲"); !errors.Is(err, ErrTicketNotActive) {
			t.Fatalf("want ErrTicketNotActive, got %v", err)
		}
	})

	t.Run("重複撤銷 409", func(t *testing.T) {
		svc, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		approved := approveByScope(t, svc)
		if _, err := svc.Revoke(2, false, "approver", approved.ID, "第一次"); err != nil {
			t.Fatalf("first revoke: %v", err)
		}
		if _, err := svc.Revoke(3, true, "boss", approved.ID, "第二次"); !errors.Is(err, ErrTicketNotActive) {
			t.Fatalf("want ErrTicketNotActive, got %v", err)
		}
	})

	t.Run("並發撤銷先到者贏（CAS）", func(t *testing.T) {
		svc, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		approved := approveByScope(t, svc)

		// 於軟刪 callback 前用同交易搶先撤銷（Change 1 GORM callback 模擬招式）：
		// 命中 Revoke 交易內的 CAS RowsAffected=0 分支
		raced := false
		if err := db.Callback().Delete().Before("gorm:delete").Register("test:revoke_race", func(op *gorm.DB) {
			if raced || op.Statement.Table != "asset_authorizations" {
				return
			}
			raced = true
			op.Session(&gorm.Session{NewDB: true}).Exec(
				"UPDATE asset_authorizations SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL",
				time.Now(), *approved.AuthorizationID)
		}); err != nil {
			t.Fatalf("register callback: %v", err)
		}
		defer db.Callback().Delete().Remove("test:revoke_race")

		_, err := svc.Revoke(2, false, "approver", approved.ID, "併發一")
		if !errors.Is(err, ErrAccessRequestConflict) {
			t.Fatalf("want ErrAccessRequestConflict（先到者贏）, got %v", err)
		}
	})

	t.Run("斷線聯動：政策開啟收線 end_reason=revoked", func(t *testing.T) {
		svc, policies, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		if err := db.AutoMigrate(&model.Session{}); err != nil {
			t.Fatalf("migrate session: %v", err)
		}
		oldDB := database.DB
		database.DB = db
		t.Cleanup(func() { database.DB = oldDB })

		approved := approveByScope(t, svc)
		sess := &model.Session{SessionID: "rev-1", Status: model.SessionStatusActive,
			Protocol: model.ProtocolSSH, UserID: 1, StartTime: time.Now()}
		aid := uint(1)
		sess.AssetID = &aid
		if err := db.Create(sess).Error; err != nil {
			t.Fatalf("seed session: %v", err)
		}
		// 另一資產的會話不得被誤傷
		other := &model.Session{SessionID: "rev-2", Status: model.SessionStatusActive,
			Protocol: model.ProtocolSSH, UserID: 1, StartTime: time.Now()}
		bid := uint(2)
		other.AssetID = &bid
		db.Create(other)

		if _, err := policies.Update(policy.PolicyAccessRevokeDisconnect, "true", "admin"); err != nil {
			t.Fatalf("set policy: %v", err)
		}
		term := &recordingSessionTerminator{}
		svc.SetSessionService(term)

		if _, err := svc.Revoke(2, false, "approver", approved.ID, "立即斷線"); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		// 收線委派須恰好發生一次，且引數精確——assetID 傳錯正是「誤傷其他資產
		// 會話」的唯一成因（原 DB 副作用斷言以 other/sess 兩列間接表達同一件事）
		if len(term.calls) != 1 {
			t.Fatalf("政策開啟時應恰好委派一次收線, got %d 次: %+v", len(term.calls), term.calls)
		}
		if got := term.calls[0]; got.UserID != 1 || got.AssetID != *sess.AssetID ||
			got.Reason != model.EndReasonRevoked {
			t.Fatalf("收線引數錯誤: %+v（應為 user=1 asset=%d reason=%s；"+
				"asset 傳錯即誤傷 asset=%d 的會話 %s）",
				got, *sess.AssetID, model.EndReasonRevoked, *other.AssetID, other.SessionID)
		}
	})

	t.Run("預設不硬斷（政策關）", func(t *testing.T) {
		svc, _, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		if err := db.AutoMigrate(&model.Session{}); err != nil {
			t.Fatalf("migrate session: %v", err)
		}
		oldDB := database.DB
		database.DB = db
		t.Cleanup(func() { database.DB = oldDB })

		approved := approveByScope(t, svc)
		aid := uint(1)
		sess := &model.Session{SessionID: "rev-3", Status: model.SessionStatusActive,
			Protocol: model.ProtocolSSH, UserID: 1, AssetID: &aid, StartTime: time.Now()}
		db.Create(sess)
		term := &recordingSessionTerminator{}
		svc.SetSessionService(term)

		if _, err := svc.Revoke(2, false, "approver", approved.ID, "只擋新連線"); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		// 「零委派」比「會話仍 active」更嚴：後者在「有委派但收線失敗」時也成立
		if len(term.calls) != 0 {
			t.Fatalf("預設不硬斷：不得委派收線, got %+v", term.calls)
		}
		var got model.Session
		db.First(&got, sess.ID)
		if got.Status != model.SessionStatusActive {
			t.Fatal("預設不硬斷：進行中會話不得被終止")
		}
	})
}

func TestAccessRequest_BreakGlassReview(t *testing.T) {
	// breakGlassFixture 破窗單就緒（user1 對 asset1 常設 connect＋開關開）
	breakGlassFixture := func(t *testing.T) (*AccessRequestService, *policy.SecurityPolicyService, *gorm.DB, *model.AccessRequest) {
		t.Helper()
		svc, policies, db := setupAccessRequestEnv(t)
		seedRequestFixture(t, db)
		grantConnect(t, db, 1, 1)
		enableBreakGlass(t, policies)
		bg, err := svc.BreakGlass(1, "requester", model.RoleUser, 1, "半夜事故")
		if err != nil {
			t.Fatalf("break glass: %v", err)
		}
		return svc, policies, db, bg
	}

	t.Run("範圍 approver 補審成功＋不可重複", func(t *testing.T) {
		svc, _, _, bg := breakGlassFixture(t)
		reviewed, err := svc.Review(2, false, bg.ID, model.BreakGlassDispositionConfirmed, "確認為正當維運")
		if err != nil {
			t.Fatalf("review: %v", err)
		}
		if reviewed.ReviewStatus != model.BreakGlassReviewReviewed ||
			reviewed.ReviewDisposition != model.BreakGlassDispositionConfirmed ||
			reviewed.ReviewedBy == nil || *reviewed.ReviewedBy != 2 {
			t.Fatalf("補審欄位缺漏: %+v", reviewed)
		}
		if _, err := svc.Review(3, true, bg.ID, model.BreakGlassDispositionViolation, "翻案"); !errors.Is(err, ErrAlreadyReviewed) {
			t.Fatalf("want ErrAlreadyReviewed, got %v", err)
		}
	})

	t.Run("破窗人不可自審", func(t *testing.T) {
		svc, _, _, bg := breakGlassFixture(t)
		if _, err := svc.Review(1, false, bg.ID, model.BreakGlassDispositionConfirmed, ""); !errors.Is(err, ErrSelfReview) {
			t.Fatalf("want ErrSelfReview, got %v", err)
		}
	})

	t.Run("範圍外 approver 不可補審", func(t *testing.T) {
		svc, _, _, bg := breakGlassFixture(t)
		if _, err := svc.Review(4, false, bg.ID, model.BreakGlassDispositionConfirmed, ""); !errors.Is(err, ErrNotEligibleApprover) {
			t.Fatalf("want ErrNotEligibleApprover, got %v", err)
		}
	})

	t.Run("處置值非法與非破窗單", func(t *testing.T) {
		svc, _, db, bg := breakGlassFixture(t)
		if _, err := svc.Review(2, false, bg.ID, "maybe", ""); !errors.Is(err, ErrInvalidReviewDisposition) {
			t.Fatalf("want ErrInvalidReviewDisposition, got %v", err)
		}
		normal := submitBasic(t, svc, 4, 1)
		_ = db
		if _, err := svc.Review(2, false, normal.ID, model.BreakGlassDispositionConfirmed, ""); !errors.Is(err, ErrNotBreakGlass) {
			t.Fatalf("want ErrNotBreakGlass, got %v", err)
		}
	})

	t.Run("待補審視圖範圍過濾＋排除本人單", func(t *testing.T) {
		svc, _, db, bg := breakGlassFixture(t)
		// admin 視圖含該單
		list, err := svc.ListPendingReview(3, true)
		if err != nil || len(list) != 1 || list[0].ID != bg.ID {
			t.Fatalf("admin 待補審: %v len=%d", err, len(list))
		}
		// 範圍 approver 含該單；範圍外空
		if n, _ := svc.PendingReviewCount(2, false); n != 1 {
			t.Fatalf("scope approver count = %d", n)
		}
		if n, _ := svc.PendingReviewCount(4, false); n != 0 {
			t.Fatalf("out-of-scope count = %d", n)
		}
		// 破窗人本人（若也是 approver）不見自己的單
		a1 := uint(1)
		db.Create(&model.ApproverScope{ApproverID: uptrScope(1), AssetID: &a1, GrantedBy: 3})
		if n, _ := svc.PendingReviewCount(1, false); n != 0 {
			t.Fatalf("本人單應排除: count = %d", n)
		}
	})

	// 本子測釘的是節流窗的**近側**（同一時刻重掃不重發）。跨窗必重發的遠側由
	// access_request_no_approver_deadlock_test.go 釘住——W7b 對抗輪前只有近側，
	// 於是「每單至多一次」的假保底能全綠通過
	t.Run("逾期升級告警防重", func(t *testing.T) {
		svc, _, db, bg := breakGlassFixture(t)
		// 回溯建立時間逾 24h（政策鍵預設）
		db.Model(&model.AccessRequest{}).Where("id = ?", bg.ID).
			Update("created_at", time.Now().Add(-25*time.Hour))
		n, err := svc.NotifyOverdueReviews(time.Now())
		if err != nil || n != 1 {
			t.Fatalf("first sweep: n=%d err=%v", n, err)
		}
		n, err = svc.NotifyOverdueReviews(time.Now())
		if err != nil || n != 0 {
			t.Fatalf("second sweep 應防重: n=%d err=%v", n, err)
		}
		// 補審後不再列入逾期掃描對象（review_status 已離開 pending_review）
		if _, err := svc.Review(2, false, bg.ID, model.BreakGlassDispositionViolation, "逾期後判違規"); err != nil {
			t.Fatalf("review after overdue: %v", err)
		}
	})
}

// TestAnnotateBreakGlassAvailable 破窗可用性標註（break-glass-revocation 六題 6）：
// 開關關恆 false；開啟時=非 open 段×常設 connect×無有效票證；ticket 在手不標
func TestAnnotateBreakGlassAvailable(t *testing.T) {
	svc, policies, db := setupAccessRequestEnv(t)
	seedRequestFixture(t, db)
	ap := svc
	grantConnect(t, db, 1, 1) // user1 對 asset1（approval 段）常設 connect

	loadDTOs := func() []*AuthorizedAssetDTO {
		dtos := []*AuthorizedAssetDTO{}
		for aid := uint(1); aid <= 2; aid++ {
			var asset model.Asset
			db.First(&asset, aid)
			dtos = append(dtos, &AuthorizedAssetDTO{Asset: asset, Permission: model.PermissionView})
		}
		return dtos
	}

	// 開關關：恆 false（藏入口）
	dtos := loadDTOs()
	if err := ap.AnnotateConnectStates(1, dtos); err != nil {
		t.Fatalf("annotate: %v", err)
	}
	if dtos[0].BreakGlassAvailable || dtos[1].BreakGlassAvailable {
		t.Fatalf("開關關閉不得標破窗可用: %+v %+v", dtos[0], dtos[1])
	}

	enableBreakGlass(t, policies)

	// 開啟：asset1（常設 connect）標可破窗；asset2（僅 view）不標
	dtos = loadDTOs()
	if err := ap.AnnotateConnectStates(1, dtos); err != nil {
		t.Fatalf("annotate: %v", err)
	}
	if !dtos[0].BreakGlassAvailable {
		t.Fatalf("常設 connect＋approval 段應標可破窗: %+v", dtos[0])
	}
	if dtos[1].BreakGlassAvailable {
		t.Fatalf("view-only 不得標可破窗: %+v", dtos[1])
	}

	// 在途 pending 不影響可破窗（在途單不阻擋破窗）
	submitBasic(t, svc, 1, 1)
	dtos = loadDTOs()
	_ = ap.AnnotateConnectStates(1, dtos)
	if dtos[0].AccessState != policy.AccessStatePending || !dtos[0].BreakGlassAvailable {
		t.Fatalf("申請中仍應可破窗: %+v", dtos[0])
	}

	// 有效票證在手：正常可連，不標破窗
	u1, a1 := uint(1), uint(1)
	start := time.Now().Add(-time.Minute)
	exp := time.Now().Add(time.Hour)
	db.Create(&model.AssetAuthorization{
		UserID: &u1, AssetID: &a1, Permission: model.PermissionConnect, GrantedBy: 3,
		Source: model.AuthorizationSourceTicket, DateStart: &start, DateExpired: &exp,
	})
	dtos = loadDTOs()
	_ = ap.AnnotateConnectStates(1, dtos)
	if dtos[0].AccessState != policy.AccessStateConnectable || dtos[0].BreakGlassAvailable {
		t.Fatalf("持票證應 connectable 且不標破窗: %+v", dtos[0])
	}
}

// TestBreakGlass_EligibilityRecheckedInTx codex #2 回歸：破窗於鎖後同交易重判
// 資格——常設授權在交易前被撤，破窗應失敗（此測試以「交易前即無常設」代理
// 驗證重判路徑存在且生效；完整 TOCTOU 需並發，Postgres FOR UPDATE 保證）
func TestBreakGlass_EligibilityRecheckedInTx(t *testing.T) {
	svc, policies, db := setupAccessRequestEnv(t)
	seedRequestFixture(t, db)
	grantConnect(t, db, 1, 1)
	enableBreakGlass(t, policies)

	// 撤掉常設 connect（模擬資格消失）後破窗應 403
	db.Where("user_id = ? AND asset_id = ? AND permission = ? AND source = ?",
		1, 1, model.PermissionConnect, model.AuthorizationSourceManual).
		Delete(&model.AssetAuthorization{})
	if _, err := svc.BreakGlass(1, "requester", model.RoleUser, 1, "資格已撤"); !errors.Is(err, ErrBreakGlassNotEligible) {
		t.Fatalf("撤常設後破窗應 ErrBreakGlassNotEligible, got %v", err)
	}
}
