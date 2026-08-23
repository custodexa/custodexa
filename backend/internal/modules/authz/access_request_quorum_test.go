package authz

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/policy"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// ---- 核准路由與門檻：申請人維度範圍 ----

// TestApproverScope_SubjectSide 申請人側範圍：群組命中/直配命中/退組失效/
// 不隱含資產可視/待審列表路由
func TestApproverScope_SubjectSide(t *testing.T) {
	svc, _, db := setupAccessRequestEnv(t)
	seedRequestFixture(t, db)

	// user 5＝approver2（無任何資產側範圍）；SRE 群組（id 1）成員＝user 1
	if err := db.Create(&model.User{Username: "approver2", Email: strPtr("a2@x"), Active: true}).Error; err != nil {
		t.Fatalf("seed approver2: %v", err)
	}
	if err := db.Create(&model.UserGroup{Name: "SRE"}).Error; err != nil {
		t.Fatalf("seed group: %v", err)
	}
	if err := db.Exec("INSERT INTO user_group_members (user_group_id, user_id) VALUES (1, 1)").Error; err != nil {
		t.Fatalf("seed member: %v", err)
	}
	sre := uint(1)
	if err := db.Create(&model.ApproverScope{ApproverID: uptrScope(5), SubjectGroupID: &sre, GrantedBy: 3}).Error; err != nil {
		t.Fatalf("seed subject scope: %v", err)
	}

	req := submitBasic(t, svc, 1, 1)

	t.Run("群組命中可核", func(t *testing.T) {
		pending, err := svc.ListPending(5, false, time.Now())
		if err != nil {
			t.Fatalf("list pending: %v", err)
		}
		if len(pending) != 1 || pending[0].ID != req.ID {
			t.Fatalf("申請人側路由未命中待審列表: %d 筆", len(pending))
		}
		if _, err := svc.Approve(5, false, req.ID, DecideInput{}); err != nil {
			t.Fatalf("群組命中核准應成功: %v", err)
		}
	})

	t.Run("直配使用者命中", func(t *testing.T) {
		// user 4 的申請：approver2 無命中（範圍只蓋 SRE，user 4 不在組內）
		req4 := submitBasic(t, svc, 4, 1)
		if _, err := svc.Approve(5, false, req4.ID, DecideInput{}); !errors.Is(err, ErrNotEligibleApprover) {
			t.Fatalf("未命中應拒: %v", err)
		}
		// 直配 user 4 後命中
		u4 := uint(4)
		if err := db.Create(&model.ApproverScope{ApproverID: uptrScope(5), SubjectUserID: &u4, GrantedBy: 3}).Error; err != nil {
			t.Fatalf("seed subject user scope: %v", err)
		}
		if _, err := svc.Approve(5, false, req4.ID, DecideInput{}); err != nil {
			t.Fatalf("直配命中核准應成功: %v", err)
		}
	})

	t.Run("退組即失效", func(t *testing.T) {
		if err := db.Exec("DELETE FROM user_group_members WHERE user_group_id = 1 AND user_id = 1").Error; err != nil {
			t.Fatalf("remove member: %v", err)
		}
		// user 1 的新申請（asset 2 轉 approval 段位避免撞去重）
		db.Model(&model.Asset{}).Where("id = 2").Update("access_policy", model.AccessPolicyApproval)
		req2 := submitBasic(t, svc, 1, 2)
		if _, err := svc.Approve(5, false, req2.ID, DecideInput{}); !errors.Is(err, ErrNotEligibleApprover) {
			t.Fatalf("退組後應拒: %v", err)
		}
		pending, _ := svc.ListPending(5, false, time.Now())
		for _, p := range pending {
			if p.ID == req2.ID {
				t.Fatalf("退組後待審列表不應含 user 1 的單")
			}
		}
	})

	t.Run("申請人側不隱含資產可視", func(t *testing.T) {
		repo := newAssetAuthorizationRepository(db)
		assets, err := repo.ApproverScopedAssets(5)
		if err != nil {
			t.Fatalf("scoped assets: %v", err)
		}
		if len(assets) != 0 {
			t.Fatalf("純申請人側範圍不應帶出任何資產可視，得 %d 筆", len(assets))
		}
	})
}

// TestApproverScope_SingleListEquivalence 整改防復發：同一組四維範圍下，
// 單筆資格判定（ApproverScopeCoversRequest）與待審列表過濾結論必須一致
func TestApproverScope_SingleListEquivalence(t *testing.T) {
	svc, _, db := setupAccessRequestEnv(t)
	seedRequestFixture(t, db)
	repo := newAssetAuthorizationRepository(db)

	// 節點樹：g3（prod，root）→ g4（db，child）；asset 4 掛 g4（子樹涵蓋驗證）
	approval := model.AccessPolicyApproval
	db.Create(&model.AssetGroup{Name: "prod"}) // id 3
	parent := uint(3)
	db.Create(&model.AssetGroup{Name: "db", ParentID: &parent})                                                             // id 4
	db.Create(&model.Asset{Name: "a-prod-db", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 3, AccessPolicy: &approval}) // id 4
	db.Create(&model.AssetNode{AssetID: 4, NodeID: 4})
	u1, a4 := uint(1), uint(4)
	db.Create(&model.AssetAuthorization{UserID: &u1, AssetID: &a4, Permission: model.PermissionView, GrantedBy: 3})

	// 三位 approver、三種範圍維度：
	// user 5＝節點範圍 prod（含子樹應蓋 asset 4）
	// user 6＝申請人側直配 user 1
	// user 7＝資產側直配 asset 1（不蓋 asset 4）
	for _, u := range []string{"ap-node", "ap-subj", "ap-asset"} {
		if err := db.Create(&model.User{Username: u, Email: strPtr(u + "@x"), Active: true}).Error; err != nil {
			t.Fatalf("seed %s: %v", u, err)
		}
	}
	g3, a1 := uint(3), uint(1)
	db.Create(&model.ApproverScope{ApproverID: uptrScope(5), AssetGroupID: &g3, GrantedBy: 3})
	db.Create(&model.ApproverScope{ApproverID: uptrScope(6), SubjectUserID: &u1, GrantedBy: 3})
	db.Create(&model.ApproverScope{ApproverID: uptrScope(7), AssetID: &a1, GrantedBy: 3})

	// user 8＝審核方群組成員（群組即資格）：群組 REV(id 1) × 節點 prod——與 user 5 同涵蓋、
	// 資格經群組
	if err := db.Create(&model.User{Username: "ap-gmember", Email: strPtr("gm@x"), Active: true}).Error; err != nil {
		t.Fatalf("seed ap-gmember: %v", err)
	}
	if err := db.Create(&model.UserGroup{Name: "REV"}).Error; err != nil {
		t.Fatalf("seed rev group: %v", err)
	}
	if err := db.Exec("INSERT INTO user_group_members (user_group_id, user_id) VALUES (1, 8)").Error; err != nil {
		t.Fatalf("seed rev member: %v", err)
	}
	rev := uint(1)
	db.Create(&model.ApproverScope{ApproverGroupID: &rev, AssetGroupID: &g3, GrantedBy: 3})

	// 兩張 pending 單：user 1×asset 4（節點子樹＋申請人側命中）、user 4×asset 1（資產側命中）
	reqA := submitBasic(t, svc, 1, 4)
	reqB := submitBasic(t, svc, 4, 1)

	for _, approverID := range []uint{5, 6, 7, 8} {
		pending, err := svc.ListPending(approverID, false, time.Now())
		if err != nil {
			t.Fatalf("list pending (%d): %v", approverID, err)
		}
		inList := map[uint]bool{}
		for _, p := range pending {
			inList[p.ID] = true
		}
		for _, req := range []*model.AccessRequest{reqA, reqB} {
			covered, err := repo.ApproverScopeCoversRequest(approverID, req.AssetID, req.RequesterID)
			if err != nil {
				t.Fatalf("covers (%d, req %d): %v", approverID, req.ID, err)
			}
			if covered != inList[req.ID] {
				t.Fatalf("approver %d × req %d：單筆判定 %v 與列表過濾 %v 分裂",
					approverID, req.ID, covered, inList[req.ID])
			}
		}
	}
}

// ---- 核准路由與門檻：最少核准人數 ----

// TestAccessRequest_Quorum 門檻 2：逐票推進/同人重複拒/admin 不單票通過/
// 任一人拒即拒（票留存）/僅一次授權
func TestAccessRequest_Quorum(t *testing.T) {
	svc, policies, db := setupAccessRequestEnv(t)
	seedRequestFixture(t, db)

	// user 5＝approver2（資產側同蓋 asset 1，湊第二票）
	if err := db.Create(&model.User{Username: "approver2", Email: strPtr("a2@x"), Active: true}).Error; err != nil {
		t.Fatalf("seed approver2: %v", err)
	}
	a1 := uint(1)
	db.Create(&model.ApproverScope{ApproverID: uptrScope(5), AssetID: &a1, GrantedBy: 3})

	if _, err := policies.Update(policy.PolicyAccessRequestMinApprovals, "2", "admin"); err != nil {
		t.Fatalf("set policy: %v", err)
	}

	t.Run("逐票推進與僅一次授權", func(t *testing.T) {
		req := submitBasic(t, svc, 1, 1)
		r1, err := svc.Approve(2, false, req.ID, DecideInput{})
		if err != nil {
			t.Fatalf("第一票: %v", err)
		}
		if r1.Status != model.AccessRequestPending {
			t.Fatalf("第一票後應仍 pending，得 %s", r1.Status)
		}
		if r1.ApprovalsReceived != 1 || r1.ApprovalsRequired != 2 {
			t.Fatalf("進度應 1/2，得 %d/%d", r1.ApprovalsReceived, r1.ApprovalsRequired)
		}
		if r1.AuthorizationID != nil {
			t.Fatalf("未達門檻不應產生授權")
		}

		r2, err := svc.Approve(5, false, req.ID, DecideInput{})
		if err != nil {
			t.Fatalf("第二票: %v", err)
		}
		if r2.Status != model.AccessRequestApproved {
			t.Fatalf("第二票應轉 approved，得 %s", r2.Status)
		}
		if r2.AuthorizationID == nil {
			t.Fatalf("達門檻應產生授權")
		}
		if r2.ApproverID == nil || *r2.ApproverID != 5 {
			t.Fatalf("最終核准人應為補齊門檻者（user 5）")
		}
		var authCount int64
		db.Model(&model.AssetAuthorization{}).Where("source = ?", model.AuthorizationSourceTicket).Count(&authCount)
		if authCount != 1 {
			t.Fatalf("臨時授權應恰一筆，得 %d", authCount)
		}
	})

	t.Run("同人重複核准被拒", func(t *testing.T) {
		db.Model(&model.Asset{}).Where("id = 2").Update("access_policy", model.AccessPolicyApproval)
		req := submitBasic(t, svc, 1, 2)
		// approver（user 2）範圍擴 asset 2
		a2 := uint(2)
		db.Create(&model.ApproverScope{ApproverID: uptrScope(2), AssetID: &a2, GrantedBy: 3})
		if _, err := svc.Approve(2, false, req.ID, DecideInput{}); err != nil {
			t.Fatalf("第一票: %v", err)
		}
		if _, err := svc.Approve(2, false, req.ID, DecideInput{}); !errors.Is(err, ErrAlreadyApprovedByActor) {
			t.Fatalf("同人第二票應拒: %v", err)
		}
		var votes int64
		db.Model(&model.AccessRequestApproval{}).Where("request_id = ?", req.ID).Count(&votes)
		if votes != 1 {
			t.Fatalf("重複票不應入帳，得 %d", votes)
		}
	})

	// **審核資格收斂後的射程界定**：service 層的 admin 兜底分支仍在（撤銷端點與
	// 既有契約需要），但**審核 HTTP 路徑已不再產生 isAdmin=true**——handler 一律傳
	// false（`api.notEffectiveAdmin`）。故本子測試驗的是 service 契約，不再對應
	// 任何可經 API 觸發的情境；池不足時的補位改走脫困路徑（admin 指派 approver）
	t.Run("admin 一票計入不單票通過", func(t *testing.T) {
		req := submitBasic(t, svc, 4, 1)
		r1, err := svc.Approve(3, true, req.ID, DecideInput{})
		if err != nil {
			t.Fatalf("admin 票: %v", err)
		}
		if r1.Status != model.AccessRequestPending {
			t.Fatalf("admin 單票不應轉態，得 %s", r1.Status)
		}
		r2, err := svc.Approve(2, false, req.ID, DecideInput{})
		if err != nil {
			t.Fatalf("補位票: %v", err)
		}
		if r2.Status != model.AccessRequestApproved {
			t.Fatalf("admin＋approver 兩票應轉 approved，得 %s", r2.Status)
		}
	})

	t.Run("任一人拒即拒且票留存", func(t *testing.T) {
		db.Model(&model.Asset{}).Where("id = 2").Update("access_policy", model.AccessPolicyApproval)
		req := submitBasic(t, svc, 4, 2)
		a2 := uint(2)
		db.Create(&model.ApproverScope{ApproverID: uptrScope(5), AssetID: &a2, GrantedBy: 3})
		if _, err := svc.Approve(2, false, req.ID, DecideInput{}); err != nil {
			t.Fatalf("第一票: %v", err)
		}
		r, err := svc.Reject(5, false, req.ID, "不符合維護窗")
		if err != nil {
			t.Fatalf("拒絕: %v", err)
		}
		if r.Status != model.AccessRequestRejected {
			t.Fatalf("應轉 rejected，得 %s", r.Status)
		}
		var votes int64
		db.Model(&model.AccessRequestApproval{}).Where("request_id = ?", req.ID).Count(&votes)
		if votes != 1 {
			t.Fatalf("拒絕後既有票應留存供審計，得 %d", votes)
		}
	})

	t.Run("門檻回 1 零行為差異", func(t *testing.T) {
		if _, err := policies.Update(policy.PolicyAccessRequestMinApprovals, "1", "admin"); err != nil {
			t.Fatalf("set policy: %v", err)
		}
		db.Model(&model.Asset{}).Where("id = 3").Update("access_policy", model.AccessPolicyApproval)
		// asset 3 給 approver 範圍
		a3 := uint(3)
		db.Create(&model.ApproverScope{ApproverID: uptrScope(2), AssetID: &a3, GrantedBy: 3})
		req := submitBasic(t, svc, 1, 3)
		r, err := svc.Approve(2, false, req.ID, DecideInput{})
		if err != nil {
			t.Fatalf("單票: %v", err)
		}
		if r.Status != model.AccessRequestApproved || r.AuthorizationID == nil {
			t.Fatalf("門檻 1 單票應即轉 approved 並授權")
		}
	})
}

// TestAccessRequest_QuorumExpiredVoteBlocked 逾期單投票守衛：
// 門檻>1 時未達門檻的票不呼叫 approveInTx，其逾時守衛被繞過——鎖單 CAS 必須自帶
// pending_expires_at > now，讓 scheduler 未掃描的逾期單投票落敗回衝突、不記任何票
func TestAccessRequest_QuorumExpiredVoteBlocked(t *testing.T) {
	svc, policies, db := setupAccessRequestEnv(t)
	seedRequestFixture(t, db)

	if _, err := policies.Update(policy.PolicyAccessRequestMinApprovals, "2", "admin"); err != nil {
		t.Fatalf("set policy: %v", err)
	}
	// approver（user 2）範圍蓋 asset 1
	a1 := uint(1)
	db.Create(&model.ApproverScope{ApproverID: uptrScope(2), AssetID: &a1, GrantedBy: 3})

	req := submitBasic(t, svc, 1, 1)
	// 模擬 scheduler 五分鐘間隙內的逾期單：pending_expires_at 已過但仍 pending
	if err := db.Model(&model.AccessRequest{}).Where("id = ?", req.ID).
		Update("pending_expires_at", time.Now().Add(-time.Hour)).Error; err != nil {
		t.Fatalf("set expired: %v", err)
	}

	if _, err := svc.Approve(2, false, req.ID, DecideInput{}); !errors.Is(err, ErrAccessRequestConflict) {
		t.Fatalf("逾期單投票應回衝突（不得記部分票），得: %v", err)
	}
	var votes int64
	db.Model(&model.AccessRequestApproval{}).Where("request_id = ?", req.ID).Count(&votes)
	if votes != 0 {
		t.Fatalf("逾期單不應記入任何票，得 %d", votes)
	}
}

// TestPolicyMinApprovalsValidation 政策值驗證：0 與超上限拒絕
func TestPolicyMinApprovalsValidation(t *testing.T) {
	_, policies, _ := setupAccessRequestEnv(t)
	if _, err := policies.Update(policy.PolicyAccessRequestMinApprovals, "0", "admin"); err == nil {
		t.Fatalf("0 應被拒（非 ZeroDisables int）")
	}
	if _, err := policies.Update(policy.PolicyAccessRequestMinApprovals, "11", "admin"); err == nil {
		t.Fatalf("超上限 10 應被拒")
	}
	if _, err := policies.Update(policy.PolicyAccessRequestMinApprovals, "2", "admin"); err != nil {
		t.Fatalf("合法值應過: %v", err)
	}
}

// ---- 核准路由與門檻：審核方群組（群組即資格）----

// TestApproverScope_GroupActor 審核方群組：成員命中可核/成員不得自審/
// 門檻下成員逐票/退組即失效/admin 補位（使用者兩鐵則）
func TestApproverScope_GroupActor(t *testing.T) {
	svc, policies, db := setupAccessRequestEnv(t)
	seedRequestFixture(t, db)

	// DBA 群組（id 1）：成員 dba1(5)、dba2(6)、requester(1)——requester 刻意入組
	// 驗自審禁止穿透群組資格
	for _, u := range []string{"dba1", "dba2"} {
		if err := db.Create(&model.User{Username: u, Email: strPtr(u + "@x"), Active: true}).Error; err != nil {
			t.Fatalf("seed %s: %v", u, err)
		}
	}
	if err := db.Create(&model.UserGroup{Name: "DBA"}).Error; err != nil {
		t.Fatalf("seed group: %v", err)
	}
	for _, uid := range []uint{5, 6, 1} {
		if err := db.Exec("INSERT INTO user_group_members (user_group_id, user_id) VALUES (1, ?)", uid).Error; err != nil {
			t.Fatalf("seed member %d: %v", uid, err)
		}
	}
	gid, a1 := uint(1), uint(1)
	if err := db.Create(&model.ApproverScope{ApproverGroupID: &gid, AssetID: &a1, GrantedBy: 3}).Error; err != nil {
		t.Fatalf("seed group scope: %v", err)
	}

	t.Run("成員命中可核且成員不得自審", func(t *testing.T) {
		req := submitBasic(t, svc, 1, 1)

		// requester 自己也是 DBA 成員——自審一律 403（鐵則 1）
		if _, err := svc.Approve(1, false, req.ID, DecideInput{}); !errors.Is(err, ErrSelfApproval) {
			t.Fatalf("群組成員自審應 ErrSelfApproval: %v", err)
		}
		// 待審列表不含自己的單
		mine, _ := svc.ListPending(1, false, time.Now())
		for _, p := range mine {
			if p.ID == req.ID {
				t.Fatalf("自己的單不應出現在自己的待審列表")
			}
		}

		// dba1 待審可見＋可核（群組即資格，無 approver 角色）
		pending, err := svc.ListPending(5, false, time.Now())
		if err != nil {
			t.Fatalf("list pending: %v", err)
		}
		found := false
		for _, p := range pending {
			if p.ID == req.ID {
				found = true
			}
		}
		if !found {
			t.Fatalf("群組成員待審列表應含該單")
		}
		if _, err := svc.Approve(5, false, req.ID, DecideInput{}); err != nil {
			t.Fatalf("群組成員核准應成功: %v", err)
		}
	})

	t.Run("門檻2成員逐票與admin補位", func(t *testing.T) {
		if _, err := policies.Update(policy.PolicyAccessRequestMinApprovals, "2", "admin"); err != nil {
			t.Fatalf("set policy: %v", err)
		}
		defer policies.Update(policy.PolicyAccessRequestMinApprovals, "1", "admin")

		req := submitBasic(t, svc, 4, 1)
		r1, err := svc.Approve(5, false, req.ID, DecideInput{})
		if err != nil {
			t.Fatalf("dba1 一票: %v", err)
		}
		if r1.Status != model.AccessRequestPending || r1.ApprovalsReceived != 1 {
			t.Fatalf("一票後應 pending 1/2，得 %s %d", r1.Status, r1.ApprovalsReceived)
		}
		// admin 補位第二票（鐵則 2：池不足或缺席時 admin 可介入湊門檻）
		// **審核資格收斂後**：此路徑僅存於 service 契約，API 已不會產生 isAdmin=true；
		// 池不足的實際解法是 admin 先指派 approver 角色（脫困路徑）再由該人投票
		r2, err := svc.Approve(3, true, req.ID, DecideInput{})
		if err != nil {
			t.Fatalf("admin 補位: %v", err)
		}
		if r2.Status != model.AccessRequestApproved {
			t.Fatalf("成員＋admin 兩票應 approved，得 %s", r2.Status)
		}
	})

	t.Run("退組即失效", func(t *testing.T) {
		if err := db.Exec("DELETE FROM user_group_members WHERE user_group_id = 1 AND user_id = 5").Error; err != nil {
			t.Fatalf("remove member: %v", err)
		}
		db.Model(&model.Asset{}).Where("id = 2").Update("access_policy", model.AccessPolicyApproval)
		req := submitBasic(t, svc, 4, 1)
		if _, err := svc.Approve(5, false, req.ID, DecideInput{}); !errors.Is(err, ErrNotEligibleApprover) {
			t.Fatalf("退組後應無資格: %v", err)
		}
		// dba2 仍可核（群組其餘成員不受影響）
		if _, err := svc.Approve(6, false, req.ID, DecideInput{}); err != nil {
			t.Fatalf("在組成員應仍可核: %v", err)
		}
	})
}

// TestApproverScopeCoversRequestTx_TxVisibility 交易內資格重查（TOCTOU）：
// Tx 變體必須讀傳入交易的未提交狀態——鎖單交易內撤銷的範圍即時失效，
// 而非透過 r.db 讀到交易外的舊快照（否則重查形同虛設）
func TestApproverScopeCoversRequestTx_TxVisibility(t *testing.T) {
	_, _, db := setupAccessRequestEnv(t)
	seedRequestFixture(t, db)
	repo := newAssetAuthorizationRepository(db)

	if err := db.Create(&model.User{Username: "approver2", Email: strPtr("a2@x"), Active: true}).Error; err != nil {
		t.Fatalf("seed approver2: %v", err)
	}
	a1 := uint(1)
	if err := db.Create(&model.ApproverScope{ApproverID: uptrScope(5), AssetID: &a1, GrantedBy: 3}).Error; err != nil {
		t.Fatalf("seed scope: %v", err)
	}

	errRollback := errors.New("rollback")
	err := db.Transaction(func(tx *gorm.DB) error {
		// 模擬 TOCTOU 窗口：外層資格判定通過後、鎖單交易內範圍被刪
		if err := tx.Where("approver_id = ?", 5).Delete(&model.ApproverScope{}).Error; err != nil {
			return err
		}
		covered, err := repo.ApproverScopeCoversRequestTx(tx, 5, 1, 1)
		if err != nil {
			return err
		}
		if covered {
			t.Errorf("交易內已撤範圍，Tx 重查應判無資格")
		}
		return errRollback
	})
	if !errors.Is(err, errRollback) {
		t.Fatalf("transaction: %v", err)
	}

	// 回滾後範圍仍在——交易外判定不受影響，證明 Tx 變體讀的是交易內狀態
	covered, err := repo.ApproverScopeCoversRequest(5, 1, 1)
	if err != nil {
		t.Fatalf("covers after rollback: %v", err)
	}
	if !covered {
		t.Fatalf("回滾後範圍應復原且命中")
	}
}
