package authz

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 防自我授權守衛：授權規則、帳號範圍、審核範圍、申請決定共用同一份「本人範圍」判定。
//
// 突變自檢：把 self_grant_guard.go 的 CheckRuleSubjects／CheckApproverScope／IsOwnAgentRequest
// 改成一律放行，本檔三個頂層測試的「應拒絕」案例全部轉紅。

// selfGuardEnv 以 sqlite 建立授權規則守衛的最小夾具：
// user 1 操作者（非超管）、user 2 他人、group 1（1 為手動成員）、group 2（1 為映射成員）、
// group 3（1 不在其中）、agent 4（owner=1，啟用）、agent 5（owner=1，停用）、agent 6（owner=2）、
// asset 1。
func selfGuardEnv(t *testing.T) (*AssetAuthorizationService, *gorm.DB) {
	t.Helper()
	svc, db := setupScopeEnv(t)
	if err := db.AutoMigrate(&model.UserGroupMember{}); err != nil {
		t.Fatalf("migrate members: %v", err)
	}
	users := []model.User{
		{Username: "operator", Active: true, Kind: model.KindHuman},
		{Username: "other", Active: true, Kind: model.KindHuman},
		{Username: "third", Active: true, Kind: model.KindHuman},
	}
	for i := range users {
		if err := db.Create(&users[i]).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
	}
	one, two := uint(1), uint(2)
	agents := []model.User{
		{Username: "bot-active", Active: true, Kind: model.KindAgent, OwnerUserID: &one},
		{Username: "bot-disabled", Active: false, Kind: model.KindAgent, OwnerUserID: &one},
		{Username: "bot-other", Active: true, Kind: model.KindAgent, OwnerUserID: &two},
	}
	for i := range agents {
		if err := db.Create(&agents[i]).Error; err != nil {
			t.Fatalf("seed agent: %v", err)
		}
	}
	for _, name := range []string{"manual-grp", "mapped-grp", "outside-grp"} {
		if err := db.Create(&model.UserGroup{Name: name}).Error; err != nil {
			t.Fatalf("seed group: %v", err)
		}
	}
	// 手動與映射來源各一（manual 旗標不同），兩者都是「直接所屬」
	for _, m := range []model.UserGroupMember{{UserGroupID: 1, UserID: 1, Manual: true}, {UserGroupID: 2, UserID: 1, Manual: false}, {UserGroupID: 3, UserID: 2, Manual: true}} {
		if err := db.Create(&m).Error; err != nil {
			t.Fatalf("seed member: %v", err)
		}
	}
	if err := db.Create(&model.Asset{Name: "box", Protocol: model.ProtocolSSH, Host: "h", Port: 22, CreatedBy: 2, Active: true}).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	return svc, db
}

func countRules(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	if err := db.Unscoped().Model(&model.AssetAuthorization{}).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

func TestAuthorizationSelfSubjectGuard(t *testing.T) {
	svc, db := selfGuardEnv(t)
	asset := uint(1)
	grant := func(ctx context.Context, user, group *uint) error {
		_, err := svc.Grant(ctx, GrantSpec{UserID: user, UserGroupID: group, AssetID: &asset,
			Permission: model.PermissionConnect, GrantedBy: 1})
		return err
	}
	u := func(v uint) *uint { return &v }

	t.Run("非超管以本人範圍為主體建規則皆被拒且零寫入", func(t *testing.T) {
		before := countRules(t, db)
		cases := []struct {
			name        string
			user, group *uint
		}{
			{"自己", u(1), nil},
			{"自己為成員的群組（手動來源）", nil, u(1)},
			{"自己為成員的群組（映射來源）", nil, u(2)},
			{"自己擁有的 agent（啟用）", u(4), nil},
			{"自己擁有的 agent（停用）", u(5), nil},
		}
		for _, c := range cases {
			err := grant(operatorCtx(1), c.user, c.group)
			if !errors.Is(err, ErrSelfSubjectGrant) {
				t.Errorf("%s：應回 ErrSelfSubjectGrant，實得 %v", c.name, err)
			}
			// 拒絕訊息不帶主體名稱、ID 或數量
			if err != nil {
				for _, leak := range []string{"operator", "bot-", "manual-grp", "mapped-grp", "ID=", "id="} {
					if strings.Contains(err.Error(), leak) {
						t.Errorf("%s：拒絕訊息洩漏 %q：%s", c.name, leak, err.Error())
					}
				}
			}
		}
		if after := countRules(t, db); after != before {
			t.Fatalf("被拒的建立不得寫入任何列：before=%d after=%d", before, after)
		}
	})

	t.Run("批次含一個自己群組時整批零寫入", func(t *testing.T) {
		before := countRules(t, db)
		_, err := svc.GrantBatch(operatorCtx(1), []uint{2}, []uint{3, 1}, []uint{asset}, nil,
			model.PermissionConnect, 1, nil)
		if !errors.Is(err, ErrSelfSubjectGrant) {
			t.Fatalf("批次含本人群組應整批拒絕: %v", err)
		}
		if after := countRules(t, db); after != before {
			t.Fatalf("批次不得部分成功：before=%d after=%d", before, after)
		}
	})

	t.Run("以他人、自己不在其中的群組、他人擁有的 agent 為主體成功", func(t *testing.T) {
		for _, c := range []struct {
			name        string
			user, group *uint
		}{{"他人", u(2), nil}, {"自己不在其中的群組", nil, u(3)}, {"他人擁有的 agent", u(6), nil}} {
			if err := grant(operatorCtx(1), c.user, c.group); err != nil {
				t.Errorf("%s：應成功，實得 %v", c.name, err)
			}
		}
	})

	t.Run("主體屬本人範圍的規則調整帳號範圍被拒、刪除成功", func(t *testing.T) {
		// 由他人（超管）替 group 1 建一筆，再由 operator 1 調整與刪除
		created, err := svc.Grant(superAdminOperatorCtx(2), GrantSpec{UserGroupID: u(1), AssetID: &asset,
			Permission: model.PermissionConnect, GrantedBy: 2})
		if err != nil {
			t.Fatalf("超管建立: %v", err)
		}
		if _, err := svc.UpdateAccountScope(operatorCtx(1), created.ID, &[]string{"app"}); !errors.Is(err, ErrSelfSubjectGrant) {
			t.Fatalf("本人群組規則的帳號範圍調整應被拒: %v", err)
		}
		var row model.AssetAuthorization
		if err := db.First(&row, created.ID).Error; err != nil {
			t.Fatal(err)
		}
		if !row.Accounts.IsAll() {
			t.Fatalf("被拒後帳號範圍不得改變: %+v", row.Accounts)
		}
		if err := svc.RevokePermission(operatorCtx(1), created.ID); err != nil {
			t.Fatalf("刪除不受本人範圍限制: %v", err)
		}
	})

	t.Run("超管以自己所屬群組為主體建規則成功", func(t *testing.T) {
		if err := db.Create(&model.UserGroupMember{UserGroupID: 3, UserID: 3, Manual: true}).Error; err != nil {
			t.Fatal(err)
		}
		_, err := svc.Grant(superAdminOperatorCtx(3), GrantSpec{UserGroupID: u(3), AssetID: &asset,
			Permission: model.PermissionView, GrantedBy: 3})
		if err != nil {
			t.Fatalf("超管不受本人範圍限制: %v", err)
		}
	})

	t.Run("先建規則後操作者加入該群組，規則與成員皆保留", func(t *testing.T) {
		// operator 1 不在 group 3；先對另一資產建規則（asset 1 × group 3 已在前案建過）
		if err := db.Create(&model.Asset{Name: "box2", Protocol: model.ProtocolSSH, Host: "h", Port: 22, CreatedBy: 2, Active: true}).Error; err != nil {
			t.Fatal(err)
		}
		asset2 := uint(2)
		created, err := svc.Grant(operatorCtx(1), GrantSpec{UserGroupID: u(3), AssetID: &asset2,
			Permission: model.PermissionConnect, GrantedBy: 1})
		if err != nil {
			t.Fatalf("建立: %v", err)
		}
		if err := db.Create(&model.UserGroupMember{UserGroupID: 3, UserID: 1, Manual: true}).Error; err != nil {
			t.Fatalf("事後加入群組不得被拒: %v", err)
		}
		var n int64
		if err := db.Model(&model.AssetAuthorization{}).Where("id = ?", created.ID).Count(&n).Error; err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("事後成員異動不得追溯撤銷規則: count=%d", n)
		}
		var m int64
		if err := db.Table("user_group_members").Where("user_group_id = 3 AND user_id = 1").Count(&m).Error; err != nil {
			t.Fatal(err)
		}
		if m != 1 {
			t.Fatalf("成員關係應保留: count=%d", m)
		}
	})

	t.Run("脈絡無主體時帳號範圍調整 fail-close", func(t *testing.T) {
		created, err := svc.Grant(superAdminOperatorCtx(2), GrantSpec{UserID: u(3), AssetID: &asset,
			Permission: model.PermissionConnect, GrantedBy: 2})
		if err != nil {
			t.Fatalf("建立: %v", err)
		}
		if _, err := svc.UpdateAccountScope(context.Background(), created.ID, &[]string{"app"}); !errors.Is(err, ErrOperatorUnknown) {
			t.Fatalf("無主體應回 ErrOperatorUnknown: %v", err)
		}
	})
}

// ownAgentEnv 在既有申請流夾具上加：agent 7（owner=approver 2）、user 5 另一具資格審核者
// （直配 asset 1）；asset 1 為需核准段位。
func ownAgentEnv(t *testing.T) (*AccessRequestService, *gorm.DB) {
	t.Helper()
	svc, _, db := setupAccessRequestEnv(t)
	seedRequestFixture(t, db)
	if err := db.Create(&model.User{Username: "approver2", Email: strPtr("a2@x"), Active: true}).Error; err != nil {
		t.Fatal(err)
	}
	a1 := uint(1)
	if err := db.Create(&model.ApproverScope{ApproverID: uptrScope(5), AssetID: &a1, GrantedBy: 3}).Error; err != nil {
		t.Fatal(err)
	}
	// user 6 佔位，讓 agent 落在 id 7
	if err := db.Create(&model.User{Username: "filler", Email: strPtr("f@x"), Active: true}).Error; err != nil {
		t.Fatal(err)
	}
	owner := uint(2)
	if err := db.Create(&model.User{Username: "report-bot", Active: true, Kind: model.KindAgent, OwnerUserID: &owner}).Error; err != nil {
		t.Fatal(err)
	}
	for aid := uint(1); aid <= 3; aid++ {
		u, a := uint(7), aid
		if err := db.Create(&model.AssetAuthorization{UserID: &u, AssetID: &a, Permission: model.PermissionView, GrantedBy: 3}).Error; err != nil {
			t.Fatal(err)
		}
	}
	svc.SetAccountPresenceSource(func(*gorm.DB, uint, string) (bool, error) { return true, nil })
	return svc, db
}

func submitByAgent(t *testing.T, svc *AccessRequestService) *model.AccessRequest {
	t.Helper()
	req, err := svc.Submit(7, "report-bot", false, SubmitAccessRequestInput{
		AssetID: 1, Reason: "nightly job", DurationMinutes: 60, Accounts: &[]string{"app"},
	})
	if err != nil {
		t.Fatalf("agent submit: %v", err)
	}
	return req
}

func countVotes(t *testing.T, db *gorm.DB, requestID uint) int64 {
	t.Helper()
	var n int64
	if err := db.Model(&model.AccessRequestApproval{}).Where("request_id = ?", requestID).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSelfApprovalOwnAgent(t *testing.T) {
	svc, db := ownAgentEnv(t)
	req := submitByAgent(t, svc)
	var items []model.AccessRequestItem
	if err := db.Where("request_id = ?", req.ID).Find(&items).Error; err != nil || len(items) == 0 {
		t.Fatalf("items: %v len=%d", err, len(items))
	}
	itemID := items[0].ID

	assertUntouched := func(t *testing.T, label string) {
		t.Helper()
		var row model.AccessRequest
		if err := db.First(&row, req.ID).Error; err != nil {
			t.Fatal(err)
		}
		if row.Status != model.AccessRequestPending {
			t.Fatalf("%s：單狀態不得改變: %s", label, row.Status)
		}
		if v := countVotes(t, db, req.ID); v != 0 {
			t.Fatalf("%s：票數不得改變: %d", label, v)
		}
	}

	t.Run("擁有者對自有 agent 的申請四條決定路徑皆回自核禁止", func(t *testing.T) {
		paths := []struct {
			name string
			do   func() error
		}{
			{"逐項核准", func() error { _, err := svc.Approve(2, false, req.ID, DecideInput{ItemID: itemID}); return err }},
			{"逐項拒絕", func() error { _, err := svc.RejectItem(2, false, req.ID, itemID, "no"); return err }},
			{"整單核准", func() error { _, err := svc.Approve(2, false, req.ID, DecideInput{}); return err }},
			{"批次核決", func() error {
				_, err := svc.Approve(2, false, req.ID, DecideInput{Items: []ItemDecision{{ItemID: itemID}}})
				return err
			}},
			{"舊整單資格判定", func() error { return svc.eligibleToDecide(2, false, req) }},
		}
		for _, p := range paths {
			if err := p.do(); !errors.Is(err, ErrSelfApproval) {
				t.Errorf("%s：應回 ErrSelfApproval，實得 %v", p.name, err)
			}
			assertUntouched(t, p.name)
		}
	})

	t.Run("該單不在擁有者的待審列表與計數", func(t *testing.T) {
		pending, err := svc.ListPending(2, false, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range pending {
			if p.ID == req.ID {
				t.Fatalf("自有 agent 的單不得出現在擁有者待審列表")
			}
		}
		n, err := svc.PendingCount(2, false, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("擁有者待審計數應排除自有 agent 的單: %d", n)
		}
		// 另一具資格者看得到
		other, err := svc.ListPending(5, false, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, p := range other {
			found = found || p.ID == req.ID
		}
		if !found {
			t.Fatalf("另一具資格者的待審列表應含該單")
		}
	})

	t.Run("另一具資格者核准成功", func(t *testing.T) {
		if _, err := svc.Approve(5, false, req.ID, DecideInput{}); err != nil {
			t.Fatalf("另一具資格者核准: %v", err)
		}
	})

	t.Run("擁有者改為他人後原擁有者可決定", func(t *testing.T) {
		req2 := submitByAgent(t, svc)
		if err := db.Model(&model.User{}).Where("id = 7").Update("owner_user_id", 6).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Approve(2, false, req2.ID, DecideInput{}); err != nil {
			t.Fatalf("擁有關係以決定當下現查，改擁有者後應可決定: %v", err)
		}
	})
}

// approverScopeEnv 在 selfGuardEnv 之上建審核範圍夾具：user 1、2 具 approver 角色。
// group 1：成員 1；group 2：成員 1；group 3：成員 2。user 1 屬 1 與 2。
func approverScopeEnv(t *testing.T) (*ApproverScopeService, *gorm.DB, func() int64) {
	t.Helper()
	_, db := selfGuardEnv(t)
	if err := db.AutoMigrate(&model.ApproverScope{}, &model.Role{}, &model.UserRole{}); err != nil {
		t.Fatal(err)
	}
	// 個人審核方須具 approver 角色：user 1、2 皆配
	role := model.Role{Name: model.RoleApprover}
	if err := db.Create(&role).Error; err != nil {
		t.Fatal(err)
	}
	if role.BuiltinKey == nil {
		key := model.BuiltinApprover
		if err := db.Model(&role).Update("builtin_key", key).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, uid := range []uint{1, 2} {
		if err := db.Exec("INSERT INTO user_roles (user_id, role_id, scope_kind) VALUES (?, ?, ?)", uid, role.ID, model.ScopeKindGlobal).Error; err != nil {
			t.Fatal(err)
		}
	}
	countScopes := func() int64 {
		var n int64
		if err := db.Unscoped().Model(&model.ApproverScope{}).Count(&n).Error; err != nil {
			t.Fatal(err)
		}
		return n
	}
	return NewApproverScopeService(db), db, countScopes
}

func TestApproverScopeSubjectOverlap(t *testing.T) {
	svc, db, countScopes := approverScopeEnv(t)
	u := func(v uint) *uint { return &v }

	t.Run("三種相交組合被拒且零寫入", func(t *testing.T) {
		before := countScopes()
		cases := []struct {
			name string
			spec ApproverScopeSpec
		}{
			{"個人對個人同一人", ApproverScopeSpec{ApproverID: u(1), SubjectUserID: u(1), GrantedBy: 2}},
			{"個人屬申請人群組", ApproverScopeSpec{ApproverID: u(1), SubjectGroupID: u(1), GrantedBy: 2}},
			{"群組對群組有共同成員", ApproverScopeSpec{ApproverGroupID: u(1), SubjectGroupID: u(2), GrantedBy: 2}},
			{"群組審核方含申請人本人", ApproverScopeSpec{ApproverGroupID: u(3), SubjectUserID: u(2), GrantedBy: 2}},
		}
		for _, c := range cases {
			if _, err := svc.Create(operatorCtx(c.spec.GrantedBy), c.spec); !errors.Is(err, ErrApproverScopeSubjectOverlap) {
				t.Errorf("%s：應回 ErrApproverScopeSubjectOverlap，實得 %v", c.name, err)
			}
		}
		if after := countScopes(); after != before {
			t.Fatalf("被拒不得寫入: before=%d after=%d", before, after)
		}
	})

	t.Run("無共同成員成功", func(t *testing.T) {
		// group 3（成員 2）審核 group 1（成員 1）
		if _, err := svc.Create(operatorCtx(2), ApproverScopeSpec{ApproverGroupID: u(3), SubjectGroupID: u(1), GrantedBy: 2}); err != nil {
			t.Fatalf("不相交應成功: %v", err)
		}
		if _, err := svc.Create(operatorCtx(2), ApproverScopeSpec{ApproverID: u(2), SubjectUserID: u(1), GrantedBy: 2}); err != nil {
			t.Fatalf("個人對他人應成功: %v", err)
		}
	})

	t.Run("資產型與節點型範圍不檢查", func(t *testing.T) {
		if err := db.Create(&model.AssetGroup{Name: "node"}).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Create(operatorCtx(1), ApproverScopeSpec{ApproverID: u(1), AssetID: u(1), GrantedBy: 1}); err != nil {
			t.Fatalf("資產型範圍不受不相交檢查: %v", err)
		}
		if _, err := svc.Create(operatorCtx(1), ApproverScopeSpec{ApproverGroupID: u(1), AssetGroupID: u(1), GrantedBy: 1}); err != nil {
			t.Fatalf("節點型範圍不受不相交檢查: %v", err)
		}
	})

	t.Run("建立後加入共同成員，範圍保留", func(t *testing.T) {
		// 上面已建 group 3 審核 group 1；把 user 2 加進 group 1 形成相交
		if err := db.Create(&model.UserGroupMember{UserGroupID: 1, UserID: 2, Manual: true}).Error; err != nil {
			t.Fatalf("事後加入不得被拒: %v", err)
		}
		var n int64
		if err := db.Model(&model.ApproverScope{}).Where("approver_group_id = 3 AND subject_group_id = 1").Count(&n).Error; err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("既有相交範圍不追溯撤銷: count=%d", n)
		}
	})

	t.Run("超管建立相交範圍同樣被拒", func(t *testing.T) {
		// 不相交檢查是範圍內容的規則，與操作者是誰無關：以 GrantedBy=超管身分建立仍拒
		before := countScopes()
		if _, err := svc.Create(superAdminOperatorCtx(3), ApproverScopeSpec{ApproverID: u(2), SubjectUserID: u(2), GrantedBy: 3}); !errors.Is(err, ErrApproverScopeSubjectOverlap) {
			t.Fatalf("超管建立相交範圍應被拒: %v", err)
		}
		if after := countScopes(); after != before {
			t.Fatalf("被拒不得寫入")
		}
	})
}

// TestSelfGrantOperatorOnlyFromContext 釘住「操作者只能取自請求脈絡主體」：
// 呼叫端自報的 GrantedBy 不得影響本人範圍判定，脈絡無主體即拒。
//
// 突變自檢：把 guardRuleSubjects／guardBatchSubjects 改回以 grantedBy 參數為操作者，
// 前三個案例轉紅。
func TestSelfGrantOperatorOnlyFromContext(t *testing.T) {
	svc, db := selfGuardEnv(t)
	asset := uint(1)
	u := func(v uint) *uint { return &v }

	t.Run("脈絡主體 1 自報 GrantedBy=2 以自己為主體：拒且零寫入", func(t *testing.T) {
		before := countRules(t, db)
		_, err := svc.Grant(operatorCtx(1), GrantSpec{UserID: u(1), AssetID: &asset,
			Permission: model.PermissionConnect, GrantedBy: 2})
		if !errors.Is(err, ErrOperatorMismatch) {
			t.Fatalf("應回 ErrOperatorMismatch，得 %v", err)
		}
		if after := countRules(t, db); after != before {
			t.Fatalf("不得寫入：before=%d after=%d", before, after)
		}
	})

	t.Run("批次：脈絡主體 1 自報 grantedBy=2、主體集含自己所屬群組：整批拒", func(t *testing.T) {
		before := countRules(t, db)
		_, err := svc.GrantBatch(operatorCtx(1), []uint{2}, []uint{1}, []uint{asset}, nil,
			model.PermissionConnect, 2, nil)
		if !errors.Is(err, ErrOperatorMismatch) {
			t.Fatalf("應回 ErrOperatorMismatch，得 %v", err)
		}
		if after := countRules(t, db); after != before {
			t.Fatalf("不得寫入：before=%d after=%d", before, after)
		}
	})

	t.Run("脈絡無主體：即使主體是他人也拒（fail-close）", func(t *testing.T) {
		before := countRules(t, db)
		_, err := svc.Grant(context.Background(), GrantSpec{UserID: u(3), AssetID: &asset,
			Permission: model.PermissionView, GrantedBy: 2})
		if !errors.Is(err, ErrOperatorUnknown) {
			t.Fatalf("應回 ErrOperatorUnknown，得 %v", err)
		}
		_, err = svc.GrantBatch(context.Background(), []uint{3}, nil, []uint{asset}, nil,
			model.PermissionView, 2, nil)
		if !errors.Is(err, ErrOperatorUnknown) {
			t.Fatalf("批次應回 ErrOperatorUnknown，得 %v", err)
		}
		if after := countRules(t, db); after != before {
			t.Fatalf("不得寫入：before=%d after=%d", before, after)
		}
	})

	t.Run("超管脈絡自報他人 GrantedBy 同樣拒（granted_by 須與操作者一致）", func(t *testing.T) {
		_, err := svc.Grant(superAdminOperatorCtx(2), GrantSpec{UserID: u(3), AssetID: &asset,
			Permission: model.PermissionView, GrantedBy: 1})
		if !errors.Is(err, ErrOperatorMismatch) {
			t.Fatalf("應回 ErrOperatorMismatch，得 %v", err)
		}
	})

	t.Run("脈絡主體與 GrantedBy 一致照常判定：他人可授、本人拒", func(t *testing.T) {
		if _, err := svc.Grant(operatorCtx(2), GrantSpec{UserID: u(3), AssetID: &asset,
			Permission: model.PermissionView, GrantedBy: 2}); err != nil {
			t.Fatalf("他人為主體應成功: %v", err)
		}
		if _, err := svc.Grant(operatorCtx(2), GrantSpec{UserID: u(6), AssetID: &asset,
			Permission: model.PermissionView, GrantedBy: 2}); !errors.Is(err, ErrSelfSubjectGrant) {
			t.Fatalf("自己擁有的 agent 應拒，得 %v", err)
		}
	})
}

// TestApproverScopeOperatorOnlyFromContext 釘住審核範圍建立的操作者只取自請求脈絡主體：
// granted_by 會被擁有者轉移守衛讀取，呼叫端自報的 GrantedBy 與主體不符即拒，脈絡無主體即拒，
// 超管也不例外。三種拒絕皆零寫入。
//
// 突變自檢：拿掉 ApproverScopeService.Create 開頭的 trustedOperator 核對，三個拒絕案例轉紅。
func TestApproverScopeOperatorOnlyFromContext(t *testing.T) {
	svc, db, countScopes := approverScopeEnv(t)
	u := func(v uint) *uint { return &v }

	t.Run("脈絡主體 1 自報 GrantedBy=2：拒且零寫入", func(t *testing.T) {
		before := countScopes()
		_, err := svc.Create(operatorCtx(1), ApproverScopeSpec{ApproverID: u(2), AssetID: u(1), GrantedBy: 2})
		if !errors.Is(err, ErrOperatorMismatch) {
			t.Fatalf("應回 ErrOperatorMismatch，得 %v", err)
		}
		if after := countScopes(); after != before {
			t.Fatalf("不得寫入：before=%d after=%d", before, after)
		}
	})

	t.Run("脈絡無主體：拒且零寫入（fail-close）", func(t *testing.T) {
		before := countScopes()
		_, err := svc.Create(context.Background(), ApproverScopeSpec{ApproverID: u(2), AssetID: u(1), GrantedBy: 2})
		if !errors.Is(err, ErrOperatorUnknown) {
			t.Fatalf("應回 ErrOperatorUnknown，得 %v", err)
		}
		if after := countScopes(); after != before {
			t.Fatalf("不得寫入：before=%d after=%d", before, after)
		}
	})

	t.Run("超管脈絡自報他人 GrantedBy 同樣拒", func(t *testing.T) {
		before := countScopes()
		_, err := svc.Create(superAdminOperatorCtx(3), ApproverScopeSpec{ApproverID: u(2), AssetID: u(1), GrantedBy: 1})
		if !errors.Is(err, ErrOperatorMismatch) {
			t.Fatalf("應回 ErrOperatorMismatch，得 %v", err)
		}
		if after := countScopes(); after != before {
			t.Fatalf("不得寫入：before=%d after=%d", before, after)
		}
	})

	t.Run("脈絡主體與 GrantedBy 一致：建立成功且 granted_by 為該主體", func(t *testing.T) {
		scope, err := svc.Create(superAdminOperatorCtx(3), ApproverScopeSpec{ApproverID: u(2), AssetID: u(1), GrantedBy: 3})
		if err != nil {
			t.Fatalf("應成功: %v", err)
		}
		var row model.ApproverScope
		if err := db.First(&row, scope.ID).Error; err != nil {
			t.Fatal(err)
		}
		if row.GrantedBy != 3 {
			t.Fatalf("granted_by 應為脈絡主體 3，得 %d", row.GrantedBy)
		}
	})
}
