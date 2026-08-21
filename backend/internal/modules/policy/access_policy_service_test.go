package policy

import (
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupAccessPolicyDB 真 SQL（in-memory SQLite）：政策解析的資產欄位/全域鍵
// 兩層路徑用實際查詢驗證（asset-level-access-policy D1）
func setupAccessPolicyDB(t *testing.T) (*AccessPolicyService, *SecurityPolicyService, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.SecurityPolicy{}, &model.Asset{}, &model.AssetGroup{}, &model.AssetNode{},
		&model.AssetAuthorization{}, &model.AccessRequest{}, &model.AuditLog{},
		&model.User{}, &model.UserGroup{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	policies := NewSecurityPolicyService(db)
	return NewAccessPolicyService(db, policies, stubConnectSources{}), policies, db
}

func strPtr(s string) *string { return &s }

// stubConnectSources 測試用的 ConnectSourceResolver 空實作（W3 §4.8 拆環後
// policy 不再自持 authz 的 repository）。本檔只驗段位解析（AccessPolicyOf），
// 不走票證／在途單分支，故回零值即可；走那兩個分支的行為測試在 authz 側
// （internal/service 的 access_request_service_test.go）與兌換點整合測試。
type stubConnectSources struct {
	ticket    bool
	pendingID *uint
	err       error
}

func (s stubConnectSources) HasTicketConnect(uint, uint, time.Time) (bool, error) {
	return s.ticket, s.err
}

func (s stubConnectSources) PendingConnectRequestID(uint, uint) (*uint, error) {
	return s.pendingID, s.err
}

// TestAccessPolicyOf 政策解析兩層路徑：資產設定/未設定走全域/非法值視同未設定
// （asset-level-access-policy D1：政策掛資產，組織結構不影響解析）
func TestAccessPolicyOf(t *testing.T) {
	svc, policies, db := setupAccessPolicyDB(t)

	// 資產掛節點與否不影響政策（組織結構已卸下政策職責）——刻意掛節點驗證解耦
	db.Create(&model.AssetGroup{Name: "g-any"}) // id 1
	assetSet := &model.Asset{Name: "a1", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1,
		AccessPolicy: strPtr(model.AccessPolicyApproval)}
	assetUnset := &model.Asset{Name: "a2", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1}
	assetNoGroup := &model.Asset{Name: "a3", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1}
	for _, a := range []*model.Asset{assetSet, assetUnset, assetNoGroup} {
		if err := db.Create(a).Error; err != nil {
			t.Fatalf("seed asset: %v", err)
		}
	}
	for _, aid := range []uint{1, 2} {
		if err := db.Create(&model.AssetNode{AssetID: aid, NodeID: 1}).Error; err != nil {
			t.Fatalf("seed node member: %v", err)
		}
	}

	// 資產設定 approval 直接生效
	if got := svc.AccessPolicyOf(assetSet); got != model.AccessPolicyApproval {
		t.Errorf("資產設定 approval 應生效, got %s", got)
	}
	// 未設定＋全域出廠預設 open（分組與否無別）
	if got := svc.AccessPolicyOf(assetUnset); got != model.AccessPolicyOpen {
		t.Errorf("未設定應走全域出廠 open, got %s", got)
	}
	if got := svc.AccessPolicyOf(assetNoGroup); got != model.AccessPolicyOpen {
		t.Errorf("未分組未設定應走全域出廠 open, got %s", got)
	}

	// 全域改 reason：未設定資產跟隨，已設定資產不受影響
	if _, err := policies.Update(PolicyAccessPolicyDefault, model.AccessPolicyReason, "admin"); err != nil {
		t.Fatalf("update global policy: %v", err)
	}
	if got := svc.AccessPolicyOf(assetUnset); got != model.AccessPolicyReason {
		t.Errorf("未設定應跟隨全域 reason, got %s", got)
	}
	if got := svc.AccessPolicyOf(assetSet); got != model.AccessPolicyApproval {
		t.Errorf("資產設定不應被全域覆蓋, got %s", got)
	}

	// 組織結構不影響政策：摘掉全部節點掛載後解析結果不變（spec scenario）
	if err := db.Where("asset_id = ?", assetSet.ID).Delete(&model.AssetNode{}).Error; err != nil {
		t.Fatalf("clear node membership: %v", err)
	}
	if got := svc.AccessPolicyOf(assetSet); got != model.AccessPolicyApproval {
		t.Errorf("摘節點不應影響資產政策, got %s", got)
	}

	// 資產欄位非法值（手動改庫）視同未設定
	assetBad := &model.Asset{Name: "a4", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1,
		AccessPolicy: strPtr("block")}
	if err := db.Create(assetBad).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	if got := svc.AccessPolicyOf(assetBad); got != model.AccessPolicyReason {
		t.Errorf("資產欄位非法值應視同未設定回全域, got %s", got)
	}
}
