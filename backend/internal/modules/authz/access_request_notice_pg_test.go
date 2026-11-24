package authz

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/notifycat"
	"github.com/custodexa/backend/internal/testgate"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 連線申請族與破窗的 savepoint 在 PostgreSQL 上的行為（TEST_PG_DSN gated）：通知內容 INSERT 在資料庫層
// 失敗時，業務交易不得進入 aborted 狀態。

func newNoticeEnvPG(t *testing.T) *noticeEnv {
	t.Helper()
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	var b [6]byte
	_, _ = rand.Read(b[:])
	schema := "ndl_c_" + hex.EncodeToString(b[:])
	if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE")
		if s, err := admin.DB(); err == nil {
			_ = s.Close()
		}
	})
	db, err := gorm.Open(postgres.Open(dsn+" search_path="+schema), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if s, err := db.DB(); err == nil {
			_ = s.Close()
		}
	})
	if err := db.AutoMigrate(&model.User{}, &model.UserGroup{}, &model.Asset{}, &model.AssetGroup{}, &model.AssetNode{},
		&model.AssetAuthorization{}, &model.AccessRequest{}, &model.AccessRequestItem{}, &model.AgentVisibilityExposure{}, &model.AccessRequestApproval{}, &model.ApproverScope{},
		&model.SecurityPolicy{}, &model.AuditLog{}, &model.NotificationChannel{}, &model.UserRole{},
		&model.NotificationMessage{}, &model.NotificationDelivery{}, &model.SystemAlertDetail{}, &model.AuthzState{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_access_request_pending_dedup
		ON access_requests (requester_id, asset_id) WHERE status = 'pending' AND deleted_at IS NULL AND kind = 'normal'`).Error; err != nil {
		t.Fatal(err)
	}
	policies := policy.NewSecurityPolicyService(db)
	accessPolicy := policy.NewAccessPolicyService(db, policies, NewAssetAuthorizationService(db))
	svc := NewAccessRequestService(db, policies, accessPolicy, nil, nil)
	seedRequestFixture(t, db)
	svc.notifier = audit.NewAlertNotifier(db, nil)
	return &noticeEnv{svc: svc, policies: policies, db: db}
}

func failRequestNoticesPG(t *testing.T, db *gorm.DB) {
	t.Helper()
	for _, s := range []string{
		`CREATE OR REPLACE FUNCTION fail_request_notice() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'injected'; END $$ LANGUAGE plpgsql`,
		`CREATE TRIGGER fail_request_notice BEFORE INSERT ON notification_messages FOR EACH ROW EXECUTE FUNCTION fail_request_notice()`,
	} {
		if err := db.Exec(s).Error; err != nil {
			t.Fatal(err)
		}
	}
}

func TestAccessRequestNoticeSavepointPG(t *testing.T) {
	t.Run("破窗：內容列 INSERT 失敗時破窗單與臨時授權照常提交", func(t *testing.T) {
		e := newNoticeEnvPG(t)
		grantConnect(t, e.db, 1, 1)
		enableBreakGlass(t, e.policies)
		failRequestNoticesPG(t, e.db)
		req, err := e.svc.BreakGlass(1, "requester", false, 1, "半夜事故")
		if err != nil {
			t.Fatalf("通知寫不進去不得讓破窗失敗: %v", err)
		}
		if req.Status != model.AccessRequestApproved || req.AuthorizationID == nil {
			t.Fatalf("破窗單應已核准並有臨時授權: %+v", req)
		}
		var n int64
		e.db.Model(&model.NotificationMessage{}).Count(&n)
		if n != 0 {
			t.Fatalf("內容列應為 0，得 %d", n)
		}
	})
	t.Run("建單與核准：內容列 INSERT 失敗時業務照常提交；成功時資產與名稱參照正確", func(t *testing.T) {
		e := newNoticeEnvPG(t)
		req := submitBasic(t, e.svc, 1, 1)
		msgs := e.messages(t)
		if len(msgs) != 1 || msgs[0].EventKey != string(notifycat.EventAccessRequestCreated) || noticeRefs(t, msgs[0])["asset_name"].ID != 1 {
			t.Fatalf("建單通知不符: %+v", msgs)
		}
		failRequestNoticesPG(t, e.db)
		got, err := e.svc.Approve(3, true, req.ID, DecideInput{Note: "ok"})
		if err != nil {
			t.Fatalf("通知寫不進去不得讓核准失敗: %v", err)
		}
		if got.Status != model.AccessRequestApproved {
			t.Fatalf("申請應已核准: %s", got.Status)
		}
		if n := len(e.messages(t)); n != 1 {
			t.Fatalf("核准通知寫不進去，內容列應維持 1，得 %d", n)
		}
	})
}
