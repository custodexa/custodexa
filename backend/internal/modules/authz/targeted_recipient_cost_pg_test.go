package authz

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/testgate"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 定向通知收件人求得的耗時量測（TNL_MEASURE=1 且設 TEST_PG_DSN 才執行，不是回歸測試）。
// 量的是本 change 段 A 的判定本身：連線申請 50 位候選人的求得、每日簽核在小規模與 2,000 位使用者的求得，
// 以及「每位收件人一筆 INSERT」在一個交易內的耗時（分派交易因本 change 多出的部分）。
// 分派交易的全程與送達延遲要等分派與投遞接上（段 B）後在同一套量測上重跑。

func newCostEnvPG(t *testing.T) (*AccessRequestService, *gorm.DB) {
	t.Helper()
	if os.Getenv("TNL_MEASURE") != "1" {
		t.Skip("量測測試：TNL_MEASURE=1 才執行")
	}
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	var b [6]byte
	_, _ = rand.Read(b[:])
	schema := "tnl_cost_" + hex.EncodeToString(b[:])
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
		&model.SecurityPolicy{}, &model.AuditLog{}, &model.NotificationChannel{}, &model.Role{}, &model.RolePermission{},
		&model.NotificationMessage{}, &model.NotificationDelivery{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.AutoMigrate(&model.UserRole{}, &model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	policies := policy.NewSecurityPolicyService(db)
	accessPolicy := policy.NewAccessPolicyService(db, policies, NewAssetAuthorizationService(db))
	return NewAccessRequestService(db, policies, accessPolicy, nil, nil), db
}

func p95(d []time.Duration) time.Duration {
	s := append([]time.Duration{}, d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[(len(s)*95+99)/100-1]
}

// TestMeasureTargetedRecipientCostPG 量測並以 t.Logf 輸出（附負載口徑由執行者記錄）。
func TestMeasureTargetedRecipientCostPG(t *testing.T) {
	svc, db := newCostEnvPG(t)
	const rounds = 20

	// (a) 連線申請：50 位候選人（approver 角色、直配同一資產），一張單一項
	approver := model.Role{Name: model.RoleApprover}
	if err := db.Create(&approver).Error; err != nil {
		t.Fatal(err)
	}
	asset := model.Asset{Name: "cost-asset", Protocol: model.ProtocolSSH, Host: "h", Port: 22, CreatedBy: 1}
	if err := db.Create(&asset).Error; err != nil {
		t.Fatal(err)
	}
	requester := model.User{Username: "cost-requester", Password: "x", Active: true}
	if err := db.Create(&requester).Error; err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		u := model.User{Username: fmt.Sprintf("cost-approver-%02d", i), Password: "x", Active: true}
		if err := db.Create(&u).Error; err != nil {
			t.Fatal(err)
		}
		if err := db.Create(&model.UserRole{UserID: u.ID, RoleID: approver.ID, ScopeKind: model.ScopeKindGlobal}).Error; err != nil {
			t.Fatal(err)
		}
		uid, aid := u.ID, asset.ID
		if err := db.Create(&model.ApproverScope{ApproverID: &uid, AssetID: &aid, GrantedBy: 1}).Error; err != nil {
			t.Fatal(err)
		}
	}
	req := model.AccessRequest{RequesterID: requester.ID, AssetID: asset.ID, Reason: "x", RequestedDurationMinutes: 60,
		Status: model.AccessRequestPending, Kind: model.AccessRequestKindNormal, PendingExpiresAt: time.Now().Add(time.Hour)}
	if err := db.Create(&req).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.AccessRequestItem{RequestID: req.ID, RequesterID: requester.ID, AssetID: asset.ID,
		Status: model.AccessRequestPending, PolicySnapshot: "{}"}).Error; err != nil {
		t.Fatal(err)
	}
	var resolve []time.Duration
	var got []uint
	for i := 0; i < rounds; i++ {
		start := time.Now()
		ids, err := svc.TargetedAccessRequestRecipients(db, req.ID, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		resolve = append(resolve, time.Since(start))
		got = ids
	}
	if len(got) != 50 {
		t.Fatalf("收件人應為 50 位，得 %d", len(got))
	}
	msg := model.NotificationMessage{Category: model.NotificationCategorySystemEvent, EventKey: "access_request.created",
		Severity: "medium", OccurredAt: time.Now(), CreatedAt: time.Now()}
	if err := db.Create(&msg).Error; err != nil {
		t.Fatal(err)
	}
	channelID := uint(1)
	var insert []time.Duration
	for i := 0; i < rounds; i++ {
		start := time.Now()
		err := db.Transaction(func(tx *gorm.DB) error {
			return tx.Transaction(func(sp *gorm.DB) error { // savepoint，與分派的寫入擴充點相同形狀
				for _, uid := range got {
					rid := uid
					row := model.NotificationDelivery{Category: model.NotificationCategorySystemEvent, MessageID: &msg.ID, Severity: "medium",
						SourceChannelID: &channelID, State: model.NotificationDeliveryPending, NextAttemptAt: time.Now(), CreatedAt: time.Now(),
						Audience: model.NotificationAudienceUser, RecipientUserID: &rid, DeliveryKey: fmt.Sprintf("%016x%016x", i, uid)}
					if err := sp.Create(&row).Error; err != nil {
						return err
					}
				}
				return nil
			})
		})
		if err != nil {
			t.Fatal(err)
		}
		insert = append(insert, time.Since(start))
		if err := db.Exec("DELETE FROM system_alert_outbox").Error; err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("MEASURE access_request 50 candidates: resolve p95=%v max=%v; 50 inserts in tx p95=%v max=%v (rounds=%d)",
		p95(resolve), maxDur(resolve), p95(insert), maxDur(insert), rounds)

	// (b) 每日簽核：小規模（20 位）與 2,000 位使用者，每位都有一筆角色指派（候選人上界的最壞情況），
	// 其中 1/10 持可簽核的自訂角色
	signer := model.Role{Name: "cost-signer", DefinitionVersion: 1}
	plain := model.Role{Name: "cost-plain", DefinitionVersion: 1}
	for _, r := range []*model.Role{&signer, &plain} {
		if err := db.Create(r).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []Permission{PermAuditView, PermAlertManage} {
		if err := db.Create(&model.RolePermission{RoleID: signer.ID, PermissionKey: string(p)}).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Create(&model.RolePermission{RoleID: plain.ID, PermissionKey: string(PermAssetView)}).Error; err != nil {
		t.Fatal(err)
	}
	seeded := 0
	for _, scale := range []int{20, 2000} {
		for ; seeded < scale; seeded++ {
			u := model.User{Username: fmt.Sprintf("cost-user-%04d", seeded), Password: "x", Active: true}
			if err := db.Create(&u).Error; err != nil {
				t.Fatal(err)
			}
			role := plain.ID
			if seeded%10 == 0 {
				role = signer.ID
			}
			if err := db.Create(&model.UserRole{UserID: u.ID, RoleID: role, ScopeKind: model.ScopeKindGlobal}).Error; err != nil {
				t.Fatal(err)
			}
		}
		var durs []time.Duration
		var allowed int
		n := 5
		for i := 0; i < n; i++ {
			start := time.Now()
			cands, err := DailyReviewSignerCandidates(db)
			if err != nil {
				t.Fatal(err)
			}
			allowed = 0
			for _, id := range cands {
				ok, err := DailyReviewSignerAllowed(db, id)
				if err != nil {
					t.Fatal(err)
				}
				if ok {
					allowed++
				}
			}
			durs = append(durs, time.Since(start))
		}
		t.Logf("MEASURE daily_review users=%d (+50 approver fixtures): recipients=%d resolve p95=%v max=%v (rounds=%d)",
			scale, allowed, p95(durs), maxDur(durs), n)
	}
}

func maxDur(d []time.Duration) time.Duration {
	var m time.Duration
	for _, v := range d {
		if v > m {
			m = v
		}
	}
	return m
}
