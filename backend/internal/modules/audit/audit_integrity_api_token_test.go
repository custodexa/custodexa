package audit

import (
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// legacyIntegrityGolden 涵蓋內容加入 API token 兩欄之前，以固定金鑰對 legacyIntegritySample 算出的驗證碼。
// 兩欄為空的列重算後必須逐位元相同，否則既有已蓋章列會集體誤判為竄改。
const legacyIntegrityGolden = "97f31e336583814939e7d5fc04672f820d030b0d45915b4080b266231a09867c"

func legacyIntegritySample() *model.AuditLog {
	rid, aid := uint(41), uint(7)
	return &model.AuditLog{
		CreatedAt: time.Date(2026, 3, 4, 5, 6, 7, 891011000, time.UTC),
		Action:    model.ActionUpdate, Resource: model.ResourceUser, ResourceID: &rid, AssetID: &aid,
		Status: model.StatusSuccess, UserID: 3, Username: "admin", ClientIP: "10.0.0.1",
		Method: "PUT", Path: "/api/v1/users/41", ErrorMsg: "", Details: `{"k":"v"}`,
		RequestBody: `{"name":"x"}`, RequestID: "req-1", KeyVersion: 1,
	}
}

// TestAuditIntegrityAPITokenLegacyRowUnchanged 升級前格式的列（兩欄為 NULL，含名稱為空字串的指標）
// 驗證碼與加入新欄前相同。
func TestAuditIntegrityAPITokenLegacyRowUnchanged(t *testing.T) {
	svc := &AuditIntegrityService{}
	key := []byte("legacy-golden-key")
	l := legacyIntegritySample()
	if got := svc.computeWith(key, l); got != legacyIntegrityGolden {
		t.Fatalf("舊列驗證碼改變：got %s want %s", got, legacyIntegrityGolden)
	}
	empty := ""
	l.APITokenName = &empty
	if got := svc.computeWith(key, l); got != legacyIntegrityGolden {
		t.Fatalf("名稱為空字串時鍵應不出現：got %s", got)
	}
}

// TestAuditIntegrityAPITokenTamperDetected token 列的識別或名稱被改值、清空，驗證皆失敗；
// 未竄改的 token 列與舊列照常通過。
func TestAuditIntegrityAPITokenTamperDetected(t *testing.T) {
	cases := []struct {
		name string
		sql  string
	}{
		{"改 token 識別", "UPDATE audit_logs SET api_token_id = 99 WHERE id = ?"},
		{"改名稱", "UPDATE audit_logs SET api_token_name = 'other' WHERE id = ?"},
		{"清空識別", "UPDATE audit_logs SET api_token_id = NULL WHERE id = ?"},
		{"清空名稱", "UPDATE audit_logs SET api_token_name = NULL WHERE id = ?"},
		{"兩欄皆清空", "UPDATE audit_logs SET api_token_id = NULL, api_token_name = NULL WHERE id = ?"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := newIntegrityDB(t)
			svc := newIntegrityService(t, db)
			tokenID, name := uint(12), "terraform-prod"
			legacy := &model.AuditLog{CreatedAt: time.Now(), Action: model.ActionUpdate, Resource: model.ResourceUser,
				Status: model.StatusSuccess, UserID: 3, Username: "admin"}
			viaToken := &model.AuditLog{CreatedAt: time.Now(), Action: model.ActionUpdate, Resource: model.ResourceUser,
				Status: model.StatusSuccess, UserID: 3, Username: "admin", APITokenID: &tokenID, APITokenName: &name}
			untouched := &model.AuditLog{CreatedAt: time.Now(), Action: model.ActionCreate, Resource: model.ResourceUser,
				Status: model.StatusSuccess, UserID: 3, Username: "admin", APITokenID: &tokenID, APITokenName: &name}
			rows := []*model.AuditLog{legacy, viaToken, untouched}
			svc.Stamp(rows)
			for _, r := range rows {
				if err := db.Create(r).Error; err != nil {
					t.Fatalf("create: %v", err)
				}
			}
			if err := db.Exec(tc.sql, viaToken.ID).Error; err != nil {
				t.Fatalf("tamper: %v", err)
			}
			report, err := svc.Verify(db, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if report.Passed != 2 || report.Mismatched != 1 ||
				len(report.MismatchedIDs) != 1 || report.MismatchedIDs[0] != viaToken.ID {
				t.Fatalf("report = %+v, want 2 passed / 1 mismatched (id %d)", report, viaToken.ID)
			}
		})
	}
}
