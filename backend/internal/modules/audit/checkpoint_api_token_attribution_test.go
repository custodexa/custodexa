package audit

import (
	"context"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
)

// token 標示經實際寫入路徑落地（交易內寫入面、依交易 context 歸因、條目），於入庫匯流點先歸因再蓋章；
// 封章後竄改標示，跨檢查點的內容驗證指認出該列。

func tokenRequestCtx(id uint, name string) context.Context {
	ctx := model.WithRequestCredential(context.Background(), model.RequestCredentialAPIToken)
	return model.WithAPITokenRef(ctx, model.APITokenRef{ID: id, Name: name})
}

// writeAttributedRows 三種落地方式各寫一列，回傳列識別（依寫入順序）。
func writeAttributedRows(t *testing.T, db *gorm.DB) []uint {
	t.Helper()
	sink := NewTxSink()
	var ids []uint
	collect := func(tx *gorm.DB) {
		var id uint
		if err := tx.Raw("SELECT MAX(id) FROM audit_logs").Scan(&id).Error; err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	// 交易內寫入面：事件的請求欄位帶標示
	if err := db.Transaction(func(tx *gorm.DB) error {
		if err := port.WriteInTx(sink, tx, port.AuditEvent{Action: string(model.ActionUpdate), Resource: string(model.ResourceUser),
			Status: string(model.StatusSuccess), Actor: gatewayapi.Actor{UserID: 3, Username: "admin"},
			Request: gatewayapi.RequestMeta{ClientIP: "192.0.2.1"}.WithAPIToken(21, "tf-prod")}); err != nil {
			return err
		}
		collect(tx)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// 依交易 context 歸因：事件本身不帶標示，交易綁上只帶歸因標示的 context
	if err := db.WithContext(model.AuditAttributionContext(tokenRequestCtx(21, "tf-prod"))).Transaction(func(tx *gorm.DB) error {
		if err := port.WriteInTx(sink, tx, port.AuditEvent{Action: string(model.ActionCreate), Resource: string(model.ResourceAsset),
			Status: string(model.StatusSuccess), Actor: gatewayapi.Actor{UserID: 3, Username: "admin"}}); err != nil {
			return err
		}
		collect(tx)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// 依請求 context 歸因：請求 context 本身
	if err := db.WithContext(tokenRequestCtx(21, "tf-prod")).Create(&model.AuditLog{Action: model.ActionDelete,
		Resource: model.ResourceAsset, Status: model.StatusSuccess, UserID: 3, Username: "admin"}).Error; err != nil {
		t.Fatal(err)
	}
	collect(db)
	return ids
}

// TestAuditAPITokenAttributionWritePaths 三種落地方式的列都帶標示；人類工作階段的 context 不帶標示。
func TestAuditAPITokenAttributionWritePaths(t *testing.T) {
	f := setupVerifyFixture(t)
	model.SetAuditCreateHooks(f.integrity.StampOne, nil)
	t.Cleanup(func() { model.SetAuditCreateHooks(nil, nil) })
	ids := writeAttributedRows(t, f.db)
	var rows []model.AuditLog
	if err := f.db.Where("id IN ?", ids).Order("id").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %d", len(rows))
	}
	for _, r := range rows {
		if r.APITokenID == nil || *r.APITokenID != 21 || r.APITokenName == nil || *r.APITokenName != "tf-prod" {
			t.Fatalf("列 %d 應帶標示：%v %v", r.ID, r.APITokenID, r.APITokenName)
		}
	}
	human := model.WithRequestCredential(context.Background(), model.RequestCredentialHumanSession)
	if err := f.db.WithContext(model.AuditAttributionContext(human)).Create(&model.AuditLog{Action: model.ActionUpdate,
		Resource: model.ResourceUser, Status: model.StatusSuccess, UserID: 3, Username: "admin"}).Error; err != nil {
		t.Fatal(err)
	}
	var last model.AuditLog
	if err := f.db.Order("id DESC").First(&last).Error; err != nil {
		t.Fatal(err)
	}
	if last.APITokenID != nil || last.APITokenName != nil {
		t.Fatal("人類工作階段的列不帶標示")
	}
	rep, err := f.integrity.VerifyIDRange(f.db, ids[0], last.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Mismatched != 0 {
		t.Fatalf("先歸因再蓋章：驗證應全數通過，不符 %v", rep.MismatchedIDs)
	}
}

// TestAuditAPITokenAttributionTamperDetectedAcrossCheckpoints 兩個檢查點各涵蓋 token 列；封章後改識別、改名稱、
// 清空，對兩個檢查點涵蓋範圍的逐列驗證指認出被改的列，未竄改的列照常通過；鏈本身不因內容欄改動而失敗。
func TestAuditAPITokenAttributionTamperDetectedAcrossCheckpoints(t *testing.T) {
	cases := []struct {
		name string
		sql  string
	}{
		{"改 token 識別", "UPDATE audit_logs SET api_token_id = 99 WHERE id = ?"},
		{"改名稱", "UPDATE audit_logs SET api_token_name = 'other' WHERE id = ?"},
		{"清空", "UPDATE audit_logs SET api_token_id = NULL, api_token_name = NULL WHERE id = ?"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := setupVerifyFixture(t)
			model.SetAuditCreateHooks(f.integrity.StampOne, nil)
			t.Cleanup(func() { model.SetAuditCreateHooks(nil, nil) })
			first := writeAttributedRows(t, f.db)
			cp1, err := f.seal.SealNow()
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			second := writeAttributedRows(t, f.db)
			cp2, err := f.seal.SealNow()
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			before, err := f.verifier.VerifyContentBySeq(cp1.Seq, cp2.Seq)
			if err != nil {
				t.Fatal(err)
			}
			for _, iv := range before.Intervals {
				if iv.Status != IntervalStatusPassed || len(iv.InvalidHMACIDs) != 0 {
					t.Fatalf("竄改前 seq=%d 狀態 %s、不符 %v：前提不成立", iv.Seq, iv.Status, iv.InvalidHMACIDs)
				}
			}
			victim := first[1]
			f.mustExec(t, tc.sql, victim)
			// 檢查點聚合只含列的識別、金鑰版本與完整性驗證碼：鏈仍通過，內容竄改由逐列驗證承擔
			after, err := f.verifier.VerifyContentBySeq(cp1.Seq, cp2.Seq)
			if err != nil {
				t.Fatal(err)
			}
			for _, iv := range after.Intervals {
				if iv.Status != IntervalStatusPassed {
					t.Fatalf("seq=%d 鏈狀態 %s：改內容欄不動聚合輸入", iv.Seq, iv.Status)
				}
			}
			rep, err := f.integrity.VerifyIDRange(f.db, cp1.IDFrom, cp2.IDTo)
			if err != nil {
				t.Fatal(err)
			}
			if rep.Mismatched != 1 || len(rep.MismatchedIDs) != 1 || rep.MismatchedIDs[0] != victim {
				t.Fatalf("跨兩個檢查點的逐列驗證指認 = %v, want [%d]（第二個檢查點的列 %v 不受影響）", rep.MismatchedIDs, victim, second)
			}
			if rep.Passed != int64(len(first)+len(second)-1) {
				t.Fatalf("通過 %d 列, want %d", rep.Passed, len(first)+len(second)-1)
			}
		})
	}
}
