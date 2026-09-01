package offsite

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"

	"github.com/custodexa/backend/internal/modules/keyvault"
	"gorm.io/gorm"
)

// 離機儲存設定服務（含第二輪審查修訂）的行為層驗收。

// captureLog 攔截 operational log，供「憑證與端點值不進日誌」的 grep 斷言。
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	orig := log.Writer()
	flags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(orig)
		log.SetFlags(flags)
	})
	return &buf
}

// ── 互斥鎖 ──────────────────────────────────────────────────────────────

// TestOffsiteProfileLockKeyDistinct advisory lock key 撞號守衛
// （沿 TestLDAPDirectoryLockKeyDistinct 的先例）。
//
// **本包只比對得到 keyvault 與 database 兩把**：identity 的兩把在此不可見——
// `internal/offsite` 的測試若 import identity，會構成 identity → audit → offsite
// 的測試期 import cycle（audit import offsite 以排入證據包）。
// 五把的完整兩兩比對置於組裝根的 `TestInstanceGuardLockKeyDistinct`，
// 沿 `database.InstanceGuardLockKey` 的既有先例（infra 不得反向 import keyvault，
// 故該守衛本來就住在那裡）。本處保留的是**值本身**與 keyspace 登記的釘子。
func TestOffsiteProfileLockKeyDistinct(t *testing.T) {
	keys := []struct {
		name string
		key  int64
	}{
		{"keyvault.KEKDataKeysLockKey", keyvault.KEKDataKeysLockKey},
		{"database.InstanceGuardLockKey", database.InstanceGuardLockKey},
		{"offsite.OffsiteProfileLockKey", OffsiteProfileLockKey},
	}
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[i].key == keys[j].key {
				t.Fatalf("advisory lock key 撞號：%s 與 %s 同為 %#x",
					keys[i].name, keys[j].name, keys[i].key)
			}
		}
	}
	if OffsiteProfileLockKey != 0x6F74_6B65_6B00_0005 {
		t.Fatalf("OffsiteProfileLockKey=%#x，登記值為 0x6F74_6B65_6B00_0005",
			OffsiteProfileLockKey)
	}
	// keyspace 登記處必須有 0x0005 一行——該檔明文要求「新增 advisory lock
	// 一律在此檔登記」，漏登的症狀是下一個人取到同一個號而兩個子系統無謂互斥
	reg := readRepoFile(t, "internal", "modules", "keyvault", "key_manager_lock.go")
	if !strings.Contains(reg, "0x0005") || !strings.Contains(reg, "OffsiteProfileLockKey") {
		t.Fatal("key_manager_lock.go 的 keyspace 登記清單缺 0x0005（OffsiteProfileLockKey）一行")
	}
}

// ── Save：驗證核心與落點變更拒沿用 ────────────────────────────────────

// TestOffsiteProfileServiceSaveCreatesFirstGeneration 首次設定。
func TestOffsiteProfileServiceSaveCreatesFirstGeneration(t *testing.T) {
	rig := newOffsiteRig(t)
	res := mustSave(t, rig, s3Settings("evidence"))

	if res.View.GenerationID == 0 {
		t.Fatal("首次儲存應建立一個世代")
	}
	if got := currentCount(t, rig.db); got != 1 {
		t.Fatalf("現行世代數 = %d, want 1", got)
	}
	row := profileRow(t, rig.db, res.View.GenerationID)
	if row.CredentialMode != model.OffsiteCredentialStored {
		t.Fatalf("credential_mode = %q, want stored", row.CredentialMode)
	}
	if row.CredentialsEnc == "" || strings.Contains(row.CredentialsEnc, "s3cr3t-example-value") {
		t.Fatalf("憑證未加密落庫（密文=%q）", row.CredentialsEnc)
	}
	// write-only：讀取視圖恆不含憑證與其遮罩
	view, err := rig.svc.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !view.HasCredentials || view.Configured != true || view.Disabled {
		t.Fatalf("Get 視圖不正確: %+v", view)
	}
	// 端點顯示形態只印 origin，不含 path
	if view.EndpointOrigin != "https://minio.example.internal:9000" {
		t.Fatalf("EndpointOrigin = %q", view.EndpointOrigin)
	}
	// codec 的 AAD 身分必須是本欄
	refs := rig.codec.Refs()
	if len(refs) == 0 || refs[0] != keyvault.RefOffsiteCredentials {
		t.Fatalf("codec 呼叫的 CipherRef = %+v, want %+v", refs, keyvault.RefOffsiteCredentials)
	}
}

// TestOffsiteSaveRejectsCredentialReuseOnEndpointChange 落點變更拒絕沿用既存憑證。
//
// provider／端點／bucket **各一格**：三者任一變更都會讓既存憑證被送往新位址。
func TestOffsiteSaveRejectsCredentialReuseOnEndpointChange(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(in *SettingsInput)
	}{
		{"provider 變更", func(in *SettingsInput) {
			in.Provider = ProviderGCS
			in.Region = ""
		}},
		{"端點變更", func(in *SettingsInput) { in.Endpoint = "https://other.example.internal:9000" }},
		{"bucket 變更", func(in *SettingsInput) { in.Bucket = "another-bucket" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rig := newOffsiteRig(t)
			mustSave(t, rig, s3Settings("evidence"))

			next := s3Settings("evidence")
			next.AccessKeyID, next.SecretAccessKey = "", "" // 憑證欄留空＝沿用
			tc.mutate(&next)

			_, err := rig.svc.Save(context.Background(), next, OffsiteActor{ID: 1})
			if got := ReasonOf(err); got != ReasonCredentialReuseOnMove {
				t.Fatalf("拒因 = %q, want %q（err=%v）", got, ReasonCredentialReuseOnMove, err)
			}
			if n := currentCount(t, rig.db); n != 1 {
				t.Fatalf("被拒後現行世代數 = %d, want 1（拒絕路徑不得留下寫入）", n)
			}
		})
	}

	// 對照組：**只改 prefix／region**（不改落點）時沿用成立——
	// 規則寫太寬會讓正常的前綴調整每次都要重輸憑證
	t.Run("只改 prefix 不觸發", func(t *testing.T) {
		rig := newOffsiteRig(t)
		first := mustSave(t, rig, s3Settings("evidence"))
		next := s3Settings("evidence")
		next.AccessKeyID, next.SecretAccessKey = "", ""
		next.Prefix = "custodexa/v2"
		res := mustSave(t, rig, next)
		if res.View.GenerationID == first.View.GenerationID {
			t.Fatal("prefix 進指紋，改它應建立新世代")
		}
		row := profileRow(t, rig.db, res.View.GenerationID)
		if row.CredentialMode != model.OffsiteCredentialStored || row.CredentialsEnc == "" {
			t.Fatalf("同落點的新世代應沿用既存憑證，實得 mode=%q enc空=%v",
				row.CredentialMode, row.CredentialsEnc == "")
		}
	})

	// 對照組：既存世代**沒有**憑證時不套此規則（那時根本沒有憑證可被沿用）
	t.Run("既存無憑證時不套規則", func(t *testing.T) {
		rig := newOffsiteRig(t)
		base := s3Settings("evidence")
		base.AccessKeyID, base.SecretAccessKey = "", ""
		base.ClearCredentials = true
		mustSave(t, rig, base)

		next := s3Settings("moved")
		next.AccessKeyID, next.SecretAccessKey = "", ""
		if _, err := rig.svc.Save(context.Background(), next, OffsiteActor{ID: 1}); err != nil {
			t.Fatalf("既存為 default_chain 時換 bucket 不應被拒: %v", err)
		}
	})
}

// TestOffsiteProfileServiceRejectsCredentialConflict 同時給新憑證與清除旗標。
func TestOffsiteProfileServiceRejectsCredentialConflict(t *testing.T) {
	rig := newOffsiteRig(t)
	in := s3Settings("evidence")
	in.ClearCredentials = true
	_, err := rig.svc.Save(context.Background(), in, OffsiteActor{ID: 1})
	if got := ReasonOf(err); got != ReasonCredentialConflict {
		t.Fatalf("拒因 = %q, want %q（err=%v）", got, ReasonCredentialConflict, err)
	}
	if n := currentCount(t, rig.db); n != 0 {
		t.Fatalf("被拒後應零寫入，現行世代數 = %d", n)
	}
}

// TestOffsiteProfileServiceRejectsEndpointWithSecrets 端點三成分各一格，
// 且**錯誤訊息與日誌 grep 不到值**（被拒的三個成分正是秘密的藏身處）。
func TestOffsiteProfileServiceRejectsEndpointWithSecrets(t *testing.T) {
	const secret = "AKIALEAKEDVALUE"
	for _, tc := range []struct {
		name, endpoint, detail string
	}{
		{"userinfo", "https://" + secret + ":pw@minio.example.internal:9000", string(EndpointRejectUserinfo)},
		{"query", "https://minio.example.internal:9000/?X-Amz-Token=" + secret, string(EndpointRejectQuery)},
		{"fragment", "https://minio.example.internal:9000/#" + secret, string(EndpointRejectFragment)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureLog(t)
			rig := newOffsiteRig(t)
			in := s3Settings("evidence")
			in.Endpoint = tc.endpoint

			_, err := rig.svc.Save(context.Background(), in, OffsiteActor{ID: 1})
			if got := ReasonOf(err); got != ReasonEndpointHasSecrets {
				t.Fatalf("拒因 = %q, want %q（err=%v）", got, ReasonEndpointHasSecrets, err)
			}
			var se *SettingsError
			if errors.As(err, &se) && se.Detail != tc.detail {
				t.Fatalf("次級原因 = %q, want %q", se.Detail, tc.detail)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("錯誤訊息回顯了被拒端點的值: %s", err.Error())
			}
			if strings.Contains(buf.String(), secret) {
				t.Fatalf("operational log 出現被拒端點的值: %s", buf.String())
			}
		})
	}
	// 對照組：合法端點（含 path）通過，且 path 只入指紋、不進顯示面
	t.Run("含 path 的端點合法且顯示面只印 origin", func(t *testing.T) {
		rig := newOffsiteRig(t)
		in := s3Settings("evidence")
		in.Endpoint = "https://gw.example.internal/minio-prefix"
		res := mustSave(t, rig, in)
		if res.View.EndpointOrigin != "https://gw.example.internal" {
			t.Fatalf("顯示面 origin = %q（不得含 path）", res.View.EndpointOrigin)
		}
		row := profileRow(t, rig.db, res.View.GenerationID)
		if row.Endpoint != "https://gw.example.internal/minio-prefix" {
			t.Fatalf("落庫端點應為完整正規化含 path，實得 %q", row.Endpoint)
		}
	})
}

// TestOffsiteProfileServiceRejectsInvalidInputs 驗證核心的其餘拒因各一格。
func TestOffsiteProfileServiceRejectsInvalidInputs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		in     SettingsInput
		reason string
	}{
		{"provider 枚舉", SettingsInput{Provider: "azure", Bucket: "b"}, ReasonProviderInvalid},
		{"bucket 必填", SettingsInput{Provider: ProviderS3, Region: "us-east-1"}, ReasonBucketRequired},
		{"s3 端點與 region 皆空", SettingsInput{Provider: ProviderS3, Bucket: "b"}, ReasonRegionOrEndpointRequired},
		{"憑證半套", SettingsInput{Provider: ProviderS3, Bucket: "b", Region: "us-east-1",
			AccessKeyID: "only-id"}, ReasonCredentialHalfSet},
		{"端點非 URL", SettingsInput{Provider: ProviderS3, Bucket: "b", Endpoint: "ftp://h/"},
			ReasonEndpointInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rig := newOffsiteRig(t)
			_, err := rig.svc.Save(context.Background(), tc.in, OffsiteActor{ID: 1})
			if got := ReasonOf(err); got != tc.reason {
				t.Fatalf("拒因 = %q, want %q（err=%v）", got, tc.reason, err)
			}
		})
	}
}

// TestOffsiteEncryptErrorIsStaticSentinel 加密失敗回**靜態哨兵**，
// 且 `err.Error()` grep 不到明文片段（codec 的錯誤刻意夾帶明文）。
func TestOffsiteEncryptErrorIsStaticSentinel(t *testing.T) {
	buf := captureLog(t)
	rig := newOffsiteRig(t)
	rig.codec.encFail = errors.New("injected")

	_, err := rig.svc.Save(context.Background(), s3Settings("evidence"), OffsiteActor{ID: 1})
	if got := ReasonOf(err); got != ReasonEncryptFailed {
		t.Fatalf("拒因 = %q, want %q（err=%v）", got, ReasonEncryptFailed, err)
	}
	var se *SettingsError
	if !errors.As(err, &se) {
		t.Fatalf("錯誤不是 *SettingsError: %T", err)
	}
	for _, frag := range []string{"s3cr3t-example-value", "AKIAEXAMPLEKEY", "plaintext_fragment"} {
		if strings.Contains(err.Error(), frag) {
			t.Fatalf("錯誤鏈夾帶明文片段 %q: %s", frag, err.Error())
		}
		if strings.Contains(buf.String(), frag) {
			t.Fatalf("operational log 夾帶明文片段 %q: %s", frag, buf.String())
		}
	}
	if n := currentCount(t, rig.db); n != 0 {
		t.Fatalf("加密失敗後應零寫入，現行世代數 = %d", n)
	}
}

// TestOffsiteProfileServiceAuditPayloadHasNoCredentials 同事務審計的具名事實投影。
func TestOffsiteProfileServiceAuditPayloadHasNoCredentials(t *testing.T) {
	rig := newOffsiteRig(t)
	mustSave(t, rig, s3Settings("evidence"))

	events := rig.journal.all()
	if len(events) == 0 {
		t.Fatal("儲存未寫任何保管鏈事件")
	}
	var save *CustodyEvent
	for i := range events {
		if events[i].Details["event"] == "offsite_settings_create" {
			save = &events[i]
		}
	}
	if save == nil {
		t.Fatalf("找不到 offsite_settings_create 事件（實得 %v）", rig.journal.actions())
	}
	for _, key := range []string{"generation_id", "profile_fingerprint", "provider",
		"endpoint_origin", "bucket", "credential_mode", "has_credentials", "credentials_cleared"} {
		if _, ok := save.Details[key]; !ok {
			t.Errorf("審計負載缺欄位 %q", key)
		}
	}
	dump := formatDetails(save.Details)
	for _, frag := range []string{"s3cr3t-example-value", "AKIAEXAMPLEKEY", "encfake:"} {
		if strings.Contains(dump, frag) {
			t.Fatalf("審計負載夾帶憑證或密文片段 %q: %s", frag, dump)
		}
	}
	// 端點只記 origin，不含 path（path 不顯示、不入日誌、不入審計）
	if got, _ := save.Details["endpoint_origin"].(string); got != "https://minio.example.internal:9000" {
		t.Fatalf("審計的端點欄 = %q，應為不含 path 的 canonical origin", got)
	}
}

// TestOffsiteSaveAuditFailureRollsBackRow 審計失敗即整筆回滾
// （沿 TestLDAPSeedAuditFailureRollsBackRowAndMarker 的形態）。
func TestOffsiteSaveAuditFailureRollsBackRow(t *testing.T) {
	rig := newOffsiteRig(t)
	rig.journal.failInTx = errors.New("審計落地面暫時不可寫")

	_, err := rig.svc.Save(context.Background(), s3Settings("evidence"), OffsiteActor{ID: 1})
	if err == nil {
		t.Fatal("審計失敗時儲存應失敗")
	}
	var total int64
	if err := rig.db.Model(&model.OffsiteProfile{}).Count(&total).Error; err != nil {
		t.Fatalf("計數失敗: %v", err)
	}
	if total != 0 {
		t.Fatalf("審計失敗後仍留下 %d 列設定：離機落點被建立卻無審計紀錄不是可接受的終局", total)
	}
}

// ── 世代切換確認流程 ──────────────────────────────────────────────────

// TestOffsiteProfileServiceNeedsConfirmationWhenLedgerHasObjects
// 指紋不同且帳冊有存量 → 回「需確認」**且不做任何寫入**。
func TestOffsiteProfileServiceNeedsConfirmationWhenLedgerHasObjects(t *testing.T) {
	rig := newOffsiteRig(t)
	first := mustSave(t, rig, s3Settings("evidence"))
	seedObject(t, rig.db, first.View.GenerationID, 1, StateUploaded)

	next := s3Settings("evidence-v2")
	res, err := rig.svc.Save(context.Background(), next, OffsiteActor{ID: 1})
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if !res.NeedsConfirmation {
		t.Fatal("帳冊有存量物件時換落點應回「需確認」")
	}
	if res.ObjectCount != 1 {
		t.Fatalf("受影響物件數 = %d, want 1", res.ObjectCount)
	}
	if res.ExpectedCurrentGenerationID != first.View.GenerationID {
		t.Fatalf("expected_current_generation_id = %d, want %d",
			res.ExpectedCurrentGenerationID, first.View.GenerationID)
	}
	if res.SettingsDigest == "" {
		t.Fatal("需確認回應缺 settings digest")
	}
	// **確認前零變更**
	var total int64
	rig.db.Model(&model.OffsiteProfile{}).Count(&total)
	if total != 1 {
		t.Fatalf("需確認回應不得寫入，設定世代數 = %d", total)
	}
	if row := profileRow(t, rig.db, first.View.GenerationID); row.RetiredAt != nil {
		t.Fatal("需確認回應不得退役現行世代")
	}
}

// TestOffsiteConfirmCompletesFourStepsInOneTransaction
// 確認後同交易四件事齊全：舊列退役、新列建立並 activate、帳冊該批轉 foreign、審計。
func TestOffsiteConfirmCompletesFourStepsInOneTransaction(t *testing.T) {
	rig := newOffsiteRig(t)
	first := mustSave(t, rig, s3Settings("evidence"))
	obj := seedObject(t, rig.db, first.View.GenerationID, 1, StateUploaded)
	pending := seedObject(t, rig.db, first.View.GenerationID, 2, StatePending)

	next := s3Settings("evidence-v2")
	res, err := rig.svc.Save(context.Background(), next, OffsiteActor{ID: 1})
	if err != nil || !res.NeedsConfirmation {
		t.Fatalf("預期需確認，實得 err=%v res=%+v", err, res)
	}
	view, err := rig.svc.ConfirmGenerationSwitch(context.Background(), ConfirmRequest{
		Settings:                    next,
		ExpectedCurrentGenerationID: res.ExpectedCurrentGenerationID,
		SettingsDigest:              res.SettingsDigest,
	}, OffsiteActor{ID: 1})
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}

	// (1) 舊列退役 (2) 新列現行
	if old := profileRow(t, rig.db, first.View.GenerationID); old.RetiredAt == nil {
		t.Error("舊世代未退役")
	}
	if n := currentCount(t, rig.db); n != 1 {
		t.Errorf("現行世代數 = %d, want 1", n)
	}
	if view.GenerationID == first.View.GenerationID {
		t.Error("確認後應建立新世代（generation_id 不可重用）")
	}
	if row := profileRow(t, rig.db, view.GenerationID); row.ActivatedAt.IsZero() {
		t.Error("新世代未 activate")
	}
	// (3) 帳冊該批轉 foreign
	for _, id := range []uint{obj.ID, pending.ID} {
		var row model.OffsiteObject
		if err := rig.db.Where("id = ?", id).First(&row).Error; err != nil {
			t.Fatalf("讀取帳冊列失敗: %v", err)
		}
		if row.State != StateForeign {
			t.Errorf("帳冊列 %d state = %q, want foreign", id, row.State)
		}
	}
	// (4) 保管鏈事件（含 never_uploaded_count：那批 pending 從未離機）
	var profileEvent *CustodyEvent
	for _, ev := range rig.journal.all() {
		if ev.Action == CustodyActionProfile && ev.Details["new_generation_id"] != nil {
			e := ev
			profileEvent = &e
		}
	}
	if profileEvent == nil {
		t.Fatalf("缺世代切換的保管鏈事件（實得 %v）", rig.journal.actions())
	}
	if got := profileEvent.Details["never_uploaded_count"]; got != int64(1) {
		t.Errorf("never_uploaded_count = %v, want 1（pending 者從未離機，不註記即黑洞）", got)
	}
}

// TestOffsiteConfirmMidFlightFailureLeavesNoResidue 中途失敗零殘留。
func TestOffsiteConfirmMidFlightFailureLeavesNoResidue(t *testing.T) {
	rig := newOffsiteRig(t)
	first := mustSave(t, rig, s3Settings("evidence"))
	obj := seedObject(t, rig.db, first.View.GenerationID, 1, StateUploaded)

	next := s3Settings("evidence-v2")
	res, _ := rig.svc.Save(context.Background(), next, OffsiteActor{ID: 1})
	rig.journal.failInTx = errors.New("審計落地面暫時不可寫")

	_, err := rig.svc.ConfirmGenerationSwitch(context.Background(), ConfirmRequest{
		Settings:                    next,
		ExpectedCurrentGenerationID: res.ExpectedCurrentGenerationID,
		SettingsDigest:              res.SettingsDigest,
	}, OffsiteActor{ID: 1})
	if err == nil {
		t.Fatal("審計失敗時確認應失敗")
	}
	var total int64
	rig.db.Model(&model.OffsiteProfile{}).Count(&total)
	if total != 1 {
		t.Errorf("設定世代數 = %d, want 1（新列不得殘留）", total)
	}
	if row := profileRow(t, rig.db, first.View.GenerationID); row.RetiredAt != nil {
		t.Error("舊世代不得殘留退役標記")
	}
	var ledgerRow model.OffsiteObject
	rig.db.Where("id = ?", obj.ID).First(&ledgerRow)
	if ledgerRow.State != StateUploaded {
		t.Errorf("帳冊列 state = %q, want uploaded（不得殘留 foreign）", ledgerRow.State)
	}
}

// TestOffsiteStaleConfirmationRejected 乙先切換、甲以舊 expected 送出 → 靜態拒因，
// 設定表不變，且**回應不回顯現行設定的任何細節**。
func TestOffsiteStaleConfirmationRejected(t *testing.T) {
	rig := newOffsiteRig(t)
	first := mustSave(t, rig, s3Settings("evidence"))
	seedObject(t, rig.db, first.View.GenerationID, 1, StateUploaded)

	// 甲讀到的狀態
	nextA := s3Settings("evidence-a")
	resA, _ := rig.svc.Save(context.Background(), nextA, OffsiteActor{ID: 1})

	// 乙先完成一次切換
	nextB := s3Settings("evidence-b")
	resB, _ := rig.svc.Save(context.Background(), nextB, OffsiteActor{ID: 2})
	if _, err := rig.svc.ConfirmGenerationSwitch(context.Background(), ConfirmRequest{
		Settings:                    nextB,
		ExpectedCurrentGenerationID: resB.ExpectedCurrentGenerationID,
		SettingsDigest:              resB.SettingsDigest,
	}, OffsiteActor{ID: 2}); err != nil {
		t.Fatalf("乙的確認應成立: %v", err)
	}
	before := currentGenerationID(t, rig)

	// 甲以過期的 expected 送出
	_, err := rig.svc.ConfirmGenerationSwitch(context.Background(), ConfirmRequest{
		Settings:                    nextA,
		ExpectedCurrentGenerationID: resA.ExpectedCurrentGenerationID,
		SettingsDigest:              resA.SettingsDigest,
	}, OffsiteActor{ID: 1})
	if got := ReasonOf(err); got != ReasonStaleConfirmation {
		t.Fatalf("拒因 = %q, want %q（err=%v）", got, ReasonStaleConfirmation, err)
	}
	if after := currentGenerationID(t, rig); after != before {
		t.Fatalf("過期確認改動了現行世代（%d → %d）", before, after)
	}
	// 訊息不得回顯現行設定細節
	for _, frag := range []string{"evidence-b", "minio.example.internal"} {
		if strings.Contains(err.Error(), frag) {
			t.Fatalf("過期確認的訊息回顯了現行設定 %q: %s", frag, err.Error())
		}
	}
}

// TestOffsiteConfirmDigestMismatchRejected 攜回 digest 與請求體設定不符 → 拒。
//
// 防的是「確認畫面顯示 A、送出的卻是 B」——CAS 只綁現行世代，擋不住這一格。
func TestOffsiteConfirmDigestMismatchRejected(t *testing.T) {
	rig := newOffsiteRig(t)
	first := mustSave(t, rig, s3Settings("evidence"))
	seedObject(t, rig.db, first.View.GenerationID, 1, StateUploaded)

	shown := s3Settings("evidence-shown")
	res, _ := rig.svc.Save(context.Background(), shown, OffsiteActor{ID: 1})

	sent := s3Settings("evidence-actually-sent")
	_, err := rig.svc.ConfirmGenerationSwitch(context.Background(), ConfirmRequest{
		Settings:                    sent,
		ExpectedCurrentGenerationID: res.ExpectedCurrentGenerationID,
		SettingsDigest:              res.SettingsDigest, // 畫面上那一份的摘要
	}, OffsiteActor{ID: 1})
	if got := ReasonOf(err); got != ReasonDigestMismatch {
		t.Fatalf("拒因 = %q, want %q（err=%v）", got, ReasonDigestMismatch, err)
	}
	if n := currentGenerationID(t, rig); n != first.View.GenerationID {
		t.Fatal("digest 不符時不得寫入")
	}
}

// TestOffsiteConfirmEndpointRevalidatesAllInputs 略過 Save 直呼 confirm，
// 端點含 query／bucket 空／落點變更而憑證留空 **各一格皆被拒**。
//
// 這一格證明的是：「先 Save 被拒、再直接打 confirm 端點」不是繞過路徑。
func TestOffsiteConfirmEndpointRevalidatesAllInputs(t *testing.T) {
	base := func(t *testing.T) (*offsiteTestRig, uint) {
		rig := newOffsiteRig(t)
		first := mustSave(t, rig, s3Settings("evidence"))
		seedObject(t, rig.db, first.View.GenerationID, 1, StateUploaded)
		return rig, first.View.GenerationID
	}
	for _, tc := range []struct {
		name   string
		build  func() SettingsInput
		reason string
	}{
		{"端點含 query", func() SettingsInput {
			in := s3Settings("evidence-v2")
			in.Endpoint = "https://minio.example.internal:9000/?X-Amz-Token=leak"
			return in
		}, ReasonEndpointHasSecrets},
		{"bucket 空", func() SettingsInput {
			in := s3Settings("evidence-v2")
			in.Bucket = ""
			return in
		}, ReasonBucketRequired},
		{"落點變更而憑證留空", func() SettingsInput {
			in := s3Settings("evidence-v2")
			in.AccessKeyID, in.SecretAccessKey = "", ""
			return in
		}, ReasonCredentialReuseOnMove},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rig, genID := base(t)
			in := tc.build()
			// 直呼 confirm：digest 由**請求體自己**算出（模擬繞過者能算對 digest 的最壞情況）
			norm, nerr := validateAndNormalizeOffsiteSettings(in)
			digest := ""
			if nerr == nil {
				digest = norm.settingsDigest()
			}
			_, err := rig.svc.ConfirmGenerationSwitch(context.Background(), ConfirmRequest{
				Settings:                    in,
				ExpectedCurrentGenerationID: genID,
				SettingsDigest:              digest,
			}, OffsiteActor{ID: 1})
			if got := ReasonOf(err); got != tc.reason {
				t.Fatalf("拒因 = %q, want %q（err=%v）", got, tc.reason, err)
			}
			if n := currentGenerationID(t, rig); n != genID {
				t.Fatal("被拒的確認不得寫入")
			}
		})
	}
}

// TestOffsiteConfirmUsesSharedValidationCore AST 守衛：confirm 路徑**必須**呼叫
// 共用驗證核心。
//
// 行為測試證明「目前的 confirm 有驗」；本守衛證明「日後也不會有人替它開簡化路徑」
// ——兩者缺一都留下缺口（行為測試只能覆蓋列舉得出的輸入）。
func TestOffsiteConfirmUsesSharedValidationCore(t *testing.T) {
	const coreFn = "validateAndNormalizeOffsiteSettings"
	fset := token.NewFileSet()
	path := repoPath(t, "internal", "offsite", "profile_service.go")
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("解析 profile_service.go 失敗: %v", err)
	}
	found := map[string]bool{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if fn.Name.Name != "Save" && fn.Name.Name != "ConfirmGenerationSwitch" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == coreFn {
				found[fn.Name.Name] = true
			}
			return true
		})
	}
	for _, name := range []string{"Save", "ConfirmGenerationSwitch"} {
		if !found[name] {
			t.Errorf("%s 未呼叫共用驗證核心 %s：\n"+
				"confirm 若有自己的簡化路徑，「先 Save 被拒、再直接打 confirm 端點」"+
				"就是一條真正的繞過路徑（confirm 收的是完整的新設定）", name, coreFn)
		}
	}
}

// TestOffsiteConcurrentConfirmKeepsSingleCurrentGeneration 並發確認。
//
// 以 pre-write hook 製造**確定性**交錯（不靠時間競賽）：甲進到鎖內、寫入之前暫停，
// 乙在此期間嘗試確認。乙必然拿不到鎖（try 語義）；甲完成後乙以原本的 expected 重試，
// 必因 CAS 失敗被拒。**任何交錯後 `retired_at IS NULL` 恆 ≤ 1 列**。
func TestOffsiteConcurrentConfirmKeepsSingleCurrentGeneration(t *testing.T) {
	rig := newOffsiteRig(t)
	first := mustSave(t, rig, s3Settings("evidence"))
	seedObject(t, rig.db, first.View.GenerationID, 1, StateUploaded)

	nextA := s3Settings("evidence-a")
	resA, _ := rig.svc.Save(context.Background(), nextA, OffsiteActor{ID: 1})
	nextB := s3Settings("evidence-b")
	resB, _ := rig.svc.Save(context.Background(), nextB, OffsiteActor{ID: 2})

	inLock := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	offsiteProfilePreWriteHook = func() {
		once.Do(func() {
			close(inLock)
			<-release
		})
	}

	var (
		wg    sync.WaitGroup
		errA  error
		errB  error
		bBusy bool
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, errA = rig.svc.ConfirmGenerationSwitch(context.Background(), ConfirmRequest{
			Settings:                    nextA,
			ExpectedCurrentGenerationID: resA.ExpectedCurrentGenerationID,
			SettingsDigest:              resA.SettingsDigest,
		}, OffsiteActor{ID: 1})
	}()

	<-inLock
	// 交錯點：甲仍在鎖內、交易未提交。
	//
	// **此處刻意不查資料庫**：測試庫是 sqlite `:memory:` 且連線池限一條
	// （見 newOffsiteDB 的註解），甲的交易正持著那條連線，任何查詢都會死等。
	// 交錯的證據由「乙在此刻拿不到鎖」與「兩者都結束後恆只有一列現行世代」承擔。
	_, errB = rig.svc.ConfirmGenerationSwitch(context.Background(), ConfirmRequest{
		Settings:                    nextB,
		ExpectedCurrentGenerationID: resB.ExpectedCurrentGenerationID,
		SettingsDigest:              resB.SettingsDigest,
	}, OffsiteActor{ID: 2})
	bBusy = errors.Is(errB, ErrOffsiteProfileBusy)
	close(release)
	wg.Wait()

	if errA != nil {
		t.Fatalf("先到者應成立: %v", errA)
	}
	if errB == nil {
		t.Fatal("後到者不應成立（鎖或 CAS 缺一即兩列現行世代）")
	}
	if !bBusy {
		t.Fatalf("後到者的拒絕應為可重試的 Busy，實得 %v", errB)
	}
	// 乙重試：此時鎖已釋放，改由 CAS 擋下
	_, retry := rig.svc.ConfirmGenerationSwitch(context.Background(), ConfirmRequest{
		Settings:                    nextB,
		ExpectedCurrentGenerationID: resB.ExpectedCurrentGenerationID,
		SettingsDigest:              resB.SettingsDigest,
	}, OffsiteActor{ID: 2})
	if got := ReasonOf(retry); got != ReasonStaleConfirmation {
		t.Fatalf("重試的拒因 = %q, want %q（err=%v）", got, ReasonStaleConfirmation, retry)
	}
	if n := currentCount(t, rig.db); n != 1 {
		t.Fatalf("任何交錯後現行世代數 = %d, want 1", n)
	}
}

// TestOffsiteSwitchBackToIdenticalSettingsCreatesThirdGeneration
// A→B→A：三列、generation_id 互異、第一與第三**指紋相同**、各自憑證獨立，
// 撤銷第一不影響第三。
//
// 這一格正是「主鍵取 generation_id 而非指紋」的理由本身。
func TestOffsiteSwitchBackToIdenticalSettingsCreatesThirdGeneration(t *testing.T) {
	rig := newOffsiteRig(t)
	genA := mustSave(t, rig, s3Settings("bucket-a")).View
	genB := mustSave(t, rig, s3Settings("bucket-b")).View

	// 切回與第一世代完全相同的連線參數（憑證重新輸入——落點變更拒沿用仍成立）
	backA := s3Settings("bucket-a")
	backA.SecretAccessKey = "rotated-secret-value"
	genC := mustSave(t, rig, backA).View

	ids := map[uint]bool{genA.GenerationID: true, genB.GenerationID: true, genC.GenerationID: true}
	if len(ids) != 3 {
		t.Fatalf("三個世代的 generation_id 應互異，實得 %v", ids)
	}
	rowA := profileRow(t, rig.db, genA.GenerationID)
	rowC := profileRow(t, rig.db, genC.GenerationID)
	if rowA.ProfileFingerprint != rowC.ProfileFingerprint {
		t.Fatalf("相同連線參數的指紋應相同：%q vs %q", rowA.ProfileFingerprint, rowC.ProfileFingerprint)
	}
	if rowA.CredentialsEnc == rowC.CredentialsEnc {
		t.Fatal("第一與第三世代的憑證應各自獨立（離開又回來期間憑證可能已輪替）")
	}
	// 撤銷第一世代不影響第三
	if err := rig.svc.RevokeCredentials(context.Background(), genA.GenerationID, OffsiteActor{ID: 1}); err != nil {
		t.Fatalf("撤銷第一世代失敗: %v", err)
	}
	if got := profileRow(t, rig.db, genC.GenerationID); got.CredentialMode != model.OffsiteCredentialStored ||
		got.CredentialsEnc == "" {
		t.Fatal("撤銷第一世代不得影響第三世代的憑證")
	}
	if _, err := rig.svc.ClientFor(context.Background(), genC.GenerationID); err != nil {
		t.Fatalf("第三世代仍應可建 client: %v", err)
	}
}

// ── 停止離機 ────────────────────────────────────────────────────────────

// TestOffsiteDisableRetiresCurrentWithoutNewGeneration
// 零現行世代、帳冊轉 foreign、never_uploaded 標記、**憑證未被撤銷**。
func TestOffsiteDisableRetiresCurrentWithoutNewGeneration(t *testing.T) {
	rig := newOffsiteRig(t)
	gen := mustSave(t, rig, s3Settings("evidence")).View
	uploaded := seedObject(t, rig.db, gen.GenerationID, 1, StateUploaded)
	pending := seedObject(t, rig.db, gen.GenerationID, 2, StatePending)

	if err := rig.svc.Disable(context.Background(), OffsiteActor{ID: 1}); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if n := currentCount(t, rig.db); n != 0 {
		t.Fatalf("停用後現行世代數 = %d, want 0（零列是合法終局態）", n)
	}
	var total int64
	rig.db.Model(&model.OffsiteProfile{}).Count(&total)
	if total != 1 {
		t.Fatalf("停用**不得建新列**，設定世代數 = %d, want 1", total)
	}
	for _, id := range []uint{uploaded.ID, pending.ID} {
		var row model.OffsiteObject
		rig.db.Where("id = ?", id).First(&row)
		if row.State != StateForeign {
			t.Errorf("帳冊列 %d state = %q, want foreign", id, row.State)
		}
	}
	// **憑證不隨停用撤銷**：歷史取回要用
	row := profileRow(t, rig.db, gen.GenerationID)
	if row.CredentialMode != model.OffsiteCredentialStored || row.CredentialsEnc == "" {
		t.Fatalf("停用不得撤銷憑證，實得 mode=%q enc空=%v", row.CredentialMode, row.CredentialsEnc == "")
	}
	if row.CredentialsClearedAt != nil {
		t.Fatal("停用不得寫 credentials_cleared_at")
	}
	// 保管鏈事件：停止離機無 new_generation_id，且註記從未上傳者
	var ev *CustodyEvent
	for _, e := range rig.journal.all() {
		if e.Action == CustodyActionProfile && e.Details["result"] == "disabled" {
			c := e
			ev = &c
		}
	}
	if ev == nil {
		t.Fatalf("缺停止離機的保管鏈事件（實得 %v）", rig.journal.actions())
	}
	if _, has := ev.Details["new_generation_id"]; has {
		t.Error("停止離機的事件不得帶 new_generation_id")
	}
	if got := ev.Details["never_uploaded_count"]; got != int64(1) {
		t.Errorf("never_uploaded_count = %v, want 1", got)
	}

	// 停用態的讀取視圖：Configured=true 且 Disabled=true（與「從未設定」分立）
	view, err := rig.svc.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !view.Configured || !view.Disabled {
		t.Fatalf("停用態視圖 = %+v，應為 Configured=true, Disabled=true", view)
	}
	// 歷史取回仍可用（憑證在，client 建得起來）
	if _, err := rig.svc.ClientFor(context.Background(), gen.GenerationID); err != nil {
		t.Fatalf("停用態下歷史世代仍應可建 client: %v", err)
	}
	// 停用後可重新設定（partial index 不涵蓋已退役列）
	if _, err := rig.svc.Save(context.Background(), s3Settings("evidence-again"), OffsiteActor{ID: 1}); err != nil {
		t.Fatalf("停用後應可重新設定: %v", err)
	}
}

// TestOffsiteDisableWithoutCurrentGenerationRejected 無現行世代時停用被拒。
func TestOffsiteDisableWithoutCurrentGenerationRejected(t *testing.T) {
	rig := newOffsiteRig(t)
	err := rig.svc.Disable(context.Background(), OffsiteActor{ID: 1})
	if got := ReasonOf(err); got != ReasonNoCurrentGeneration {
		t.Fatalf("拒因 = %q, want %q（err=%v）", got, ReasonNoCurrentGeneration, err)
	}
}

// ── 撤銷憑證 ────────────────────────────────────────────────────────────

// TestOffsiteRevokeClearsCiphertextAndBumpsRevision
// 密文為空、credential_mode='revoked'、credentials_cleared_at 非空、revision +1，
// 且**同交易失敗時三者全回滾**。
func TestOffsiteRevokeClearsCiphertextAndBumpsRevision(t *testing.T) {
	rig := newOffsiteRig(t)
	gen := mustSave(t, rig, s3Settings("evidence")).View
	before := profileRow(t, rig.db, gen.GenerationID)

	// 先驗回滾：審計失敗時三者全不動
	rig.journal.failInTx = errors.New("審計落地面暫時不可寫")
	if err := rig.svc.RevokeCredentials(context.Background(), gen.GenerationID,
		OffsiteActor{ID: 1}); err == nil {
		t.Fatal("審計失敗時撤銷應失敗")
	}
	mid := profileRow(t, rig.db, gen.GenerationID)
	if mid.CredentialsEnc != before.CredentialsEnc || mid.CredentialMode != before.CredentialMode ||
		mid.CredentialRevision != before.CredentialRevision || mid.CredentialsClearedAt != nil {
		t.Fatalf("審計失敗後撤銷未完整回滾: %+v", mid)
	}

	rig.journal.failInTx = nil
	if err := rig.svc.RevokeCredentials(context.Background(), gen.GenerationID,
		OffsiteActor{ID: 1}); err != nil {
		t.Fatalf("RevokeCredentials: %v", err)
	}
	after := profileRow(t, rig.db, gen.GenerationID)
	if after.CredentialsEnc != "" {
		t.Error("撤銷後密文應為空")
	}
	if after.CredentialMode != model.OffsiteCredentialRevoked {
		t.Errorf("credential_mode = %q, want revoked", after.CredentialMode)
	}
	if after.CredentialsClearedAt == nil {
		t.Error("credentials_cleared_at 應非空")
	}
	if after.CredentialRevision != before.CredentialRevision+1 {
		t.Errorf("credential_revision = %d, want %d", after.CredentialRevision, before.CredentialRevision+1)
	}
	// 保管鏈事件不含憑證與端點
	var ev *CustodyEvent
	for _, e := range rig.journal.all() {
		if e.Action == CustodyActionCredRevoke {
			c := e
			ev = &c
		}
	}
	if ev == nil {
		t.Fatalf("缺撤銷憑證的保管鏈事件（實得 %v）", rig.journal.actions())
	}
	dump := formatDetails(ev.Details)
	for _, frag := range []string{"encfake:", "s3cr3t", "minio.example.internal"} {
		if strings.Contains(dump, frag) {
			t.Fatalf("撤銷事件夾帶 %q: %s", frag, dump)
		}
	}
	// 冪等提示：再撤一次是靜態拒因，不是 500
	if got := ReasonOf(rig.svc.RevokeCredentials(context.Background(), gen.GenerationID,
		OffsiteActor{ID: 1})); got != ReasonCredentialsAlreadyRevoked {
		t.Errorf("重複撤銷的拒因 = %q, want %q", got, ReasonCredentialsAlreadyRevoked)
	}
	// 世代查無
	if got := ReasonOf(rig.svc.RevokeCredentials(context.Background(), 99999,
		OffsiteActor{ID: 1})); got != ReasonGenerationNotFound {
		t.Errorf("查無世代的拒因 = %q, want %q", got, ReasonGenerationNotFound)
	}
}

// TestOffsiteRevokedGenerationNeverFallsBackToDefaultChain
// 環境備妥可用預設鏈，仍以 `offsite.foreign_credentials_missing` 失敗，
// **driver 建構計數＝0**。
func TestOffsiteRevokedGenerationNeverFallsBackToDefaultChain(t *testing.T) {
	rig := newOffsiteRig(t)
	gen := mustSave(t, rig, s3Settings("evidence")).View
	if _, err := rig.svc.ClientFor(context.Background(), gen.GenerationID); err != nil {
		t.Fatalf("撤銷前應可建 client: %v", err)
	}
	baseline := rig.factory.count()
	if baseline == 0 {
		t.Fatal("factory 計數器沒動：偵測器失效，「零建構」不構成證據")
	}

	if err := rig.svc.RevokeCredentials(context.Background(), gen.GenerationID,
		OffsiteActor{ID: 1}); err != nil {
		t.Fatalf("RevokeCredentials: %v", err)
	}
	// 「環境備妥可用預設鏈」＝factory 對空憑證也會成功回一個 client。
	// 若實作誤走 default_chain 分支，本呼叫就會成功而計數 +1
	_, err := rig.svc.ClientFor(context.Background(), gen.GenerationID)
	if err == nil {
		t.Fatal("已撤銷的世代不得建出 client（絕不 fallback 預設鏈）")
	}
	if !strings.Contains(err.Error(), ErrCodeForeignCredentialsMissing) {
		t.Fatalf("錯誤應帶機器碼 %s，實得 %v", ErrCodeForeignCredentialsMissing, err)
	}
	for _, want := range []string{"世代", ProviderS3} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("錯誤應指名 %q：%v", want, err)
		}
	}
	if got := rig.factory.count(); got != baseline {
		t.Fatalf("撤銷後 driver 建構計數 = %d, want %d（零建構、零預設鏈探測）", got, baseline)
	}
}

// TestOffsiteClientCacheInvalidatedByCredentialRevision
// 先成功取回使 client 進 cache → 撤銷 → 再取回失敗，斷言 cache 未被沿用。
func TestOffsiteClientCacheInvalidatedByCredentialRevision(t *testing.T) {
	rig := newOffsiteRig(t)
	gen := mustSave(t, rig, s3Settings("evidence")).View

	c1, err := rig.svc.ClientFor(context.Background(), gen.GenerationID)
	if err != nil {
		t.Fatalf("首次建 client: %v", err)
	}
	c2, err := rig.svc.ClientFor(context.Background(), gen.GenerationID)
	if err != nil {
		t.Fatalf("第二次取 client: %v", err)
	}
	if c1 != c2 {
		t.Fatal("同一 revision 下應命中 cache（否則每次上傳都重建連線）")
	}
	if got := rig.factory.count(); got != 1 {
		t.Fatalf("cache 命中時 driver 建構計數 = %d, want 1", got)
	}

	// **不經 service 的撤銷**（模擬另一個行程／重啟後的狀態）：
	// cache 失效不得只靠行程內事件，必須靠每次取用前的 revision 核對
	if err := rig.db.Model(&model.OffsiteProfile{}).
		Where("generation_id = ?", gen.GenerationID).
		Updates(map[string]any{"credential_revision": gen.GenerationID + 100}).Error; err != nil {
		t.Fatalf("直改 revision 失敗: %v", err)
	}
	c3, err := rig.svc.ClientFor(context.Background(), gen.GenerationID)
	if err != nil {
		t.Fatalf("revision 變更後應重建 client: %v", err)
	}
	if c3 == c1 {
		t.Fatal("revision 已變更卻沿用了舊 client：cache 失效只靠行程內事件是不夠的")
	}
	if got := rig.factory.count(); got != 2 {
		t.Fatalf("revision 變更後 driver 建構計數 = %d, want 2", got)
	}
}

// ── ClientFor 的世代匹配與三態 ──────────────────────────────────────────

// TestOffsiteProfileServiceClientForUsesOwnGenerationCredentials
// 跨世代取回：歷史世代用**該列**憑證，不是現行世代的。
func TestOffsiteProfileServiceClientForUsesOwnGenerationCredentials(t *testing.T) {
	rig := newOffsiteRig(t)
	old := mustSave(t, rig, s3Settings("bucket-old")).View

	// 切到 gcs（跨 provider）——歷史物件因此散在不同後端
	next := SettingsInput{
		Provider: ProviderGCS, Bucket: "bucket-new", Prefix: "custodexa",
		ServiceAccountJSON: `{"type":"service_account","client_email":"sa@example.iam"}`,
	}
	current := mustSave(t, rig, next).View

	if _, err := rig.svc.ClientFor(context.Background(), old.GenerationID); err != nil {
		t.Fatalf("歷史世代應可建 client: %v", err)
	}
	spec := rig.factory.lastSpec(t)
	if spec.Provider != ProviderS3 || spec.Bucket != "bucket-old" {
		t.Fatalf("歷史世代的建構參數錯：%+v（不得以現行世代設定取歷史物件）", spec)
	}
	if spec.AccessKeyID != "AKIAEXAMPLEKEY" || spec.SecretAccessKey != "s3cr3t-example-value" {
		t.Fatalf("歷史世代未使用該列自己的憑證：%+v", spec)
	}
	if spec.ServiceAccountJSON != "" {
		t.Fatal("s3 世代不得帶 gcs 憑證")
	}

	if _, err := rig.svc.ClientFor(context.Background(), current.GenerationID); err != nil {
		t.Fatalf("現行世代應可建 client: %v", err)
	}
	spec = rig.factory.lastSpec(t)
	if spec.Provider != ProviderGCS || !strings.Contains(spec.ServiceAccountJSON, "sa@example.iam") {
		t.Fatalf("現行世代的建構參數錯：%+v", spec)
	}
}

// TestOffsiteProfileServiceClientForMissingGeneration 世代查無＝fail-close。
func TestOffsiteProfileServiceClientForMissingGeneration(t *testing.T) {
	rig := newOffsiteRig(t)
	mustSave(t, rig, s3Settings("evidence"))
	_, err := rig.svc.ClientFor(context.Background(), 4242)
	if err == nil || !strings.Contains(err.Error(), ErrCodeProfileMissing) {
		t.Fatalf("世代查無應以 %s fail-close，實得 %v", ErrCodeProfileMissing, err)
	}
	if !strings.Contains(err.Error(), "4242") {
		t.Errorf("訊息應指名對不上的世代：%v", err)
	}
	if rig.factory.count() != 0 {
		t.Fatal("世代查無時不得建構 driver（不退回「用現行設定猜」）")
	}
}

// TestOffsiteProfileServiceCredentialStateThreeWay 三態各一格，
// 且「**解密失敗不呈現為 unconfigured**」單獨一格。
func TestOffsiteProfileServiceCredentialStateThreeWay(t *testing.T) {
	t.Run("unconfigured：無現行世代", func(t *testing.T) {
		rig := newOffsiteRig(t)
		got, err := rig.svc.CredentialState(context.Background())
		if err != nil || got != CredentialStateUnconfigured {
			t.Fatalf("state = %q err = %v, want unconfigured", got, err)
		}
	})
	t.Run("ok：stored 可解", func(t *testing.T) {
		rig := newOffsiteRig(t)
		mustSave(t, rig, s3Settings("evidence"))
		got, err := rig.svc.CredentialState(context.Background())
		if err != nil || got != CredentialStateOK {
			t.Fatalf("state = %q err = %v, want ok", got, err)
		}
	})
	t.Run("ok：刻意走預設鏈", func(t *testing.T) {
		rig := newOffsiteRig(t)
		in := s3Settings("evidence")
		in.AccessKeyID, in.SecretAccessKey = "", ""
		in.ClearCredentials = true
		mustSave(t, rig, in)
		got, _ := rig.svc.CredentialState(context.Background())
		if got != CredentialStateOK {
			t.Fatalf("state = %q, want ok（default_chain 是刻意選擇，不是故障）", got)
		}
	})
	t.Run("failed：解密失敗不得併吞為未設定", func(t *testing.T) {
		rig := newOffsiteRig(t)
		mustSave(t, rig, s3Settings("evidence"))
		rig.codec.decFail = errors.New("KEK 事故")
		got, err := rig.svc.CredentialState(context.Background())
		if got == CredentialStateUnconfigured {
			t.Fatal("解密失敗被呈現為 unconfigured：金鑰事故被偽裝成功能關閉")
		}
		if got != CredentialStateFailed {
			t.Fatalf("state = %q, want failed（err=%v）", got, err)
		}
		if ReasonOf(err) != ReasonDecryptFailed {
			t.Errorf("拒因 = %q, want %q", ReasonOf(err), ReasonDecryptFailed)
		}
	})
}

// TestOffsiteProfileServiceGetDistinguishesNeverConfiguredFromDisabled
// **設定表零列**（從未設定）與**零現行世代**（已停用）兩態分立。
func TestOffsiteProfileServiceGetDistinguishesNeverConfiguredFromDisabled(t *testing.T) {
	rig := newOffsiteRig(t)
	view, err := rig.svc.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if view.Configured || view.Disabled {
		t.Fatalf("設定表零列時應為 Configured=false（從未設定），實得 %+v", view)
	}
	// 帳冊零列＝UI 空狀態的判準
	if n, err := rig.ledger.TotalObjects(); err != nil || n != 0 {
		t.Fatalf("帳冊列數 = %d err = %v", n, err)
	}

	gen := mustSave(t, rig, s3Settings("evidence")).View
	if err := rig.svc.Disable(context.Background(), OffsiteActor{ID: 1}); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	view, _ = rig.svc.Get()
	if !view.Configured || !view.Disabled {
		t.Fatalf("停用態應為 Configured=true, Disabled=true，實得 %+v", view)
	}
	// **EnqueueTx 在兩態下皆回同一個哨兵且零寫入**：兩者對「要不要建新帳冊列」
	// 的答案相同，差異在其他三個面（worker／指標／管理介面）
	err = rig.db.Transaction(func(tx *gorm.DB) error {
		_, _, e := rig.ledger.EnqueueTx(tx, KindRecording, 7, OriginLive)
		return e
	})
	if !errors.Is(err, ErrNoCurrentGeneration) {
		t.Fatalf("停用態下 EnqueueTx 應回 ErrNoCurrentGeneration，實得 %v", err)
	}
	if n, _ := rig.ledger.TotalObjects(); n != 0 {
		t.Fatalf("停用態下 EnqueueTx 不得建列，帳冊列數 = %d", n)
	}
	_ = gen
}

// ── 歷史世代列表 ────────────────────────────────────────────────────────

// TestOffsiteProfileServiceListHistoryCountsObjects 歷史世代列表含物件數與憑證狀態。
func TestOffsiteProfileServiceListHistoryCountsObjects(t *testing.T) {
	rig := newOffsiteRig(t)
	genA := mustSave(t, rig, s3Settings("bucket-a")).View
	genB := mustSave(t, rig, s3Settings("bucket-b")).View
	// **切換之後**才建帳冊列：切換前建會使第二次 Save 回「需確認」
	// （那是另一格測的事，見 TestOffsiteProfileServiceNeedsConfirmationWhenLedgerHasObjects）
	seedObject(t, rig.db, genA.GenerationID, 1, StateUploaded)
	seedObject(t, rig.db, genA.GenerationID, 2, StateUploaded)

	list, err := rig.svc.ListHistory()
	if err != nil {
		t.Fatalf("ListHistory: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("世代數 = %d, want 2", len(list))
	}
	// 新到舊
	if list[0].GenerationID != genB.GenerationID {
		t.Errorf("排序應為新到舊，首列 = %d", list[0].GenerationID)
	}
	for _, v := range list {
		if v.GenerationID == genA.GenerationID {
			if v.ObjectCount != 2 {
				t.Errorf("世代 %d 的物件數 = %d, want 2", v.GenerationID, v.ObjectCount)
			}
			if v.RetiredAt == nil {
				t.Errorf("世代 %d 應已退役", v.GenerationID)
			}
		}
		if v.CredentialMode == "" {
			t.Errorf("世代 %d 缺 credential_mode", v.GenerationID)
		}
	}
}

// ── 輔助 ────────────────────────────────────────────────────────────────

func currentGenerationID(t *testing.T, rig *offsiteTestRig) uint {
	t.Helper()
	var rows []model.OffsiteProfile
	if err := rig.db.Where("retired_at IS NULL").Find(&rows).Error; err != nil {
		t.Fatalf("讀取現行世代失敗: %v", err)
	}
	if len(rows) == 0 {
		return 0
	}
	return rows[0].GenerationID
}

// formatDetails 把審計負載攤平成單行字串，供「grep 不到憑證」的斷言。
func formatDetails(d map[string]any) string {
	var sb strings.Builder
	for k, v := range d {
		sb.WriteString(k)
		sb.WriteString("=")
		sb.WriteString(strings.ReplaceAll(fmt.Sprintf("%v", v), "\n", " "))
		sb.WriteString(" ")
	}
	return sb.String()
}

// repoRootForOffsiteTests 以本檔位置為錨點往上找 module 根（非 cwd、非層數推算）。
func repoRootForOffsiteTests(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("取不到本檔路徑：module 根無從定位")
	}
	dir := filepath.Dir(self)
	for i := 0; i < 10; i++ {
		if b, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
			if strings.Contains(string(b), "module github.com/custodexa/backend") {
				return dir
			}
			t.Fatalf("%s/go.mod 的 module 名不是預期值", dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("往上找不到 go.mod")
	return ""
}

func repoPath(t *testing.T, parts ...string) string {
	t.Helper()
	return filepath.Join(append([]string{repoRootForOffsiteTests(t)}, parts...)...)
}

func readRepoFile(t *testing.T, parts ...string) string {
	t.Helper()
	b, err := os.ReadFile(repoPath(t, parts...))
	if err != nil {
		t.Fatalf("讀取 %v 失敗: %v", parts, err)
	}
	return string(b)
}
