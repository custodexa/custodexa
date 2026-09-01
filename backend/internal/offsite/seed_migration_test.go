package offsite

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// env→DB **初次** seed（`OFFSITE_*` 鍵組降為 seed-only）的驗收。
//
// 六步判定各一格，另加「seed 與還原的五組終局」矩陣——後者的每一格都是真實可達的
// 部署狀態（marker 落 runtime marker 表，隨資料庫備份一起還原）。

// setSeedEnv 設定 s3 的 seed env（t.Setenv 會在測試結束自動還原）。
func setSeedEnv(t *testing.T, bucket string) {
	t.Helper()
	t.Setenv("OFFSITE_PROVIDER", ProviderS3)
	t.Setenv("OFFSITE_S3_BUCKET", bucket)
	t.Setenv("OFFSITE_S3_ENDPOINT", "https://minio.example.internal:9000")
	t.Setenv("OFFSITE_S3_REGION", "us-east-1")
	t.Setenv("OFFSITE_S3_PREFIX", "custodexa")
	t.Setenv("OFFSITE_S3_PATH_STYLE", "true")
	t.Setenv("OFFSITE_S3_ACCESS_KEY_ID", "AKIASEEDEXAMPLE")
	t.Setenv("OFFSITE_S3_SECRET_ACCESS_KEY", "seed-secret-example")
}

// clearSeedEnv 清空全部 seed 鍵（「env 未設定」那一格）。
func clearSeedEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"OFFSITE_PROVIDER", "OFFSITE_S3_BUCKET", "OFFSITE_S3_ENDPOINT", "OFFSITE_S3_REGION",
		"OFFSITE_S3_PREFIX", "OFFSITE_S3_PATH_STYLE", "OFFSITE_S3_ACCESS_KEY_ID",
		"OFFSITE_S3_SECRET_ACCESS_KEY", "OFFSITE_GCS_BUCKET", "OFFSITE_GCS_PREFIX",
		"OFFSITE_GCS_CREDENTIALS_FILE", "OFFSITE_GCS_ENDPOINT",
	} {
		t.Setenv(k, "")
	}
}

func markerWritten(t *testing.T, db *gorm.DB) bool {
	t.Helper()
	var n int64
	if err := db.Table("schema_migrations").
		Where("version = ?", database.OffsiteSeedMarkerVersion).Count(&n).Error; err != nil {
		t.Fatalf("查 marker 失敗: %v", err)
	}
	return n > 0
}

func writeMarker(t *testing.T, db *gorm.DB) {
	t.Helper()
	if err := offsiteSeedWriteMarker(db); err != nil {
		t.Fatalf("寫 marker 失敗: %v", err)
	}
}

func profileCount(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	if err := db.Model(&model.OffsiteProfile{}).Count(&n).Error; err != nil {
		t.Fatalf("計數設定世代失敗: %v", err)
	}
	return n
}

// TestOffsiteSeedTableMissingIsNoOp (1) 表不存在 → no-op、不寫 marker。
//
// 單元測試庫普遍無此表；此格若回 error 會把既有測試的失敗計數斷言打紅，
// 且生產上「表還沒建好」本就不是可記錄的終局。
func TestOffsiteSeedTableMissingIsNoOp(t *testing.T) {
	setSeedEnv(t, "evidence")
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if sqlDB, e := db.DB(); e == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	if err := db.Exec(
		"CREATE TABLE schema_migrations (version varchar(50) PRIMARY KEY, applied_at datetime NOT NULL)").Error; err != nil {
		t.Fatalf("schema_migrations: %v", err)
	}
	if err := RunOffsiteEnvSeed(db, &fakeCodec{}, &recordingJournal{}); err != nil {
		t.Fatalf("表不存在時應 no-op，實得 %v", err)
	}
	if markerWritten(t, db) {
		t.Fatal("表不存在時不得寫 marker（表建好後仍要 seed）")
	}
}

// TestOffsiteSeedEnvDisabledWritesMarker (2) env 未設定 → 寫 marker 返回。
//
// **排在 marker 檢查之前**是刻意的：全新部署首啟即完成評估並留痕，
// 日後 env 被填上也不會回灌。
func TestOffsiteSeedEnvDisabledWritesMarker(t *testing.T) {
	clearSeedEnv(t)
	db := newOffsiteDB(t)
	if err := RunOffsiteEnvSeed(db, &fakeCodec{}, &recordingJournal{}); err != nil {
		t.Fatalf("env 未設定時應成功返回: %v", err)
	}
	if !markerWritten(t, db) {
		t.Fatal("env 未設定時應寫 marker（marker 語義是「已完成評估」而非「已建立資料」）")
	}
	if n := profileCount(t, db); n != 0 {
		t.Fatalf("env 未設定時不得建列，實得 %d", n)
	}
}

// TestOffsiteSeedMarkerWriteIsIdempotent marker 寫入冪等。
//
// 判定順序把「env 未設定 → 寫 marker」排在「marker 已寫 → 返回」之前，
// 故 env 未設定的部署每次啟動都會走到寫入；直接 INSERT 會在第二次啟動撞主鍵，
// 使佇列項每次啟動都記一筆失敗。
func TestOffsiteSeedMarkerWriteIsIdempotent(t *testing.T) {
	clearSeedEnv(t)
	db := newOffsiteDB(t)
	for i := 0; i < 3; i++ {
		if err := RunOffsiteEnvSeed(db, &fakeCodec{}, &recordingJournal{}); err != nil {
			t.Fatalf("第 %d 次執行失敗: %v", i+1, err)
		}
	}
	var n int64
	if err := db.Table("schema_migrations").
		Where("version = ?", database.OffsiteSeedMarkerVersion).Count(&n).Error; err != nil {
		t.Fatalf("查 marker 失敗: %v", err)
	}
	if n != 1 {
		t.Fatalf("marker 列數 = %d, want 1", n)
	}
}

// TestOffsiteSeedEnabledSeedsEncryptedRow (6) 實際 seed：插列＋審計＋marker 同交易。
func TestOffsiteSeedEnabledSeedsEncryptedRow(t *testing.T) {
	setSeedEnv(t, "evidence")
	db := newOffsiteDB(t)
	codec := &fakeCodec{}
	journal := &recordingJournal{}

	if err := RunOffsiteEnvSeed(db, codec, journal); err != nil {
		t.Fatalf("seed 失敗: %v", err)
	}
	if !markerWritten(t, db) {
		t.Fatal("seed 成功後應寫 marker")
	}
	var row model.OffsiteProfile
	if err := db.First(&row).Error; err != nil {
		t.Fatalf("讀取 seed 出的列失敗: %v", err)
	}
	if row.Provider != ProviderS3 || row.Bucket != "evidence" || row.Region != "us-east-1" ||
		!row.PathStyle || row.Prefix != "custodexa" {
		t.Fatalf("seed 出的連線參數不正確: %+v", row)
	}
	if row.Endpoint != "https://minio.example.internal:9000" {
		t.Fatalf("端點應為正規化完整形態，實得 %q", row.Endpoint)
	}
	if row.CredentialMode != model.OffsiteCredentialStored {
		t.Fatalf("credential_mode = %q, want stored", row.CredentialMode)
	}
	// **密文非空且不等於明文**
	if row.CredentialsEnc == "" {
		t.Fatal("credentials_enc 為空")
	}
	for _, frag := range []string{"seed-secret-example", "AKIASEEDEXAMPLE"} {
		if strings.Contains(row.CredentialsEnc, frag) {
			t.Fatalf("credentials_enc 含明文片段 %q", frag)
		}
	}
	if refs := codec.Refs(); len(refs) == 0 || refs[0].Table != "offsite_profiles" ||
		refs[0].Column != "credentials_enc" {
		t.Fatalf("seed 的 CipherRef 不正確: %+v", refs)
	}
	// 審計：source=seed，且不含憑證
	var ev *CustodyEvent
	for _, e := range journal.all() {
		if e.Details["source"] == "seed" {
			c := e
			ev = &c
		}
	}
	if ev == nil {
		t.Fatalf("缺 seed 的審計事件（實得 %v）", journal.actions())
	}
	dump := formatDetails(ev.Details)
	for _, frag := range []string{"seed-secret-example", "AKIASEEDEXAMPLE", "encfake:"} {
		if strings.Contains(dump, frag) {
			t.Fatalf("seed 審計夾帶 %q: %s", frag, dump)
		}
	}
	// **seed 不得產生 revoked**
	if row.CredentialMode == model.OffsiteCredentialRevoked {
		t.Fatal("seed 不得產生 revoked")
	}
}

// TestOffsiteSeedEnabledWithoutCredentialsUsesDefaultChain env 有 bucket 但無憑證。
func TestOffsiteSeedEnabledWithoutCredentialsUsesDefaultChain(t *testing.T) {
	setSeedEnv(t, "evidence")
	t.Setenv("OFFSITE_S3_ACCESS_KEY_ID", "")
	t.Setenv("OFFSITE_S3_SECRET_ACCESS_KEY", "")
	db := newOffsiteDB(t)
	if err := RunOffsiteEnvSeed(db, &fakeCodec{}, &recordingJournal{}); err != nil {
		t.Fatalf("seed 失敗: %v", err)
	}
	var row model.OffsiteProfile
	if err := db.First(&row).Error; err != nil {
		t.Fatalf("讀取失敗: %v", err)
	}
	if row.CredentialMode != model.OffsiteCredentialDefaultChain || row.CredentialsEnc != "" {
		t.Fatalf("無憑證的 seed 應為 default_chain 且密文空，實得 mode=%q enc=%q",
			row.CredentialMode, row.CredentialsEnc)
	}
}

// TestOffsiteSeedSkipsWhenTableNotEmpty (5) 表非空 → 寫 marker 返回、不覆蓋。
func TestOffsiteSeedSkipsWhenTableNotEmpty(t *testing.T) {
	setSeedEnv(t, "from-env")
	rig := newOffsiteRig(t)
	existing := mustSave(t, rig, s3Settings("from-ui")).View

	if err := RunOffsiteEnvSeed(rig.db, rig.codec, rig.journal); err != nil {
		t.Fatalf("seed 失敗: %v", err)
	}
	if !markerWritten(t, rig.db) {
		t.Fatal("表非空時應補寫 marker")
	}
	if n := profileCount(t, rig.db); n != 1 {
		t.Fatalf("表非空時不得建第二列，實得 %d", n)
	}
	if row := profileRow(t, rig.db, existing.GenerationID); row.Bucket != "from-ui" {
		t.Fatalf("seed 覆蓋了既有設定（bucket=%q）", row.Bucket)
	}
}

// TestOffsiteSeedDoesNotRefillAfterHardDelete (4) marker 已寫 → env 不再回灌。
//
// 沒有這條，管理員硬刪設定列後只要 env 仍有值，下次啟動就會**靜默重建**
// 一個離機上傳落點。
func TestOffsiteSeedDoesNotRefillAfterHardDelete(t *testing.T) {
	setSeedEnv(t, "evidence")
	db := newOffsiteDB(t)
	if err := RunOffsiteEnvSeed(db, &fakeCodec{}, &recordingJournal{}); err != nil {
		t.Fatalf("首次 seed 失敗: %v", err)
	}
	if err := db.Exec("DELETE FROM offsite_profiles").Error; err != nil {
		t.Fatalf("硬刪失敗: %v", err)
	}
	if err := RunOffsiteEnvSeed(db, &fakeCodec{}, &recordingJournal{}); err != nil {
		t.Fatalf("第二次 seed 失敗: %v", err)
	}
	if n := profileCount(t, db); n != 0 {
		t.Fatalf("marker 已寫時不得回灌，實得 %d 列", n)
	}
}

// TestOffsiteSeedInfrastructureFailureLeavesNoMarker 基礎設施失敗 → 不寫 marker。
func TestOffsiteSeedInfrastructureFailureLeavesNoMarker(t *testing.T) {
	setSeedEnv(t, "evidence")
	db := newOffsiteDB(t)
	codec := &fakeCodec{encFail: errors.New("KEK 暫時不可用")}

	if err := RunOffsiteEnvSeed(db, codec, &recordingJournal{}); err == nil {
		t.Fatal("加密失敗時 seed 應回錯")
	}
	if markerWritten(t, db) {
		t.Fatal("基礎設施失敗時不得寫 marker（下次啟動要重試）")
	}
	if n := profileCount(t, db); n != 0 {
		t.Fatalf("加密失敗時不得建列，實得 %d", n)
	}

	// codec 缺席（組裝疏漏）同樣是基礎設施失敗
	if err := RunOffsiteEnvSeed(db, nil, &recordingJournal{}); err == nil {
		t.Fatal("codec 為 nil 時 seed 應回錯")
	}
	if markerWritten(t, db) {
		t.Fatal("codec 缺席時不得寫 marker")
	}
}

// TestOffsiteSeedAuditFailureRollsBackRowAndMarker 審計失敗 → 列與 marker 全回滾。
//
// 審計表暫時不可寫時，若設定列與 marker 已提交，一個離機上傳落點就被永久建立而
// **沒有任何審計紀錄**，且 marker 使後續啟動不再補寫。
func TestOffsiteSeedAuditFailureRollsBackRowAndMarker(t *testing.T) {
	setSeedEnv(t, "evidence")
	db := newOffsiteDB(t)
	journal := &recordingJournal{failInTx: errors.New("審計落地面暫時不可寫")}

	if err := RunOffsiteEnvSeed(db, &fakeCodec{}, journal); err == nil {
		t.Fatal("審計失敗時 seed 應回錯")
	}
	if n := profileCount(t, db); n != 0 {
		t.Fatalf("審計失敗後仍留下 %d 列設定", n)
	}
	if markerWritten(t, db) {
		t.Fatal("審計失敗後仍寫了 marker：下次啟動不會補寫，該部署將永久無審計地帶著一個離機落點")
	}
}

// TestOffsiteSeedEnvContradictionLeavesNoMarker (3) env 組態矛盾 →
// 不寫列、不寫 marker、**不拒啟**（回錯由佇列記錄，主服務照常啟動）。
func TestOffsiteSeedEnvContradictionLeavesNoMarker(t *testing.T) {
	for _, tc := range []struct {
		name  string
		apply func(t *testing.T)
	}{
		{"provider 枚舉", func(t *testing.T) { t.Setenv("OFFSITE_PROVIDER", "azure") }},
		{"端點含 query", func(t *testing.T) {
			t.Setenv("OFFSITE_S3_ENDPOINT", "https://minio.example.internal:9000/?X-Amz-Token=leak")
		}},
		{"憑證半套", func(t *testing.T) { t.Setenv("OFFSITE_S3_SECRET_ACCESS_KEY", "") }},
		{"端點與 region 皆空", func(t *testing.T) {
			t.Setenv("OFFSITE_S3_ENDPOINT", "")
			t.Setenv("OFFSITE_S3_REGION", "")
		}},
		{"gcs 憑證檔不可讀", func(t *testing.T) {
			t.Setenv("OFFSITE_PROVIDER", ProviderGCS)
			t.Setenv("OFFSITE_GCS_BUCKET", "evidence")
			t.Setenv("OFFSITE_GCS_CREDENTIALS_FILE", "/nonexistent/sa.json")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setSeedEnv(t, "evidence")
			tc.apply(t)
			db := newOffsiteDB(t)
			err := RunOffsiteEnvSeed(db, &fakeCodec{}, &recordingJournal{})
			if err == nil {
				t.Fatal("env 矛盾時 seed 應回可見錯誤")
			}
			if markerWritten(t, db) {
				t.Fatal("env 矛盾時不得寫 marker（下次啟動重試）")
			}
			if n := profileCount(t, db); n != 0 {
				t.Fatalf("env 矛盾時不得建列，實得 %d", n)
			}
		})
	}
}

// ── seed 與還原的五組終局（逐格一支）──────────────────────

// TestOffsiteSeedSkipsWhenUIConfiguredFirst 格 1：UI 先設定、之後才補 env 並重啟。
func TestOffsiteSeedSkipsWhenUIConfiguredFirst(t *testing.T) {
	rig := newOffsiteRig(t)
	ui := mustSave(t, rig, s3Settings("configured-by-ui")).View
	before := profileRow(t, rig.db, ui.GenerationID)

	setSeedEnv(t, "added-to-env-later")
	if err := RunOffsiteEnvSeed(rig.db, rig.codec, rig.journal); err != nil {
		t.Fatalf("seed 失敗: %v", err)
	}
	if !markerWritten(t, rig.db) {
		t.Fatal("格 1：應只寫 marker")
	}
	if n := profileCount(t, rig.db); n != 1 {
		t.Fatalf("格 1：不得建列，實得 %d", n)
	}
	after := profileRow(t, rig.db, ui.GenerationID)
	if after.Bucket != before.Bucket || after.Endpoint != before.Endpoint ||
		after.CredentialsEnc != before.CredentialsEnc {
		t.Fatal("格 1：執行期應沿用 DB 中的設定，env 不參與任何判定")
	}
}

// TestOffsiteSeedAndUISaveConcurrentlyKeepSingleGeneration 格 2：seed 與 UI 儲存並發。
//
// 以 pre-write hook 製造**確定性**交錯（不靠時間競賽）：seed 進到鎖內、寫入之前暫停，
// UI 的 Save 在此期間嘗試寫入。兩者**共用同一把鎖**，故後到者拿不到鎖而以可重試的
// Busy 收場——不共用即「兩者都在鎖外看到空表、各插一列」，其一撞 unique violation
// 而對 admin 回 500。
func TestOffsiteSeedAndUISaveConcurrentlyKeepSingleGeneration(t *testing.T) {
	setSeedEnv(t, "from-env")
	rig := newOffsiteRig(t)

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
		wg      sync.WaitGroup
		seedErr error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		seedErr = RunOffsiteEnvSeed(rig.db, rig.codec, rig.journal)
	}()

	<-inLock
	// 交錯點：seed 仍在鎖內、交易未提交。此處刻意不查資料庫（見並發確認格的同一理由）
	_, uiErr := rig.svc.Save(context.Background(), s3Settings("from-ui"), OffsiteActor{ID: 1})
	close(release)
	wg.Wait()

	if seedErr != nil {
		t.Fatalf("seed 應成立: %v", seedErr)
	}
	if uiErr == nil {
		t.Fatal("並發的 UI 儲存不應同時成立（不共用鎖即兩列現行世代）")
	}
	if !errors.Is(uiErr, ErrOffsiteProfileBusy) {
		t.Fatalf("並發的拒絕應為可重試的 Busy、**不是 500**，實得 %v", uiErr)
	}
	if n := currentCount(t, rig.db); n != 1 {
		t.Fatalf("任何交錯後現行世代數 = %d, want 1", n)
	}
	if n := profileCount(t, rig.db); n != 1 {
		t.Fatalf("任何交錯後設定世代總數 = %d, want 1（不得撞 unique violation）", n)
	}
	// 重試即成立（Busy 是可重試語義）；此時表非空，故走「就地更新／新世代」的一般路徑
	if _, err := rig.svc.Save(context.Background(), s3Settings("from-ui"), OffsiteActor{ID: 1}); err != nil {
		t.Fatalf("鎖釋放後重試應成立: %v", err)
	}
}

// TestOffsiteSeedMarkerOnlyRestoreLeavesUnconfigured 格 3：**只還原了 marker**。
//
// env **不再**回灌，狀態＝未設定，且**重新設定路徑仍可用**。
// 營運文件必須明載這一格，否則部署方會一直改 `.env` 等它生效。
func TestOffsiteSeedMarkerOnlyRestoreLeavesUnconfigured(t *testing.T) {
	setSeedEnv(t, "evidence")
	rig := newOffsiteRig(t)
	writeMarker(t, rig.db) // 還原到「marker 已寫、設定列尚未建立」的時點

	if err := RunOffsiteEnvSeed(rig.db, rig.codec, rig.journal); err != nil {
		t.Fatalf("seed 失敗: %v", err)
	}
	if n := profileCount(t, rig.db); n != 0 {
		t.Fatalf("格 3：marker 在則 env 不得回灌，實得 %d 列", n)
	}
	view, err := rig.svc.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if view.Configured {
		t.Fatal("格 3：狀態應為未設定")
	}
	// **救援路徑是產品內的**（UI 重新設定），不需要改 DB、不需要清 marker
	if _, err := rig.svc.Save(context.Background(), s3Settings("reconfigured"),
		OffsiteActor{ID: 1}); err != nil {
		t.Fatalf("格 3：重新設定路徑必須可用: %v", err)
	}
	if n := currentCount(t, rig.db); n != 1 {
		t.Fatalf("格 3：重新設定後現行世代數 = %d, want 1", n)
	}
}

// TestOffsiteSeedProfileOnlyRestoreBackfillsMarker 格 4：**只還原了設定表**（marker 缺）。
// 只補寫 marker、既有設定逐欄不變。
func TestOffsiteSeedProfileOnlyRestoreBackfillsMarker(t *testing.T) {
	rig := newOffsiteRig(t)
	gen := mustSave(t, rig, s3Settings("restored")).View
	before := profileRow(t, rig.db, gen.GenerationID)
	if err := rig.db.Exec("DELETE FROM schema_migrations WHERE version = ?",
		database.OffsiteSeedMarkerVersion).Error; err != nil {
		t.Fatalf("清 marker 失敗: %v", err)
	}

	setSeedEnv(t, "from-env")
	if err := RunOffsiteEnvSeed(rig.db, rig.codec, rig.journal); err != nil {
		t.Fatalf("seed 失敗: %v", err)
	}
	if !markerWritten(t, rig.db) {
		t.Fatal("格 4：應補寫 marker")
	}
	after := profileRow(t, rig.db, gen.GenerationID)
	if after.Provider != before.Provider || after.Endpoint != before.Endpoint ||
		after.Bucket != before.Bucket || after.Prefix != before.Prefix ||
		after.Region != before.Region || after.PathStyle != before.PathStyle ||
		after.CredentialMode != before.CredentialMode ||
		after.CredentialsEnc != before.CredentialsEnc ||
		after.CredentialRevision != before.CredentialRevision {
		t.Fatalf("格 4：既有設定應逐欄不變\n  before=%+v\n  after=%+v", before, after)
	}
	if n := profileCount(t, rig.db); n != 1 {
		t.Fatalf("格 4：不得建第二列，實得 %d", n)
	}
}

// TestOffsiteSeedFullRestoreIsIdempotent 格 5：完整時間點還原 → 再啟動零變更。
func TestOffsiteSeedFullRestoreIsIdempotent(t *testing.T) {
	setSeedEnv(t, "evidence")
	db := newOffsiteDB(t)
	if err := RunOffsiteEnvSeed(db, &fakeCodec{}, &recordingJournal{}); err != nil {
		t.Fatalf("首次 seed 失敗: %v", err)
	}
	var before model.OffsiteProfile
	if err := db.First(&before).Error; err != nil {
		t.Fatalf("讀取失敗: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := RunOffsiteEnvSeed(db, &fakeCodec{}, &recordingJournal{}); err != nil {
			t.Fatalf("再啟動第 %d 次失敗: %v", i+1, err)
		}
	}
	var after model.OffsiteProfile
	if err := db.First(&after).Error; err != nil {
		t.Fatalf("讀取失敗: %v", err)
	}
	if after != before {
		t.Fatalf("格 5：再啟動應零變更\n  before=%+v\n  after=%+v", before, after)
	}
	if n := profileCount(t, db); n != 1 {
		t.Fatalf("格 5：設定世代數 = %d, want 1", n)
	}
}

// TestOffsiteSeedRegistrationHasNoTransitionalSubstring seed 佇列項名不得含
// `aad`／`legacy` 子字串——過渡遷移的負向成員斷言以子字串比對佇列項名，
// 含該子字串的名稱會被誤判為「過渡遷移自動執行」而讓那兩支守衛打紅。
func TestOffsiteSeedRegistrationHasNoTransitionalSubstring(t *testing.T) {
	name := strings.ToLower(PostUnsealMigrationOffsiteSeed)
	for _, bad := range []string{"aad", "legacy"} {
		if strings.Contains(name, bad) {
			t.Fatalf("佇列項名 %q 含 %q 子字串", PostUnsealMigrationOffsiteSeed, bad)
		}
	}
	if PostUnsealMigrationOffsiteSeed != "offsite_seed" {
		t.Fatalf("佇列項名 = %q, want offsite_seed", PostUnsealMigrationOffsiteSeed)
	}
}

// 型別檢查：fakeCodec 必須滿足 crypto.ColumnCodec（介面漂移時編譯即失敗）
var _ crypto.ColumnCodec = (*fakeCodec)(nil)
