package keyvault

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// KEK provider 模組化 P1：一致性判準（1.5）、AAD 列綁定（1.6）、
// AAD 全存量遷移與 strict 把關（1.7）、解封後遷移佇列與重加密入口（1.8）。

func newAADTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := newKeyManagerDB(t)
	if err := db.AutoMigrate(&model.AuditLog{}); err != nil {
		t.Fatalf("migrate audit_logs: %v", err)
	}
	return db
}

// preReleaseEnvelope 以 active data DEK 產出**發佈前過渡格式**的 `enc:v<N>` 值。
//
// 為何在測試裡手工組：無 AAD 的寫出能力（encryptNoAADForRollback／
// crypto.EncodeEnvelope，以及 P2 起的 AESCrypto.Encrypt／EncryptBytes）已於
// 過渡格式收尾時整組刪除——那正是被驗收的事實。負向測試仍需要
// 這種值，故由測試以 stdlib 助手（sealNoAAD）自行構造，模擬「繞過 API 的
// 資料庫直寫」或「拆除前建立的資料庫」。
func preReleaseEnvelope(t *testing.T, km *KeyManagerService, plaintext string) string {
	t.Helper()
	km.mu.RLock()
	ver := km.active[model.DataKeyPurposeData]
	dek := km.keys[model.DataKeyPurposeData][ver]
	km.mu.RUnlock()
	if len(dek) == 0 {
		t.Fatal("data DEK 未初始化")
	}
	raw := sealNoAAD(t, dek, []byte(plaintext))
	return fmt.Sprintf("enc:v%d:%s", ver, base64.StdEncoding.EncodeToString(raw))
}

// ---- 1.5 一致性判準：kek_id 相等**不是**充分條件 ----

// TestConsistencyAuthorityIsUnwrapSuccess 權威判準為「代表列 Unwrap 成功」，
// kek_id 比對降為篩選。本測試偽造「kek_id 相符但材料不符」的列——現行 KEK 篩得到、
// 卻解不開——必須 fail-close（既有 unwrapRow 行為的顯式回歸釘子）。
func TestConsistencyAuthorityIsUnwrapSuccess(t *testing.T) {
	db := newAADTestDB(t)
	km := newTestKeyManager(t, db, 1)
	kekID := km.KEKRef().KeyID

	// 以**另一把** KEK 包裹材料，卻標成現行 KEK 的 kek_id
	other, err := crypto.NewEnvKEKProvider(kmTestKey(2))
	if err != nil {
		t.Fatalf("other kek: %v", err)
	}
	forged, err := wrapMaterial(other, model.DataKeyPurposeData, 1, kmTestKey(9))
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if err := db.Model(&model.DataKey{}).
		Where("purpose = ? AND version = ?", model.DataKeyPurposeData, 1).
		Update("wrapped_key", forged).Error; err != nil {
		t.Fatalf("update: %v", err)
	}

	// 以同一把現行 KEK 重新載入：kek_id 相符（篩得到），但實際解包必失敗
	kek, _ := crypto.NewEnvKEKProvider(kmTestKey(1))
	if _, err := InitKeyManager(db, kek); err == nil {
		t.Fatal("kek_id 相符但材料不符時 MUST fail-close，不得把 kek_id 相等當成一致性的充分條件")
	} else if !strings.Contains(err.Error(), "KEK 與金鑰表不符") {
		t.Fatalf("錯誤未歸為 KEK 不符: %v", err)
	}
	if kekID == "" {
		t.Fatal("現行 KEK 的金鑰識別不應為空")
	}
}

// ---- 1.6 AAD 列綁定 ----

// TestAADCrossTableAndColumnRelocationFails 搬移密文的攻擊情境：
// 具 DB 寫權者把某欄的帶 AAD 密文複製到**別的表或別的欄** → 解密 MUST 失敗、
// MUST NOT 回傳明文。
//
// **同表同欄跨列搬移則預期「可解密」**——資料層 AAD 綁 `ct|table|column`
// 而**不綁主鍵**（兩方獨立審查同結論）。這是
// **明載的信任邊界，不是缺陷**：該攻擊以 DB 寫權為前提，而具此權者另有嚴格更強
// 的等價手段（直接改同列的 host／username，或刪列重建同 pk 貼回舊密文——後者
// 綁 pk 也擋不住）；反之綁 pk 會使跨環境還原不可解、受 sqlite 自增 pk 重用影響、
// 並破壞資產多帳號的密文原樣複製契約。
// 本子測試以**斷言成功**釘住該邊界：若哪天改回綁 pk，這裡會轉紅並強迫重新裁決。
func TestAADCrossTableAndColumnRelocationFails(t *testing.T) {
	db := newAADTestDB(t)
	km := newTestKeyManager(t, db, 1)
	ctx := context.Background()

	refA := crypto.CipherRef{Table: "assets", Column: "password_enc"}
	refOtherCol := crypto.CipherRef{Table: "assets", Column: "private_key_enc"}
	refOtherTable := crypto.CipherRef{Table: "asset_accounts", Column: "password_enc"}

	ct, err := km.EncryptFor(ctx, refA, "s3cret")
	if err != nil {
		t.Fatalf("EncryptFor: %v", err)
	}
	if !strings.HasPrefix(ct, "enc:a1:v") {
		t.Fatalf("帶 AAD 密文格式應自描述方案: %s", ct)
	}
	if got, err := km.DecryptFor(ctx, refA, ct); err != nil || got != "s3cret" {
		t.Fatalf("同欄解密應成功: got=%q err=%v", got, err)
	}
	for name, ref := range map[string]crypto.CipherRef{
		"跨欄（同表不同欄）":  refOtherCol,
		"跨表（同欄名不同表）": refOtherTable,
	} {
		if got, err := km.DecryptFor(ctx, ref, ct); err == nil {
			t.Fatalf("%s 搬移後仍可解密（回傳 %q）：AAD 綁定失效", name, got)
		}
	}

	// 信任邊界（**預期成功**，非缺陷）：同表同欄的兩列共用同一份 AAD，
	// 故把第 1 列的密文複製到第 2 列後，第 2 列照樣解得開。
	aadFixture(t, db, km)
	rowRef := crypto.CipherRef{Table: "asset_accounts", Column: "password_enc"}
	rowCT, err := km.EncryptFor(ctx, rowRef, "row-1-secret")
	if err != nil {
		t.Fatalf("EncryptFor: %v", err)
	}
	if err := db.Exec("INSERT INTO asset_accounts (password_enc) VALUES (?), (?)", rowCT, "").
		Error; err != nil {
		t.Fatalf("insert: %v", err)
	}
	// 攻擊者把第 1 列的密文貼到第 2 列（同表同欄）
	if err := db.Exec("UPDATE asset_accounts SET password_enc = ? WHERE password_enc = ''", rowCT).
		Error; err != nil {
		t.Fatalf("relocate: %v", err)
	}
	var relocated string
	if err := db.Raw("SELECT password_enc FROM asset_accounts ORDER BY id DESC LIMIT 1").
		Scan(&relocated).Error; err != nil {
		t.Fatalf("讀回: %v", err)
	}
	if got, err := km.DecryptFor(ctx, rowRef, relocated); err != nil || got != "row-1-secret" {
		t.Fatalf("同表同欄跨列搬移**應可解密**（明載的信任邊界，非缺陷）: got=%q err=%v", got, err)
	}
}

// TestAADCreatePathNeedsNoTwoPhaseWrite 不綁 pk 相對於綁 pk 的核心工程紅利：
// **CipherRef 是常數**，呼叫端於 insert 之前即可完成加密——create 路徑
// SHALL NOT 退化為「先插入取得 pk、再回寫密文」的兩階段寫入。
//
// 本測試以「加密不需要任何列已存在」代表該不變式：密文在資料列尚不存在時即產出，
// 且該密文於落列後可原樣解讀。
func TestAADCreatePathNeedsNoTwoPhaseWrite(t *testing.T) {
	db := newAADTestDB(t)
	km := newTestKeyManager(t, db, 1)
	ctx := context.Background()

	// 尚未 insert 任何列即可加密（若 AAD 綁 pk，此處必須先有 pk 才能加密）
	ct, err := km.EncryptFor(ctx, RefAccountPassword, "pre-insert")
	if err != nil {
		t.Fatalf("insert 前加密失敗（AAD 疑似綁了主鍵，create 將被迫兩階段寫入）: %v", err)
	}
	aadFixture(t, db, km)
	if err := db.Exec("INSERT INTO asset_accounts (password_enc) VALUES (?)", ct).Error; err != nil {
		t.Fatalf("insert: %v", err)
	}
	var stored string
	if err := db.Raw("SELECT password_enc FROM asset_accounts WHERE password_enc = ?", ct).
		Scan(&stored).Error; err != nil {
		t.Fatalf("讀回: %v", err)
	}
	if got, err := km.DecryptFor(ctx, RefAccountPassword, stored); err != nil || got != "pre-insert" {
		t.Fatalf("落列後密文應原樣可解: got=%q err=%v", got, err)
	}
}

// TestAADRequiresCompleteCipherRef 欄位身分不完整即拒絕——AAD 綁定不得因呼叫端疏漏而靜默退化
func TestAADRequiresCompleteCipherRef(t *testing.T) {
	db := newAADTestDB(t)
	km := newTestKeyManager(t, db, 1)
	ctx := context.Background()
	for _, ref := range []crypto.CipherRef{
		{Column: "password_enc"},
		{Table: "assets"},
		{},
	} {
		if _, err := km.EncryptFor(ctx, ref, "x"); err == nil {
			t.Fatalf("不完整欄位身分 %+v 應拒絕加密", ref)
		}
	}
	// 帶 AAD 密文經無欄位身分的 Decrypt 入口必須拒絕（否則 AAD 綁定被靜默繞過）
	ct, _ := km.EncryptFor(ctx, crypto.CipherRef{Table: "assets", Column: "password_enc"}, "x")
	if _, err := km.Decrypt(ct); err == nil {
		t.Fatal("帶 AAD 密文不得經無欄位身分的 Decrypt 解出")
	}
}

// TestPreReleaseCiphertextFailsClose 終態負向：
// 兩類發佈前過渡格式密文——無前綴裸 base64（legacy 單鑰密文）與無 AAD 的
// `enc:v<N>`——一律 fail-close 回**可辨識**的 ErrNonFinalCiphertext，
// SHALL NOT 靜默回退任何解密路徑、SHALL NOT 回傳明文。
func TestPreReleaseCiphertextFailsClose(t *testing.T) {
	db := newAADTestDB(t)
	km := newTestKeyManager(t, db, 1)
	ctx := context.Background()
	ref := crypto.CipherRef{Table: "assets", Column: "password_enc"}

	// (a) 無 AAD 的 enc:v（拆除前的信封格式；材料仍是現行 DEK，故「解得開」
	//     只差在被政策拒絕——正是最容易被相容分支放行的一類）
	stale := preReleaseEnvelope(t, km, "old-value")
	for name, got := range map[string]func() (string, error){
		"DecryptFor": func() (string, error) { return km.DecryptFor(ctx, ref, stale) },
		"Decrypt":    func() (string, error) { return km.Decrypt(stale) },
	} {
		plain, err := got()
		if err == nil {
			t.Fatalf("%s: enc:v 密文 MUST fail-close，竟回傳 %q", name, plain)
		}
		if !errors.Is(err, ErrNonFinalCiphertext) {
			t.Fatalf("%s: 錯誤未可辨識為過渡格式錯: %v", name, err)
		}
		if plain != "" {
			t.Fatalf("%s: fail-close 時 MUST NOT 回傳明文", name)
		}
	}

	// (b) legacy 純 base64（升級前遺留、以單鑰直加密）
	bare := sealNoAADBase64(t, kmTestKey(1), "legacy-value")
	if plain, err := km.DecryptFor(ctx, ref, bare); err == nil || plain != "" {
		t.Fatalf("無前綴 legacy 密文 MUST fail-close，得 plain=%q err=%v", plain, err)
	} else if !errors.Is(err, ErrNonFinalCiphertext) {
		t.Fatalf("錯誤未可辨識為過渡格式錯: %v", err)
	}
}

// TestNoLegacyDecryptPathExists 系統 SHALL NOT 具備 legacy 單鑰解密路徑：
// 即使以「當初的 legacy 鑰」等同的 KEK 材料開機，無前綴密文仍不可解。
func TestNoLegacyDecryptPathExists(t *testing.T) {
	db := newAADTestDB(t)
	kek, _ := crypto.NewEnvKEKProvider(kmTestKey(1))
	km, err := InitKeyManager(db, kek)
	if err != nil {
		t.Fatalf("InitKeyManager: %v", err)
	}
	bare := sealNoAADBase64(t, kmTestKey(1), "legacy-value")
	if _, err := km.Decrypt(bare); !errors.Is(err, ErrNonFinalCiphertext) {
		t.Fatalf("無前綴密文的解密請求 MUST fail-close 為過渡格式錯: %v", err)
	}
}

// TestAADCompositionExcludesMutableIdentifier AAD 組成不含任何可變識別符：
// kek_id 被改寫（識別正規化）後，既有帶 AAD 密文仍可解包。
func TestAADCompositionSurvivesKEKIDRewrite(t *testing.T) {
	db := newAADTestDB(t)
	km := newTestKeyManager(t, db, 1)
	ctx := context.Background()
	ref := crypto.CipherRef{Table: "assets", Column: "password_enc"}
	ct, err := km.EncryptFor(ctx, ref, "value")
	if err != nil {
		t.Fatalf("EncryptFor: %v", err)
	}
	// 模擬委託模式的識別欄改寫（純識別、不重包）——AAD 若含 kek_id，此後必解不開
	if err := db.Exec("UPDATE data_keys SET kek_id = kek_id").Error; err != nil {
		t.Fatalf("update: %v", err)
	}
	if got, err := km.DecryptFor(ctx, ref, ct); err != nil || got != "value" {
		t.Fatalf("kek_id 改寫後既有密文應仍可解: got=%q err=%v", got, err)
	}
}

// TestAADCompletenessDependency AAD 完備性依賴的守衛：
// `purpose|version` 之所以完備，依賴 data_keys 的三欄 partial 唯一索引。
// 放寬該索引即靜默削弱 AAD 綁定強度——本測試釘住該依賴。
func TestAADCompletenessDependencyOnUniqueIndex(t *testing.T) {
	db := newAADTestDB(t)
	km := newTestKeyManager(t, db, 1)
	kekID := km.KEKRef().KeyID

	// 同一把 KEK 下，同 slot 的第二列帶材料必須被唯一索引擋下
	dup := model.DataKey{
		Purpose: model.DataKeyPurposeData, Version: 1,
		WrappedKey: "d3JhcHBlZA==", KEKID: kekID, Status: model.DataKeyStatusActive,
	}
	if err := db.Create(&dup).Error; err == nil {
		t.Fatal("同一 KEK 下同 slot 可存在第二列帶材料：AAD 的 purpose|version 判別式不再完備" +
			"（放寬 data_keys 三欄唯一索引即等同削弱 AAD 綁定）")
	}
}

// ---- 1.7 AAD 全存量遷移與 strict 把關 ----

// aadFixture 建一張最小的登記表存量（assets 與 asset_accounts），回傳 id
func aadFixture(t *testing.T, db *gorm.DB, km *KeyManagerService) (assetID, accountID uint) {
	t.Helper()
	for _, ddl := range []string{
		`CREATE TABLE assets (id INTEGER PRIMARY KEY AUTOINCREMENT, password_enc TEXT NOT NULL DEFAULT '',
			private_key_enc TEXT NOT NULL DEFAULT '', sftp_password_enc TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE asset_accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, password_enc TEXT NOT NULL DEFAULT '',
			private_key_enc TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, totp_secret_enc TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE export_signing_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, private_key_enc TEXT NOT NULL DEFAULT '')`,
		// 登記於 envelopeMigrationTargets，缺表即整個殘值掃描失敗
		`CREATE TABLE checkpoint_signing_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, private_key_enc TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE notification_channels (id INTEGER PRIMARY KEY AUTOINCREMENT, secret TEXT NOT NULL DEFAULT '',
			url TEXT NOT NULL DEFAULT '')`,
		// 登記於 envelopeMigrationTargets，缺表即整個殘值掃描失敗
		`CREATE TABLE change_secret_candidates (id INTEGER PRIMARY KEY AUTOINCREMENT, password_enc TEXT NOT NULL DEFAULT '',
			private_key_enc TEXT NOT NULL DEFAULT '')`,
	} {
		if err := db.Exec(ddl).Error; err != nil {
			t.Fatalf("建表失敗: %v", err)
		}
	}
	// 以**發佈前過渡格式**播種：本 fixture 的用途是餵殘值偵測（哨兵與清理閘），
	// 那正是終態下不應存在、但必須被看見的一類值
	assetPwd := preReleaseEnvelope(t, km, "asset-secret")
	acctPwd := preReleaseEnvelope(t, km, "account-secret")
	acctKey := preReleaseEnvelope(t, km, "account-privkey")
	if err := db.Exec("INSERT INTO assets (password_enc) VALUES (?)", assetPwd).Error; err != nil {
		t.Fatalf("insert asset: %v", err)
	}
	if err := db.Exec("INSERT INTO asset_accounts (password_enc, private_key_enc) VALUES (?, ?)",
		acctPwd, acctKey).Error; err != nil {
		t.Fatalf("insert account: %v", err)
	}
	return 1, 1
}

// TestEnvelopeTargetsCoverAssetAccounts 跨 change 契約的證據（交叉相容）：
// 登記集合**必須涵蓋** asset_accounts.password_enc 與 private_key_enc。
// 兩欄以 {table, column} 形式登記（未帶 pk 欄名），
// 正是**零改動契約**（契約 2）的情形——pkColumn 省略時等同 id。
//
// 註：原「AAD 全存量遷移涵蓋兩欄」的斷言隨遷移機制拆除；
// 登記集合本身仍是退役 DEK 引用掃描與
// 啟動哨兵的掃描範圍，漏登會誤判零引用而銷毀仍在用的金鑰材料，故守衛保留。
func TestEnvelopeTargetsCoverAssetAccounts(t *testing.T) {
	found := map[string]bool{}
	for _, tgt := range envelopeMigrationTargets {
		if tgt.table == "asset_accounts" {
			found[tgt.column] = true
			if tgt.pkColumn != "" {
				t.Errorf("asset_accounts.%s 登記帶了 pkColumn=%q：契約 2 要求零改動（省略即 id）",
					tgt.column, tgt.pkColumn)
			}
			if tgt.pk() != "id" {
				t.Errorf("pkColumn 省略時 pk() 應為 id, got %q", tgt.pk())
			}
		}
	}
	for _, col := range []string{"password_enc", "private_key_enc"} {
		if !found[col] {
			t.Fatalf("envelopeMigrationTargets 未涵蓋 asset_accounts.%s（跨 change 契約）", col)
		}
	}
}

// ---- 1.8 解封後遷移佇列與重加密入口 ----

// TestRecryptForNewRefThreeUsages 入口的使用時點：
// 既有 enc:a1 值換列身分、空值直通、來源身分不符即失敗，
// 以及發佈前過渡格式值不得被改綁洗白。
func TestRecryptForNewRefThreeUsages(t *testing.T) {
	db := newAADTestDB(t)
	km := newTestKeyManager(t, db, 1)
	ctx := context.Background()
	oldRef := crypto.CipherRef{Table: "assets", Column: "password_enc"}
	newRef := crypto.CipherRef{Table: "asset_accounts", Column: "password_enc"}

	t.Run("發佈前過渡格式值 MUST NOT 被改綁（fail-close 而非洗白）", func(t *testing.T) {
		stale := preReleaseEnvelope(t, km, "copy-me")
		if _, err := RecryptForNewRef(ctx, km, oldRef, newRef, stale); !errors.Is(err, ErrNonFinalCiphertext) {
			t.Fatalf("重加密入口 MUST 於解密階段 fail-close（不得把過渡格式洗白為 enc:a1）: %v", err)
		}
	})

	t.Run("既有帶 AAD 密文換列身分", func(t *testing.T) {
		bound, _ := km.EncryptFor(ctx, oldRef, "bound-value")
		out, err := RecryptForNewRef(ctx, km, oldRef, newRef, bound)
		if err != nil {
			t.Fatalf("RecryptForNewRef: %v", err)
		}
		if got, err := km.DecryptFor(ctx, newRef, out); err != nil || got != "bound-value" {
			t.Fatalf("換列身分後應可解: got=%q err=%v", got, err)
		}
	})

	t.Run("空值直通", func(t *testing.T) {
		out, err := RecryptForNewRef(ctx, km, oldRef, newRef, "")
		if err != nil || out != "" {
			t.Fatalf("空值應直通: out=%q err=%v", out, err)
		}
	})

	t.Run("來源列身分不符即失敗（不靜默產出可疑密文）", func(t *testing.T) {
		bound, _ := km.EncryptFor(ctx, oldRef, "bound-value")
		// 「不符」只能來自不同表／欄（同表同欄不論哪一列皆為同一份 AAD）
		wrong := crypto.CipherRef{Table: "assets", Column: "private_key_enc"}
		if _, err := RecryptForNewRef(ctx, km, wrong, newRef, bound); err == nil {
			t.Fatal("來源列身分不符 MUST 失敗")
		}
	})
}
