package database

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"gorm.io/gorm"
)

// 解封後轉換的**合併判準**與**失敗留痕**測試（外部審查批次 2 的回應）。
//
// 夾具沿用 migration_credential_library_test.go 的助手（`newCredentialLibraryDB`、
// `seedAsset`、`seedAccount`、`countRows`、`markerWritten`、`failingCodec`）：同一包、
// 同一批「憑證化之前的形狀」，另立一份 seed 只會讓兩邊慢慢走岔。

// credentialIDOfAccount 取掛載列當下指向的憑證 id。
func credentialIDOfAccount(t *testing.T, db *gorm.DB, accountID uint) uint {
	t.Helper()
	var id uint
	if err := db.Raw(`SELECT credential_id FROM asset_accounts WHERE id = ?`, accountID).
		Scan(&id).Error; err != nil {
		t.Fatalf("讀取帳號 #%d 的憑證 id: %v", accountID, err)
	}
	return id
}

// migrationAuditRows 取本轉換寫下的審計列（resource=credential、action=migration）；
// status 為空即不過濾。
func migrationAuditRows(t *testing.T, db *gorm.DB, status model.AuditStatus) []model.AuditLog {
	t.Helper()
	var logs []model.AuditLog
	q := db.Where("resource = ? AND action = ?", model.ResourceCredential, model.ActionMigration)
	if status != "" {
		q = q.Where("status = ?", status)
	}
	if err := q.Order("id").Find(&logs).Error; err != nil {
		t.Fatalf("讀取轉換審計列: %v", err)
	}
	return logs
}

// auditDetails 解出審計列的 details。
func auditDetails(t *testing.T, entry model.AuditLog) map[string]interface{} {
	t.Helper()
	var out map[string]interface{}
	if err := json.Unmarshal([]byte(entry.Details), &out); err != nil {
		t.Fatalf("審計列 details 非合法 JSON（%q）: %v", entry.Details, err)
	}
	return out
}

// assertGroupNotMerged 群組未被合併：無共用憑證、成員各留專用且都帶待處理標記。
func assertGroupNotMerged(t *testing.T, db *gorm.DB, group string, accounts ...uint) {
	t.Helper()
	if n := countRows(t, db, `SELECT count(*) FROM credentials WHERE scope = ? AND deleted_at IS NULL`,
		model.CredentialScopeShared); n != 0 {
		t.Fatalf("群組 %s 被合併成 %d 筆共用憑證：判準未擋下", group, n)
	}
	if n := countRows(t, db, `SELECT count(*) FROM credentials WHERE scope = ? AND deleted_at IS NULL`,
		model.CredentialScopeDedicated); n != int64(len(accounts)) {
		t.Fatalf("專用憑證數 = %d, want %d（成員應各留專用）", n, len(accounts))
	}
	want := MigrationGroupMismatchPrefix + group + "]"
	for _, acc := range accounts {
		var cred model.Credential
		if err := db.First(&cred, credentialIDOfAccount(t, db, acc)).Error; err != nil {
			t.Fatalf("讀取帳號 #%d 的憑證: %v", acc, err)
		}
		if !strings.HasPrefix(cred.Note, want) {
			t.Fatalf("憑證 #%d 的備註 = %q, want 前置 %q", cred.ID, cred.Note, want)
		}
	}
}

// TestCredentialSecretConversionRefusesMergeAcrossProtocolFamilies
// 同一隱性群組跨協定族時不得合併。
//
// **可達性**：舊版的群組識別欄由操作者自行填寫，跨主機類型填同一個值完全合法；
// 帳號名與密碼相同的 SSH 與資料庫帳號因此會落進同一組。合併後全組沿用第一位成員
// 的協定族，資料庫帳號會掛上 ssh 族的憑證——協定族正是掛載相容性的判準，
// 靜默改掉它等於把一筆永遠對不上的憑證留給部署方自己發現。
func TestCredentialSecretConversionRefusesMergeAcrossProtocolFamilies(t *testing.T) {
	db := newCredentialLibraryDB(t)
	km := newCredentialLibraryKM(t, db)

	sshAsset := seedAsset(t, db, "ssh-a", model.ProtocolSSH)
	dbAsset := seedAsset(t, db, "mysql-a", model.ProtocolMySQL)
	accSSH := seedAccount(t, db, km, sshAsset, "ops", "same-secret", "group-mixed")
	accDB := seedAccount(t, db, km, dbAsset, "ops", "same-secret", "group-mixed")

	if _, err := convertAccountsToDedicatedCredentials(db); err != nil {
		t.Fatalf("存量搬移失敗: %v", err)
	}
	// 前提條件：兩筆專用憑證的協定族真的不同，否則本測試證明不了判準有作用
	var families []string
	if err := db.Raw(`SELECT protocol_family FROM credentials ORDER BY id`).Scan(&families).Error; err != nil {
		t.Fatalf("讀取協定族: %v", err)
	}
	if len(families) != 2 || families[0] == families[1] {
		t.Fatalf("前提不成立：兩筆專用憑證的協定族應不同，實得 %v", families)
	}

	if err := RunCredentialSecretConversion(db, km); err != nil {
		t.Fatalf("轉換失敗: %v", err)
	}
	assertGroupNotMerged(t, db, "group-mixed", accSSH, accDB)

	logs := migrationAuditRows(t, db, model.StatusSuccess)
	if len(logs) != 1 {
		t.Fatalf("待處理審計列 = %d 筆, want 1", len(logs))
	}
	details := auditDetails(t, logs[0])
	if got := details["reason"]; got != conversionReasonMetadataMismatch {
		t.Fatalf("審計列 reason = %v, want %q（秘密相同、憑證屬性不同）",
			got, conversionReasonMetadataMismatch)
	}
	if !strings.Contains(logs[0].Details, "protocol_family") {
		t.Fatalf("審計列未指出是哪個屬性不一致: %q", logs[0].Details)
	}
	if strings.Contains(logs[0].Details, "same-secret") {
		t.Fatalf("審計列含明文：轉換的證據面不得落任何秘密材料: %q", logs[0].Details)
	}
}

// TestCredentialSecretConversionRefusesMergeOnCredentialMetadata
// 逐屬性驗證一致判準：秘密相同但**任一**憑證屬性不同即不合併。
//
// 三個屬性都由合併後的共用憑證單一持有（`mergeGroupIntoSharedCredential` 沿用第一位
// 成員的值），故任一不同就代表其餘成員的屬性會被靜默改寫。
func TestCredentialSecretConversionRefusesMergeOnCredentialMetadata(t *testing.T) {
	cases := []struct {
		name   string
		column string
		value  string
	}{
		{"秘密型別", "secret_type", model.ChangeSecretTypeSSHKey},
		{"認證方式", "auth_method", "domain"},
		{"協定族", "protocol_family", model.ProtocolFamilyDatabase},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := newCredentialLibraryDB(t)
			km := newCredentialLibraryKM(t, db)

			assetA := seedAsset(t, db, "ssh-a", model.ProtocolSSH)
			assetB := seedAsset(t, db, "ssh-b", model.ProtocolSSH)
			accA := seedAccount(t, db, km, assetA, "ops", "same-secret", "group-meta")
			accB := seedAccount(t, db, km, assetB, "ops", "same-secret", "group-meta")

			if _, err := convertAccountsToDedicatedCredentials(db); err != nil {
				t.Fatalf("存量搬移失敗: %v", err)
			}
			// 屬性差異直接落在憑證列上：搬移期的三個屬性各有推導來源
			//（協定族看資產、認證方式看帳號列、秘密型別看有沒有私鑰），
			// 逐案改推導來源會讓本表變成三段不同的 seed，證明的卻是同一件事
			if err := db.Exec(`UPDATE credentials SET `+tc.column+` = ? WHERE id = ?`,
				tc.value, credentialIDOfAccount(t, db, accB)).Error; err != nil {
				t.Fatalf("設定 %s: %v", tc.column, err)
			}

			if err := RunCredentialSecretConversion(db, km); err != nil {
				t.Fatalf("轉換失敗: %v", err)
			}
			assertGroupNotMerged(t, db, "group-meta", accA, accB)

			logs := migrationAuditRows(t, db, model.StatusSuccess)
			if len(logs) != 1 {
				t.Fatalf("待處理審計列 = %d 筆, want 1", len(logs))
			}
			if got := auditDetails(t, logs[0])["reason"]; got != conversionReasonMetadataMismatch {
				t.Fatalf("審計列 reason = %v, want %q", got, conversionReasonMetadataMismatch)
			}
			if !strings.Contains(logs[0].Details, tc.column) {
				t.Fatalf("審計列未指出不一致的屬性 %s: %q", tc.column, logs[0].Details)
			}
		})
	}
}

// seedSecretlessVersion 為某筆憑證補一個**沒有秘密欄的版本**並指為現行版本。
//
// 直接以 SQL 建列是刻意的：`EncryptFor` 對空明文回空字串
//（key_manager_service.go:601-604），故「密文欄有值但解開是空字串」在本系統產生不出來，
// 真正產得出來的是**這一種**——版本列存在、只帶公鑰、兩個秘密欄皆空。
// `appendCredentialVersion`（internal/modules/asset/credential_resolver.go）不拒絕
// 兩欄皆空的呼叫，故此形狀在寫入路徑上沒有守門人。受測的正是「版本在不在」
// 這件事不得與「秘密是空的」混為一談。
func seedSecretlessVersion(t *testing.T, db *gorm.DB, credentialID uint) uint {
	t.Helper()
	version := model.CredentialSecretVersion{
		CredentialID:  credentialID,
		VersionNo:     1,
		SecretType:    model.ChangeSecretTypePassword,
		PublicKey:     "ssh-ed25519 AAAA-public-only",
		CreatedReason: model.CredentialVersionReasonManual,
	}
	if err := db.Create(&version).Error; err != nil {
		t.Fatalf("建立無秘密欄的版本: %v", err)
	}
	if err := db.Model(&model.Credential{}).Where("id = ?", credentialID).
		Update("current_version_id", version.ID).Error; err != nil {
		t.Fatalf("指定現行版本: %v", err)
	}
	return version.ID
}

// TestCredentialSecretConversionSeparatesMissingVersionFromEmptySecret
// 「沒有版本」與「有版本但秘密欄是空的」不得視為相同，且**兩種成員順序結果一致**。
//
// 兩者混同的代價：全組被判為一致而合併，該版本列連同它記錄的公鑰與版本歷史
// 一併刪除，成員的就位版本指標全部清成空——而畫面上看不出差別。
func TestCredentialSecretConversionSeparatesMissingVersionFromEmptySecret(t *testing.T) {
	// 群組成員的排序＝掛載列 id 序，故「誰在前」由建立順序決定
	cases := []struct{ name string; emptyVersionFirst bool }{
		{"無版本者在前", false},
		{"空秘密版本者在前", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := newCredentialLibraryDB(t)
			km := newCredentialLibraryKM(t, db)

			assetA := seedAsset(t, db, "ssh-a", model.ProtocolSSH)
			assetB := seedAsset(t, db, "ssh-b", model.ProtocolSSH)
			// 兩者皆無密碼：搬移後各得一筆沒有版本的專用憑證
			accFirst := seedAccount(t, db, km, assetA, "ops", "", "group-empty")
			accSecond := seedAccount(t, db, km, assetB, "ops", "", "group-empty")

			if _, err := convertAccountsToDedicatedCredentials(db); err != nil {
				t.Fatalf("存量搬移失敗: %v", err)
			}
			if n := countRows(t, db, `SELECT count(*) FROM credential_secret_versions`); n != 0 {
				t.Fatalf("前提不成立：無密碼的帳號不應產生版本列，實得 %d 筆", n)
			}
			target := accSecond
			if tc.emptyVersionFirst {
				target = accFirst
			}
			versionID := seedSecretlessVersion(t, db, credentialIDOfAccount(t, db, target))

			if err := RunCredentialSecretConversion(db, km); err != nil {
				t.Fatalf("轉換失敗: %v", err)
			}
			assertGroupNotMerged(t, db, "group-empty", accFirst, accSecond)
			if n := countRows(t, db,
				`SELECT count(*) FROM credential_secret_versions WHERE id = ?`, versionID); n != 1 {
				t.Fatalf("版本 #%d 被刪除了：不合併就不得動任何成員的版本列", versionID)
			}
			logs := migrationAuditRows(t, db, model.StatusSuccess)
			if len(logs) != 1 {
				t.Fatalf("待處理審計列 = %d 筆, want 1", len(logs))
			}
			if got := auditDetails(t, logs[0])["reason"]; got != conversionReasonSecretsMismatch {
				t.Fatalf("審計列 reason = %v, want %q（秘密的有無不同）",
					got, conversionReasonSecretsMismatch)
			}
		})
	}
}

// TestCredentialSecretConversionSurvivesMarkerLoss 執行標記不在時重跑不得壞掉。
//
// **標記是唯一的重試閘，而它會不見**：結構回退後重跑（Down→Up 會清掉
// schema_migrations 的列）、或庫被還原到寫標記之前的時點。此時改綁步會對
// **已經改綁過**的密文再跑一次；重加密入口若恆以來源身分解密，那批值一律解不開、
// 整段回滾，於是每次啟動都失敗一次而服務照常起來，管理者從畫面上看不出差別。
func TestCredentialSecretConversionSurvivesMarkerLoss(t *testing.T) {
	db := newCredentialLibraryDB(t)
	km := newCredentialLibraryKM(t, db)

	assetA := seedAsset(t, db, "ssh-a", model.ProtocolSSH)
	assetB := seedAsset(t, db, "ssh-b", model.ProtocolSSH)
	seedAccount(t, db, km, assetA, "ops", "same-secret", "group-1")
	seedAccount(t, db, km, assetB, "ops", "same-secret", "group-1")
	if _, err := convertAccountsToDedicatedCredentials(db); err != nil {
		t.Fatalf("存量搬移失敗: %v", err)
	}
	if err := RunCredentialSecretConversion(db, km); err != nil {
		t.Fatalf("第一次轉換失敗: %v", err)
	}
	if err := db.Exec(`DELETE FROM schema_migrations WHERE version = ?`,
		CredentialSecretConversionMarkerVersion).Error; err != nil {
		t.Fatalf("清除執行標記: %v", err)
	}

	if err := RunCredentialSecretConversion(db, km); err != nil {
		t.Fatalf("標記不在時重跑 MUST 成功（已改綁的值不得再被當成舊身分解）: %v", err)
	}
	if n := countRows(t, db, `SELECT count(*) FROM credentials WHERE scope = ? AND deleted_at IS NULL`,
		model.CredentialScopeShared); n != 1 {
		t.Fatalf("重跑後共用憑證數 = %d, want 1", n)
	}
	var shared model.Credential
	if err := db.Where("scope = ?", model.CredentialScopeShared).First(&shared).Error; err != nil {
		t.Fatalf("讀取共用憑證: %v", err)
	}
	if shared.CurrentVersionID == nil {
		t.Fatal("重跑後共用憑證失去現行版本")
	}
	var version model.CredentialSecretVersion
	if err := db.First(&version, *shared.CurrentVersionID).Error; err != nil {
		t.Fatalf("讀取現行版本: %v", err)
	}
	plain, err := km.DecryptFor(context.Background(),
		keyvault.RefCredentialVersionPassword, version.PasswordEnc)
	if err != nil || plain != "same-secret" {
		t.Fatalf("重跑後仍應以版本表身分解回原明文，實得 %q err=%v", plain, err)
	}
	if !markerWritten(t, db) {
		t.Fatal("重跑成功卻未重新寫入執行標記")
	}
}

// TestCredentialSecretConversionRecordsFailureAudit 轉換失敗留下持久痕跡：
// 每次失敗嘗試一筆審計列，且**寫在交易之外**（交易內寫會隨回滾一起消失）。
//
// 只留啟動日誌的代價：服務照常起來，未改綁的存量憑證要等到有人去連線才暴露錯誤，
// 而那時已經沒有任何可查的紀錄說「開機時這件事失敗過」。
func TestCredentialSecretConversionRecordsFailureAudit(t *testing.T) {
	db := newCredentialLibraryDB(t)
	km := newCredentialLibraryKM(t, db)

	assetA := seedAsset(t, db, "ssh-a", model.ProtocolSSH)
	assetB := seedAsset(t, db, "ssh-b", model.ProtocolSSH)
	seedAccount(t, db, km, assetA, "ops", "same-secret", "group-1")
	seedAccount(t, db, km, assetB, "ops", "same-secret", "group-1")
	if _, err := convertAccountsToDedicatedCredentials(db); err != nil {
		t.Fatalf("存量搬移失敗: %v", err)
	}

	// 情形一：金鑰不可用（codec 為 nil）——交易根本沒開始
	if err := RunCredentialSecretConversion(db, nil); err == nil {
		t.Fatal("金鑰不可用時應回錯")
	}
	// 情形二：codec 在但解不開——交易開了又整批回滾
	if err := RunCredentialSecretConversion(db, failingCodec{}); err == nil {
		t.Fatal("解密失敗時應回錯")
	}

	logs := migrationAuditRows(t, db, model.StatusFailure)
	if len(logs) != 2 {
		t.Fatalf("失敗審計列 = %d 筆, want 2（每次失敗嘗試一筆，且不隨交易回滾消失）", len(logs))
	}
	first := auditDetails(t, logs[0])
	if first["stage"] != conversionStageCodec {
		t.Fatalf("第一筆的失敗階段 = %v, want %q", first["stage"], conversionStageCodec)
	}
	second := auditDetails(t, logs[1])
	if second["stage"] != conversionStageRebind {
		t.Fatalf("第二筆的失敗階段 = %v, want %q（改綁是交易內的第一步）",
			second["stage"], conversionStageRebind)
	}
	// 待處理筆數：改綁待辦 2 筆版本、待評估群組 1 組
	if second["pending_versions"] != float64(2) || second["pending_groups"] != float64(1) {
		t.Fatalf("待處理筆數 = 版本 %v／群組 %v, want 2／1", second["pending_versions"], second["pending_groups"])
	}
	for _, entry := range logs {
		if strings.Contains(entry.Details, "same-secret") || strings.Contains(entry.Details, "enc:") {
			t.Fatalf("失敗審計列含秘密材料或密文: %q", entry.Details)
		}
	}
	if markerWritten(t, db) {
		t.Fatal("失敗卻寫了執行標記")
	}
}
