package asset

import (
	"context"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
)

// 帳號密文欄安全紅線的**行為面**守衛。AST 守衛
// （envelope_targets_guard_test.go）只證 asset_accounts 的加密欄位「列於清單」，
// 不證清單成員真的被輪替與銷毀前引用掃描吃到。以下兩測試各鎖一端：
// 漏掉任一端的後果都是「帳號密文所依賴的金鑰材料被誤銷毀 → 資料永久不可解」。

// TestRotationReencryptsAssetAccountCiphertext DEK 輪替涵蓋 asset_accounts：
// 舊版本密文被重加密至新版本且明文不變
func TestRotationReencryptsAssetAccountCiphertext(t *testing.T) {
	db, km := setupKM(t)

	const secret = "account-password"
	enc := encryptColumn(t, km, "asset_accounts", "password_enc", secret) // 現行版本（v1）
	acct := model.AssetAccount{AssetID: 1, Username: "root", PasswordEnc: enc, IsDefault: true}
	if err := db.Create(&acct).Error; err != nil {
		t.Fatalf("seed 帳號: %v", err)
	}

	if _, err := km.RotateDataDEK(); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	var got string
	if err := db.Raw("SELECT password_enc FROM asset_accounts WHERE id = ?", acct.ID).
		Scan(&got).Error; err != nil {
		t.Fatalf("查詢帳號密文: %v", err)
	}
	if !strings.HasPrefix(got, "enc:a1:v2:") {
		t.Fatalf("輪替後帳號密文應為帶 AAD 的 v2（漏登記＝該欄不被重加密）: %q", got)
	}
	if plain, err := decryptColumn(km, "asset_accounts", "password_enc", got); err != nil || plain != secret {
		t.Fatalf("輪替後帳號密文應仍可解回原文: %q err=%v", plain, err)
	}
}

// TestRetiredKeyNotPurgedWhileAssetAccountReferences 退役 DEK 版本引用掃描涵蓋
// asset_accounts（spec「退役金鑰引用掃描」場景）：帳號表殘留舊版本密文時拒清，
// 殘值清除後方可清理
func TestRetiredKeyNotPurgedWhileAssetAccountReferences(t *testing.T) {
	db, km := setupKM(t)

	// **先以 v1 產出殘值密文**（輪替後 active 即為 v2，屆時再加密只會得到 v2）。
	// 此處僅計算字串、尚未落庫，故不影響下方 RewrapKEK 的 pending 前置檢查
	v1AAD, err := km.EncryptFor(context.Background(), keyvault.RefAccountPassword, "account-secret-v1")
	if err != nil {
		t.Fatalf("以 v1 DEK 產生 enc:a1 殘值: %v", err)
	}
	if !strings.HasPrefix(v1AAD, "enc:a1:v1:") {
		t.Fatalf("殘值須為 v1 的帶 AAD 密文（否則本測試未覆蓋銷毀側漏數路徑）: %q", v1AAD)
	}

	// 收斂 KEK 狀態（清理閘要求全收斂），再輪替 DEK v1→v2 使 v1 成退役版本
	if _, err := rewrapKEKWith(t, km, newTestKEKMaterial(t)); err != nil {
		t.Fatalf("rewrap: %v", err)
	}
	if _, err := km.AbandonRewrap(); err != nil {
		t.Fatalf("abandon: %v", err)
	}
	if _, err := km.RotateDataDEK(); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// 引用只植在 asset_accounts（其他目標表輪替後皆為 v2）——若掃描漏了本表，
	// v1 會被判零引用而清理，此測試即紅。
	//
	// **殘值刻意用真正的 enc:a1 v1 密文而非 enc:v1:AAAA**：
	// cutover 後所有寫入端產出的都是 enc:a1，若引用掃描的版本判定退回只認
	// `enc:v` 的 ParseEnvelope，enc:a1 值會被漏數 → 誤判零引用 → 銷毀仍在用的
	// 金鑰材料＝**資料永久不可解**。輪替側有間接釘子（pending 永不收斂），
	// 但銷毀側原本無直接釘子，這一格即補在此。
	acct := model.AssetAccount{AssetID: 1, Username: "root", PasswordEnc: v1AAD, IsDefault: true}
	if err := db.Create(&acct).Error; err != nil {
		t.Fatalf("seed v1 殘值: %v", err)
	}

	result, err := km.CleanupRetiredMaterial()
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	var skipped bool
	for _, sk := range result.Skipped {
		if sk.Purpose == model.DataKeyPurposeData && sk.Version == 1 {
			skipped = true
			if sk.Refs < 1 || sk.Reason != "version_referenced" {
				t.Fatalf("拒清應帶引用數與原因: %+v", sk)
			}
		}
	}
	if !skipped {
		t.Fatalf("asset_accounts 尚有 v1 密文，data v1 材料不得被清理: %+v", result)
	}
	// 只驗**現行 KEK 底下**的 v1 材料：RewrapKEK→AbandonRewrap 會留下同
	// (purpose, version) 但包在已退役 KEK 下的過渡列，那份是 stale 副本，被清理
	// 屬正確行為。不帶 kek_id 條件的查詢會隨列序抓到那份空材料而假紅（本測試
	// 原寫法即如此，整包跑時穩定紅）。
	var material string
	if err := db.Raw("SELECT wrapped_key FROM data_keys WHERE purpose = ? AND version = 1 AND kek_id = ?",
		model.DataKeyPurposeData, km.KEKKeyID()).Scan(&material).Error; err != nil {
		t.Fatalf("查詢 v1 材料: %v", err)
	}
	if material == "" {
		t.Fatal("被引用的 v1 金鑰材料遭清空——帳號密文將永久不可解")
	}

	// 殘值清除後 v1 應可清（證明拒清確實來自帳號表引用，而非其他恆定阻擋）
	if err := db.Unscoped().Delete(&acct).Error; err != nil {
		t.Fatalf("清除殘值: %v", err)
	}
	result2, err := km.CleanupRetiredMaterial()
	if err != nil {
		t.Fatalf("cleanup2: %v", err)
	}
	for _, sk := range result2.Skipped {
		if sk.Purpose == model.DataKeyPurposeData && sk.Version == 1 {
			t.Fatalf("零引用後 v1 應可清，仍被拒: %+v", sk)
		}
	}
}
