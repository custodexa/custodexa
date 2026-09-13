package main

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/pkg/crypto/vaulttransit"
)

// 解封世代憑證持有者的守衛。
//
// 這裡守的是封存抹除那條規格的**可觀察面**：
//
//	(1) `Close()` 逐位元組覆寫本世代持有的秘密；
//	(2) `Close()` 之後任何取用一律失敗（不是拿到一段全零的位元組繼續走）；
//	(3) `Close()` 冪等；
//	(4) 重新解封配置**新的**持有者，不重用前一世代。
//
// 誠實邊界：本檔驗的是「由本產品配置、承載明文的那些位元組被覆寫」，
// 不是「行程記憶體中不再存在該明文」——後者在 Go 的語義下不可達成。

// ownedSecrets 造一組可追蹤的秘密：回傳持有者與**原始位元組的參考**，
// 使「原位元組是否被歸零」成為可檢查的事實（而非只看欄位是否被設為 nil）。
func ownedSecrets(t *testing.T) (*credentialOwner, [][]byte) {
	t.Helper()
	aws1 := []byte("fixture-access-key-id")
	aws2 := []byte("fixture-secret-access-key")
	gcp := []byte(`{"type":"service_account","private_key":"fixture"}`)
	vsecret := []byte("fixture-vault-secret-id")
	vtoken := []byte("fixture-vault-token")
	originals := [][]byte{aws1, aws2, gcp, vsecret, vtoken}

	o := newCredentialOwner()
	o.adopt(config.KMSSettings{Provider: vaulttransit.ProviderVault, KeyID: "fixture-key"},
		delegatedSecrets{
			awsAccessKeyID: aws1, awsSecretAccessKey: aws2,
			gcpServiceAccountJSON: gcp, vaultSecretID: vsecret, vaultToken: vtoken,
		})
	return o, originals
}

func allZero(b []byte) bool { return bytes.Equal(b, make([]byte, len(b))) }

// TestCredentialOwnerCloseZeroizesSecrets 封存抹除：原位元組全零。
//
// **突變自檢的對象**：拿掉 `credentialOwner.Close()` 內的 `o.secrets.zeroize()`
// 之後本案必紅（整包 `-count=1` 跑，不以 `-run` 窄化）。
func TestCredentialOwnerCloseZeroizesSecrets(t *testing.T) {
	o, originals := ownedSecrets(t)
	for i, raw := range originals {
		if len(raw) == 0 || allZero(raw) {
			t.Fatalf("夾具第 %d 段在 Close 之前就已為零，本案將無法分辨歸零有沒有發生", i)
		}
	}
	o.Close()
	for i, raw := range originals {
		if !allZero(raw) {
			t.Fatalf("第 %d 段秘密在封存後未歸零：%q", i, raw)
		}
	}
}

// TestCredentialOwnerClosedRejectsUse 收束後取用一律失敗。
//
// 拿到一段全零的位元組繼續走下去，會在保管處端表現為一次難以歸因的認證失敗；
// 在本行程內就失敗才指得出原因。
func TestCredentialOwnerClosedRejectsUse(t *testing.T) {
	o, _ := ownedSecrets(t)
	if _, err := o.settings(); err != nil {
		t.Fatalf("收束前的取用不應失敗: %v", err)
	}
	o.Close()

	if _, err := o.settings(); !errors.Is(err, errCredentialOwnerClosed) {
		t.Fatalf("收束後的 settings() 應回 errCredentialOwnerClosed，得 %v", err)
	}
	if _, err := o.provider(context.Background(), vaulttransit.Settings{KeyID: "fixture-key"}); err == nil {
		t.Fatal("收束後仍建得出 provider——封存並未使憑證不可再用")
	}
	if _, _, err := o.buildStartup(context.Background(),
		&config.KEKDecision{Mode: config.KEKModeKMS}); err == nil {
		t.Fatal("收束後仍建得出啟動期 provider")
	}
	if _, err := o.buildDelegated(context.Background(), "vault", "fixture-key"); err == nil {
		t.Fatal("收束後仍建得出委託重包目標")
	}
}

// TestCredentialOwnerCloseIsIdempotent 重複收束冪等。
func TestCredentialOwnerCloseIsIdempotent(t *testing.T) {
	o, originals := ownedSecrets(t)
	o.Close()
	o.Close()
	o.Close()
	for i, raw := range originals {
		if !allZero(raw) {
			t.Fatalf("第 %d 段秘密未歸零", i)
		}
	}
	if _, err := o.settings(); !errors.Is(err, errCredentialOwnerClosed) {
		t.Fatalf("重複收束後的取用應仍失敗，得 %v", err)
	}
	// nil 接收者亦不得 panic（收束路徑在多條返回路徑上被登記）。
	var nilOwner *credentialOwner
	nilOwner.Close()
}

// TestCredentialOwnerAdoptAfterCloseDropsSecrets 收束後接手的秘密立即歸零。
//
// 這條擋的是「世代已結束卻還有人塞憑證進來」——那些位元組不會有人再負責抹它。
func TestCredentialOwnerAdoptAfterCloseDropsSecrets(t *testing.T) {
	o := newCredentialOwner()
	o.Close()
	late := []byte("late-arriving-secret")
	o.adopt(config.KMSSettings{Provider: vaulttransit.ProviderVault}, delegatedSecrets{vaultSecretID: late})
	if !allZero(late) {
		t.Fatalf("收束後接手的秘密未立即歸零：%q", late)
	}
}

// TestNewGenerationDoesNotReuseCredentials 重新解封配置新的持有者。
//
// 規格明文：封存 SHALL 抹除該世代所持有的秘密並使其不可再用；重新解封 SHALL
// 配置新的世代與新的持有者，SHALL NOT 重用前一世代的憑證。
func TestNewGenerationDoesNotReuseCredentials(t *testing.T) {
	first, originals := ownedSecrets(t)
	first.Close()

	second := newCredentialOwner()
	settings, err := second.settings()
	if err != nil {
		t.Fatalf("新世代的持有者應可用: %v", err)
	}
	if settings.Vault.SecretID != "" || settings.Vault.Token != "" ||
		settings.AWSAccessKeyID != "" || settings.AWSSecretAccessKey != "" ||
		len(settings.GCPServiceAccountJSON) != 0 {
		t.Fatalf("新世代不得帶有任何前一世代的憑證: %+v", settings)
	}
	for i, raw := range originals {
		if !allZero(raw) {
			t.Fatalf("前一世代的第 %d 段秘密仍可讀", i)
		}
	}
	second.Close()
}

// TestSealZeroizesDelegatedCredentials 封存路徑實際抹除該世代的委託憑證。
//
// 與上列四案的差別：這一案走的是**封存時真正會被呼叫的那條路**
//（服務圖釋放後收束持有者），而不是直接呼叫 Close。
func TestSealZeroizesDelegatedCredentials(t *testing.T) {
	o, originals := ownedSecrets(t)
	s1 := &stage1{credentials: o}
	// closeStartupVault 是組裝根在收尾與封存後實際呼叫的那一個。
	s1.closeStartupVault()
	for i, raw := range originals {
		if !allZero(raw) {
			t.Fatalf("封存路徑未抹除第 %d 段委託憑證：%q", i, raw)
		}
	}
	if _, err := o.settings(); !errors.Is(err, errCredentialOwnerClosed) {
		t.Fatalf("封存後取用應失敗，得 %v", err)
	}
}
