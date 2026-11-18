package database

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
)

// 測試金鑰一律於執行期產生。

// convTestKey 當下產生的一把 Ed25519 私鑰（PEM）與其 authorized_keys 兩段。
func convTestKey(t *testing.T) (privatePEM, publicLine string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("產生金鑰: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "conv-test")
	if err != nil {
		t.Fatalf("編碼私鑰: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("公鑰: %v", err)
	}
	return string(pem.EncodeToMemory(block)), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}

// mergeFixture 兩個帶同一把私鑰的帳號（各自加密），已搬成各自的專用憑證、尚未合併。
type mergeFixture struct {
	db         *gorm.DB
	km         *keyvault.KeyManagerService
	accA, accB uint
}

func newMergeFixture(t *testing.T, privatePEM string) *mergeFixture {
	t.Helper()
	db := newCredentialLibraryDB(t)
	km := newCredentialLibraryKM(t, db)
	assetA := seedAsset(t, db, "ssh-a", model.ProtocolSSH)
	assetB := seedAsset(t, db, "ssh-b", model.ProtocolSSH)
	accA := seedAccount(t, db, km, assetA, "ops", "same-secret", "group-pk")
	accB := seedAccount(t, db, km, assetB, "ops", "same-secret", "group-pk")
	for _, acc := range []uint{accA, accB} {
		enc, err := km.EncryptFor(context.Background(), keyvault.RefAccountPrivateKey, privatePEM)
		if err != nil {
			t.Fatalf("加密帳號私鑰: %v", err)
		}
		if err := db.Exec(`UPDATE asset_accounts SET private_key_enc = ? WHERE id = ?`, enc, acc).Error; err != nil {
			t.Fatalf("seed 私鑰: %v", err)
		}
	}
	if _, err := convertAccountsToDedicatedCredentials(db); err != nil {
		t.Fatalf("存量搬移失敗: %v", err)
	}
	return &mergeFixture{db: db, km: km, accA: accA, accB: accB}
}

// setMemberPublicKey 設定某帳號專用憑證版本的公鑰（模擬該版本保存的公鑰）。
func (f *mergeFixture) setMemberPublicKey(t *testing.T, accountID uint, line string) {
	t.Helper()
	if err := f.db.Exec(`UPDATE credential_secret_versions SET public_key = ?
		WHERE id = (SELECT effective_version_id FROM asset_accounts WHERE id = ?)`, line, accountID).Error; err != nil {
		t.Fatalf("seed 成員公鑰: %v", err)
	}
}

// captureDeletedVersions 合併會刪除成員原本的版本列；以觸發器在刪除前記下每一列的密文與公鑰，
// 合併後就能以密文辨認新版本取自哪一個成員，不必假設成員的排序。
func (f *mergeFixture) captureDeletedVersions(t *testing.T) {
	t.Helper()
	for _, stmt := range []string{
		`CREATE TABLE zz_deleted_versions (private_key_enc TEXT, public_key TEXT)`,
		`CREATE TRIGGER zz_capture_deleted_versions BEFORE DELETE ON credential_secret_versions
			BEGIN INSERT INTO zz_deleted_versions VALUES (OLD.private_key_enc, OLD.public_key); END`,
	} {
		if err := f.db.Exec(stmt).Error; err != nil {
			t.Fatalf("建立擷取觸發器: %v", err)
		}
	}
}

type convVersionRow struct {
	PrivateKeyEnc string
	PublicKey     string
}

func (f *mergeFixture) mergedVersion(t *testing.T) convVersionRow {
	t.Helper()
	credID := credentialIDOfAccount(t, f.db, f.accA)
	if credID != credentialIDOfAccount(t, f.db, f.accB) {
		t.Fatalf("PRECONDITION: 群組應合併為同一筆共用憑證")
	}
	var row convVersionRow
	if err := f.db.Raw(`SELECT COALESCE(v.private_key_enc, '') AS private_key_enc, COALESCE(v.public_key, '') AS public_key
		FROM credentials c JOIN credential_secret_versions v ON v.id = c.current_version_id WHERE c.id = ?`, credID).
		Scan(&row).Error; err != nil {
		t.Fatalf("讀取合併後版本: %v", err)
	}
	if row.PrivateKeyEnc == "" {
		t.Fatalf("PRECONDITION: 合併後版本應帶私鑰")
	}
	return row
}

// TestCredentialSecretConversionMergeCarriesPublicKey 隱性共用合併時，合併後版本的公鑰取自與私鑰密文
// 同一個成員版本：來源有公鑰就帶，沒有就維持空，不取另一個成員的公鑰。
//
// 兩個成員設成不同的公鑰（或一有一無），所以「密文取自 A、公鑰取自 B」會使斷言失敗。
func TestCredentialSecretConversionMergeCarriesPublicKey(t *testing.T) {
	privatePEM, _ := convTestKey(t)
	_, lineX := convTestKey(t)
	_, lineY := convTestKey(t)
	for _, tc := range []struct {
		name       string
		pubA, pubB string
	}{
		{"members_differ", lineX, lineY},
		{"only_a_known", lineX, ""},
		{"only_b_known", "", lineY},
		{"both_unknown", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMergeFixture(t, privatePEM)
			f.setMemberPublicKey(t, f.accA, tc.pubA)
			f.setMemberPublicKey(t, f.accB, tc.pubB)
			f.captureDeletedVersions(t)

			if err := RunCredentialSecretConversion(f.db, f.km); err != nil {
				t.Fatalf("轉換失敗: %v", err)
			}
			merged := f.mergedVersion(t)

			var deleted []convVersionRow
			if err := f.db.Raw(`SELECT COALESCE(private_key_enc, '') AS private_key_enc, COALESCE(public_key, '') AS public_key
				FROM zz_deleted_versions`).Scan(&deleted).Error; err != nil {
				t.Fatalf("讀取擷取列: %v", err)
			}
			if len(deleted) != 2 {
				t.Fatalf("PRECONDITION: 合併應刪除兩個成員的版本列，得 %d", len(deleted))
			}
			if deleted[0].PrivateKeyEnc == deleted[1].PrivateKeyEnc {
				t.Fatalf("PRECONDITION: 兩個成員的密文應不同（各自加密），才能辨認來源")
			}
			if tc.pubA != tc.pubB && deleted[0].PublicKey == deleted[1].PublicKey {
				t.Fatalf("PRECONDITION: 兩個成員的公鑰應不同")
			}
			var source *convVersionRow
			for i := range deleted {
				if deleted[i].PrivateKeyEnc == merged.PrivateKeyEnc {
					source = &deleted[i]
				}
			}
			if source == nil {
				t.Fatalf("PRECONDITION: 合併後的密文應原樣取自其中一個成員")
			}
			if merged.PublicKey != source.PublicKey {
				t.Fatalf("合併後版本的公鑰 = %q，應取自密文來源的成員 %q", merged.PublicKey, source.PublicKey)
			}
		})
	}
}

// TestCredentialSecretConversionMergedPublicKeyMatchesCiphertext 合併後版本保存的公鑰，
// 與解開該版本私鑰密文後由私鑰推導出的公鑰相同。
func TestCredentialSecretConversionMergedPublicKeyMatchesCiphertext(t *testing.T) {
	privatePEM, line := convTestKey(t)
	f := newMergeFixture(t, privatePEM)
	f.setMemberPublicKey(t, f.accA, line)
	f.setMemberPublicKey(t, f.accB, line)
	if err := RunCredentialSecretConversion(f.db, f.km); err != nil {
		t.Fatalf("轉換失敗: %v", err)
	}
	merged := f.mergedVersion(t)
	plain, err := f.km.DecryptFor(context.Background(), keyvault.RefCredentialVersionPrivateKey, merged.PrivateKeyEnc)
	if err != nil {
		t.Fatalf("解開合併後的私鑰密文: %v", err)
	}
	signer, err := ssh.ParsePrivateKey([]byte(plain))
	if err != nil {
		t.Fatalf("解析合併後的私鑰: %v", err)
	}
	derived := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	if merged.PublicKey != derived {
		t.Fatalf("合併後版本的公鑰與其私鑰不相符")
	}
}
