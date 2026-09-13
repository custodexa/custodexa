package keyvault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/crypto/vaulttransit"
	"gorm.io/gorm"
)

// This service fixture uses local cryptography and Vault identity, not Vault wire I/O.
type vaultServiceFixture struct {
	crypto.KEKProvider
	id                                 string
	unwrapCalls, wrapCalls, failWrapAt int
}

func vaultServiceProvider(t *testing.T, name string, material byte) *vaultServiceFixture {
	t.Helper()
	local, err := crypto.NewEnvKEKProvider(kmTestKey(material))
	if err != nil {
		t.Fatal(err)
	}
	id, err := vaulttransit.CanonicalKeyID("https://vault.example", name)
	if err != nil {
		t.Fatal(err)
	}
	return &vaultServiceFixture{KEKProvider: local, id: id}
}
func (p *vaultServiceFixture) KeyRef() crypto.KeyRef {
	return crypto.KeyRef{Provider: crypto.KeyRefProviderVault, KeyID: p.id}
}
func (p *vaultServiceFixture) Mode() string      { return crypto.KEKModeKMS }
func (p *vaultServiceFixture) FormatTag() string { return crypto.WrappedFormatVault }
func (p *vaultServiceFixture) Wrap(ctx context.Context, plain, aad []byte) ([]byte, error) {
	p.wrapCalls++
	if p.failWrapAt > 0 && p.wrapCalls == p.failWrapAt {
		return nil, errors.New("injected target failure")
	}
	return p.KEKProvider.Wrap(ctx, plain, aad)
}
func (p *vaultServiceFixture) Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error) {
	p.unwrapCalls++
	return p.KEKProvider.Unwrap(ctx, wrapped, aad)
}
func vaultServiceTarget(t *testing.T, p *vaultServiceFixture) *RewrapTarget {
	t.Helper()
	target, err := NewDelegatedRewrapTarget(context.Background(), RewrapTargetModeVault, p.id, func(context.Context, string, string) (crypto.KEKProvider, error) { return p, nil })
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func TestVaultRetiredRowGuard(t *testing.T) {
	p := vaultServiceProvider(t, "key", 11)
	km := &KeyManagerService{kek: p}
	raw := kmTestKey(17)
	wrapped, err := wrapMaterial(p, model.DataKeyPurposeData, 1, raw)
	if err != nil {
		t.Fatal(err)
	}
	row := model.DataKey{Purpose: model.DataKeyPurposeData, Version: 1, KEKID: p.id, WrappedKey: wrapped, Status: model.DataKeyStatusActive}
	if got, err := km.unwrapRow(row); err != nil || !bytes.Equal(got, raw) {
		t.Fatal("live positive control failed")
	}
	retired := time.Now()
	row.KEKRetiredAt = &retired
	// The provider itself still decrypts this blob; only the row guard knows retirement.
	_, blob, err := crypto.ParseWrappedKey(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := p.Unwrap(context.Background(), blob, crypto.DEKAAD(row.Purpose, row.Version)); err != nil || !bytes.Equal(got, raw) {
		t.Fatal("fixture prematurely retired remote material")
	}
	for _, name := range []string{"retired", "retired-and-foreign-id", "retired-and-malformed-wrapped"} {
		t.Run(name, func(t *testing.T) {
			candidate := row
			if name == "retired-and-foreign-id" {
				candidate.KEKID = "foreign"
			}
			if name == "retired-and-malformed-wrapped" {
				candidate.WrappedKey = "invalid"
			}
			p.unwrapCalls = 0
			got, err := km.unwrapRow(candidate)
			if got != nil || !errors.Is(err, ErrKEKMismatch) || !strings.Contains(err.Error(), "退役") || p.unwrapCalls != 0 {
				t.Fatal("retired guard order or zero-decrypt invariant failed")
			}
		})
	}
}

func TestVaultHistoricalDEK(t *testing.T) {
	db := newKeyManagerDB(t)
	p := vaultServiceProvider(t, "key", 11)
	km, err := InitKeyManager(db, p)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := km.EncryptFor(context.Background(), RefCredentialVersionPassword, "fixture-password")
	if err != nil {
		t.Fatal(err)
	}
	retired := time.Now()
	if err := db.Model(&model.DataKey{}).Where("purpose = ? AND version = ?", model.DataKeyPurposeData, 1).Updates(map[string]any{"status": model.DataKeyStatusRetired, "retired_at": retired}).Error; err != nil {
		t.Fatal(err)
	}
	wrapped, err := wrapMaterial(p, model.DataKeyPurposeData, 2, kmTestKey(18))
	if err != nil {
		t.Fatal(err)
	}
	row := model.DataKey{Purpose: model.DataKeyPurposeData, Version: 2, KEKID: p.id, WrappedKey: wrapped, Status: model.DataKeyStatusActive}
	if err := db.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	p.unwrapCalls = 0
	reloaded, err := InitKeyManager(db, p)
	if err != nil {
		t.Fatal(err)
	}
	if p.unwrapCalls < 3 {
		t.Fatal("historical material was not loaded")
	}
	got, err := reloaded.DecryptFor(context.Background(), RefCredentialVersionPassword, ciphertext)
	if err != nil || got != "fixture-password" {
		t.Fatal("historical DEK ciphertext lost")
	}
	var history model.DataKey
	if err := db.Where("purpose = ? AND version = ?", model.DataKeyPurposeData, 1).First(&history).Error; err != nil {
		t.Fatal(err)
	}
	if history.Status != model.DataKeyStatusRetired || history.KEKRetiredAt != nil {
		t.Fatal("DEK retirement confused with KEK retirement")
	}
}

func TestVaultServiceFailCloseUnit(t *testing.T) {
	t.Run("same-key-zero-wrap", func(t *testing.T) {
		db := newKeyManagerDB(t)
		p := vaultServiceProvider(t, "key", 11)
		km, err := InitKeyManager(db, p)
		if err != nil {
			t.Fatal(err)
		}
		same := vaultServiceProvider(t, "key", 11)
		before := snapshotVaultRows(t, db)
		result, err := km.RewrapKEK(context.Background(), vaultServiceTarget(t, same))
		if result != nil || !errors.Is(err, ErrRewrapTargetSameAsCurrent) || same.wrapCalls != 0 || !bytes.Equal(before, snapshotVaultRows(t, db)) || km.RewrapPending() {
			t.Fatal("same-key request changed state")
		}
	})
	t.Run("second-wrap-failure-rolls-back-first-insert", func(t *testing.T) {
		db := newKeyManagerDB(t)
		km := newTestKeyManager(t, db, 1)
		target := vaultServiceProvider(t, "next", 22)
		target.failWrapAt = 2
		before := snapshotVaultRows(t, db)
		inserts := 0
		name := "vault_test_count_target_insert"
		if err := db.Callback().Create().After("gorm:create").Register(name, func(tx *gorm.DB) {
			if row, ok := tx.Statement.Dest.(*model.DataKey); ok && row.KEKID == target.id && tx.Error == nil {
				inserts++
			}
		}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Callback().Create().Remove(name) })
		result, err := km.RewrapKEK(context.Background(), vaultServiceTarget(t, target))
		if result != nil || err == nil || target.wrapCalls != 2 || inserts != 1 {
			t.Fatal("did not exercise partial write before failure")
		}
		if !bytes.Equal(before, snapshotVaultRows(t, db)) || km.RewrapPending() {
			t.Fatal("partial rewrap escaped transaction")
		}
		t.Log("first insert executed; second wrap failed; database unchanged; pending=false")
	})
}
func snapshotVaultRows(t *testing.T, db *gorm.DB) []byte {
	t.Helper()
	var rows []model.DataKey
	if err := db.Order("id").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
