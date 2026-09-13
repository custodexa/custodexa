package keyvault

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/crypto/gcpkms"
)

func TestGCPRetiredRowGuard(t *testing.T) {
	db := newKeyManagerDB(t)
	s, target, f := gcpServiceFixture(t, db)
	row := gcpRows(t, db)[0]
	want, err := s.unwrapRow(row)
	if err != nil || len(want) != 32 {
		t.Fatal("live positive control failed")
	}
	now := time.Now()
	row.KEKRetiredAt = &now
	_, blob, err := crypto.ParseWrappedKey(row.WrappedKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.kek.Unwrap(context.Background(), blob, crypto.DEKAAD(row.Purpose, row.Version))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("fake stopped decrypting historical material")
	}
	for _, name := range []string{"retired", "retired-and-foreign-id", "retired-and-malformed-wrapped"} {
		t.Run(name, func(t *testing.T) {
			candidate := row
			if name == "retired-and-foreign-id" {
				candidate.KEKID = gcpTargetRef
			}
			if name == "retired-and-malformed-wrapped" {
				candidate.WrappedKey = "invalid"
			}
			f.calls = nil
			out, err := s.unwrapRow(candidate)
			if out != nil || !errors.Is(err, ErrKEKMismatch) || len(f.calls) != 0 {
				t.Fatal("retired row reached provider or guard order changed")
			}
			column, err := rewrapGCPRow(context.Background(), s.kek, target, candidate)
			if column != "" || !errors.Is(err, ErrKEKMismatch) || len(f.calls) != 0 {
				t.Fatal("transaction adapter bypassed retirement")
			}
		})
	}
}
func TestGCPHistoricalDEK(t *testing.T) {
	db := newKeyManagerDB(t)
	s, _, f := gcpServiceFixture(t, db)
	ctx := context.Background()
	ciphertext, err := s.EncryptFor(ctx, RefCredentialVersionPassword, "historical-password")
	if err != nil {
		t.Fatal(err)
	}
	retired := time.Now()
	if err := db.Model(&model.DataKey{}).Where("purpose = ? AND version = ?", model.DataKeyPurposeData, 1).Updates(map[string]any{"status": model.DataKeyStatusRetired, "retired_at": retired}).Error; err != nil {
		t.Fatal(err)
	}
	wrapped, err := wrapMaterial(s.kek, model.DataKeyPurposeData, 2, kmTestKey(29))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.DataKey{Purpose: model.DataKeyPurposeData, Version: 2, KEKID: gcpSourceRef, WrappedKey: wrapped, Status: model.DataKeyStatusActive}).Error; err != nil {
		t.Fatal(err)
	}
	f.calls = nil
	reloaded, err := InitKeyManager(db, s.kek)
	if err != nil {
		t.Fatal(err)
	}
	decrypts := 0
	for _, method := range f.calls {
		if method == "decrypt" {
			decrypts++
		}
	}
	if decrypts != 3 {
		t.Fatal("historical DEK was not loaded")
	}
	got, err := reloaded.DecryptFor(ctx, RefCredentialVersionPassword, ciphertext)
	if err != nil || got != "historical-password" {
		t.Fatal("historical ciphertext unreadable")
	}
	var row model.DataKey
	if err := db.Where("purpose = ? AND version = ?", model.DataKeyPurposeData, 1).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != model.DataKeyStatusRetired || row.KEKRetiredAt != nil {
		t.Fatal("DEK retirement confused with KEK retirement")
	}
}

// These cases exercise service objects and SQLite, not a running server or SSH session.
func TestGCPAvailabilityRollback(t *testing.T) {
	t.Run("cached-data-and-audit-material", func(t *testing.T) {
		db := newKeyManagerDB(t)
		s, target, f := gcpServiceFixture(t, db)
		ctx := context.Background()
		ciphertext, err := s.EncryptFor(ctx, RefCredentialVersionPassword, "existing-password")
		if err != nil {
			t.Fatal(err)
		}
		version, key := s.ActiveHMACKey()
		beforeKey := bytes.Clone(key)
		f.calls = nil
		f.hook = func(context.Context, string, []byte) error { return errors.New("fake service unavailable") }
		got, err := s.DecryptFor(ctx, RefCredentialVersionPassword, ciphertext)
		if err != nil || got != "existing-password" {
			t.Fatal("cached decryption required remote KMS")
		}
		next, err := s.EncryptFor(ctx, RefCredentialVersionPassword, "next-password")
		if err != nil {
			t.Fatal(err)
		}
		got, err = s.DecryptFor(ctx, RefCredentialVersionPassword, next)
		if err != nil || got != "next-password" {
			t.Fatal("cached encryption failed")
		}
		nextVersion, nextKey := s.ActiveHMACKey()
		if nextVersion != version || !bytes.Equal(nextKey, beforeKey) || len(f.calls) != 0 {
			t.Fatal("cached audit key depended on remote service")
		}
		before := gcpRows(t, db)
		memory := snapshotGCPMemory(s)
		result, err := s.RewrapKEK(ctx, gcpTarget(t, target))
		if result != nil || err == nil {
			t.Fatal("remote rewrap succeeded during outage")
		}
		assertGCPRollback(t, s, before, memory)
		if reloaded, err := InitKeyManager(db, s.kek); reloaded != nil || err == nil {
			t.Fatal("service reload ignored unavailable provider")
		}
	})
	t.Run("local-pending-abandon", func(t *testing.T) {
		db := newKeyManagerDB(t)
		s := newTestKeyManager(t, db, 1)
		f := newGCPTxAPI(t)
		scope, err := gcpkms.ResolveProjectScope(gcpTargetRef)
		if err != nil {
			t.Fatal(err)
		}
		p, err := gcpkms.NewProvider(context.Background(), gcpkms.Settings{KeyID: gcpTargetRef, Scope: scope}, f)
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		ciphertext, err := s.EncryptFor(ctx, RefCredentialVersionPassword, "local-password")
		if err != nil {
			t.Fatal(err)
		}
		live := gcpRows(t, db)
		result, err := s.RewrapKEK(ctx, gcpTarget(t, p))
		if result == nil || err != nil || !s.RewrapPending() {
			t.Fatal("pending rewrap failed")
		}
		f.calls = nil
		f.hook = func(context.Context, string, []byte) error { return errors.New("fake service unavailable") }
		got, err := s.DecryptFor(ctx, RefCredentialVersionPassword, ciphertext)
		if err != nil || got != "local-password" {
			t.Fatal("pending target replaced current local key")
		}
		count, err := s.AbandonRewrap()
		if err != nil || count != 2 || s.RewrapPending() || len(f.calls) != 0 {
			t.Fatal("abandon required remote target or left pending state")
		}
		got, err = s.DecryptFor(ctx, RefCredentialVersionPassword, ciphertext)
		if err != nil || got != "local-password" {
			t.Fatal("abandon lost current local data")
		}
		rows := gcpRows(t, db)
		for _, old := range live {
			found := false
			for _, row := range rows {
				if row.ID == old.ID {
					found = true
					if row.WrappedKey != old.WrappedKey || row.KEKID != old.KEKID || row.KEKRetiredAt != nil {
						t.Fatal("abandon changed live source")
					}
				}
			}
			if !found {
				t.Fatal("live source removed")
			}
		}
		retired := 0
		for _, row := range rows {
			if row.KEKID == gcpTargetRef && row.KEKRetiredAt != nil {
				retired++
			}
		}
		if retired != 2 {
			t.Fatal("pending target rows not retired")
		}
	})
}
