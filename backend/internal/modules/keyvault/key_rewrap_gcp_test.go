package keyvault

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

func TestGCPRewrapUsesSourceCiphertext(t *testing.T) {
	t.Run("cache-is-not-authority", func(t *testing.T) {
		db := newKeyManagerDB(t)
		s, target, f := gcpServiceFixture(t, db)
		before := gcpRows(t, db)
		for purpose, versions := range s.keys {
			for version := range versions {
				s.keys[purpose][version] = bytes.Repeat([]byte{99}, 32)
			}
		}
		result, err := s.RewrapKEK(context.Background(), gcpTarget(t, target))
		if err != nil || result == nil {
			t.Fatal("rewrap failed")
		}
		for _, source := range before {
			var clone model.DataKey
			if err := db.Where("purpose = ? AND version = ? AND kek_id = ?", source.Purpose, source.Version, gcpTargetRef).First(&clone).Error; err != nil {
				t.Fatal(err)
			}
			got, err := unwrapMaterial(target, clone.Purpose, clone.Version, clone.WrappedKey)
			if err != nil {
				t.Fatal(err)
			}
			want, err := unwrapMaterial(s.kek, source.Purpose, source.Version, source.WrappedKey)
			if err != nil || !bytes.Equal(got, want) || bytes.Equal(got, s.keys[source.Purpose][source.Version]) {
				t.Fatal("cached plaintext replaced persisted source")
			}
		}
		if len(f.calls) < 4 {
			t.Fatal("missing remote operations")
		}
	})
	for _, failure := range []string{"corrupt", "format", "retired", "reference"} {
		t.Run(failure, func(t *testing.T) {
			db := newKeyManagerDB(t)
			s, target, f := gcpServiceFixture(t, db)
			row := gcpRows(t, db)[0]
			switch failure {
			case "corrupt":
				row.WrappedKey = "wk:2:gcp:YmFk"
			case "format":
				row.WrappedKey = "wk:2:kms:YmFk"
			case "retired":
				now := time.Now()
				row.KEKRetiredAt = &now
			case "reference":
				row.KEKID = gcpTargetRef
			}
			if failure == "corrupt" || failure == "format" {
				if err := db.Model(&row).Update("wrapped_key", row.WrappedKey).Error; err != nil {
					t.Fatal(err)
				}
				before := gcpRows(t, db)
				mem := snapshotGCPMemory(s)
				result, err := s.RewrapKEK(context.Background(), gcpTarget(t, target))
				if result != nil || err == nil {
					t.Fatal("bad row accepted despite valid cache")
				}
				assertGCPRollback(t, s, before, mem)
			} else {
				if result, err := rewrapGCPRow(context.Background(), s.kek, target, row); result != "" || !errors.Is(err, ErrKEKMismatch) {
					t.Fatal("ineligible source accepted")
				}
			}
			if failure != "corrupt" && len(f.calls) != 0 {
				t.Fatal("ineligible row left process")
			}
		})
	}
}
func TestGCPRewrapInTransaction(t *testing.T) {
	db := newKeyManagerDB(t)
	s, target, f := gcpServiceFixture(t, db)
	pool := installGCPTxPool(t, db)
	ctx := context.WithValue(context.Background(), gcpContextKey{}, "request")
	f.hook = func(call context.Context, method string, aad []byte) error {
		if !pool.active || call.Value(gcpContextKey{}) != "request" {
			t.Fatal("operation escaped request transaction")
		}
		if kekProcessMu.TryLock() {
			kekProcessMu.Unlock()
			t.Fatal("operation escaped key lock")
		}
		if _, ok := call.Deadline(); !ok {
			t.Fatal("remote operation has no deadline")
		}
		if len(aad) == 0 {
			t.Fatal("missing source AAD")
		}
		pool.events = append(pool.events, method)
		return nil
	}
	result, err := s.RewrapKEK(ctx, gcpTarget(t, target))
	if err != nil || result == nil {
		t.Fatalf("transaction rewrap failed: %v", err)
	}
	want := []string{"begin", "decrypt", "encrypt", "create", "decrypt", "encrypt", "create", "commit"}
	if !reflect.DeepEqual(pool.events, want) {
		t.Fatalf("unexpected operation order: %v", pool.events)
	}
}

type gcpContextKey struct{}

func TestGCPRewrapPlaceholder(t *testing.T) {
	db := newKeyManagerDB(t)
	s, target, f := gcpServiceFixture(t, db)
	if err := db.Model(&model.DataKey{}).Where("kek_id = ?", gcpSourceRef).Updates(map[string]any{"wrapped_key": "", "status": model.DataKeyStatusRetired}).Error; err != nil {
		t.Fatal(err)
	}
	result, err := s.RewrapKEK(context.Background(), gcpTarget(t, target))
	if err != nil || result == nil || result.RewrappedKeys != 2 || len(f.calls) != 0 {
		t.Fatal("placeholder required material")
	}
	var count int64
	db.Model(&model.DataKey{}).Where("kek_id = ? AND kek_pending = ? AND wrapped_key = ?", gcpTargetRef, true, "").Count(&count)
	if count != 2 {
		t.Fatal("placeholder chain changed")
	}
}
