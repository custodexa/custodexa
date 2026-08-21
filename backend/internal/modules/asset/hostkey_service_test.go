package asset

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupHostKeyDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.AssetHostKey{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func genHostKey(t *testing.T) ssh.PublicKey {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh pub: %v", err)
	}
	return sshPub
}

func TestHostKeyTOFUAndMatch(t *testing.T) {
	svc := NewHostKeyService(setupHostKeyDB(t))
	key := genHostKey(t)
	cb := svc.Callback(7)

	// 首連：TOFU 記錄
	if err := cb("host:22", nil, key); err != nil {
		t.Fatalf("first use should pass: %v", err)
	}
	rec, err := svc.Get(7)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if rec.Fingerprint != ssh.FingerprintSHA256(key) {
		t.Errorf("fingerprint mismatch: %s", rec.Fingerprint)
	}

	// 重連同金鑰：放行
	if err := cb("host:22", nil, key); err != nil {
		t.Errorf("same key should pass: %v", err)
	}
}

func TestHostKeyChangedRejected(t *testing.T) {
	svc := NewHostKeyService(setupHostKeyDB(t))
	cb := svc.Callback(7)

	if err := cb("host:22", nil, genHostKey(t)); err != nil {
		t.Fatalf("first: %v", err)
	}
	err := cb("host:22", nil, genHostKey(t)) // 不同金鑰
	if !errors.Is(err, ErrHostKeyChanged) {
		t.Errorf("changed key must be rejected, got %v", err)
	}
}

func TestHostKeyReset(t *testing.T) {
	svc := NewHostKeyService(setupHostKeyDB(t))
	cb := svc.Callback(7)
	_ = cb("host:22", nil, genHostKey(t))

	existed, err := svc.Reset(7)
	if err != nil || !existed {
		t.Fatalf("Reset = %v, %v", existed, err)
	}

	// 重置後新金鑰重新 TOFU
	newKey := genHostKey(t)
	if err := cb("host:22", nil, newKey); err != nil {
		t.Errorf("re-TOFU after reset should pass: %v", err)
	}

	existed, _ = svc.Reset(999)
	if existed {
		t.Error("reset unknown asset should report false")
	}
}
