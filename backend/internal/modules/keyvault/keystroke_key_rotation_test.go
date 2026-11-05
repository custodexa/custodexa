package keyvault

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/keystroke"
	"github.com/custodexa/backend/internal/keystroke/format"
	"github.com/custodexa/backend/internal/keystroke/reader"
	"github.com/custodexa/backend/internal/keystroke/writer"
	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/model"
)

const ksRotUUID = "11111111-2222-4333-8444-555555555555"

// writeKeystrokeFile 以真實寫入器寫出一份紀錄檔，檔案金鑰以資料 DEK 封存，回封存值與檔案路徑資訊。
func writeKeystrokeFile(t *testing.T, km *KeyManagerService, root string, sessionID uint) (enc string, rel string) {
	t.Helper()
	fek := make([]byte, 32)
	if _, err := rand.Read(fek); err != nil {
		t.Fatal(err)
	}
	var err error
	enc, err = km.EncryptBytesFor(context.Background(), RefKeystrokeFileKey, fek)
	if err != nil {
		t.Fatalf("seal FEK: %v", err)
	}
	start := time.Date(2026, 11, 5, 3, 4, 5, 0, time.UTC)
	w, err := writer.Open(writer.Config{
		Root: root, RecordUUID: ksRotUUID, SessionID: uint64(sessionID), Protocol: "ssh",
		Start: start, Key: material.Adopt(append([]byte(nil), fek...)),
	})
	if err != nil {
		t.Fatalf("open writer: %v", err)
	}
	_ = w.Append(format.KindBytes, 0, []byte("whoami\r"))
	if _, err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	return enc, keystroke.RelPath(ksRotUUID, start)
}

func fileSHA(t *testing.T, path string) [32]byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(b)
}

// 2.5：資料 DEK 輪替後舊紀錄仍可解、檔案位元組未被改寫（SHA-256 相同）；
// 檔案金鑰封存值被重加密至新版本。
func TestKeystrokeRotationKeepsFileUnchangedAndReadable(t *testing.T) {
	db, km := setupKM(t)
	root := filepath.Join(t.TempDir(), "keystrokes")
	enc, rel := writeKeystrokeFile(t, km, root, 91)
	row := model.KeystrokeRecord{RecordUUID: ksRotUUID, SessionID: 91, Protocol: "ssh",
		Status: model.KeystrokeStatusComplete, FileKeyEnc: enc, FilePath: rel, StartedAt: time.Now()}
	if err := db.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	before := fileSHA(t, filepath.Join(root, rel))

	if _, err := km.RotateDataDEK(); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	if after := fileSHA(t, filepath.Join(root, rel)); after != before {
		t.Fatal("rotation must not rewrite keystroke files (SHA-256 changed)")
	}
	var got string
	if err := db.Raw("SELECT file_key_enc FROM keystroke_records WHERE id = ?", row.ID).Scan(&got).Error; err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "enc:a1:v2:") {
		t.Fatalf("file key envelope not re-encrypted to v2: prefix=%q", got[:min(len(got), 10)])
	}
	fek, err := km.DecryptBytesFor(context.Background(), RefKeystrokeFileKey, got)
	if err != nil {
		t.Fatalf("decrypt FEK after rotation: %v", err)
	}
	defer fek.Destroy()
	var res reader.Result
	if err := fek.Borrow(func(k []byte) error {
		res = reader.Read(root, reader.Record{UUID: ksRotUUID, SessionID: 91, Protocol: "ssh", FilePath: rel}, k, reader.Options{})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if res.Status != reader.StatusComplete || res.TotalEvents != 1 {
		t.Fatalf("status=%s events=%d", res.Status, res.TotalEvents)
	}
}

// 2.5：退役的資料 DEK 版本在仍有紀錄引用其封存的檔案金鑰時不可銷毀；
// 清除後（file_key_enc 設空字串）不再計入引用，方可銷毀。
func TestRetiredKeyNotPurgedWhileKeystrokeRecordReferences(t *testing.T) {
	db, km := setupKM(t)
	root := filepath.Join(t.TempDir(), "keystrokes")
	// 以 v1 封存（輪替後 active 為 v2，屆時再加密只會得到 v2）
	enc, rel := writeKeystrokeFile(t, km, root, 92)
	if !strings.HasPrefix(enc, "enc:a1:v1:") {
		t.Fatalf("seal must be v1: %q", enc[:min(len(enc), 10)])
	}
	if _, err := rewrapKEKWith(t, km, newTestKEKMaterial(t)); err != nil {
		t.Fatalf("rewrap: %v", err)
	}
	if _, err := km.AbandonRewrap(); err != nil {
		t.Fatalf("abandon: %v", err)
	}
	if _, err := km.RotateDataDEK(); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	// 輪替會把列重加密到 v2；把 v1 殘值放回去模擬「仍有紀錄引用舊版本」的狀態
	row := model.KeystrokeRecord{RecordUUID: ksRotUUID, SessionID: 92, Protocol: "ssh",
		Status: model.KeystrokeStatusComplete, FileKeyEnc: enc, FilePath: rel, StartedAt: time.Now()}
	if err := db.Create(&row).Error; err != nil {
		t.Fatal(err)
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
				t.Fatalf("skip must carry refs and reason: %+v", sk)
			}
		}
	}
	if !skipped {
		t.Fatalf("data v1 must not be purged while a keystroke record references it: %+v", result)
	}

	// 保留期清除：金鑰欄清為空字串後不計入引用
	if err := db.Model(&model.KeystrokeRecord{}).Where("id = ?", row.ID).
		Updates(map[string]interface{}{"file_key_enc": "", "status": model.KeystrokeStatusPurged}).Error; err != nil {
		t.Fatal(err)
	}
	result2, err := km.CleanupRetiredMaterial()
	if err != nil {
		t.Fatalf("cleanup2: %v", err)
	}
	for _, sk := range result2.Skipped {
		if sk.Purpose == model.DataKeyPurposeData && sk.Version == 1 {
			t.Fatalf("empty file_key_enc must not count as a reference: %+v", sk)
		}
	}
}
