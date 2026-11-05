package session

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/keystroke"
	"github.com/custodexa/backend/internal/model"
)

func ksPutFile(t *testing.T, root, rel string, mtime time.Time) {
	t.Helper()
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(full, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

func ksRow(t *testing.T, r *ksRig, sid uint, status string, started time.Time, last, ended *time.Time) string {
	t.Helper()
	uid := "00000000-0000-4000-8000-0000000000" + string(rune('0'+sid/10)) + string(rune('0'+sid%10))
	rel := keystroke.RelPath(uid, started)
	if status != model.KeystrokeStatusNotCovered {
		ksPutFile(t, r.root, rel, started)
	}
	if err := r.db.Create(&model.KeystrokeRecord{
		RecordUUID: uid, SessionID: sid, Protocol: "ssh", Status: status, FilePath: rel,
		FileKeyEnc: "enc:aa", StartedAt: started, LastWriteAt: last, EndedAt: ended,
	}).Error; err != nil {
		t.Fatal(err)
	}
	return rel
}

func TestKeystrokeRetentionPurgesExpiredOnly(t *testing.T) {
	r := newKsRig(t)
	now := time.Now()
	old := now.AddDate(0, 0, -40)
	fresh := now.AddDate(0, 0, -2)
	oldRel := ksRow(t, r, 1, model.KeystrokeStatusComplete, old, &old, &old)
	freshRel := ksRow(t, r, 2, model.KeystrokeStatusComplete, fresh, &fresh, &fresh)
	// 寫入中的長會話：起點很舊但心跳新，且狀態是 recording，絕不可刪
	recRel := ksRow(t, r, 3, model.KeystrokeStatusRecording, old, &now, nil)
	// 只有 started_at 的失敗列會到期
	failRel := ksRow(t, r, 4, model.KeystrokeStatusFailed, old, nil, nil)

	res, err := r.svc.PurgeExpiredKeystrokes(30, 100)
	if err != nil || res.Purged != 2 || res.Errors != 0 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	for _, rel := range []string{oldRel, failRel} {
		if _, err := os.Stat(filepath.Join(r.root, rel)); !os.IsNotExist(err) {
			t.Fatalf("%s should be deleted", rel)
		}
	}
	for _, rel := range []string{freshRel, recRel} {
		if _, err := os.Stat(filepath.Join(r.root, rel)); err != nil {
			t.Fatalf("%s must be kept: %v", rel, err)
		}
	}
	for sid, want := range map[uint]string{1: model.KeystrokeStatusPurged, 2: model.KeystrokeStatusComplete,
		3: model.KeystrokeStatusRecording, 4: model.KeystrokeStatusPurged} {
		row := r.row(t, sid)
		if row.Status != want {
			t.Fatalf("session %d status=%s want %s", sid, row.Status, want)
		}
		if want == model.KeystrokeStatusPurged && (row.FileKeyEnc != "" || row.PurgedAt == nil || row.FilePath == "") {
			t.Fatalf("purged row must clear key, set purged_at and keep file_path: %+v", row)
		}
		if want != model.KeystrokeStatusPurged && row.FileKeyEnc == "" {
			t.Fatalf("session %d lost its key", sid)
		}
	}
}

func TestKeystrokeRetentionMissingFileStillPurged(t *testing.T) {
	r := newKsRig(t)
	old := time.Now().AddDate(0, 0, -40)
	rel := ksRow(t, r, 5, model.KeystrokeStatusIncomplete, old, &old, &old)
	_ = os.Remove(filepath.Join(r.root, rel))
	res, err := r.svc.PurgeExpiredKeystrokes(30, 100)
	if err != nil || res.Purged != 1 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestKeystrokeRetentionIgnoresRecordingRetention(t *testing.T) {
	// 鍵盤紀錄的到期只由自己的天數決定：天數 0 不清任何東西
	r := newKsRig(t)
	old := time.Now().AddDate(0, 0, -400)
	ksRow(t, r, 6, model.KeystrokeStatusComplete, old, &old, &old)
	res, err := r.svc.PurgeExpiredKeystrokes(0, 100)
	if err != nil || res.Purged != 0 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if r.row(t, 6).Status != model.KeystrokeStatusComplete {
		t.Fatal("row must be untouched when retention is 0 (keep forever)")
	}
}

func TestKeystrokeRetentionOrphansClearedInBatches(t *testing.T) {
	r := newKsRig(t)
	old := time.Now().AddDate(0, 0, -40)
	day := old.UTC().Format("2006-01-02")
	known := ksRow(t, r, 7, model.KeystrokeStatusRecording, old, &old, nil) // 有列、狀態為 recording：不是孤兒
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		ksPutFile(t, r.root, filepath.Join(day, n+".cxkr"), old)
	}
	ksPutFile(t, r.root, filepath.Join(day, "notes.txt"), old)       // 非 .cxkr：不動
	ksPutFile(t, r.root, filepath.Join(day, "young.cxkr"), time.Now()) // mtime 新：不動

	total := 0
	for i := 0; i < 5; i++ { // 單次上限 2，分次清完
		res, err := r.svc.PurgeExpiredKeystrokes(30, 2)
		if err != nil {
			t.Fatal(err)
		}
		if res.Orphans > 2 {
			t.Fatalf("limit exceeded: %+v", res)
		}
		total += res.Orphans
	}
	if total != 5 {
		t.Fatalf("orphans removed=%d want 5", total)
	}
	for _, keep := range []string{known, filepath.Join(day, "notes.txt"), filepath.Join(day, "young.cxkr")} {
		if _, err := os.Stat(filepath.Join(r.root, keep)); err != nil {
			t.Fatalf("%s must be kept: %v", keep, err)
		}
	}
}

func TestKeystrokeRetentionRemovesEmptyDateDirs(t *testing.T) {
	r := newKsRig(t)
	old := time.Now().AddDate(0, 0, -40)
	day := old.UTC().Format("2006-01-02")
	ksPutFile(t, r.root, filepath.Join(day, "z.cxkr"), old)
	if _, err := r.svc.PurgeExpiredKeystrokes(30, 100); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(r.root, day)); !os.IsNotExist(err) {
		t.Fatal("empty date directory should be removed")
	}
}

func TestKeystrokeRetentionRejectsEscapingPath(t *testing.T) {
	r := newKsRig(t)
	if err := os.MkdirAll(r.root, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(filepath.Dir(r.root), "victim.txt")
	_ = os.WriteFile(outside, []byte("keep"), 0o600)
	old := time.Now().AddDate(0, 0, -40)
	if err := r.db.Create(&model.KeystrokeRecord{
		RecordUUID: "00000000-0000-4000-8000-000000000099", SessionID: 99, Protocol: "ssh",
		Status: model.KeystrokeStatusComplete, FilePath: "../victim.txt", FileKeyEnc: "enc:aa",
		StartedAt: old, EndedAt: &old,
	}).Error; err != nil {
		t.Fatal(err)
	}
	res, err := r.svc.PurgeExpiredKeystrokes(30, 100)
	if err != nil || res.Errors != 1 || res.Purged != 0 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatal("file outside the root must not be deleted")
	}
}
