package sealjournal

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestOpenCreatesJournalAndSyncsParentDirectory 驗收：首次建立路徑（含目錄項 fsync）。
// 啟動恢復 (0)：建立 → 預配置 → 初始 header → fdatasync → fsync 父目錄。
func TestOpenCreatesJournalAndSyncsParentDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "audit")

	var syncedDirs []string
	orig := syncDirFn
	syncDirFn = func(d string) error {
		syncedDirs = append(syncedDirs, d)
		return orig(d)
	}
	t.Cleanup(func() { syncDirFn = orig })

	j := openTestJournal(t, dir)
	path := journalPath(dir)

	if len(syncedDirs) != 1 || syncedDirs[0] != dir {
		t.Fatalf("首次建立必須同步父目錄項一次（目標 %q），實際 %v", dir, syncedDirs)
	}
	want := layout{criticalSlots: 64, rejectedSlots: 16}.fileSize()
	if got := fileSizeOf(t, path); got != want {
		t.Fatalf("建立後應為預配置大小 %d，得 %d", want, got)
	}
	// 檔案必須實體預配置（非 sparse truncate）：實際佔用的位元組已寫入。
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("讀檔失敗: %v", err)
	}
	if int64(len(raw)) != want {
		t.Fatalf("預配置長度不符: %d", len(raw))
	}
	st := mustStatus(t, j)
	if st.HeaderGeneration == 0 || st.SeqNext != 1 {
		t.Fatalf("初始 header 不正確: %+v", st)
	}
}

// TestOpenFailsWhenParentDirSyncFails 驗收：建立過程任一步失敗即回錯（不開放監聽）。
func TestOpenFailsWhenParentDirSyncFails(t *testing.T) {
	dir := t.TempDir()
	orig := syncDirFn
	syncDirFn = func(string) error { return errors.New("模擬目錄同步失敗") }
	t.Cleanup(func() { syncDirFn = orig })

	if _, err := Open(dir, testOptions()...); err == nil {
		t.Fatal("父目錄項同步失敗時必須回錯")
	}
}

// TestOpenFailsWhenJournalCannotBeCreated 驗收：journal 無法建立時回錯
// （B 模式呼叫端據此拒絕開放監聽）。
func TestOpenFailsWhenJournalCannotBeCreated(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "blocker")
	if err := os.WriteFile(blocker, []byte("not a dir"), 0o600); err != nil {
		t.Fatalf("前置失敗: %v", err)
	}
	// 目標目錄的父層是一個 regular file，MkdirAll 必然失敗。
	if _, err := Open(filepath.Join(blocker, "sub"), testOptions()...); err == nil {
		t.Fatal("無法建立 journal 時必須回錯")
	}
}

// TestOpenRejectsBothHeadersInvalidWithoutTouchingFile 驗收：
// 啟動恢復 (i)——兩 header 皆無效 → 拒絕開啟、保留原樣、絕不截斷／重建／掃槽重置。
// 斷言打在檔案位元雜湊上。
func TestOpenRejectsBothHeadersInvalidWithoutTouchingFile(t *testing.T) {
	dir := t.TempDir()
	j := openTestJournal(t, dir)
	writeAttempt(t, j, 1, OutcomeSuccess)
	writeAttempt(t, j, 1, OutcomeMaterialFailure)
	if err := j.Close(); err != nil {
		t.Fatalf("Close 失敗: %v", err)
	}
	path := journalPath(dir)

	// 破壞兩個 header 槽（資料槽保持原樣）。
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("開檔失敗: %v", err)
	}
	garbage := make([]byte, headerSlotSize*headerSlotCount)
	for i := range garbage {
		garbage[i] = 0xAB
	}
	if _, err := f.WriteAt(garbage, 0); err != nil {
		t.Fatalf("寫入失敗: %v", err)
	}
	_ = f.Close()

	sizeBefore := fileSizeOf(t, path)
	hashBefore := fileHash(t, path)

	reopened, err := Open(dir, testOptions()...)
	if !errors.Is(err, ErrHeaderInvalid) {
		if reopened != nil {
			_ = reopened.Close()
		}
		t.Fatalf("兩 header 皆無效必須回 ErrHeaderInvalid（不得自動重建），得 %v", err)
	}
	if got := fileHash(t, path); got != hashBefore {
		t.Fatal("拒絕開啟時檔案位元必須完全未被改寫")
	}
	if got := fileSizeOf(t, path); got != sizeBefore {
		t.Fatalf("檔案長度不得變動：%d → %d", sizeBefore, got)
	}
}

// TestOpenSurvivesSingleCorruptHeaderSlot 驗收：雙槽輪替——
// 只有一個 header 槽毀損時，取另一個有效且 generation 較大者繼續運作。
func TestOpenSurvivesSingleCorruptHeaderSlot(t *testing.T) {
	dir := t.TempDir()
	j := openTestJournal(t, dir)
	writeAttempt(t, j, 1, OutcomeSuccess) // 至少兩次 header 推進，兩槽都有內容
	writeAttempt(t, j, 1, OutcomeSuccess)
	stBefore := mustStatus(t, j)
	_ = j.Close()

	path := journalPath(dir)
	f, _ := os.OpenFile(path, os.O_RDWR, 0o600)
	// 只破壞當前較新的那個槽，較舊的仍有效。
	stale := headerSlotOffset(stBefore.HeaderGeneration)
	garbage := make([]byte, headerSlotSize)
	if _, err := f.WriteAt(garbage, stale); err != nil {
		t.Fatalf("寫入失敗: %v", err)
	}
	_ = f.Close()

	reopened, err := Open(dir, testOptions()...)
	if err != nil {
		t.Fatalf("單槽毀損時應以另一槽恢復: %v", err)
	}
	defer reopened.Close()
	st := mustStatus(t, reopened)
	if st.ReceivedTotal == 0 {
		t.Fatalf("恢復後計數器不得歸零: %+v", st)
	}
}

// TestOpenRejectsNonRegularFile 驗收：(i-b) 非 regular file 一律 fail-close。
func TestOpenRejectsNonRegularFile(t *testing.T) {
	dir := t.TempDir()
	j := openTestJournal(t, dir, WithFileName("real.bin"))
	_ = j.Close()

	link := filepath.Join(dir, DefaultFileName)
	if err := os.Symlink(filepath.Join(dir, "real.bin"), link); err != nil {
		t.Fatalf("建立 symlink 失敗: %v", err)
	}
	hashBefore := fileHash(t, filepath.Join(dir, "real.bin"))

	if _, err := Open(dir, testOptions()...); !errors.Is(err, ErrNotRegularFile) {
		t.Fatalf("symlink 必須被拒，得 %v", err)
	}
	if got := fileHash(t, filepath.Join(dir, "real.bin")); got != hashBefore {
		t.Fatal("拒絕時不得改寫目標檔案")
	}
}

// TestOpenRejectsSizeMismatch 驗收：(i-b) 長度不符預配置即 fail-close，且不補齊不截斷。
func TestOpenRejectsSizeMismatch(t *testing.T) {
	dir := t.TempDir()
	j := openTestJournal(t, dir)
	_ = j.Close()
	path := journalPath(dir)

	f, _ := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0o600)
	if _, err := f.Write([]byte{0x01}); err != nil {
		t.Fatalf("寫入失敗: %v", err)
	}
	_ = f.Close()
	hashBefore := fileHash(t, path)

	if _, err := Open(dir, testOptions()...); !errors.Is(err, ErrSizeMismatch) {
		t.Fatalf("長度不符必須被拒，得 %v", err)
	}
	if got := fileHash(t, path); got != hashBefore {
		t.Fatal("拒絕時不得截斷或補齊檔案")
	}
}

// TestOpenRejectsLayoutMismatch 驗收：(i-b) 佈局偏移不合即 fail-close。
// 兩組容量刻意取相同總長度，證明檢查不是只比大小。
func TestOpenRejectsLayoutMismatch(t *testing.T) {
	dir := t.TempDir()
	a := layout{criticalSlots: 8, rejectedSlots: 4}
	b := layout{criticalSlots: 7, rejectedSlots: 6}
	if a.fileSize() != b.fileSize() {
		t.Fatalf("測試前提：兩組佈局總長度應相同（%d vs %d）", a.fileSize(), b.fileSize())
	}

	j, err := Open(dir, WithCapacity(8, 4), WithRejectedFlushInterval(time.Hour))
	if err != nil {
		t.Fatalf("Open 失敗: %v", err)
	}
	_ = j.Close()
	hashBefore := fileHash(t, journalPath(dir))

	if _, err := Open(dir, WithCapacity(7, 6), WithRejectedFlushInterval(time.Hour)); !errors.Is(err, ErrLayoutMismatch) {
		t.Fatalf("佈局偏移不合必須被拒，得 %v", err)
	}
	if got := fileHash(t, journalPath(dir)); got != hashBefore {
		t.Fatal("拒絕時不得改寫檔案")
	}
}

// TestCorruptCriticalSlotProducesSeqGap 驗收：
// (ii) 序號缺口與 (iii) 環繞中 torn overwrite——CRC 不符即標 corrupt，缺口據實回報。
func TestCorruptCriticalSlotProducesSeqGap(t *testing.T) {
	dir := t.TempDir()
	j := openTestJournal(t, dir)
	for i := 0; i < 3; i++ {
		writeAttempt(t, j, 1, "")
	}
	_ = j.Close()
	path := journalPath(dir)

	// 模擬 torn write：翻動第 2 槽（seq=2）的一個位元組，CRC 隨即不符。
	f, _ := os.OpenFile(path, os.O_RDWR, 0o600)
	off := criticalRingOffset + criticalSlotSize + 80
	if _, err := f.WriteAt([]byte{0xFF}, off); err != nil {
		t.Fatalf("寫入失敗: %v", err)
	}
	_ = f.Close()

	reopened := openTestJournal(t, dir)
	st := mustStatus(t, reopened)
	if st.CorruptCriticalSlots != 1 {
		t.Fatalf("應偵測到 1 個 corrupt 槽，得 %d", st.CorruptCriticalSlots)
	}
	if len(st.MissingSeqs) != 1 || st.MissingSeqs[0] != 2 {
		t.Fatalf("序號缺口應為 [2]，得 %v", st.MissingSeqs)
	}
}
