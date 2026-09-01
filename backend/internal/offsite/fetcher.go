package offsite

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// 取回：本機優先由呼叫端判定，本檔負責「離機來源」那一半——
// **先落暫存、驗過才交付**。
//
// 為什麼不直接把 `GetObject` 的串流轉發出去：交付後才發現雜湊不符，等於已經
// 把不可信的內容播給稽核員看了；而 Range 讀取根本無從驗。落暫存的代價是首次
// 取回的延遲與一塊有上限的磁碟，換到的是「Range 播放也是驗過的內容」。

// ErrNoOffsiteCopy 該帳冊列沒有可取回的遠端副本（從未上傳成功，
// 或已判完整性不符）。**與「取回失敗」分立**：這是「本來就沒有」。
var ErrNoOffsiteCopy = errors.New("offsite: 該物件沒有可取回的離機副本")

// ErrIntegrityMismatch 取回內容與上傳當下的 SHA-256／大小不符，**已拒絕交付**
// （fail-close）。零位元組對外，帳冊轉 integrity_mismatch 並留痕。
var ErrIntegrityMismatch = errors.New(ErrCodeIntegrityMismatch)

// spoolIdleTTL 暫存檔的閒置回收門檻。
const spoolIdleTTL = 30 * time.Minute

// spoolMaxBytes 暫存總量上限；超過時淘汰最久未用。
// **單一物件大於上限仍會取回**（暫時超額）——否則大檔永遠播不出來。
const spoolMaxBytes int64 = 4 << 30 // 4 GiB

// spoolDirPerm 暫存根權限（0700）：內容是解密／驗證後的證據副本。
const spoolDirPerm os.FileMode = 0o700

// FetchedObject 已驗證的暫存副本。
type FetchedObject struct {
	// Path 暫存檔絕對路徑（已驗過 SHA-256 與大小）
	Path string
	Size int64
	// UploadedAt 上傳當下的時刻（供 ServeContent 的 Last-Modified；
	// 用暫存檔自己的 mtime 會讓同一份證據每次取回都「變新」）
	UploadedAt time.Time
	// Kind／OwnerID 供呼叫端組檔名與審計
	Kind    string
	OwnerID uint
}

// fetchWait 單飛（singleflight）的等待格。
type fetchWait struct {
	done chan struct{}
	out  *FetchedObject
	err  error
}

// Fetcher 離機副本的取回與暫存。
type Fetcher struct {
	root     string
	ledger   *Ledger
	profiles *OffsiteProfileService
	journal  CustodyJournal
	failure  FailureReporter
	adapters map[string]Adapter
	now      func() time.Time

	mu       sync.Mutex
	inflight map[uint]*fetchWait
}

// NewFetcher 建立取回器。root 為暫存根（`OFFSITE_SPOOL_PATH`，容器本地、
// **放在錄影資料根之外**——資料根下的常規檔會被儲存量統計與 mtime 清理當成錄影）。
func NewFetcher(root string, ledger *Ledger, profiles *OffsiteProfileService,
	journal CustodyJournal, failure FailureReporter, adapters ...Adapter) *Fetcher {
	if journal == nil {
		journal = noopCustodyJournal{}
	}
	m := map[string]Adapter{}
	for _, a := range adapters {
		if a != nil {
			m[a.Kind()] = a
		}
	}
	return &Fetcher{
		root: root, ledger: ledger, profiles: profiles, journal: journal,
		failure: failure, adapters: m, now: time.Now,
		inflight: map[uint]*fetchWait{},
	}
}

// SetClockForTest 覆寫時間源（僅測試）。
func (f *Fetcher) SetClockForTest(now func() time.Time) { f.now = now }

// Object 取帳冊列（來源判定需要 size／sha256／state；**擁有表快取不可作判定依據**，
// 它只是顯示用的旁路副本）。
func (f *Fetcher) Object(objectID uint) (*model.OffsiteObject, error) {
	return f.ledger.Get(objectID)
}

// Fetch 取回並驗證某帳冊列的離機副本；同一物件的並發呼叫合併為一次下載。
func (f *Fetcher) Fetch(ctx context.Context, objectID uint) (*FetchedObject, error) {
	f.mu.Lock()
	if w, ok := f.inflight[objectID]; ok {
		f.mu.Unlock()
		select {
		case <-w.done:
			return w.out, w.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	w := &fetchWait{done: make(chan struct{})}
	f.inflight[objectID] = w
	f.mu.Unlock()

	w.out, w.err = f.fetchOnce(ctx, objectID)
	close(w.done)

	f.mu.Lock()
	delete(f.inflight, objectID)
	f.mu.Unlock()
	return w.out, w.err
}

// fetchOnce 單次取回（命中已驗證的暫存檔即直接服務）。
func (f *Fetcher) fetchOnce(ctx context.Context, objectID uint) (*FetchedObject, error) {
	row, err := f.ledger.Get(objectID)
	if err != nil {
		return nil, err
	}
	if row.State == StateIntegrityMismatch {
		// 已判不可信：不再重取（重取只會再驗一次同樣的內容）
		return nil, ErrIntegrityMismatch
	}
	if row.ObjectKey == "" || row.SHA256 == "" {
		// 從未上傳成功（pending／failed，或那兩者到期轉成的 local_purged）
		return nil, ErrNoOffsiteCopy
	}

	out := &FetchedObject{
		Path: f.dataPath(objectID, row.ObjectKey), Size: row.Size,
		Kind: row.Kind, OwnerID: row.OwnerID,
	}
	if row.UploadedAt != nil {
		out.UploadedAt = *row.UploadedAt
	}
	if f.hitSpool(out.Path, objectID, row.Size) {
		return out, nil
	}

	client, err := f.profiles.ClientFor(ctx, row.StorageGenerationID)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(f.root, spoolDirPerm); err != nil {
		return nil, fmt.Errorf("建立離機取回暫存目錄失敗: %w", err)
	}

	rc, err := client.Fetch(ctx, ObjectRef{Bucket: row.Bucket, Key: row.ObjectKey}, row.Size)
	if err != nil {
		return nil, fmt.Errorf("取回離機副本失敗（世代 %d／provider %s）: %w",
			row.StorageGenerationID, row.Provider, err)
	}
	defer rc.Close()

	tmp := f.tmpPath(objectID)
	sum, n, err := writeAndHash(tmp, rc)
	if err != nil {
		os.Remove(tmp)
		return nil, err
	}
	if sum != row.SHA256 || n != row.Size {
		os.Remove(tmp)
		f.rejectMismatch(row, sum, n)
		return nil, ErrIntegrityMismatch
	}
	if err := os.Rename(tmp, out.Path); err != nil {
		os.Remove(tmp)
		return nil, fmt.Errorf("暫存離機副本更名失敗: %w", err)
	}
	if err := f.markVerified(objectID); err != nil {
		log.Printf("[OffsiteFetcher] 寫入暫存驗證標記失敗（object=%d）: %v", objectID, err)
	}
	f.Reclaim()
	return out, nil
}

// writeAndHash 寫入暫存檔並同時計算 SHA-256 與大小（驗過才交付）。
func writeAndHash(path string, r io.Reader) (string, int64, error) {
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", 0, fmt.Errorf("建立離機取回暫存檔失敗: %w", err)
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(fh, h), r)
	closeErr := fh.Close()
	if copyErr != nil {
		return "", 0, fmt.Errorf("寫入離機取回暫存檔失敗: %w", copyErr)
	}
	if closeErr != nil {
		return "", 0, fmt.Errorf("關閉離機取回暫存檔失敗: %w", closeErr)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// rejectMismatch 完整性不符的四件事：帳冊態、擁有表快取、保管鏈事件、機制級告警。
//
// **不含實際雜湊值以外的任何遠端細節**（無端點、無憑證）；四件事任一失敗只記 log
// ——內容已被拒絕交付，這才是使用者面的正確結果，補記失敗不該把它翻回「可播放」。
func (f *Fetcher) rejectMismatch(row *model.OffsiteObject, gotSum string, gotSize int64) {
	if err := f.ledger.MarkIntegrityMismatch(row.ID); err != nil {
		log.Printf("[OffsiteFetcher] 標記完整性不符失敗（object=%d）: %v", row.ID, err)
	}
	if a, ok := f.adapters[row.Kind]; ok {
		if err := a.SetStatus(row.OwnerID, row.ID, StateIntegrityMismatch); err != nil {
			log.Printf("[OffsiteFetcher] 寫回擁有表快取失敗（object=%d）: %v", row.ID, err)
		}
	}
	ownerID := row.OwnerID
	if err := f.journal.Record(CustodyEvent{
		Action:     CustodyActionIntegrity,
		Resource:   custodyResourceOf(row.Kind),
		ResourceID: &ownerID,
		Status:     string(model.StatusFailure),
		Details: map[string]any{
			"object_id":     row.ID,
			"kind":          row.Kind,
			"bucket":        row.Bucket,
			"key":           row.ObjectKey,
			"expected_size": row.Size,
			"actual_size":   gotSize,
			"sha256_match":  gotSum == row.SHA256,
			"error_code":    ErrCodeIntegrityMismatch,
		},
	}); err != nil {
		log.Printf("[OffsiteFetcher] 寫入完整性保管鏈事件失敗（object=%d）: %v", row.ID, err)
	}
	if f.failure != nil {
		f.failure.Report(model.MechanismOffsiteUpload, model.CauseOffsiteIntegrityMismatch,
			map[string]string{
				"object_id": strconv.FormatUint(uint64(row.ID), 10),
				"kind":      row.Kind,
			})
	}
}

// ── 暫存目錄 ──────────────────────────────────────────────────────────────

func (f *Fetcher) dataPath(objectID uint, key string) string {
	ext := filepath.Ext(key)
	return filepath.Join(f.root, fmt.Sprintf("%d%s", objectID, ext))
}

func (f *Fetcher) tmpPath(objectID uint) string {
	return filepath.Join(f.root, fmt.Sprintf("%d.tmp", objectID))
}

func (f *Fetcher) okPath(objectID uint) string {
	return filepath.Join(f.root, fmt.Sprintf("%d.ok", objectID))
}

// hitSpool 命中已驗證的暫存檔？**標記檔與資料檔都在、且大小相符**才算。
//
// 標記檔的存在是「這份內容驗過」的唯一憑據：只看資料檔會把中斷留下的殘檔
// （或被更名為 .tmp 之外形態的東西）當成驗過的內容直接播出去。命中時順手
// 更新標記檔 mtime——閒置回收據此判定「最久未用」。
func (f *Fetcher) hitSpool(dataPath string, objectID uint, wantSize int64) bool {
	ok := f.okPath(objectID)
	if _, err := os.Stat(ok); err != nil {
		return false
	}
	info, err := os.Stat(dataPath)
	if err != nil || info.Size() != wantSize {
		return false
	}
	now := f.now()
	if err := os.Chtimes(ok, now, now); err != nil {
		log.Printf("[OffsiteFetcher] 更新暫存使用時刻失敗（object=%d）: %v", objectID, err)
	}
	return true
}

func (f *Fetcher) markVerified(objectID uint) error {
	return os.WriteFile(f.okPath(objectID), []byte("ok"), 0o600)
}

// spoolEntry 一份暫存副本（資料檔＋標記檔）。
type spoolEntry struct {
	objectID uint
	data     string
	size     int64
	lastUsed time.Time
}

// listSpool 列出目前的暫存副本（以標記檔為準——沒有標記檔的資料檔不算副本）。
func (f *Fetcher) listSpool() ([]spoolEntry, int64, error) {
	entries, err := os.ReadDir(f.root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, nil
		}
		return nil, 0, err
	}
	marks := map[uint]time.Time{}
	files := map[uint]os.DirEntry{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		base := strings.TrimSuffix(name, filepath.Ext(name))
		id64, err := strconv.ParseUint(base, 10, 64)
		if err != nil {
			continue
		}
		id := uint(id64)
		if strings.HasSuffix(name, ".ok") {
			if info, err := e.Info(); err == nil {
				marks[id] = info.ModTime()
			}
			continue
		}
		if strings.HasSuffix(name, ".tmp") {
			continue
		}
		files[id] = e
	}
	var out []spoolEntry
	var total int64
	for id, mark := range marks {
		de, ok := files[id]
		if !ok {
			continue
		}
		info, err := de.Info()
		if err != nil {
			continue
		}
		total += info.Size()
		out = append(out, spoolEntry{objectID: id, data: filepath.Join(f.root, de.Name()),
			size: info.Size(), lastUsed: mark})
	}
	return out, total, nil
}

// SpoolBytes 暫存目前佔用（指標 `custodexa_offsite_spool_bytes`）。
func (f *Fetcher) SpoolBytes() int64 {
	_, total, err := f.listSpool()
	if err != nil {
		log.Printf("[OffsiteFetcher] 統計暫存佔用失敗: %v", err)
		return 0
	}
	return total
}

// Reclaim 暫存回收：先清閒置逾 30 分鐘者，再於總量超上限時淘汰最久未用。
//
// 由 worker 每輪順帶呼叫，取回成功後亦呼叫一次（避免只有取回而 worker 未啟用的
// 停用態部署把暫存長成無界）。
func (f *Fetcher) Reclaim() {
	list, total, err := f.listSpool()
	if err != nil {
		log.Printf("[OffsiteFetcher] 暫存回收列舉失敗: %v", err)
		return
	}
	now := f.now()
	kept := make([]spoolEntry, 0, len(list))
	for _, e := range list {
		if now.Sub(e.lastUsed) > spoolIdleTTL {
			f.dropSpool(e)
			total -= e.size
			continue
		}
		kept = append(kept, e)
	}
	if total <= spoolMaxBytes {
		return
	}
	// 最久未用先淘汰；單一物件大於上限的情況下仍會留下它（暫時超額）
	sort.Slice(kept, func(i, j int) bool { return kept[i].lastUsed.Before(kept[j].lastUsed) })
	for _, e := range kept {
		if total <= spoolMaxBytes {
			return
		}
		f.dropSpool(e)
		total -= e.size
	}
}

func (f *Fetcher) dropSpool(e spoolEntry) {
	if err := os.Remove(e.data); err != nil && !os.IsNotExist(err) {
		log.Printf("[OffsiteFetcher] 清除暫存副本失敗（object=%d）: %v", e.objectID, err)
		return
	}
	if err := os.Remove(f.okPath(e.objectID)); err != nil && !os.IsNotExist(err) {
		log.Printf("[OffsiteFetcher] 清除暫存標記失敗（object=%d）: %v", e.objectID, err)
	}
}

// MachineCodeOf 自錯誤鏈取出對外機器碼（`offsite.*`）；無法辨識回空字串。
//
// 取回路徑的錯誤來源分散在三處（設定服務的世代與憑證判定、driver、本檔的完整性
// 判定），而 API 層要回的是**單一收斂碼**。集中在此比對，handler 就不必各自
// 認得每一種錯誤形狀——漏認一種的後果是把可辨識的失敗降級成 500。
func MachineCodeOf(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, ErrIntegrityMismatch) {
		return ErrCodeIntegrityMismatch
	}
	msg := err.Error()
	for _, code := range []string{
		ErrCodeProfileMissing, ErrCodeForeignCredentialsMissing,
		ErrCodeCredentialsUnavailable, ErrCodeIntegrityMismatch,
	} {
		if strings.Contains(msg, code) {
			return code
		}
	}
	return ""
}
