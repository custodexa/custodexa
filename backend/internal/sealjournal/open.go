package sealjournal

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

// DefaultFileName 為 journal 的固定檔名。
// 落點沿用既有 AUDIT_LOG_PATH 所在目錄，不新增任何 env 鍵。
const DefaultFileName = "seal_journal.bin"

// 預設參數。
const (
	DefaultMinAdmissionInterval  = 500 * time.Millisecond
	DefaultRejectedFlushInterval = 2 * time.Second
	DefaultWriteTimeout          = 5 * time.Second
)

// 開檔與運行期錯誤。這些錯誤一律為 fail-close 訊號：
// 呼叫端收到即 SHALL NOT 開放解封端點監聽（B 模式建立失敗＝不開放監聽）。
var (
	// ErrHeaderInvalid 對應啟動恢復 (i)：檔案存在但兩個 header 皆無效。
	// 此時 SHALL NOT 截斷、SHALL NOT 重建、SHALL NOT 掃槽重置——保留原樣供人工檢視。
	ErrHeaderInvalid = errors.New("sealjournal: 兩個 header 槽皆無效，拒絕開啟且保留檔案原樣")
	// ErrNotRegularFile 對應 (i-b)：非 regular file（symlink／FIFO／device）。
	ErrNotRegularFile = errors.New("sealjournal: journal 不是 regular file")
	// ErrSizeMismatch 對應 (i-b)：長度不符預配置大小。
	ErrSizeMismatch = errors.New("sealjournal: journal 長度不符預配置大小")
	// ErrLayoutMismatch 對應 (i-b)：固定佈局偏移不合。
	ErrLayoutMismatch = errors.New("sealjournal: journal 佈局偏移與預配置不符")
	// ErrUnreadable 對應 (i-b)：無法完整讀寫。
	ErrUnreadable = errors.New("sealjournal: journal 無法完整讀取")

	ErrClosed              = errors.New("sealjournal: journal 已關閉")
	ErrIOFaulted           = errors.New("sealjournal: journal 處於 I/O 故障狀態，拒收新嘗試")
	ErrInvalidSourceDigest = errors.New("sealjournal: sourceDigest 必須為 64 字元內的小寫十六進位摘要")
	ErrInvalidOutcome      = errors.New("sealjournal: 不合法的 outcome 結果碼")
	ErrUnknownSeq          = errors.New("sealjournal: 引用了不存在的全域序號")
)

// Options 為 journal 的可調參數。容量與間隔均為建構期固定值，運行期不變。
type Options struct {
	// FileName 為 journal 檔名（預設 DefaultFileName）。
	FileName string
	// CriticalSlots／RejectedSlots 為兩個定長環的槽數。檔案大小由此決定且永不成長。
	CriticalSlots int
	RejectedSlots int
	// MinAdmissionInterval 為固定最小 admission 間隔（非配額，無扣減／重置／視窗語義）。
	MinAdmissionInterval time.Duration
	// RejectedFlushInterval 為 rejected 記憶體聚合器的固定合批頻率。
	RejectedFlushInterval time.Duration
	// WriteTimeout 為單筆 critical 寫入（含 header fdatasync）的逾時上限。
	WriteTimeout time.Duration

	// wrapFile 僅供測試注入觀察／故障；產品路徑為 nil。
	wrapFile func(fileIO) fileIO
}

// Option 為函式式選項。
type Option func(*Options)

// WithFileName 覆寫檔名（測試與多實例隔離用）。
func WithFileName(name string) Option {
	return func(o *Options) { o.FileName = name }
}

// WithCapacity 設定兩個環的槽數。
func WithCapacity(critical, rejected int) Option {
	return func(o *Options) { o.CriticalSlots, o.RejectedSlots = critical, rejected }
}

// WithMinAdmissionInterval 設定固定最小 admission 間隔。
func WithMinAdmissionInterval(d time.Duration) Option {
	return func(o *Options) { o.MinAdmissionInterval = d }
}

// WithRejectedFlushInterval 設定 rejected 合批頻率。
func WithRejectedFlushInterval(d time.Duration) Option {
	return func(o *Options) { o.RejectedFlushInterval = d }
}

// WithWriteTimeout 設定 critical 寫入逾時。
func WithWriteTimeout(d time.Duration) Option {
	return func(o *Options) { o.WriteTimeout = d }
}

// withWrapFile 僅供本套件測試使用。
func withWrapFile(fn func(fileIO) fileIO) Option {
	return func(o *Options) { o.wrapFile = fn }
}

func defaultOptions() Options {
	return Options{
		FileName:              DefaultFileName,
		CriticalSlots:         DefaultCriticalSlots,
		RejectedSlots:         DefaultRejectedSlots,
		MinAdmissionInterval:  DefaultMinAdmissionInterval,
		RejectedFlushInterval: DefaultRejectedFlushInterval,
		WriteTimeout:          DefaultWriteTimeout,
	}
}

// ResolveDir 決定 journal 落點目錄。
// 沿用既有 AUDIT_LOG_PATH（審計降級 fallback 的同一目錄），未設時退回內建相對路徑；
// 本套件 SHALL NOT 新增任何 env 鍵，亦不受 FEATURE_AUDIT_FALLBACK_TO_FILE 影響。
func ResolveDir() string {
	if p := os.Getenv("AUDIT_LOG_PATH"); p != "" {
		return p
	}
	return filepath.Join("logs", "audit_fallback")
}

// Open 開啟（或首次建立）封印期 journal。
//
// 啟動恢復以「檔案是否存在」嚴格分流，SHALL NOT 以「header 是否可解析」合流：
//   - (0) 不存在：建立 → 預配置全零 → 寫初始 header → fdatasync → fsync 父目錄；
//     任一步失敗即回錯（呼叫端據此不開放監聽）。
//   - (i) 存在但兩 header 皆無效：回 ErrHeaderInvalid，保留原樣，不截斷不重建。
//   - (i-b) 存在且 header 有效，但非 regular file／長度不符／佈局不合／不可完整讀取：
//     同樣回錯且不修改檔案。
//   - (ii)(iii) 序號缺口與環繞 torn overwrite：不阻擋開啟，記入 Status 供回灌據實入審計。
func Open(dir string, options ...Option) (*Journal, error) {
	opt := defaultOptions()
	for _, fn := range options {
		fn(&opt)
	}
	if opt.CriticalSlots < 2 || opt.RejectedSlots < 2 {
		return nil, fmt.Errorf("sealjournal: 環容量至少各 2 槽")
	}
	if dir == "" {
		dir = ResolveDir()
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("sealjournal: 建立目錄失敗: %w", err)
	}
	path := filepath.Join(dir, opt.FileName)
	lay := layout{criticalSlots: opt.CriticalSlots, rejectedSlots: opt.RejectedSlots}

	// 分流依據＝檔案是否存在（Lstat 不追隨 symlink）。
	info, statErr := os.Lstat(path)
	var (
		f   fileIO
		h   *header
		err error
	)
	switch {
	case statErr != nil && errors.Is(statErr, fs.ErrNotExist):
		f, h, err = createJournal(path, dir, lay, opt)
	case statErr != nil:
		return nil, fmt.Errorf("sealjournal: 檢視 journal 失敗: %w", statErr)
	default:
		f, h, err = openExisting(path, info, lay, opt)
	}
	if err != nil {
		return nil, err
	}

	// 開檔時完整掃描一次：兼作 (i-b) 的「可完整讀取」檢查。
	scan, scanErr := scanRings(f, h)
	if scanErr != nil {
		_ = f.Close()
		return nil, fmt.Errorf("%w: %v", ErrUnreadable, scanErr)
	}

	j := newJournal(path, f, h, opt, scan)
	return j, nil
}

// createJournal 走啟動恢復 (0)。任一步失敗即回錯；
// 刻意不刪除半成品檔案——與 (i) 一致地把「既存但不完整」交由人工處置，
// 避免留下任何自動重建（＝把歷史歸零）的途徑。
func createJournal(path, dir string, lay layout, opt Options) (fileIO, *header, error) {
	osf, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("sealjournal: 建立 journal 失敗: %w", err)
	}
	var f fileIO = &osFile{f: osf}
	if opt.wrapFile != nil {
		f = opt.wrapFile(f)
	}

	// 預配置全零（實寫，非 sparse truncate），使檔案大小自建立起即為最終大小。
	total := lay.fileSize()
	chunk := make([]byte, 64*1024)
	for off := int64(0); off < total; {
		n := int64(len(chunk))
		if total-off < n {
			n = total - off
		}
		if _, err := f.WriteAt(chunk[:n], off); err != nil {
			_ = f.Close()
			return nil, nil, fmt.Errorf("sealjournal: 預配置失敗: %w", err)
		}
		off += n
	}
	if err := f.Datasync(); err != nil {
		_ = f.Close()
		return nil, nil, fmt.Errorf("sealjournal: 預配置同步失敗: %w", err)
	}

	h := &header{
		Generation:         1,
		SeqNext:            1,
		CriticalSlotCount:  uint64(lay.criticalSlots),
		RejectedSlotCount:  uint64(lay.rejectedSlots),
		CriticalSlotSize:   criticalSlotSize,
		RejectedSlotSize:   rejectedSlotSize,
		CriticalRingOffset: uint64(criticalRingOffset),
		RejectedRingOffset: uint64(lay.rejectedRingOffset()),
		FileSize:           uint64(lay.fileSize()),
	}
	id := uuid.New()
	copy(h.JournalUUID[:], id[:])

	if _, err := f.WriteAt(encodeHeader(h), headerSlotOffset(h.Generation)); err != nil {
		_ = f.Close()
		return nil, nil, fmt.Errorf("sealjournal: 寫入初始 header 失敗: %w", err)
	}
	if err := f.Datasync(); err != nil {
		_ = f.Close()
		return nil, nil, fmt.Errorf("sealjournal: 初始 header 同步失敗: %w", err)
	}
	// 同步父目錄項：否則崩潰後檔案可能不存在，下次啟動又走「首次」而從零起算。
	if err := syncDirFn(dir); err != nil {
		_ = f.Close()
		return nil, nil, fmt.Errorf("sealjournal: 同步父目錄項失敗: %w", err)
	}
	return f, h, nil
}

// openExisting 走啟動恢復 (i)／(i-b)。全程只讀，不修改任何位元。
func openExisting(path string, info fs.FileInfo, lay layout, opt Options) (fileIO, *header, error) {
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%w: %s (mode=%s)", ErrNotRegularFile, path, info.Mode())
	}
	if info.Size() != lay.fileSize() {
		return nil, nil, fmt.Errorf("%w: 實際 %d 預期 %d", ErrSizeMismatch, info.Size(), lay.fileSize())
	}
	osf, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("sealjournal: 開啟 journal 失敗: %w", err)
	}
	var f fileIO = &osFile{f: osf}
	if opt.wrapFile != nil {
		f = opt.wrapFile(f)
	}

	h, err := readValidHeader(f)
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if err := checkLayout(h, lay); err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return f, h, nil
}

// readValidHeader 讀兩個 header 槽，取 CRC 有效且 generation 較大者。
func readValidHeader(f fileIO) (*header, error) {
	var best *header
	var readErr error
	for slot := 0; slot < headerSlotCount; slot++ {
		buf := make([]byte, headerSlotSize)
		if _, err := f.ReadAt(buf, int64(slot*headerSlotSize)); err != nil {
			readErr = err
			continue
		}
		h, err := decodeHeader(buf)
		if err != nil {
			continue
		}
		if best == nil || h.Generation > best.Generation {
			best = h
		}
	}
	if best == nil {
		if readErr != nil {
			return nil, fmt.Errorf("%w (讀取錯誤: %v)", ErrHeaderInvalid, readErr)
		}
		return nil, ErrHeaderInvalid
	}
	return best, nil
}

func checkLayout(h *header, lay layout) error {
	switch {
	case h.CriticalSlotCount != uint64(lay.criticalSlots),
		h.RejectedSlotCount != uint64(lay.rejectedSlots),
		h.CriticalSlotSize != criticalSlotSize,
		h.RejectedSlotSize != rejectedSlotSize,
		h.CriticalRingOffset != uint64(criticalRingOffset),
		h.RejectedRingOffset != uint64(lay.rejectedRingOffset()),
		h.FileSize != uint64(lay.fileSize()):
		return fmt.Errorf("%w: header 記載的佈局與預配置不一致", ErrLayoutMismatch)
	}
	return nil
}

// headerSlotOffset 依 generation 奇偶輪替兩個 header 槽，
// 使新 header 永不覆蓋當前有效的那一份（雙槽提交）。
func headerSlotOffset(generation uint64) int64 {
	return int64(generation%headerSlotCount) * headerSlotSize
}

func newBootID() [16]byte {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand 失敗屬不可恢復環境問題；退回時間戳仍保留可辨識性。
		ts := uint64(time.Now().UnixNano())
		for i := 0; i < 8; i++ {
			b[i] = byte(ts >> (8 * i))
		}
	}
	return b
}
