package offsite

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 單一泛用上傳 worker＋模組側 adapter 的分工。
//
// **一個 goroutine、一套退避與租約邏輯**：兩個模組各自一個 worker 會讓退避、上限、
// recover 三份邏輯各自演化，指標也要聚合兩個來源。泛用迴圈＋adapter 只多一個介面，
// 少一個 goroutine。

// ErrNotReadyYet adapter 表示「這件現在還不能取」（圖形錄影的寬限期未到、
// 會話仍在進行中）。**延後，且不計 attempts**——寬限期不是失敗。
var ErrNotReadyYet = errors.New("offsite: 上傳目標尚未就緒（寬限期未到）")

// GraphicsUploadGraceSeconds 圖形錄影的上傳寬限期（單一定義點）。
//
// guacd 直寫錄影檔且無收尾訊號：尾段寫入晚於 rename，而 dispose 在
// `guac_client_free` 內、毫秒級。60 秒遠大於實測尾段抵達時間，又不至於讓稽核員等太久。
// **調小即降低保護**，守衛 TestGraphicsUploadGraceNotLowered 釘住下限。
const GraphicsUploadGraceSeconds = 60

// 雙車道每輪配額：live 16 ＋ backfill 4（4:1）。
//
// 純「最新優先」在持續高流量下會讓回填**無限期**停在本機唯一副本；配額給回填一個
// 有界的下限而不搶新件。任一車道不足時另一車道補滿（總量仍為 20）。
const (
	LaneQuotaLive     = 16
	LaneQuotaBackfill = 4
	LaneQuotaTotal    = LaneQuotaLive + LaneQuotaBackfill
)

// uploadTickInterval 取件輪詢間隔；件與件序列（單一 goroutine，上傳大檔期間
// 不並行搶頻寬）。
const uploadTickInterval = 5 * time.Second

// backfillScanInterval 回填掃描間隔（在 worker goroutine 內執行，**不另起 goroutine**）。
const backfillScanInterval = 10 * time.Minute

// backfillScanBatch 每輪回填掃描的檢視上限（每筆一次 stat 與一句冪等 INSERT）。
const backfillScanBatch = 200

// leaseSlack 租約在 Put deadline 之外的餘裕。
const leaseSlack = time.Minute

// BackfillClass 回填掃描的三分類。
type BackfillClass string

const (
	// BackfillUploadable 本機檔 stat 成功且未逾保留期 → 排入 backfill 車道
	BackfillUploadable BackfillClass = "uploadable"
	// BackfillMissing 路徑非空但 stat 失敗 → **不建帳冊列**，快取 skipped_missing；
	// 下一輪掃描會再看一次（還原備份後檔案回來即可上傳）
	BackfillMissing BackfillClass = "missing"
	// BackfillExpired 已逾保留期 → **不建帳冊列**，快取 skipped_expired；
	// 交給保留清理刪本機，不與清理競跑
	BackfillExpired BackfillClass = "expired"
)

// OwnerDescription 失敗清單與管理介面顯示所需的擁有者事實。
type OwnerDescription struct {
	// Label 人可讀的識別（會話標題／證據包名）
	Label string
	// EndedAt 會話結束／打包完成時刻
	EndedAt time.Time
	// RetentionDeadline 本機保留到期日；nil＝無保留期（永久）
	RetentionDeadline *time.Time
}

// Adapter 模組側的窄適配（分工反轉後的形狀）。
//
// worker 擁有並讀寫 `offsite_objects`；adapter 縮為「開啟本機檔＋寬限期判斷＋
// 寫回擁有表快取＋描述擁有者」。由組裝根注入，`internal/offsite` 對業務模組零 import。
type Adapter interface {
	// Kind 本 adapter 服務的上傳目標種類（KindRecording／KindExport）
	Kind() string
	// Open 開啟本機檔；回傳大小與 mtime（上傳前後各 stat 一次比對用）。
	// 寬限期未到或擁有者仍在進行中回 ErrNotReadyYet（延後，**不計 attempts**）
	Open(ownerID uint) (io.ReadSeekCloser, int64, time.Time, error)
	// Stat 只取大小與 mtime（上傳完成後的複驗，不必再開檔）
	Stat(ownerID uint) (int64, time.Time, error)
	// SetStatus 寫回擁有表的顯示快取
	SetStatus(ownerID, objectID uint, status string) error
	// Describe 擁有者的顯示事實（失敗清單用）
	Describe(ownerID uint) (OwnerDescription, error)
	// ListUnenqueued 尚未排入的擁有者 id（partial index 查詢；最新優先）
	ListUnenqueued(limit int) ([]uint, error)
	// Classify 回填掃描的三分類
	Classify(ownerID uint) (BackfillClass, error)
	// Extension 物件 key 的副檔名（不含點；cast／guac／zip）
	Extension(ownerID uint) (string, error)
	// MarkForeignBatch 世代退役時批次把擁有表快取寫成 foreign。
	// **在設定服務的鎖內交易中呼叫**——快取與帳冊同進退
	MarkForeignBatch(tx *gorm.DB, generationID uint) error
}

// FailureReporter 機制級失效事件的上報面（audit 的 AuditFailureService 實作之）。
type FailureReporter interface {
	Report(mechanism, causeCode string, params map[string]string)
	Resolve(mechanism string)
}

// UploadMetrics 上傳車道的指標面（「worker 直寫」四項）。
//
// **消費者側窄介面**，沿本包 `CustodyJournal`／`FailureReporter` 的形態：
// `internal/offsite` 因此不 import observability，指標實體由組裝根注入。
// 未注入時走 no-op——單元測試建構路徑不該被迫準備一個 Prometheus registry。
//
// **方法名刻意帶 `Offsite` 前綴**（在本包內讀來冗餘）：如此 `*observability.Metrics`
// 直接滿足本介面，組裝根不必為三個方法寫一層只做轉名的 adapter——而那種 adapter
// 正是「有人改了其中一邊的語義、另一邊靜默沿用」的典型落點。
//
// **指標是旁路，任何一個方法都不得回 error**：上傳已經發生，計數寫不進去
// 不該讓呼叫端有機會把它當成失敗。
type UploadMetrics interface {
	// ObserveOffsiteUpload 一次上傳嘗試的結果；result 見 UploadResult* 常數。
	// bytes 僅在成功時有意義
	ObserveOffsiteUpload(kind, result string, bytes int64)
	// ObserveOffsiteLeaseExpired 一次租約回收（卡死訊號）
	ObserveOffsiteLeaseExpired(kind string)
	// SetOffsiteLastSuccess 最近一次上傳成功的時刻
	SetOffsiteLastSuccess(ts time.Time)
}

// 上傳結果標籤（與 observability 的 OffsiteUploadResult* 同值；
// 兩處各自定義是為了不讓本包 import 指標包，值不一致由組裝根的接線測試釘住）。
const (
	UploadResultUploaded = "uploaded"
	UploadResultFailed   = "failed"
)

// noopUploadMetrics 未注入時的退路。
type noopUploadMetrics struct{}

func (noopUploadMetrics) ObserveOffsiteUpload(string, string, int64) {}
func (noopUploadMetrics) ObserveOffsiteLeaseExpired(string)          {}
func (noopUploadMetrics) SetOffsiteLastSuccess(time.Time)            {}

// Uploader 上傳 worker。
type Uploader struct {
	ledger   *Ledger
	profiles *OffsiteProfileService
	adapters map[string]Adapter
	failure  FailureReporter
	metrics  UploadMetrics
	now      func() time.Time

	lastBackfillScan time.Time
}

// NewUploader 建立 worker。adapters 以 Kind() 為索引。
func NewUploader(ledger *Ledger, profiles *OffsiteProfileService, failure FailureReporter, adapters ...Adapter) *Uploader {
	m := map[string]Adapter{}
	for _, a := range adapters {
		if a != nil {
			m[a.Kind()] = a
		}
	}
	return &Uploader{
		ledger: ledger, profiles: profiles, adapters: m, failure: failure,
		metrics: noopUploadMetrics{}, now: time.Now,
	}
}

// SetMetrics 注入上傳車道的指標面（組裝根；nil 視為不注入）。
func (u *Uploader) SetMetrics(m UploadMetrics) {
	if m == nil {
		m = noopUploadMetrics{}
	}
	u.metrics = m
}

// SetClockForTest 覆寫時間源（僅測試）。
func (u *Uploader) SetClockForTest(now func() time.Time) { u.now = now }

// Run 主迴圈（由組裝根以 goroutine 啟動；ctx 取消即返回）。
func (u *Uploader) Run(ctx context.Context) {
	ticker := time.NewTicker(uploadTickInterval)
	defer ticker.Stop()
	// 啟動即跑一輪回填掃描（涵蓋功能啟用前的歷史證據）
	u.runBackfillScan(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			u.RunCycle(ctx)
		}
	}
}

// RunCycle 單輪：租約回收 → 雙車道取件 → 逐件上傳 → 週期性回填掃描。
//
// **panic 不得殺行程**（Go 的 goroutine panic 直接終止行程；旁路功能不該有這個
// 權力）：本函式一層 recover、單件另一層。守衛
// TestUploaderPanicDoesNotKillProcessAndHitsRetryCap 以注入證明兩層都走到。
func (u *Uploader) RunCycle(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[OffsiteUploader] 單輪 panic 已攔截（行程續行）: %v", r)
		}
	}()

	u.reapLeases()

	live, err := u.ledger.ListDue(OriginLive, LaneQuotaTotal)
	if err != nil {
		log.Printf("[OffsiteUploader] 查詢 live 車道失敗: %v", err)
		return
	}
	backfill, err := u.ledger.ListDue(OriginBackfill, LaneQuotaTotal)
	if err != nil {
		log.Printf("[OffsiteUploader] 查詢 backfill 車道失敗: %v", err)
		return
	}
	for _, obj := range planLanes(live, backfill) {
		if ctx.Err() != nil {
			return
		}
		u.processOne(ctx, obj)
	}

	u.maybeBackfillScan(ctx)
}

// planLanes 雙車道配額（純函式，供逐格測試）。
//
// live 取 16、backfill 取 4；**任一車道不足時另一車道補滿**（總量恆 ≤ 20）。
// 兩條車道各自已是「最新優先」（ListDue 的 ORDER BY id DESC）。
func planLanes(live, backfill []model.OffsiteObject) []model.OffsiteObject {
	takeLive := min(len(live), LaneQuotaLive)
	takeBackfill := min(len(backfill), LaneQuotaBackfill)
	// 補滿：另一車道未用完的額度讓給有件的那一條
	if spare := LaneQuotaLive - takeLive; spare > 0 {
		takeBackfill = min(len(backfill), takeBackfill+spare)
	}
	if spare := LaneQuotaBackfill - takeBackfill; spare > 0 {
		takeLive = min(len(live), takeLive+spare)
	}
	out := make([]model.OffsiteObject, 0, takeLive+takeBackfill)
	out = append(out, live[:takeLive]...)
	return append(out, backfill[:takeBackfill]...)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// reapLeases 回收過期租約並判卡死。
//
// 卡死判準＝同一物件 `lease_expiries >= 2`（**不等到 attempts 上限**）：租約反覆
// 到期代表行程被砍或 deadline 被繞過，那比「上傳失敗」更早需要人看。
func (u *Uploader) reapLeases() {
	reaped, err := u.ledger.Reap()
	if err != nil {
		log.Printf("[OffsiteUploader] 租約回收失敗: %v", err)
		return
	}
	for i := range reaped {
		obj := reaped[i]
		// **每一次回收都計數，不只卡死的那些**：卡死判準是「同一件回收 ≥2 次」，
		// 而採集端要看的是「一小時內有沒有回收發生」——只計卡死者會讓第一次回收
		// （真正的早期訊號）完全不出現
		u.metrics.ObserveOffsiteLeaseExpired(obj.Kind)
		if obj.LeaseExpiries < StalledLeaseExpiries {
			continue
		}
		u.recordCustody(obj, string(model.StatusFailure), map[string]any{
			"result":         "stalled",
			"lease_expiries": obj.LeaseExpiries,
			"attempts":       obj.Attempts,
		})
		u.report(model.MechanismOffsiteUpload, model.CauseOffsiteUploadStalled, map[string]string{
			"kind":      obj.Kind,
			"object_id": fmt.Sprintf("%d", obj.ID),
		})
	}
}

// processOne 單件上傳（含一層 recover——一件的 panic 不得中斷整輪）。
func (u *Uploader) processOne(ctx context.Context, obj model.OffsiteObject) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[OffsiteUploader] 單件 panic 已攔截（object_id=%d，行程續行）: %v", obj.ID, r)
			// **panic 走與一般失敗完全相同的收斂路徑**：退避、達上限轉 failed、
			// 保管鏈事件、機制級告警一個都不少。只寫帳冊而不發告警的話，
			// 一件必然 panic 的錄影會安靜地重試到上限然後停在 failed，
			// 而營運端看不到任何訊號
			u.fail(obj, obj.Attempts+1, ErrCodeUploadFailed, fmt.Errorf("單件 panic: %v", r))
		}
	}()

	adapter := u.adapters[obj.Kind]
	if adapter == nil {
		log.Printf("[OffsiteUploader] 無對應 adapter（kind=%s），跳過 object_id=%d", obj.Kind, obj.ID)
		return
	}

	// 寬限期／進行中判定**在領件之前**：ErrNotReadyYet 不計 attempts
	reader, size, mtime, err := adapter.Open(obj.OwnerID)
	if err != nil {
		if errors.Is(err, ErrNotReadyYet) {
			return
		}
		u.fail(obj, obj.Attempts+1, ErrCodeOpenFailed, err)
		return
	}
	defer func() { _ = reader.Close() }()

	leaseUntil := u.now().Add(transferTimeout(size) + leaseSlack)
	claimed, err := u.ledger.Claim(obj.ID, leaseUntil)
	if err != nil {
		log.Printf("[OffsiteUploader] 領件失敗（object_id=%d）: %v", obj.ID, err)
		return
	}
	if !claimed {
		return // 已被別人領走（多副本或並發輪）——不是錯誤
	}
	attempts := obj.Attempts + 1

	client, err := u.profiles.ClientFor(ctx, obj.StorageGenerationID)
	if err != nil {
		u.fail(obj, attempts, ErrCodeUploadFailed, err)
		return
	}
	ext, err := adapter.Extension(obj.OwnerID)
	if err != nil {
		u.fail(obj, attempts, ErrCodeOpenFailed, err)
		return
	}
	desc, err := adapter.Describe(obj.OwnerID)
	if err != nil {
		u.fail(obj, attempts, ErrCodeOpenFailed, err)
		return
	}
	gen, err := u.profiles.generationRef(obj.StorageGenerationID)
	if err != nil {
		u.fail(obj, attempts, ErrCodeUploadFailed, err)
		return
	}
	key := ExportObjectKey(gen.Prefix, obj.OwnerID)
	if obj.Kind == KindRecording {
		key = RecordingObjectKey(gen.Prefix, obj.OwnerID, desc.EndedAt, ext)
	}

	// SHA-256 **先算再傳、傳時再算一次**。
	//
	// 上傳契約同時要求兩件事：物件 metadata 要帶 sha256，而 sha256 是「上傳當下
	// 讀到的位元組」的雜湊。單靠 TeeReader 拿不到 metadata（值要在送出前就寫進
	// 標頭），單靠預先計算則無法保證送出的位元組就是被雜湊的那些。
	// 故：預先讀一遍算出值 → Seek(0) → 上傳時以 TeeReader 再算一次 → 兩值必須相同，
	// 不同即代表本機檔在兩次讀取之間被追加（畫格中途收線的長尾），走 file_changed 重試。
	// 代價是本機多讀一遍（相對於網路傳輸可忽略）。
	preHasher := sha256.New()
	if _, err := io.Copy(preHasher, reader); err != nil {
		u.fail(obj, attempts, ErrCodeOpenFailed, err)
		return
	}
	sum := hex.EncodeToString(preHasher.Sum(nil))
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		u.fail(obj, attempts, ErrCodeOpenFailed, err)
		return
	}
	hasher := sha256.New()
	res, err := client.Put(ctx, key, io.TeeReader(reader, hasher), PutOpts{
		ContentLength: size,
		Metadata: map[string]string{
			"sha256":              sum,
			"custodexa-object-id": fmt.Sprintf("%d", obj.ID),
			"custodexa-profile":   fmt.Sprintf("%d", obj.StorageGenerationID),
		},
	})
	if err != nil {
		u.fail(obj, attempts, ErrCodeUploadFailed, err)
		return
	}
	if sent := hex.EncodeToString(hasher.Sum(nil)); sent != sum {
		u.fail(obj, attempts, ErrCodeFileChangedDuringUpload,
			fmt.Errorf("送出位元組的雜湊與 metadata 不符（本機檔於上傳期間被改寫）"))
		return
	}

	// 上傳完成 → Head 核對大小（對同 key 的目前內容，無版本綁定）
	info, err := client.Head(ctx, ObjectRef{Bucket: gen.Bucket, Key: key})
	if err != nil {
		u.fail(obj, attempts, ErrCodeUploadFailed, err)
		return
	}
	if info.Size != size {
		u.fail(obj, attempts, ErrCodeHeadMismatch, fmt.Errorf("遠端大小 %d 與上傳大小 %d 不符", info.Size, size))
		return
	}
	// 再 stat 本機一次：畫格中途收線的長尾會讓 (size, mtime) 變動。
	// 這把「上傳後檔案又被追加」從靜默變成可見；**但不主張絕對一致**
	if size2, mtime2, serr := adapter.Stat(obj.OwnerID); serr == nil {
		if size2 != size || !mtime2.Equal(mtime) {
			u.fail(obj, attempts, ErrCodeFileChangedDuringUpload,
				fmt.Errorf("本機檔於上傳期間變動（重試＝重傳同 key）"))
			return
		}
	}

	if err := u.ledger.MarkUploaded(obj.ID, key, res.Version, sum, size); err != nil {
		// **DB 寫回失敗不回捲遠端物件**：租約到期後會重領並重傳同 key，
		// 內容相同故覆寫無害，帳冊最終收斂到 uploaded
		log.Printf("[OffsiteUploader] 上傳成功但帳冊寫回失敗（object_id=%d，租約到期後重傳同 key）: %v",
			obj.ID, err)
		return
	}
	if err := adapter.SetStatus(obj.OwnerID, obj.ID, StateUploaded); err != nil {
		log.Printf("[OffsiteUploader] 擁有表快取寫回失敗（顯示面，不影響帳冊）: %v", err)
	}
	// **記在帳冊寫回成功之後**：遠端有了物件但帳冊沒記，下一輪會重傳同 key，
	// 那一輪才是真正落定的一次；提早計數會讓累計數大於帳冊裡的 uploaded 列數
	u.metrics.ObserveOffsiteUpload(obj.Kind, UploadResultUploaded, size)
	u.metrics.SetOffsiteLastSuccess(u.now())
	u.recordCustody(obj, string(model.StatusSuccess), map[string]any{
		"result":     "uploaded",
		"key":        key,
		"bucket":     gen.Bucket,
		"sha256":     sum,
		"size":       size,
		"version_id": res.Version,
		"attempts":   attempts,
	})
	// **只在 failed 歸零時 Resolve**：「任一成功即解除」會把其他仍
	// failed 的證據在通知面誤報為恢復
	if n, err := u.ledger.CountFailed(); err == nil && n == 0 {
		u.resolve(model.MechanismOffsiteUpload)
	}
}

// fail 單次失敗的收斂處置：寫帳冊（退避或終態）、達上限才發事件。
func (u *Uploader) fail(obj model.OffsiteObject, attempts int, errorCode string, cause error) {
	log.Printf("[OffsiteUploader] 上傳失敗（object_id=%d attempts=%d code=%s）: %v",
		obj.ID, attempts, errorCode, cause)
	// **每一次失敗嘗試都計數，不只終態**：退避中的反覆失敗是積壓的來源，
	// 只計終態會讓「一直在重試但還沒到上限」在採集端完全看不見
	u.metrics.ObserveOffsiteUpload(obj.Kind, UploadResultFailed, 0)
	terminal, err := u.ledger.MarkFailed(obj.ID, attempts, errorCode)
	if err != nil {
		log.Printf("[OffsiteUploader] 寫入失敗結果亦失敗（object_id=%d）: %v", obj.ID, err)
		return
	}
	if !terminal {
		return // 退避中：**不發告警**，否則暫時性網路抖動會製造告警風暴
	}
	u.recordCustody(obj, string(model.StatusFailure), map[string]any{
		"result":     "failed",
		"attempts":   attempts,
		"error_code": errorCode,
	})
	u.report(model.MechanismOffsiteUpload, model.CauseOffsiteUploadFailed, map[string]string{
		"kind":       obj.Kind,
		"object_id":  fmt.Sprintf("%d", obj.ID),
		"error_code": errorCode,
	})
}

// recordCustody 保管鏈事件（Details 無端點、無憑證）。
func (u *Uploader) recordCustody(obj model.OffsiteObject, status string, extra map[string]any) {
	details := map[string]any{
		"object_id":             obj.ID,
		"kind":                  obj.Kind,
		"origin":                obj.Origin,
		"bucket":                obj.Bucket,
		"storage_generation_id": obj.StorageGenerationID,
	}
	for k, v := range extra {
		details[k] = v
	}
	ownerID := obj.OwnerID
	if err := u.ledger.journal.Record(CustodyEvent{
		Action:     CustodyActionUpload,
		Resource:   custodyResourceOf(obj.Kind),
		ResourceID: &ownerID,
		Status:     status,
		Details:    details,
	}); err != nil {
		log.Printf("[OffsiteUploader] 保管鏈事件寫入失敗（object_id=%d）: %v", obj.ID, err)
	}
}

func (u *Uploader) report(mechanism, cause string, params map[string]string) {
	if u.failure == nil {
		return
	}
	u.failure.Report(mechanism, cause, params)
}

func (u *Uploader) resolve(mechanism string) {
	if u.failure == nil {
		return
	}
	u.failure.Resolve(mechanism)
}

// ── 回填掃描 ────────────────────────────────────────────────

func (u *Uploader) maybeBackfillScan(ctx context.Context) {
	now := u.now()
	if !u.lastBackfillScan.IsZero() && now.Sub(u.lastBackfillScan) < backfillScanInterval {
		return
	}
	u.runBackfillScan(ctx)
}

// RunBackfillScan 逐 adapter 掃一輪未排入的擁有者並依分類處置（匯出供測試直呼）。
func (u *Uploader) RunBackfillScan(ctx context.Context) { u.runBackfillScan(ctx) }

func (u *Uploader) runBackfillScan(ctx context.Context) {
	u.lastBackfillScan = u.now()
	for kind, adapter := range u.adapters {
		if ctx.Err() != nil {
			return
		}
		ids, err := adapter.ListUnenqueued(backfillScanBatch)
		if err != nil {
			log.Printf("[OffsiteUploader] 回填掃描查詢失敗（kind=%s）: %v", kind, err)
			continue
		}
		for _, ownerID := range ids {
			class, err := adapter.Classify(ownerID)
			if err != nil {
				log.Printf("[OffsiteUploader] 回填分類失敗（kind=%s owner=%d）: %v", kind, ownerID, err)
				continue
			}
			switch class {
			case BackfillMissing:
				// **不建帳冊列**：下一輪掃描會再看一次（還原備份後檔案回來即可上傳）
				u.setOwnerCache(adapter, ownerID, 0, CacheSkippedMissing)
			case BackfillExpired:
				// **不建帳冊列**：交給保留清理刪本機，不與清理競跑
				u.setOwnerCache(adapter, ownerID, 0, CacheSkippedExpired)
			case BackfillUploadable:
				u.enqueueBackfill(adapter, kind, ownerID)
			}
		}
	}
}

func (u *Uploader) enqueueBackfill(adapter Adapter, kind string, ownerID uint) {
	var (
		row     *model.OffsiteObject
		created bool
	)
	err := u.ledger.db.Transaction(func(tx *gorm.DB) error {
		var err error
		row, created, err = u.ledger.EnqueueTx(tx, kind, ownerID, OriginBackfill)
		return err
	})
	if err != nil {
		if errors.Is(err, ErrNoCurrentGeneration) {
			return // 停用態或從未設定：回填不建列
		}
		log.Printf("[OffsiteUploader] 回填排入失敗（kind=%s owner=%d）: %v", kind, ownerID, err)
		return
	}
	// **快取寫該列的 state 而非硬寫 pending**：既有列可能已是 uploaded／foreign，
	// 這使回滾後重新升級的調和與正常回填走同一條路
	u.setOwnerCache(adapter, ownerID, row.ID, row.State)
	if created {
		log.Printf("[OffsiteUploader] 回填排入 kind=%s owner=%d object_id=%d", kind, ownerID, row.ID)
	}
}

func (u *Uploader) setOwnerCache(adapter Adapter, ownerID, objectID uint, status string) {
	if err := adapter.SetStatus(ownerID, objectID, status); err != nil {
		log.Printf("[OffsiteUploader] 擁有表快取寫回失敗（owner=%d status=%s）: %v", ownerID, status, err)
	}
}

// generationRef 由世代 id 取回落點事實（bucket／prefix；**不含憑證**）。
func (s *OffsiteProfileService) generationRef(generationID uint) (GenerationRef, error) {
	var row model.OffsiteProfile
	if err := s.db.Where("generation_id = ?", generationID).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return GenerationRef{}, fmt.Errorf("%s：世代 %d 不存在", ErrCodeProfileMissing, generationID)
		}
		return GenerationRef{}, fmt.Errorf("讀取離機儲存設定世代失敗: %w", err)
	}
	return GenerationRef{
		GenerationID: row.GenerationID,
		Provider:     row.Provider,
		Bucket:       row.Bucket,
		Prefix:       row.Prefix,
	}, nil
}
