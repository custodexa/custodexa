package offsite

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// 保管帳冊（`offsite_objects`）的唯一存取面。
//
// **帳冊即佇列**：沒有另一張佇列表，`state='pending' AND next_attempt_at<=now`
// 就是取件查詢面（partial index `idx_offsite_objects_due`）。
// 業務模組（session／audit）**只能經本型別的方法**取物件——直接碰表會被資料邊界
// 閘門判紅（`tableOwner["offsite_objects"]="offsite"`）。

// GenerationRef 帳冊寫入時需要知道的世代事實（由設定服務提供）。
//
// 只取「決定物件落點」的四個值：provider 與 bucket 進帳冊明文欄（對帳與顯示直讀、
// 免 join），prefix 供組 key，generation_id 是取回時找回憑證的**唯一**依據。
// **不含端點與憑證**——帳冊不承載機密，取回時以 generation_id 回世代表拿。
type GenerationRef struct {
	GenerationID uint
	Provider     string
	Bucket       string
	Prefix       string
}

// ErrNoCurrentGeneration 目前沒有現行世代（`retired_at IS NULL` 零列）。
//
// 兩種部署狀態共用此哨兵：**從未設定**（設定表零列）與**已停用**（有歷史世代、
// 零現行世代）。兩者對「要不要建新帳冊列」的答案相同（都不建），差異在其他三個面
// （worker／指標／管理介面），由呼叫端各自判斷——這也是為什麼它是哨兵而非布林：
// 呼叫端 `errors.Is` 之後決定要不要視為 no-op，而不是被一個 false 靜默吞掉。
var ErrNoCurrentGeneration = errors.New("offsite: 目前沒有現行的離機儲存設定世代")

// ErrObjectNotInLedger 帳冊查無該列
var ErrObjectNotInLedger = errors.New("offsite: 帳冊查無此物件")

// GenerationSource 帳冊對「現行世代」的窄依賴（由 OffsiteProfileService 實作）。
//
// 帶 tx 是必要的：`EnqueueTx` 在呼叫方的交易內執行，世代必須以**同一個交易句柄**
// 重讀——鎖外／交易外的預讀可能在兩者之間被世代切換改掉，帳冊就會記到一個
// 已退役世代的 id。
type GenerationSource interface {
	CurrentGeneration(tx *gorm.DB) (GenerationRef, error)
}

// 退避表：第 1–5 次失敗後的等待時間；第 5 次仍失敗轉 failed。
var uploadBackoff = []time.Duration{
	1 * time.Minute, 5 * time.Minute, 15 * time.Minute, 1 * time.Hour, 6 * time.Hour,
}

// MaxUploadAttempts 上傳重試上限（達此值仍失敗即轉 failed）。
const MaxUploadAttempts = 5

// StalledLeaseExpiries 卡死判準：同一物件的租約回收次數達此值即發保管鏈事件
// ＋失效事件（**不等到 attempts 上限**——租約反覆到期代表行程被砍或 deadline
// 被繞過，那比「上傳失敗」更早需要人看）。
const StalledLeaseExpiries = 2

// Ledger 保管帳冊。
type Ledger struct {
	db      *gorm.DB
	gens    GenerationSource
	journal CustodyJournal
	now     func() time.Time
}

// NewLedger 建立帳冊。journal 為 nil 時以 no-op 退路（僅單測建構路徑）。
func NewLedger(db *gorm.DB, gens GenerationSource, journal CustodyJournal) *Ledger {
	if journal == nil {
		journal = noopCustodyJournal{}
	}
	return &Ledger{db: db, gens: gens, journal: journal, now: time.Now}
}

// SetClockForTest 覆寫時間源（僅測試；生產恆為 time.Now）。
func (l *Ledger) SetClockForTest(now func() time.Time) { l.now = now }

// EnqueueTx 在**呼叫方的交易內**冪等排入一個上傳目標。
//
// 這是 tx-taking 窄介面（先例：authz 的 RevokeByAssetGroup）：交易句柄交給
// 基礎設施包，使「錄影落地」與「排入佇列」之間**沒有窗口**——沒有「落地了但沒
// 排隊」的狀態。呼叫點須登記於 internal/guards/txtaking。
//
// 冪等：`INSERT ... ON CONFLICT (kind, owner_id, storage_generation_id) DO NOTHING`
// 後回讀。回傳 created=false 時 row 是**既有列**（含其目前 state）——呼叫端把擁有表
// 快取寫成該列的 state 而非硬寫 pending，回填與正常路徑因此走同一條路。
//
// 沒有現行世代時回 ErrNoCurrentGeneration 且**不建任何列、不做任何寫入**。
func (l *Ledger) EnqueueTx(tx *gorm.DB, kind string, ownerID uint, origin string) (*model.OffsiteObject, bool, error) {
	if kind != KindRecording && kind != KindExport {
		return nil, false, fmt.Errorf("offsite: 不支援的上傳目標種類 %q", kind)
	}
	if origin != OriginLive && origin != OriginBackfill {
		return nil, false, fmt.Errorf("offsite: 不支援的排入來源 %q", origin)
	}
	if ownerID == 0 {
		return nil, false, fmt.Errorf("offsite: 擁有者 id 不得為 0")
	}
	gen, err := l.gens.CurrentGeneration(tx)
	if err != nil {
		return nil, false, err
	}

	now := l.now()
	row := &model.OffsiteObject{
		Kind:                kind,
		OwnerID:             ownerID,
		Origin:              origin,
		Provider:            gen.Provider,
		StorageGenerationID: gen.GenerationID,
		Bucket:              gen.Bucket,
		State:               StatePending,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	res := tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "kind"}, {Name: "owner_id"}, {Name: "storage_generation_id"}},
		DoNothing: true,
	}).Create(row)
	if res.Error != nil {
		return nil, false, fmt.Errorf("排入離機佇列失敗: %w", res.Error)
	}
	created := res.RowsAffected > 0

	// 一律回讀：ON CONFLICT DO NOTHING 在衝突時不填回主鍵，且呼叫端需要既有列的
	// state 才能正確寫擁有表快取
	var out model.OffsiteObject
	if err := tx.Where("kind = ? AND owner_id = ? AND storage_generation_id = ?",
		kind, ownerID, gen.GenerationID).First(&out).Error; err != nil {
		return nil, false, fmt.Errorf("回讀離機帳冊列失敗: %w", err)
	}
	return &out, created, nil
}

// HasCurrentGeneration 目前是否有現行設定世代（**開交易前的便宜預讀**）。
//
// 存在的唯一理由是「未設定＝行為完全不變」的機械保證：`offsite_profiles` 零列時，
// 擁有表的寫入路徑**不得開交易**、欄位集合逐字不變。呼叫端若直接進交易再靠
// `EnqueueTx` 回 `ErrNoCurrentGeneration` 收斂，「未設定＝行為完全不變」就少了
// 「零交易」那一半。
//
// **它只是提示，不是判定**：真正的世代讀取由 `EnqueueTx` 在呼叫方的交易內重做
// （鎖外預讀只能當提示）。讀取失敗時回 (true, err)——呼叫端據此走交易路徑，
// 讓交易內的權威讀取決定成敗，而不是靜默退回「當作沒啟用」（那會製造
// 「落地了但沒排隊」且無人知曉的窗口）。
func (l *Ledger) HasCurrentGeneration() (bool, error) {
	if _, err := l.gens.CurrentGeneration(l.db); err != nil {
		if errors.Is(err, ErrNoCurrentGeneration) {
			return false, nil
		}
		return true, err
	}
	return true, nil
}

// ListDue 取一條車道上到期可領的件（最新優先）。
//
// 兩條車道各自 `ORDER BY id DESC`：純「最新優先」在持續高流量下會讓回填無限期
// 停在本機唯一副本，故給回填一個有界的配額下限；配額由 Uploader 決定，
// 本方法只負責「這條車道有哪些到期件」。
func (l *Ledger) ListDue(lane string, limit int) ([]model.OffsiteObject, error) {
	if limit <= 0 {
		return nil, nil
	}
	now := l.now()
	var rows []model.OffsiteObject
	err := l.db.Where("state = ? AND origin = ? AND (next_attempt_at IS NULL OR next_attempt_at <= ?)",
		StatePending, lane, now).
		Order("id DESC").Limit(limit).Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("查詢離機待上傳件失敗: %w", err)
	}
	return rows, nil
}

// Claim 以 CAS 領件：`WHERE id=? AND state='pending'` → uploading、attempts+1、
// 寫租約。回 false 表示已被別人領走（多副本或並發輪）——**不是錯誤**。
func (l *Ledger) Claim(id uint, leaseUntil time.Time) (bool, error) {
	res := l.db.Model(&model.OffsiteObject{}).
		Where("id = ? AND state = ?", id, StatePending).
		Updates(map[string]any{
			"state":       StateUploading,
			"attempts":    gorm.Expr("attempts + 1"),
			"lease_until": leaseUntil,
			"updated_at":  l.now(),
		})
	if res.Error != nil {
		return false, fmt.Errorf("領取離機上傳件失敗: %w", res.Error)
	}
	return res.RowsAffected > 0, nil
}

// Reap 回收過期租約：`uploading AND lease_until < now` → pending、lease_expiries+1、
// `next_attempt_at=now`（立即可重領）。回傳被回收的列（供呼叫端判卡死並發事件）。
//
// 租約是 deadline 之外的**第二道**：deadline 是行程內的保證，行程被 SIGKILL 時
// `uploading` 會留到重啟；租約讓「未知路徑」也有界。重啟時的 uploading→pending
// 即租約回收的特例（attempts 保留，不歸零）。
func (l *Ledger) Reap() ([]model.OffsiteObject, error) {
	now := l.now()
	var expired []model.OffsiteObject
	if err := l.db.Where("state = ? AND lease_until IS NOT NULL AND lease_until < ?",
		StateUploading, now).Find(&expired).Error; err != nil {
		return nil, fmt.Errorf("查詢過期租約失敗: %w", err)
	}
	if len(expired) == 0 {
		return nil, nil
	}
	ids := make([]uint, 0, len(expired))
	for _, r := range expired {
		ids = append(ids, r.ID)
	}
	if err := l.db.Model(&model.OffsiteObject{}).
		Where("id IN ? AND state = ?", ids, StateUploading).
		Updates(map[string]any{
			"state":           StatePending,
			"lease_expiries":  gorm.Expr("lease_expiries + 1"),
			"next_attempt_at": now,
			"lease_until":     nil,
			"updated_at":      now,
		}).Error; err != nil {
		return nil, fmt.Errorf("回收過期租約失敗: %w", err)
	}
	// 回傳回收**後**的值：lease_expiries 已 +1，呼叫端據以判卡死（≥2）
	for i := range expired {
		expired[i].State = StatePending
		expired[i].LeaseExpiries++
	}
	return expired, nil
}

// MarkUploaded 上傳成功：寫身分與完整性欄、轉 uploaded、清租約與退避。
func (l *Ledger) MarkUploaded(id uint, key, versionID, sha256Hex string, size int64) error {
	now := l.now()
	res := l.db.Model(&model.OffsiteObject{}).Where("id = ?", id).
		Updates(map[string]any{
			"object_key":      key,
			"version_id":      versionID,
			"sha256":          sha256Hex,
			"size":            size,
			"state":           StateUploaded,
			"uploaded_at":     now,
			"lease_until":     nil,
			"next_attempt_at": nil,
			"error_code":      "",
			"updated_at":      now,
		})
	if res.Error != nil {
		return fmt.Errorf("寫入離機上傳結果失敗: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrObjectNotInLedger
	}
	return nil
}

// MarkFailed 單次上傳失敗：依 attempts 決定退避或轉終態。
//
// 回傳 terminal＝本次是否轉入 `failed`（達上限）。呼叫端據以決定要不要發
// 機制級失效事件——**單件的退避不發告警**，否則暫時性網路抖動會製造告警風暴。
func (l *Ledger) MarkFailed(id uint, attempts int, errorCode string) (bool, error) {
	now := l.now()
	fields := map[string]any{
		"error_code":  errorCode,
		"lease_until": nil,
		"updated_at":  now,
		// **attempts 一併落盤**：正常路徑由 Claim 遞增，寫回同值是冪等的；
		// 但 panic 攔截路徑沒有走過 Claim（例如 adapter.Open 就炸了），
		// 不在此落盤的話 attempts 永遠停在 0，重試上限**永遠到不了**——
		// 症狀是一件壞掉的錄影每 5 秒重試一次直到天荒地老，且失敗清單永不出現
		"attempts": attempts,
	}
	terminal := attempts >= MaxUploadAttempts
	if terminal {
		fields["state"] = StateFailed
		fields["next_attempt_at"] = nil
	} else {
		idx := attempts - 1
		if idx < 0 {
			idx = 0
		}
		if idx >= len(uploadBackoff) {
			idx = len(uploadBackoff) - 1
		}
		fields["state"] = StatePending
		fields["next_attempt_at"] = now.Add(uploadBackoff[idx])
	}
	res := l.db.Model(&model.OffsiteObject{}).Where("id = ?", id).Updates(fields)
	if res.Error != nil {
		return false, fmt.Errorf("寫入離機上傳失敗結果失敗: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return false, ErrObjectNotInLedger
	}
	return terminal, nil
}

// MarkIntegrityMismatch 取回驗證不符：轉 integrity_mismatch。
func (l *Ledger) MarkIntegrityMismatch(id uint) error {
	now := l.now()
	return l.db.Model(&model.OffsiteObject{}).Where("id = ?", id).
		Updates(map[string]any{
			"state":      StateIntegrityMismatch,
			"error_code": ErrCodeIntegrityMismatch,
			"updated_at": now,
		}).Error
}

// RetentionOutcome MarkLocalPurged 的結果（供呼叫端寫事件 details 與擁有表清欄）。
type RetentionOutcome struct {
	// Object 到期處置**前**的帳冊列
	Object model.OffsiteObject
	// NewState 處置後的帳冊狀態
	NewState string
	// Deferred true＝本輪不動（uploading 在租約期內），下輪再處置
	Deferred bool
	// NeverUploaded true＝該證據**從未離機**即到期銷毀（前態 pending／failed）。
	// 誠實邊界：離機不涵蓋它——事件 details 必須註記，否則「已啟用離機」會被
	// 誤讀成「這批證據都有遠端副本」
	NeverUploaded bool
	// PriorState integrity_mismatch 到期時記錄的前態（供對帳）
	PriorState string
	// Idempotent true＝已是 local_purged，本次跳過
	Idempotent bool
	// ClearOwnerColumns 呼叫端是否應清擁有表的三欄
	ClearOwnerColumns bool
}

// MarkLocalPurged 保留政策到期時的帳冊處置（逐狀態到期轉移表）。
//
// **本方法不發任何遠端呼叫**：產品對遠端物件不發 DeleteObject，遠端到期清理
// 由部署方的 bucket lifecycle 承擔。這是
// 「正式路徑零 Delete」在行為層的落點之一。
//
//	uploaded            → local_purged
//	pending／failed     → local_purged，details 註 never_uploaded=true
//	uploading           → 不動（待租約回收後下輪處置；避免與在途上傳競態）
//	integrity_mismatch  → local_purged，details 註前態
//	foreign             → **維持 foreign**（狀態語義保留供對帳），仍清擁有表三欄
//	local_purged        → 冪等跳過
func (l *Ledger) MarkLocalPurged(objectID uint) (RetentionOutcome, error) {
	var row model.OffsiteObject
	if err := l.db.Where("id = ?", objectID).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return RetentionOutcome{}, ErrObjectNotInLedger
		}
		return RetentionOutcome{}, fmt.Errorf("讀取離機帳冊列失敗: %w", err)
	}
	out := RetentionOutcome{Object: row, NewState: row.State}

	switch row.State {
	case StateLocalPurged:
		out.Idempotent = true
		out.ClearOwnerColumns = true
		return out, nil
	case StateUploading:
		// 在途上傳：租約到期回收回 pending 後，下一輪清理按 pending 處置。
		// 窗口 ≤ 一個租約期
		out.Deferred = true
		return out, nil
	case StateForeign:
		// 遠端已非現行世代所轄：帳冊狀態保留，只清擁有表側
		out.NewState = StateForeign
		out.ClearOwnerColumns = true
	case StatePending, StateFailed:
		out.NeverUploaded = true
		out.NewState = StateLocalPurged
		out.ClearOwnerColumns = true
	case StateIntegrityMismatch:
		out.PriorState = StateIntegrityMismatch
		out.NewState = StateLocalPurged
		out.ClearOwnerColumns = true
	default: // uploaded
		out.NewState = StateLocalPurged
		out.ClearOwnerColumns = true
	}

	if out.NewState != row.State {
		now := l.now()
		if err := l.db.Model(&model.OffsiteObject{}).Where("id = ?", objectID).
			Updates(map[string]any{
				"state":           out.NewState,
				"next_attempt_at": nil,
				"lease_until":     nil,
				"updated_at":      now,
			}).Error; err != nil {
			return RetentionOutcome{}, fmt.Errorf("寫入離機到期處置失敗: %w", err)
		}
	}

	details := map[string]any{
		"object_id": row.ID,
		"kind":      row.Kind,
		"bucket":    row.Bucket,
		"key":       row.ObjectKey,
	}
	if out.NeverUploaded {
		details["never_uploaded"] = true
	}
	if out.PriorState != "" {
		details["prior_state"] = out.PriorState
	}
	if row.State == StateForeign {
		details["result"] = "local_expired"
	}
	ownerID := row.OwnerID
	if err := l.journal.Record(CustodyEvent{
		Action:     CustodyActionRetention,
		Resource:   custodyResourceOf(row.Kind),
		ResourceID: &ownerID,
		Status:     string(model.StatusSuccess),
		Details:    details,
	}); err != nil {
		// 保管鏈寫不進去不回捲本機清除——檔案已經刪了，回捲只會讓帳冊說謊
		return out, fmt.Errorf("寫入保管鏈到期事件失敗（本機清除已發生，帳冊已更新）: %w", err)
	}
	return out, nil
}

// ListLocalCacheExpired 本機快取期已到的物件（快取清除段）。
//
// 判準＝`state='uploaded' AND uploaded_at < cutoff`。**foreign 不在其中**：
// 其遠端可達性已不由現行設定保證，本機副本可能是唯一可讀副本，清掉它等於在
// 不知情的狀況下銷毀證據（`state` 的等值比對天然排除了 foreign，這行註解是為了讓
// 「為什麼不是 state IN (uploaded, foreign)」有答案）。
//
// **本方法只讀不寫**：本機檔的刪除由擁有者模組進行——它才知道檔案在哪、
// 也才有權碰自己的表。
func (l *Ledger) ListLocalCacheExpired(kind string, cutoff time.Time, limit int) ([]model.OffsiteObject, error) {
	if limit <= 0 {
		return nil, nil
	}
	var rows []model.OffsiteObject
	if err := l.db.Where("kind = ? AND state = ? AND uploaded_at IS NOT NULL AND uploaded_at < ?",
		kind, StateUploaded, cutoff).
		Order("id ASC").Limit(limit).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("查詢本機快取到期的離機物件失敗: %w", err)
	}
	return rows, nil
}

// MarkForeign 把某個世代的存量物件整批轉為 foreign（世代切換確認、停止離機）。
//
// **在呼叫方的交易內**：與「退役舊列／建立新列」同一交易，任一步失敗整筆回滾
// ——否則會留下「世代已切換而舊物件仍宣稱屬現行世代」的中間態。
//
// 回傳 (轉移數, 從未上傳數)。後者供呼叫端在保管鏈事件註記——那批
// `pending`／`failed` 的證據**從未離機**，worker 停後它們永遠停在原態而佇列指標
// 又缺席，不註記即黑洞。
func (l *Ledger) MarkForeign(tx *gorm.DB, generationID uint) (int64, int64, error) {
	var neverUploaded int64
	if err := tx.Model(&model.OffsiteObject{}).
		Where("storage_generation_id = ? AND state IN ?", generationID,
			[]string{StatePending, StateFailed}).
		Count(&neverUploaded).Error; err != nil {
		return 0, 0, fmt.Errorf("計數未上傳的離機物件失敗: %w", err)
	}
	res := tx.Model(&model.OffsiteObject{}).
		Where("storage_generation_id = ? AND state NOT IN ?", generationID,
			[]string{StateLocalPurged, StateForeign}).
		Updates(map[string]any{
			"state":           StateForeign,
			"next_attempt_at": nil,
			"lease_until":     nil,
			"updated_at":      l.now(),
		})
	if res.Error != nil {
		return 0, 0, fmt.Errorf("轉移離機物件為歷史世代失敗: %w", res.Error)
	}
	return res.RowsAffected, neverUploaded, nil
}

// CountByGeneration 某世代的存量物件數（不含 local_purged——那些本機已無檔、
// 遠端由 lifecycle 承擔，對「切換世代要不要確認」不構成資訊）。
func (l *Ledger) CountByGeneration(tx *gorm.DB, generationID uint) (int64, error) {
	var n int64
	err := tx.Model(&model.OffsiteObject{}).
		Where("storage_generation_id = ? AND state <> ?", generationID, StateLocalPurged).
		Count(&n).Error
	if err != nil {
		return 0, fmt.Errorf("計數離機存量物件失敗: %w", err)
	}
	return n, nil
}

// TotalObjects 帳冊總列數（UI 空狀態的判準＝帳冊零列）。
func (l *Ledger) TotalObjects() (int64, error) {
	var n int64
	if err := l.db.Model(&model.OffsiteObject{}).Count(&n).Error; err != nil {
		return 0, fmt.Errorf("計數離機帳冊失敗: %w", err)
	}
	return n, nil
}

// Counts 各態計數（狀態頁與指標刷新來源；單表 GROUP BY）。
// **回傳的 map 一律含全部狀態鍵**（零值亦建項）：缺席與零在指標面是兩件事。
func (l *Ledger) Counts() (map[string]int64, error) {
	type row struct {
		State string
		N     int64
	}
	var rows []row
	if err := l.db.Model(&model.OffsiteObject{}).
		Select("state, count(*) as n").Group("state").Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("計數離機帳冊各態失敗: %w", err)
	}
	out := map[string]int64{}
	for _, s := range AllStates() {
		out[s] = 0
	}
	for _, r := range rows {
		out[r.State] = r.N
	}
	return out, nil
}

// CountsDetailed 各態計數的三維切面（`GROUP BY state, kind, origin`，單表一句）。
//
// 指標面需要 kind 與 origin 的標籤，而 `Counts()` 只給狀態維度；
// 兩者共存而非合併，是因為狀態頁要的是「各態總數」，把三維結果在 handler 裡
// 再加總一次只會多一處可能加錯的地方。
type StateCount struct {
	State  string
	Kind   string
	Origin string
	N      int64
}

// CountsDetailed 見 StateCount。
func (l *Ledger) CountsDetailed() ([]StateCount, error) {
	var rows []StateCount
	if err := l.db.Model(&model.OffsiteObject{}).
		Select("state, kind, origin, count(*) as n").
		Group("state, kind, origin").Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("計數離機帳冊切面失敗: %w", err)
	}
	return rows, nil
}

// OldestPendingAges 各車道最老待上傳件的年齡（秒）。
//
// **回填積壓的可見性靠它**：純「最新優先」下，回填件可能
// 長期停在本機唯一副本，而「待上傳數」這個計數在穩定積壓時是平的——年齡才會漲。
// 無待上傳件的車道**不出現在結果中**（缺席與 0 是兩件事）。
func (l *Ledger) OldestPendingAges(now time.Time) (map[string]float64, error) {
	type row struct {
		Origin string
		Oldest time.Time
	}
	var rows []row
	if err := l.db.Model(&model.OffsiteObject{}).
		Select("origin, min(created_at) as oldest").
		Where("state = ?", StatePending).Group("origin").Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("查詢最老待上傳件失敗: %w", err)
	}
	out := map[string]float64{}
	for _, r := range rows {
		if r.Oldest.IsZero() {
			continue
		}
		age := now.Sub(r.Oldest).Seconds()
		if age < 0 {
			age = 0
		}
		out[r.Origin] = age
	}
	return out, nil
}

// CountFailed 目前處於 failed 的件數。
//
// **機制級失效事件的解除判準**：只有本值為 0 才 Resolve。
// 「任一成功即解除」會把其他仍 failed 的證據在通知面誤報為恢復。
func (l *Ledger) CountFailed() (int64, error) {
	var n int64
	if err := l.db.Model(&model.OffsiteObject{}).Where("state = ?", StateFailed).
		Count(&n).Error; err != nil {
		return 0, fmt.Errorf("計數離機失敗件失敗: %w", err)
	}
	return n, nil
}

// ListFailed 失敗清單分頁（依 id 遞減；到期近者的排序由呼叫端以 adapter 的
// Describe 結果二次排序——保留到期日不在帳冊裡）。
func (l *Ledger) ListFailed(page, size int) ([]model.OffsiteObject, int64, error) {
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 200 {
		size = 20
	}
	var total int64
	if err := l.db.Model(&model.OffsiteObject{}).Where("state = ?", StateFailed).
		Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("計數離機失敗清單失敗: %w", err)
	}
	var rows []model.OffsiteObject
	if err := l.db.Where("state = ?", StateFailed).
		Order("id DESC").Offset((page - 1) * size).Limit(size).Find(&rows).Error; err != nil {
		return nil, 0, fmt.Errorf("查詢離機失敗清單失敗: %w", err)
	}
	return rows, total, nil
}

// Get 取單列。
func (l *Ledger) Get(id uint) (*model.OffsiteObject, error) {
	var row model.OffsiteObject
	if err := l.db.Where("id = ?", id).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrObjectNotInLedger
		}
		return nil, fmt.Errorf("讀取離機帳冊列失敗: %w", err)
	}
	return &row, nil
}

// RetryFailed 把 failed 列重置為 pending、attempts 歸零（管理介面的批次重試）。
// objectID 為 0＝全部 failed。
func (l *Ledger) RetryFailed(objectID uint) (int64, error) {
	now := l.now()
	q := l.db.Model(&model.OffsiteObject{}).Where("state = ?", StateFailed)
	if objectID != 0 {
		q = q.Where("id = ?", objectID)
	}
	res := q.Updates(map[string]any{
		"state":           StatePending,
		"attempts":        0,
		"next_attempt_at": now,
		"error_code":      "",
		"updated_at":      now,
	})
	if res.Error != nil {
		return 0, fmt.Errorf("重試離機失敗件失敗: %w", res.Error)
	}
	return res.RowsAffected, nil
}

// ProfileContinuityError 健檢失敗：帳冊出現的世代對不到世代表。
//
// **訊息指名世代 id 與物件數，不含端點**（端點只在設定面以 origin 顯示）。
type ProfileContinuityError struct {
	// Missing generation_id → 該世代的存量物件數
	Missing map[uint]int64
}

func (e *ProfileContinuityError) Error() string {
	ids := make([]uint, 0, len(e.Missing))
	for id := range e.Missing {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	msg := "離機保管帳冊的儲存設定世代對不到設定表（資料損壞，多半是部分還原或手動改資料庫）："
	for _, id := range ids {
		msg += fmt.Sprintf("\n  世代 %d：%d 個物件", id, e.Missing[id])
	}
	msg += "\n  處置：還原完整備份；**不要手動改資料庫補列**——補出來的世代沒有正確的憑證，" +
		"那批物件仍然取不回來，只是失敗的地方換了一處。"
	return msg
}

// CheckProfileContinuity 啟動健檢（**自世代拒啟降級而來**）。
//
// 斷言＝帳冊出現的 `storage_generation_id` ⊆ 世代表現存世代（**含已退役者
// ——退役是合法歸屬**，那正是 foreign 物件的正常狀態）。違反即資料損壞，建構失敗。
//
// **不再有世代拒啟**：世代切換與停止離機都在管理介面內以鎖內交易完成，
// DB 恆自洽；啟動時唯一可能不自洽的來源是部分還原或手動改資料庫。
func (l *Ledger) CheckProfileContinuity() error {
	type row struct {
		StorageGenerationID uint
		N                   int64
	}
	var rows []row
	if err := l.db.Model(&model.OffsiteObject{}).
		Select("storage_generation_id, count(*) as n").
		Group("storage_generation_id").Scan(&rows).Error; err != nil {
		return fmt.Errorf("彙總離機帳冊世代失敗: %w", err)
	}
	if len(rows) == 0 {
		return nil
	}
	ids := make([]uint, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.StorageGenerationID)
	}
	var known []uint
	if err := l.db.Model(&model.OffsiteProfile{}).Where("generation_id IN ?", ids).
		Pluck("generation_id", &known).Error; err != nil {
		return fmt.Errorf("讀取離機設定世代失敗: %w", err)
	}
	set := map[uint]bool{}
	for _, id := range known {
		set[id] = true
	}
	missing := map[uint]int64{}
	for _, r := range rows {
		if !set[r.StorageGenerationID] {
			missing[r.StorageGenerationID] = r.N
		}
	}
	if len(missing) > 0 {
		return &ProfileContinuityError{Missing: missing}
	}
	return nil
}

// custodyResourceOf 帳冊 kind → 審計 Resource。
func custodyResourceOf(kind string) string {
	if kind == KindExport {
		return string(model.ResourceAuditExport)
	}
	return string(model.ResourceSession)
}
