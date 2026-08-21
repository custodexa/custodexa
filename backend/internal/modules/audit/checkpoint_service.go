package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"gorm.io/gorm"
)

// 封章參數（audit-checkpoint-chain D3）：門檻可調但**不可關閉**——
// spec 明文「SHALL NOT 可被關閉為『不封章』」，故非法值一律退回預設並記 log，
// 不接受 0／負值當作停用開關
const (
	// checkpointIntervalDefault 時間門檻：距上一檢查點 sealed_at 滿此值即觸發
	checkpointIntervalDefault = time.Hour
	// checkpointIntervalMax 時間門檻上限：再長就等於實質關閉封章
	checkpointIntervalMax = 24 * time.Hour
	// checkpointRowThresholdDefault 筆數門檻：MAX(id) - 上一檢查點 id_to 達此值即觸發
	checkpointRowThresholdDefault int64 = 10000
	// checkpointRowThresholdMax 筆數門檻上限（同上，防以極大值實質關閉）
	checkpointRowThresholdMax int64 = 1000000
	// checkpointGraceDefault 在途交易 grace（D3／O2）：觸發時取上界，
	// 延遲此時長後才掃描，讓「已取號未 commit」的交易落地
	checkpointGraceDefault = 30 * time.Second
	// checkpointGraceMax grace 上限：超過即失去「每小時一個檢查點」的意義
	checkpointGraceMax = 10 * time.Minute
)

// checkpointSigner 封章所需的簽章能力（窄介面；實作為
// keyvault.CheckpointSigningService，測試注入 fake）
type checkpointSigner interface {
	ActiveVersion() int
	Sign(data []byte) (int, string)
	Verify(version int, data []byte, sigBase64 string) (bool, error)
}

// checkpointAnchorSink 離機錨定出口（實作為 *SyslogForwarder）。
// Enqueue 回傳「是否入列成功」——false＝緩衝滿被丟棄，呼叫端記 dropped
type checkpointAnchorSink interface {
	Enabled() bool
	EnqueueCheckpoint(cp *model.AuditCheckpoint) bool
}

// ErrCheckpointNoChain 鏈上無任何檢查點（genesis 未建立）
var ErrCheckpointNoChain = errors.New("檢查點鏈為空：genesis 尚未建立")

// ErrCheckpointSigningKeyRotated 簽章期間鑰版本改變（TOCTOU）
var ErrCheckpointSigningKeyRotated = errors.New("簽章鑰版本於封章期間改變，本輪放棄（下輪重試）")

// CheckpointService 審計檢查點封章器（audit-checkpoint-chain 第 4 組）。
//
// **旁路批次工作，絕不進入審計寫入熱路徑**（D3）：本型別只做「讀 audit_logs
// 三欄 → 算聚合 → 簽章 → 插一列 audit_checkpoints → 丟一則 syslog」，
// 審計寫入端不知道它存在，也不等它。封章失敗、排程停擺、簽章鑰不可用，
// 審計寫入照常成功，鏈於恢復後自上次 id_to 續接（不偽造補蓋遺漏時段）。
type CheckpointService struct {
	db     *gorm.DB
	signer checkpointSigner
	anchor checkpointAnchorSink
	// onFailure 失效上報（nil 安全）；mechanism 走 MechanismCheckpointAnchor
	onFailure failureReporter

	// interval／rowThreshold 為 env 播種的初值；執行期以安全政策頁為準
	// （policies 非 nil 時），見 Interval／RowThreshold
	interval     time.Duration
	rowThreshold int64
	grace        time.Duration

	// policies 封章門檻的執行期事實源（安全政策頁）。nil＝未接（單測與
	// 早期啟動序），此時沿用 env 初值
	policies checkpointPolicySource

	// now／sleep 為時間注入點（測試以假時鐘跑完整流程，不真的睡 30 秒）
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) bool

	// sealing 單飛旗標：排程每分鐘一跳，而單次封章含 grace 可達數十秒，
	// 重疊執行會讓兩輪都讀到同一個 last 而競爭同一個 seq
	sealing atomic.Bool
	// anchorFailing 錨定失效進行中（沿 SyslogForwarder 的觸發／恢復各上報一次）
	anchorFailing atomic.Bool
	// mu 保護 EnsureGenesis 與 SealUpTo 的「讀 last → 寫新點」臨界區（單行程內）
	mu sync.Mutex
}

// NewCheckpointService 建立封章器。門檻與 grace 自 env 讀取（非法值退回預設）。
//
// anchor／onFailure 允許為 nil（單測與未啟用轉發的部署）——錨定是附加證據，
// 缺席時檢查點仍完整落庫並簽章
func NewCheckpointService(db *gorm.DB, signer checkpointSigner, anchor checkpointAnchorSink,
	onFailure failureReporter) *CheckpointService {
	return &CheckpointService{
		db:           db,
		signer:       signer,
		anchor:       anchor,
		onFailure:    onFailure,
		interval:     checkpointDurationEnv("AUDIT_CHECKPOINT_INTERVAL_SECONDS", checkpointIntervalDefault, time.Second, checkpointIntervalMax),
		rowThreshold: checkpointInt64Env("AUDIT_CHECKPOINT_ROW_THRESHOLD", checkpointRowThresholdDefault, 1, checkpointRowThresholdMax),
		grace:        checkpointDurationEnv("AUDIT_CHECKPOINT_GRACE_SECONDS", checkpointGraceDefault, 0, checkpointGraceMax),
		now:          time.Now,
		sleep:        checkpointSleep,
	}
}

// checkpointSleep 可被 ctx 中斷的等待；回傳 true＝等滿，false＝被中斷
func checkpointSleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func checkpointDurationEnv(key string, def, min, max time.Duration) time.Duration {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	d := time.Duration(n) * time.Second
	if err != nil || d < min || d > max {
		log.Printf("[Checkpoint] %s=%q 非法（合法區間 %v..%v），改用預設 %v", key, raw, min, max, def)
		return def
	}
	return d
}

func checkpointInt64Env(key string, def, min, max int64) int64 {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < min || n > max {
		log.Printf("[Checkpoint] %s=%q 非法（合法區間 %d..%d），改用預設 %d", key, raw, min, max, def)
		return def
	}
	return n
}

// checkpointPolicySource 封章門檻的執行期來源（安全政策頁）
type checkpointPolicySource interface {
	GetInt(key string) int
}

// SetPolicySource 接上安全政策頁作為封章門檻的執行期事實源。
//
// **每次判斷都重讀而非啟動時快取一份**：管理員調短週期的目的正是縮小未封窗口
// （誠實邊界 R5），若須重啟才生效，事故當下就縮不了窗
func (s *CheckpointService) SetPolicySource(p checkpointPolicySource) { s.policies = p }

// Grace 現行 grace 值（排程器 log 與測試用）
func (s *CheckpointService) Grace() time.Duration { return s.grace }

// Interval 現行時間門檻：政策頁優先，未接或值不合法時退回 env 初值。
// 邊界複查（1 秒 ~ 上限）在此重做一次——政策層雖已驗證，但封章門檻若因
// 資料層直改而落到 0，排程會退化成每跳都封章
func (s *CheckpointService) Interval() time.Duration {
	if s.policies == nil {
		return s.interval
	}
	d := time.Duration(s.policies.GetInt(policy.PolicyAuditCheckpointIntervalSeconds)) * time.Second
	if d < time.Second || d > checkpointIntervalMax {
		return s.interval
	}
	return d
}

// RowThreshold 現行筆數門檻：政策頁優先，未接或值不合法時退回 env 初值
func (s *CheckpointService) RowThreshold() int64 {
	if s.policies == nil {
		return s.rowThreshold
	}
	n := int64(s.policies.GetInt(policy.PolicyAuditCheckpointRowThreshold))
	if n < 1 || n > checkpointRowThresholdMax {
		return s.rowThreshold
	}
	return n
}

// Latest 鏈尾檢查點（seq 最大）；鏈為空回 ErrCheckpointNoChain
func (s *CheckpointService) Latest() (*model.AuditCheckpoint, error) {
	var cp model.AuditCheckpoint
	err := s.db.Order("seq DESC").First(&cp).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return nil, ErrCheckpointNoChain
	case err != nil:
		return nil, fmt.Errorf("讀取鏈尾檢查點失敗: %w", err)
	}
	return &cp, nil
}

// maxAuditLogID 現行 audit_logs 的 MAX(id)（空表為 0）。
// 用 Unscoped：軟刪列的 id 仍佔號，區間必須涵蓋它
func (s *CheckpointService) maxAuditLogID() (uint, error) {
	var maxID uint
	if err := s.db.Unscoped().Model(&model.AuditLog{}).
		Select("COALESCE(MAX(id), 0)").Scan(&maxID).Error; err != nil {
		return 0, fmt.Errorf("讀取 audit_logs MAX(id) 失敗: %w", err)
	}
	return maxID, nil
}

// EnsureGenesis 鏈為空時建立 genesis（seq=1）。
//
// genesis 是**空區間**：`id_from = 啟用當下 MAX(id)+1`、`id_to = MAX(id)`。
// 它不覆蓋任何既有列（那些列寫入時本機制尚不存在，宣稱覆蓋等於偽造），
// 只負責把鏈頭錨定到既有完整性基準——重造鏈需同時偽造 integrity_baselines。
func (s *CheckpointService) EnsureGenesis() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var count int64
	if err := s.db.Model(&model.AuditCheckpoint{}).Count(&count).Error; err != nil {
		return fmt.Errorf("計數檢查點失敗: %w", err)
	}
	if count > 0 {
		return nil
	}

	var baseline model.IntegrityBaseline
	if err := s.db.First(&baseline, 1).Error; err != nil {
		// 完整性基準是 genesis 的錨；缺它就沒有可錨定的東西，
		// 不以零值硬蓋（零值 genesis 可被憑空重造）
		return fmt.Errorf("讀取完整性基準失敗（genesis 無錨可用）: %w", err)
	}
	prevHash, err := CheckpointGenesisPrevHash(baseline.MaxLogID, baseline.BaselineAt)
	if err != nil {
		return err
	}
	maxID, err := s.maxAuditLogID()
	if err != nil {
		return err
	}
	emptyHash, emptyCount := ComputeAggHash(nil)

	cp := model.AuditCheckpoint{
		Seq:                1,
		IDFrom:             maxID + 1,
		IDTo:               maxID,
		RowCount:           emptyCount,
		AggHash:            emptyHash,
		AggScheme:          model.AggSchemeV1,
		PrevCheckpointHash: prevHash,
		SealedAt:           s.now().UTC(),
	}
	if err := s.signAndPersist(&cp); err != nil {
		return err
	}
	log.Printf("[Checkpoint] genesis 已建立（seq=1、id_from=%d、錨定 baseline max_log_id=%d）",
		cp.IDFrom, baseline.MaxLogID)
	s.anchorCheckpoint(&cp)
	return nil
}

// Due 是否達封章觸發條件；回傳 (是否觸發, 觸發時觀測到的 MAX(id))。
//
// **觸發即取上界**（D3）：回傳的 idHi 就是本輪區間上界，呼叫端等 grace 後
// 才掃描——先取上界再等待，才可能把「已取號未 commit」的列納入
func (s *CheckpointService) Due() (bool, uint, error) {
	last, err := s.Latest()
	if err != nil {
		return false, 0, err
	}
	maxID, err := s.maxAuditLogID()
	if err != nil {
		return false, 0, err
	}
	// int64 相減：maxID < last.IDTo 時 uint 相減會下溢成天文數字而恆觸發
	if int64(maxID)-int64(last.IDTo) >= s.RowThreshold() {
		return true, maxID, nil
	}
	if s.now().Sub(last.SealedAt) >= s.Interval() {
		return true, maxID, nil
	}
	return false, maxID, nil
}

// Tick 排程器每分鐘呼叫一次：檢查觸發條件 → 記上界 → 等 grace → 封章。
//
// 單飛：上一輪仍在 grace 等待中時本輪直接跳過（兩輪讀到同一個 last 會競爭
// 同一個 seq，UNIQUE 會擋下但徒然產生錯誤記錄）
func (s *CheckpointService) Tick(ctx context.Context) error {
	if !s.sealing.CompareAndSwap(false, true) {
		return nil
	}
	defer s.sealing.Store(false)

	due, idHi, err := s.Due()
	if err != nil || !due {
		return err
	}
	if !s.sleep(ctx, s.grace) {
		// 收束中被中斷：不封章（半途封章不會產生錯誤資料，但也沒有意義——
		// 下次啟動自上次 id_to 續接）
		return nil
	}
	_, err = s.SealUpTo(idHi)
	return err
}

// SealNow 立刻封章至現行 MAX(id)（測試、e2e 與手動驗證用；不走觸發條件、不等 grace）
func (s *CheckpointService) SealNow() (*model.AuditCheckpoint, error) {
	maxID, err := s.maxAuditLogID()
	if err != nil {
		return nil, err
	}
	return s.SealUpTo(maxID)
}

// SealUpTo 封章覆蓋 `[上一檢查點 id_to + 1, idHi]`。
//
// **空區間照蓋**（D4）：idHi 等於上一檢查點 id_to 時 id_from > id_to、
// row_count=0、聚合為空輸入雜湊，照常鏈接與簽章。「那一小時沒事發生」本身
// 成為被簽章的主張——否則攻擊者可「刪光該區間資料＋刪掉該檢查點」，
// 使其看起來像那小時沒事發生。
func (s *CheckpointService) SealUpTo(idHi uint) (*model.AuditCheckpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	last, err := s.Latest()
	if err != nil {
		return nil, err
	}
	idFrom := last.IDTo + 1
	idTo := idHi
	if idTo < last.IDTo {
		// id 不可能倒退；真發生代表有人動了序列或表。不硬造負區間，
		// 退回空區間（誠實：本輪沒有新列可覆蓋）
		log.Printf("[Checkpoint] 觀測上界 %d 低於鏈尾 id_to %d（序列異常），本輪以空區間封章",
			idHi, last.IDTo)
		idTo = last.IDTo
	}
	prevHash, err := CheckpointLinkHash(last)
	if err != nil {
		return nil, err
	}
	aggHash, rowCount, minAt, maxAt, err := s.Aggregate(idFrom, idTo)
	if err != nil {
		return nil, err
	}

	cp := model.AuditCheckpoint{
		Seq:                last.Seq + 1,
		IDFrom:             idFrom,
		IDTo:               idTo,
		RowCount:           rowCount,
		AggHash:            aggHash,
		AggScheme:          model.AggSchemeV1,
		PrevCheckpointHash: prevHash,
		MinCreatedAt:       minAt,
		MaxCreatedAt:       maxAt,
		SealedAt:           s.now().UTC(),
	}
	if err := s.signAndPersist(&cp); err != nil {
		return nil, err
	}
	s.anchorCheckpoint(&cp)
	return &cp, nil
}

// signAndPersist 簽章並落庫。
//
// SigningKeyVersion 在**簽章涵蓋範圍內**，故必須先定版本再算 payload；
// Sign 回傳的版本與先前讀到的不同＝期間發生輪替，整輪放棄（下輪重試）——
// 落一筆「payload 寫 v1、實際以 v2 簽」的檢查點會永遠驗不過
func (s *CheckpointService) signAndPersist(cp *model.AuditCheckpoint) error {
	if s.signer == nil {
		return errors.New("檢查點簽章鑰未注入：拒絕落一個不可驗的檢查點")
	}
	cp.SigningKeyVersion = s.signer.ActiveVersion()
	payload, err := CheckpointSignBytes(cp)
	if err != nil {
		return err
	}
	usedVersion, sig := s.signer.Sign(payload)
	if usedVersion != cp.SigningKeyVersion {
		return fmt.Errorf("%w: payload 記 v%d、實際簽 v%d",
			ErrCheckpointSigningKeyRotated, cp.SigningKeyVersion, usedVersion)
	}
	cp.Signature = sig
	// 落庫前先定 anchor_status：欄位 not null，且**取悲觀值**——
	// 轉發已啟用時先記 dropped，入列成功再升為 enqueued。行程若在
	// 落庫與入列之間崩潰，殘留值是「這個檢查點沒有離機證據」，
	// 這是證據面唯一可接受的預設方向
	cp.AnchorStatus = model.AnchorStatusDisabled
	if s.anchor != nil && s.anchor.Enabled() {
		cp.AnchorStatus = model.AnchorStatusDropped
	}
	if err := s.db.Create(cp).Error; err != nil {
		// seq UNIQUE 衝突走這裡（並發封章的最後防線）：本輪失敗，鏈維持線性
		return fmt.Errorf("寫入檢查點 seq=%d 失敗: %w", cp.Seq, err)
	}
	return nil
}

// Aggregate 計算 `[idFrom, idTo]` 的聚合雜湊、列數與時間跨度（D2）。
//
// 只取三欄（id、key_version、integrity_hmac）＋created_at：
// 列內容真偽已由列級 HMAC 綁定，聚合的職責是「這批列的集合與順序未被動」，
// 重讀全欄位是重複勞動且封章掃描成本翻數倍。
// created_at 只為人讀映射，**不參與雜湊**（D1：時間不參與完整性判定）。
//
// Unscoped：軟刪列在範圍內（與列級驗證一致）。
func (s *CheckpointService) Aggregate(idFrom, idTo uint) (string, int64, *time.Time, *time.Time, error) {
	w := newCheckpointAggWriter()
	if idFrom > idTo {
		// 空區間：不查庫，直接回空輸入雜湊
		h, n := w.Sum()
		return h, n, nil, nil, nil
	}
	rows, err := s.db.Unscoped().Model(&model.AuditLog{}).
		Select("id", "key_version", "integrity_hmac", "created_at").
		Where("id >= ? AND id <= ?", idFrom, idTo).
		Order("id ASC").Rows()
	if err != nil {
		return "", 0, nil, nil, fmt.Errorf("掃描檢查點區間 [%d,%d] 失敗: %w", idFrom, idTo, err)
	}
	defer rows.Close()

	var minAt, maxAt *time.Time
	for rows.Next() {
		var (
			id        uint
			keyVer    sql.NullInt64
			hmac      sql.NullString
			createdAt sql.NullTime
		)
		if err := rows.Scan(&id, &keyVer, &hmac, &createdAt); err != nil {
			return "", 0, nil, nil, fmt.Errorf("讀取檢查點區間列失敗: %w", err)
		}
		// NULL 與空字串同視為「無 HMAC」——列級驗證的語義即如此，
		// 聚合不另闢一種區分
		w.Add(checkpointAggEntry{
			ID:            id,
			KeyVersion:    int(keyVer.Int64),
			IntegrityHMAC: hmac.String,
		})
		if createdAt.Valid {
			t := createdAt.Time.UTC()
			// created_at 與 id 不同序（封印期回灌列的時間是過去事件時刻），
			// 故 min/max 必須逐列比較，不可取首末列
			if minAt == nil || t.Before(*minAt) {
				v := t
				minAt = &v
			}
			if maxAt == nil || t.After(*maxAt) {
				v := t
				maxAt = &v
			}
		}
	}
	if err := rows.Err(); err != nil {
		return "", 0, nil, nil, fmt.Errorf("掃描檢查點區間 [%d,%d] 中斷: %w", idFrom, idTo, err)
	}
	h, n := w.Sum()
	return h, n, minAt, maxAt, nil
}

// anchorCheckpoint 離機錨定（D7／裁決 5）：**任何失敗都不影響檢查點落庫**。
//
// 落庫已完成才走到這裡；此處只負責把結果反映到 anchor_status 並在丟棄時
// 上報失效事件。上報用獨立機制碼 MechanismCheckpointAnchor 而非沿用
// syslog_forward——見 model 該常數的註解（O4 判定）
func (s *CheckpointService) anchorCheckpoint(cp *model.AuditCheckpoint) {
	want := model.AnchorStatusDisabled
	if s.anchor != nil && s.anchor.Enabled() {
		if s.anchor.EnqueueCheckpoint(cp) {
			want = model.AnchorStatusEnqueued
		} else {
			want = model.AnchorStatusDropped
		}
	}
	if want != cp.AnchorStatus {
		// **只認 map 形式**：model 的 BeforeUpdate 白名單守衛拒絕結構體路徑
		if err := s.db.Model(cp).Updates(map[string]any{"anchor_status": want}).Error; err != nil {
			log.Printf("[Checkpoint] 更新 seq=%d 的 anchor_status 失敗（保留悲觀值 %s）: %v",
				cp.Seq, cp.AnchorStatus, err)
		} else {
			cp.AnchorStatus = want
		}
	}
	switch want {
	case model.AnchorStatusDropped:
		s.reportAnchorFailure(cp)
	case model.AnchorStatusEnqueued:
		s.reportAnchorRecovered()
	}
}

// reportAnchorFailure 錨定失效上報（節流：進行中不重複開列）
func (s *CheckpointService) reportAnchorFailure(cp *model.AuditCheckpoint) {
	log.Printf("[Checkpoint] seq=%d 錨定入列被丟棄，該檢查點無離機證據（anchor_status=dropped）", cp.Seq)
	if s.anchorFailing.CompareAndSwap(false, true) && s.onFailure != nil {
		s.onFailure(model.MechanismCheckpointAnchor, model.CauseCheckpointAnchorDropped,
			map[string]string{"seq": strconv.FormatUint(uint64(cp.Seq), 10)}, false)
	}
}

// reportAnchorRecovered 錨定恢復上報。
//
// 恢復的語義是「錨定機制恢復可用」，**不是**「先前丟棄的檢查點補上了離機證據」
// ——那些檢查點的 anchor_status 永久為 dropped，誠實邊界 R4 的落點
func (s *CheckpointService) reportAnchorRecovered() {
	if s.anchorFailing.CompareAndSwap(true, false) && s.onFailure != nil {
		s.onFailure(model.MechanismCheckpointAnchor, "", nil, true)
	}
}
