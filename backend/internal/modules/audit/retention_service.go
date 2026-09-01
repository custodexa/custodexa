package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/policy"
	"log"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// retention 分批刪除參數（PCI 10.5.1）：
// 分批+單次上限避免首次啟用時的巨量刪除鎖表；未刪完次日排程繼續。
// 預設上限約 1.15 筆/秒的刪除預算——高流量部署（audit 每日新增遠超 10 萬）
// 追不上時以 RETENTION_MAX_PER_RUN 調高（實測發現的規模化邊界）
const (
	retentionBatchSize        = 5000
	retentionMaxPerRunDefault = 100000
	retentionBatchPause       = 50 * time.Millisecond
	// retentionMinPerRun 單次上限的下界：
	// 低於一個批次即代表單輪連一個批次都刪不完，分批機制失去意義且刪除速率
	// 必然追不上新增量——保留政策實質失效。與 PolicyRetentionMaxPerRun 的 Min 同值
	retentionMinPerRun = retentionBatchSize
)

// maxPerRunNow 本次執行的刪除上限：明確覆寫 > 安全政策頁 > 出廠預設。
//
// **每次執行現讀而非啟動時快取**：管理員調高上限的目的正是讓清理追上新增量
// （retention_service.go:19-20 自陳的規模化邊界），若須重啟才生效，
// 積壓當下就調不動。政策層已擋下低於下界的值（PolicyRetentionMaxPerRun 的 Min），
// 此處再做一次邊界複查——政策若因資料層直改而落到下界之下，
// 清理會退化成「每輪連一批都刪不完」，那正是本鍵下界要防的靜默停擺
func (s *RetentionService) maxPerRunNow() int {
	if s.maxPerRun > 0 {
		return s.maxPerRun
	}
	if s.policy == nil {
		return retentionMaxPerRunDefault
	}
	n := s.policy.GetInt(policy.PolicyRetentionMaxPerRun)
	if n < retentionMinPerRun {
		log.Printf("[Retention] 單次清理上限 %d 低於下界 %d，改用下界", n, retentionMinPerRun)
		return retentionMinPerRun
	}
	return n
}

// auditLogger 審計留痕的窄介面（單測注入 fake）
type auditLogger interface {
	Log(entry *AuditLogEntry)
}

// retentionTarget 一類受保留政策管理的 DB 資料。
// 刪除走原生 SQL（id IN 子查詢，postgres/sqlite 通用；
// 不經 GORM hook——audit_logs 的 BeforeDelete 守衛只放行此路徑）
type retentionTarget struct {
	policyKey  string
	table      string
	timeColumn string
	label      string
}

// auditLogsTable audit_logs 表名（分派層以表名辨識目標）。
//
// retentionTargets 內**刻意保留字面量**：cmd/server 的資料邊界守衛
// （TestRetentionTargetsAreAuditOwned）以 AST 讀該登記表的字串字面判定
// 每張表的所屬模組，改成常數參照會讓它解析不到而失去守衛效力
const auditLogsTable = "audit_logs"

var retentionTargets = []retentionTarget{
	{policy.PolicyRetentionAuditLogDays, "audit_logs", "created_at", "操作日誌"},
	{policy.PolicyRetentionSessionCommandDays, "session_commands", "executed_at", "指令流"},
	{policy.PolicyRetentionAlertDays, "command_alerts", "triggered_at", "告警記錄"},
}

// auditLogPurgeMode audit_logs 的清除策略（audit-checkpoint-chain 分派層）。
//
// **新舊路徑並存而非直接替換**：區間清除與逐列清除的差異只有在真實資料上
// 對跑才看得出來（design 附錄「對第 6 組的推論」），一次性替換等於把
// 「行為變了多少」的問題留到部署後首輪 retention 才回答。分派層使兩條路徑
// 可在同一組資料上交替執行並逐項比對。
type auditLogPurgeMode int

const (
	// auditLogPurgeLegacy 全表逐列過期刪除（改造前行為，無 id 上界）
	auditLogPurgeLegacy auditLogPurgeMode = iota
	// auditLogPurgeInterval 已封檢查點區間整段清除 ＋ pre-genesis 逐列殘量
	auditLogPurgeInterval
)

// RetentionService 保留政策執行器：每類過期資料分批硬刪＋清除動作入審計
type RetentionService struct {
	db        *gorm.DB
	policy    *policy.SecurityPolicyService
	recording RecordingCleaner
	audit     auditLogger

	batchSize int
	// maxPerRun 單次刪除上限的**明確覆寫**：>0 時蓋過政策。
	//
	// 僅供測試與腳本用——它們要的是「12 列資料配上限 10」這種小規模確定性，
	// 而政策下界（5000 列）不容許那麼小的值。正常部署由 NewRetentionService
	// 設為 0，一律走 maxPerRunNow() 讀政策，env 只透過 SeedFromEnv 影響初值
	maxPerRun int

	// checkpoints audit_logs 的檢查點區間清除引擎；nil＝本部署未接入檢查點鏈
	//（單元測試與 scripts/retention_smoke.go），此時 audit_logs 一律走 legacy
	checkpoints *CheckpointPurger
	// auditLogMode audit_logs 走哪條路徑；checkpoints 為 nil 時本欄無作用
	auditLogMode auditLogPurgeMode

	// offsiteRecordings 離機啟用後的錄影保留補充面；nil＝未組裝離機子系統
	// （此時本檔的行為與該功能不存在時逐字相同）
	offsiteRecordings OffsiteRecordingRetention

	// watermarks 保留期清除水位。nil＝不記水位
	//（單元測試與 scripts/retention_smoke.go），此時工作台一律回 present——
	// 那是冷啟動語義，不是錯誤
	watermarks *RetentionWatermarkService
}

// SetOffsiteRecordingRetention 接上離機錄影保留補充面（組裝根）。
func (s *RetentionService) SetOffsiteRecordingRetention(r OffsiteRecordingRetention) {
	s.offsiteRecordings = r
}

// SetWatermarks 接上保留水位記錄器。
//
// **與清除留痕並存而非取代**：留痕（audit_logs 內的 Resource=retention 列）
// 仍是 PCI 10.2.1.6 要求的「清除動作可追溯」，它會過期是既有事實；
// 水位是工作台專用的「這段區間別當成空白」標記，兩者用途不同、生命週期不同。
//
// **命名為 Set 前綴而非原先的 With 流暢式**：組裝根的注入呼叫點由
// `lifecycle_manifest_guard_test.go` 以 Set／Init／Register／Reset 前綴辨識，
// `WithWatermarks` 落在辨識範圍外——它從建立到本次修復為止**零呼叫點**，
// 而沒有任何測試轉紅，正是因為這條注入不在登記表的射程內。
func (s *RetentionService) SetWatermarks(w *RetentionWatermarkService) {
	s.watermarks = w
}

// recordWatermark 於一次清除執行後前進水位。
//
// **失敗也記**（err != nil 時仍呼叫）的判準：清除失敗不代表零筆被刪——
// 分批刪除可能刪到一半才出錯，已刪的那些不會回來。漏記水位會讓那段
// 空白被讀成「紀錄被刪」，而多記的代價只是把「可能仍完整」保守標為已清除。
// 兩個方向的錯誤不對稱，故取保守側。
//
// 水位時間上界＝本次執行所用的 cutoff（now − days），與 purgeTable／
// purgeAuditLogs 內的算式**必須同源**，否則水位會宣稱一段其實沒被碰的區間
func (s *RetentionService) recordWatermark(table string, days int, partial bool, at time.Time) {
	if s.watermarks == nil {
		return
	}
	class := retentionClassForTable(table)
	if class == "" {
		return
	}
	if err := s.watermarks.Advance(class, at.AddDate(0, 0, -days), days, partial); err != nil {
		log.Printf("[Retention] 保留水位更新失敗（%s）: %v", class, err)
	}
}

// NewRetentionService 建立保留政策執行器（未接入檢查點鏈：audit_logs 走 legacy 逐列路徑）
func NewRetentionService(db *gorm.DB, policy *policy.SecurityPolicyService, recording RecordingCleaner, audit auditLogger) *RetentionService {
	return &RetentionService{
		db: db, policy: policy, recording: recording, audit: audit,
		batchSize:    retentionBatchSize, // maxPerRun 留 0＝以政策為準
		auditLogMode: auditLogPurgeLegacy,
	}
}

// PurgeResult 單類清除結果。
//
// PreGenesis／Intervals 僅 audit_logs 的區間路徑會填；omitempty 使其餘三類
// 與 legacy 路徑的留痕 JSON 與改造前**逐位元組相同**（零行為變化的判準）
type PurgeResult struct {
	Target  string `json:"target"`
	Days    int    `json:"days"`
	Deleted int64  `json:"deleted"`
	Partial bool   `json:"partial"`
	Error   string `json:"error,omitempty"`

	// PreGenesis 走 pre-genesis 逐列路徑刪除的筆數（不寫 tombstone）
	PreGenesis int64 `json:"pre_genesis,omitempty"`
	// Intervals 本次被整段清除的檢查點區間（seq 清單入留痕，log-retention spec）
	Intervals []PurgedInterval `json:"intervals,omitempty"`
	// TrimmedThroughSeq 鏈修剪至此 seq（含）；殘鏈以修剪記錄錨定
	TrimmedThroughSeq *uint `json:"trimmed_through_seq,omitempty"`
}

// PurgedInterval 一個被合法清除的檢查點區間（留痕用）
type PurgedInterval struct {
	Seq    uint  `json:"seq"`
	IDFrom uint  `json:"id_from"`
	IDTo   uint  `json:"id_to"`
	Rows   int64 `json:"rows"`
}

// PurgeAll 依當下政策值清除全部過期資料（政策值每次執行時讀取，變更即生效）。
// 每類獨立執行與留痕，單類失敗不中斷其他類
func (s *RetentionService) PurgeAll() []PurgeResult {
	var results []PurgeResult
	// 單一時間基準：各目標若各自呼叫 time.Now()，水位上界會因執行耗時而
	// 逐類漂移，跨類別比對時看起來像是清除進度不一致
	runAt := time.Now()
	for _, target := range retentionTargets {
		days := s.policy.GetInt(target.policyKey)
		result := PurgeResult{Target: target.table, Days: days}
		if days <= 0 { // 0=永久保留
			continue
		}
		deleted, partial, err := s.purgeTarget(target, days, &result)
		result.Deleted, result.Partial = deleted, partial
		if err != nil {
			result.Error = err.Error()
			log.Printf("[Retention] %s 清除失敗（已刪 %d 筆）: %v", target.label, deleted, err)
		}
		results = append(results, result)
		s.logPurge(result, target.label)
		s.recordWatermark(target.table, days, partial, runAt)
	}

	// 檢查點鏈自身的到期修剪（log-retention「檢查點自身的保留與鏈修剪」）。
	// 排在 audit_logs 清除**之後**：剛被清除的區間在本輪即取得 tombstone，
	// 才可能滿足「不修剪仍覆蓋現存列的檢查點」這條約束
	if s.checkpoints != nil {
		if days := s.policy.GetInt(policy.PolicyRetentionCheckpointDays); days > 0 {
			result := PurgeResult{Target: "audit_checkpoints", Days: days}
			// **執行期跨鍵保守閘**（audit-checkpoint-chain）：政策值
			// 若經 SQL 直改而違反跨鍵約束，照著它修剪會刪掉仍在證明現存資料的
			// 檢查點。設定面的驗證擋不到直改 DB，故執行面自己再判一次——
			// 用的是設定面同一個比較器（policy.RetentionCovers），不另立一把尺
			if violated := s.crossKeyViolation(days); violated != "" {
				result.Error = violated
				log.Printf("[Retention] 跳過檢查點鏈修剪：%s", violated)
				results = append(results, result)
				s.logPurge(result, "檢查點鏈")
			} else {
				trimmed, trim, err := s.checkpoints.TrimChain(days)
				result.Deleted = trimmed
				if err != nil {
					result.Error = err.Error()
					log.Printf("[Retention] 檢查點鏈修剪失敗: %v", err)
				}
				if trim != nil {
					seq := trim.LastTrimmedSeq
					result.TrimmedThroughSeq = &seq
				}
				if trimmed > 0 || err != nil {
					results = append(results, result)
					s.logPurge(result, "檢查點鏈")
				}
			}
		}
	}

	// 錄影檔：政策值驅動既有檔案清理（0=永久不刪）
	if days := s.policy.GetInt(policy.PolicyRetentionRecordingDays); days > 0 && s.recording != nil {
		result := PurgeResult{Target: "recordings", Days: days}
		deleted, err := s.recording.CleanupOldRecordings(days)
		result.Deleted = int64(deleted)
		if err != nil {
			result.Error = err.Error()
			log.Printf("[Retention] 錄影清除失敗（已刪 %d 檔）: %v", deleted, err)
		}
		// 政策到期段的 DB 分支：
		// 本機已無檔（多半是被快取清除段刪掉）但仍有帳冊列的過期會話。
		// Walk 只看得到磁碟上還在的檔案，這些列不補處置就會停在
		// 「本機檔已刪卻仍被 worker 領取」的孤兒態
		if s.offsiteRecordings != nil {
			purged, perr := s.offsiteRecordings.PurgeExpiredOffsiteRecords(days, s.maxPerRunNow())
			result.Deleted += int64(purged)
			if perr != nil && result.Error == "" {
				result.Error = perr.Error()
				log.Printf("[Retention] 離機錄影到期處置失敗: %v", perr)
			}
		}
		results = append(results, result)
		s.logPurge(result, "會話錄影")
		// 錄影與前三類同記水位：會話列的錄影三態（可回放／已清除／無錄影）
		// 靠它區分「檔案被保留政策清掉」與「這場從未錄影」
		s.recordWatermark("recordings", days, false, runAt)
	}

	// 離機本機副本的**快取清除段**：獨立於保留政策之後執行。
	//
	// **刻意不記水位、不進 results**：水位的語義是「這段區間的資料已被保留政策
	// 清除」，而本段刪的是快取——錄影仍可自離機副本播放。記了水位，工作台會把
	// 一段仍然調得出錄影的區間標成已清除。
	if s.offsiteRecordings != nil {
		if cacheDays := s.policy.GetInt(policy.PolicyOffsiteLocalRetentionDays); cacheDays > 0 {
			if n, err := s.offsiteRecordings.PurgeOffsiteLocalCache(cacheDays); err != nil {
				log.Printf("[Retention] 離機本機快取清除失敗: %v", err)
			} else if n > 0 {
				log.Printf("[Retention] 離機本機快取清除 %d 檔（快取期 %d 天）", n, cacheDays)
			}
		}
	}
	return results
}

// crossKeyViolation 執行期跨鍵約束檢查（audit-checkpoint-chain）。
//
// 回傳非空字串＝違反（字串即告警文字，同時進 log 與清除留痕）。
//
// **為何執行期還要再判一次**：設定面的驗證只擋 API 路徑，政策表被 SQL 直改
// 就繞過了（design「跨鍵驗證的繞過面」）。而檢查點修剪是不可逆的刪除——
// 依一個違規政策值修剪，會刪掉仍在證明現存資料的檢查點，那些資料日後既
// 不可證為合法清除也不可證為竄改。故執行面採保守方向：**寧可不修剪**。
//
// 註：TrimChain 自身另有「仍覆蓋現存列的檢查點絕不修剪」的約束，不依賴本檢查
// 即成立；本檢查是更早一層的閘（連空區間檢查點都不修），兩者是縱深不是重複
func (s *RetentionService) crossKeyViolation(checkpointDays int) string {
	for _, key := range []string{
		policy.PolicyRetentionAuditLogDays,
		policy.PolicyRetentionSessionCommandDays,
		policy.PolicyRetentionAlertDays,
		policy.PolicyRetentionRecordingDays,
	} {
		dataDays := s.policy.GetInt(key)
		if !policy.RetentionCovers(checkpointDays, dataDays) {
			return fmt.Sprintf("政策違反跨鍵約束（%s=%d 天 < %s=%d 天，0=永久）："+
				"保守跳過鏈修剪，請修正政策值",
				policy.PolicyRetentionCheckpointDays, checkpointDays, key, dataDays)
		}
	}
	return ""
}

// purgeTarget 單類目標的清除策略分派（audit-checkpoint-chain）。
//
// audit_logs 以外的三類永遠走逐列路徑（spec：其餘三類行為不變）；
// audit_logs 依 auditLogMode 決定，未接入檢查點鏈時一律 legacy。
// result 供區間路徑回填 seq 清單等留痕欄位（legacy 路徑不碰它，
// 故留痕 JSON 與改造前逐位元組相同）
func (s *RetentionService) purgeTarget(target retentionTarget, days int, result *PurgeResult) (int64, bool, error) {
	if target.table != auditLogsTable || s.checkpoints == nil || s.auditLogMode == auditLogPurgeLegacy {
		return s.purgeTable(target, days, purgeOpts{})
	}
	return s.purgeAuditLogs(target, days, result)
}

// purgeAuditLogs audit_logs 的檢查點感知清除路徑。
//
// 兩段互斥的 id 範圍，**邊界由 genesis id_from 一刀切開**：
//
//	id <  genesis id_from   pre-genesis 殘量：不受任何檢查點覆蓋，維持逐列
//	                        過期刪除直到清空，不寫 tombstone（spec）
//	id >= genesis id_from   已被鏈覆蓋：只能整區間清除並寫 tombstone
//
// 順序是 pre-genesis 先行：那是最舊的資料，且它會隨時間縮到零；
// 額度由兩段共用，pre-genesis 用剩的才給區間路徑
func (s *RetentionService) purgeAuditLogs(target retentionTarget, days int, result *PurgeResult) (int64, bool, error) {
	genesis, err := s.checkpoints.GenesisIDFrom()
	if err != nil {
		// 鏈為空＝停手（fail-close）。此處不退回 legacy 全表逐列：
		// 那會刪掉本應由區間路徑處理的列且不留 tombstone，等於系統
		// 自己製造「列沒了但無有效 tombstone」的竄改告警
		return 0, false, err
	}
	preDeleted, prePartial, err := s.purgeTable(target, days, purgeOpts{idBelow: genesis})
	result.PreGenesis = preDeleted
	if err != nil {
		return preDeleted, prePartial, err
	}
	cutoff := time.Now().AddDate(0, 0, -days)
	budget := s.maxPerRunNow() - int(preDeleted)
	intervalDeleted, intervalPartial, err := s.purgeIntervals(cutoff, days, budget, result)
	return preDeleted + intervalDeleted, prePartial || intervalPartial, err
}

// purgeIntervals 逐個可清區間整段清除（**上限一律在區間邊界停**）。
//
// 半個區間＋無 tombstone 就是自傷告警，故額度不足以吃下整個區間時整段留待
// 次輪，而不是刪到額度用完為止。代價是單次執行可能少刪一個區間的量，
// 相對於「產生一個永遠解釋不了的證據破口」微不足道
func (s *RetentionService) purgeIntervals(cutoff time.Time, days, budget int,
	result *PurgeResult) (int64, bool, error) {
	intervals, err := s.checkpoints.PurgeableIntervals(cutoff)
	if err != nil {
		return 0, false, err
	}
	var total int64
	var partial bool
	var firstErr error
	for i := range intervals {
		cp := intervals[i]
		if int64(budget)-total < cp.RowCount {
			// 剩餘額度吃不下整個區間：整段留待次輪
			log.Printf("[Retention] 單次上限剩餘 %d 列，不足以整段清除 seq=%d（%d 列），留待次輪",
				int64(budget)-total, cp.Seq, cp.RowCount)
			return total, true, firstErr
		}
		deleted, err := s.checkpoints.PurgeInterval(&cp, days, cutoff)
		if err != nil {
			partial = true
			switch {
			case errors.Is(err, ErrPurgeIntervalNotFullyExpired):
				// 預期內：封章後落地的 straggler 使該區間本輪不清（誠實邊界 R1）
				log.Printf("[Retention] %v", err)
			default:
				// 含 ErrPurgeIntervalRowsMissing：必須進留痕，不得靜默
				log.Printf("[Retention] 區間清除失敗 seq=%d: %v", cp.Seq, err)
				if firstErr == nil {
					firstErr = err
				}
			}
			continue
		}
		total += deleted
		result.Intervals = append(result.Intervals, PurgedInterval{
			Seq: cp.Seq, IDFrom: cp.IDFrom, IDTo: cp.IDTo, Rows: deleted,
		})
		// 沿既有批間停頓節奏：連續大交易不應把 DB 壓住
		time.Sleep(retentionBatchPause)
	}
	return total, partial, firstErr
}

// UseCheckpointIntervals 把 audit_logs 切換到檢查點區間清除路徑
// （audit-checkpoint-chain 的**唯一切換點**）。
//
// 不在建構子內接線：切換是有行為差異的決定（部署後首輪 retention 會出現
// 「已過期但所屬區間未全數過期的列暫留」），必須在呼叫端顯式可見，
// 回滾也只是拿掉這一行（design Migration Plan 第 4 點）
func (s *RetentionService) UseCheckpointIntervals(purger *CheckpointPurger) {
	s.checkpoints = purger
	s.auditLogMode = auditLogPurgeInterval
}

// purgeOpts purgeTable 的可選約束。零值＝改造前的原始行為（全表、全額度）
type purgeOpts struct {
	// idBelow >0 時附加 `AND id < idBelow`，把逐列路徑限制在 pre-genesis 段
	// 0＝無上界
	idBelow uint
	// budget >0 時取代 maxPerRun 作為本次刪除額度（區間路徑已用掉的部分）
	budget int
}

// purgeTable 分批刪除單表過期列。回傳 (刪除筆數, 是否達單次上限未刪完, 錯誤)
func (s *RetentionService) purgeTable(target retentionTarget, days int, opts purgeOpts) (int64, bool, error) {
	cutoff := time.Now().AddDate(0, 0, -days)
	limit := s.maxPerRunNow()
	if opts.budget > 0 {
		limit = opts.budget
	}
	if limit <= 0 {
		// 額度已被前段用盡：一列都不碰，且誠實回報未刪完
		return 0, s.hasExpired(target, cutoff, opts.idBelow), nil
	}
	// idBound：pre-genesis 上界；空字串時 SQL 與改造前逐字相同
	idBound, idArgs := "", []any(nil)
	if opts.idBelow > 0 {
		idBound = " AND id < ?"
		idArgs = []any{opts.idBelow}
	}
	var total int64
	for total < int64(limit) {
		batch := s.batchSize
		if remaining := limit - int(total); remaining < batch {
			batch = remaining
		}
		// id IN 子查詢：postgres DELETE 無 LIMIT，此寫法 postgres/sqlite 通用
		stmt := fmt.Sprintf(
			"DELETE FROM %s WHERE id IN (SELECT id FROM %s WHERE %s < ?%s ORDER BY id LIMIT ?)",
			target.table, target.table, target.timeColumn, idBound)
		args := append([]any{cutoff}, idArgs...)
		res := s.db.Exec(stmt, append(args, batch)...)
		if res.Error != nil {
			return total, false, res.Error
		}
		total += res.RowsAffected
		if res.RowsAffected < int64(batch) {
			return total, false, nil // 本批未滿=已清完
		}
		time.Sleep(retentionBatchPause)
	}
	// 達單次上限：探測真殘留再定 partial——過期筆數恰等於上限時最後一批
	// 填滿但已清完，無探測會在留痕誤報「部分完成」（實測重現）
	return total, s.hasExpired(target, cutoff, opts.idBelow), nil
}

// hasExpired 殘留探測：該目標（在 idBelow 上界內）是否仍有過期列。
// 探測本身失敗時保守回 true——留痕寧可誤報「未刪完」也不可誤報「已清完」
func (s *RetentionService) hasExpired(target retentionTarget, cutoff time.Time, idBelow uint) bool {
	idBound, args := "", []any{cutoff}
	if idBelow > 0 {
		idBound = " AND id < ?"
		args = append(args, idBelow)
	}
	var leftover bool
	probe := fmt.Sprintf("SELECT EXISTS(SELECT 1 FROM %s WHERE %s < ?%s)",
		target.table, target.timeColumn, idBound)
	if err := s.db.Raw(probe, args...).Scan(&leftover).Error; err != nil {
		log.Printf("[Retention] %s 殘留探測失敗，保守標記 partial: %v", target.table, err)
		return true
	}
	return leftover
}

// logPurge 清除動作入審計（PCI 10.2.1.6 精神：審計資料的清除必須留痕、失敗不靜默）
func (s *RetentionService) logPurge(result PurgeResult, label string) {
	if s.audit == nil {
		return
	}
	status := model.StatusSuccess
	if result.Error != "" {
		status = model.StatusFailure
	}
	details, _ := json.Marshal(result)
	s.audit.Log(&AuditLogEntry{
		UserID:   0,
		Username: "system",
		Action:   model.ActionDelete,
		Resource: model.ResourceRetention,
		Status:   status,
		ErrorMsg: result.Error,
		Details:  string(details),
	})
	log.Printf("[Retention] %s：保留 %d 天，刪除 %d 筆（partial=%v）",
		label, result.Days, result.Deleted, result.Partial)
}
