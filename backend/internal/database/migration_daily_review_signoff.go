package database

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/reviewcal"
	"gorm.io/gorm"
)

// 每日簽核改版的資料層：daily_review_logs 加「所屬日與簽核時刻分欄」所需的欄位
// 並回填既有紀錄；新表 security_policy_history 記錄每日簽核開關與業務時區的
// 每一次變更，並由既有的政策變更審計重建升級前的啟用歷史。
// DDL 無條件、不用 IF NOT EXISTS——在已套用的庫上重跑必須大聲失敗。
//
// # 既有簽核紀錄的回填
//
//   - signed_at＝created_at：舊制簽核列建立即簽核。
//   - timezone＝升級當下偵測的伺服器時區，timezone_inferred＝true：舊制以後端
//     程序的本地時區切日，升級當下的偵測結果是能取得的最佳估計，標明是推定。
//   - window_*、due_at、late：依上述時區計算；舊制只能簽當天，結果都是準時。
//   - coverage＝until_signed：舊制快照只涵蓋到簽核時刻，不可宣稱涵蓋整天。
//   - source_status＝complete：舊制只能簽當天，簽核當下來源不可能已被清除。
//   - enabled_basis＝recorded：舊制只在開啟時能簽，簽核列本身證明當天開著。
//   - review_date 與 snapshot_json 不動。
//
// # 啟用歷史的重建
//
// 證據能確定的區段照實重建；無法證明開關狀態的區段一律推定為開，並以
// migration_presumed_* 來源標明推定與成因（審計已清除、前後銜接不上、與現值不一致）。
// 推定區段以本資料庫由 baseline 建立的時刻為起點，不往前無限延伸。
// 有簽核紀錄的日子一律在啟用範圍內，依據是簽核紀錄而不是推定。
//
// # Down 契約
//
// 有損：刪新欄與新表，失去延遲原因、時區、遲簽標示與變更歷史。只供 parity 守衛
// 與開發環境使用；生產沒有回滾入口，回退以舊版映像＋升級前備份為準。

func dailyReviewSignoffDDL() []string {
	return append(dailyReviewSignoffAddDDL(), dailyReviewSignoffConstrainDDL()...)
}

// dailyReviewSignoffAddDDL 加欄與建表。需要回填的欄先以可空加入，回填後才設 NOT NULL
func dailyReviewSignoffAddDDL() []string {
	return []string{
		`ALTER TABLE daily_review_logs ADD COLUMN signed_at timestamp with time zone`,
		`ALTER TABLE daily_review_logs ADD COLUMN timezone character varying(64)`,
		`ALTER TABLE daily_review_logs ADD COLUMN timezone_inferred boolean DEFAULT false NOT NULL`,
		`ALTER TABLE daily_review_logs ADD COLUMN window_start timestamp with time zone`,
		`ALTER TABLE daily_review_logs ADD COLUMN window_end timestamp with time zone`,
		`ALTER TABLE daily_review_logs ADD COLUMN due_at timestamp with time zone`,
		`ALTER TABLE daily_review_logs ADD COLUMN late boolean`,
		`ALTER TABLE daily_review_logs ADD COLUMN delay_reason text`,
		`ALTER TABLE daily_review_logs ADD COLUMN coverage character varying(16)`,
		`ALTER TABLE daily_review_logs ADD COLUMN source_status character varying(16)`,
		`ALTER TABLE daily_review_logs ADD COLUMN enabled_basis character varying(16) DEFAULT 'recorded'::character varying NOT NULL`,
		`CREATE TABLE security_policy_history (id bigserial, policy_key character varying(64) NOT NULL, old_value text NOT NULL, new_value text NOT NULL, changed_at timestamp with time zone NOT NULL, changed_by character varying(100) NOT NULL, source character varying(32) NOT NULL, CONSTRAINT security_policy_history_pkey PRIMARY KEY (id))`,
		`CREATE INDEX idx_security_policy_history_key_at ON security_policy_history USING btree (policy_key, changed_at)`,
	}
}

// dailyReviewSignoffConstrainDDL 回填完成後收緊為 NOT NULL
func dailyReviewSignoffConstrainDDL() []string {
	var out []string
	for _, col := range []string{"signed_at", "timezone", "window_start", "window_end", "due_at", "late", "coverage", "source_status"} {
		out = append(out, `ALTER TABLE daily_review_logs ALTER COLUMN `+col+` SET NOT NULL`)
	}
	return out
}

func applyDailyReviewSignoff(db *gorm.DB) error {
	return applyDailyReviewSignoffWith(db, signoffBackfillEnv{
		Now:        time.Now(),
		DetectedTZ: reviewcal.DetectServerTimezone(),
	})
}

// applyDailyReviewSignoffWith 加欄建表 → 回填 → 收緊；外部輸入以 env 注入
func applyDailyReviewSignoffWith(db *gorm.DB, env signoffBackfillEnv) error {
	for _, stmt := range dailyReviewSignoffAddDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 daily_review_signoff DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	if err := backfillDailyReviewSignoff(db, env); err != nil {
		return err
	}
	for _, stmt := range dailyReviewSignoffConstrainDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 daily_review_signoff DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackDailyReviewSignoff 有損卸欄與刪表；見檔頭 Down 契約。
func rollbackDailyReviewSignoff(db *gorm.DB) error {
	stmts := []string{`DROP TABLE security_policy_history`}
	for _, col := range []string{"signed_at", "timezone", "timezone_inferred", "window_start", "window_end", "due_at", "late", "delay_reason", "coverage", "source_status", "enabled_basis"} {
		stmts = append(stmts, `ALTER TABLE daily_review_logs DROP COLUMN `+col)
	}
	for _, stmt := range stmts {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("回滾 daily_review_signoff 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// signoffBackfillEnv 回填的外部輸入（測試以固定值注入）
type signoffBackfillEnv struct {
	// Now 遷移時刻 M
	Now time.Time
	// DetectedTZ 升級當下偵測的伺服器時區
	DetectedTZ string
}

const (
	policyKeyDailyReviewEnabled  = "daily_review_enabled"
	policyKeyDailyReviewTimezone = "daily_review_timezone"
	// signoffMigrationActor 遷移寫入的歷史列的變更者
	signoffMigrationActor = "migration"
	// signoffSeedActor 遷移寫入的時區政策列的更新者（與啟動播種同值）
	signoffSeedActor = "env-init"
)

// backfillDailyReviewSignoff 回填既有簽核紀錄、重建啟用歷史、寫入時區初值。
// 只用可攜的查詢，sqlite 測試與 pg 走同一支
func backfillDailyReviewSignoff(db *gorm.DB, env signoffBackfillEnv) error {
	tz := env.DetectedTZ
	if _, ok := reviewcal.LoadTimezone(tz); !ok {
		tz = reviewcal.DefaultTimezone
	}

	signedDates, err := backfillSignRows(db, tz)
	if err != nil {
		return err
	}
	rows, err := rebuildEnabledHistory(db, env.Now, tz, signedDates)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if err := db.Create(&model.SecurityPolicyHistory{
			PolicyKey: policyKeyDailyReviewEnabled, OldValue: r.old, NewValue: r.new,
			ChangedAt: r.at, ChangedBy: signoffMigrationActor, Source: r.source,
		}).Error; err != nil {
			return fmt.Errorf("寫入啟用歷史失敗: %w", err)
		}
	}

	// 業務時區初值：歷史一列，政策列無則寫入同一個值（啟動播種見到有列即不動，
	// 升級前後切日不會跳動；也使「重播末值等於政策現值」在升級當下即成立）
	if err := db.Create(&model.SecurityPolicyHistory{
		PolicyKey: policyKeyDailyReviewTimezone, OldValue: "", NewValue: tz,
		ChangedAt: env.Now, ChangedBy: signoffMigrationActor, Source: model.PolicyHistorySourceMigrationUpgrade,
	}).Error; err != nil {
		return fmt.Errorf("寫入時區歷史失敗: %w", err)
	}
	var tzRows int64
	if err := db.Model(&model.SecurityPolicy{}).Where("key = ?", policyKeyDailyReviewTimezone).Count(&tzRows).Error; err != nil {
		return fmt.Errorf("讀取時區政策列失敗: %w", err)
	}
	if tzRows == 0 {
		if err := db.Create(&model.SecurityPolicy{
			Key: policyKeyDailyReviewTimezone, Value: tz, UpdatedBy: signoffSeedActor, UpdatedAt: env.Now,
		}).Error; err != nil {
			return fmt.Errorf("寫入時區政策列失敗: %w", err)
		}
	}
	return nil
}

// backfillSignRows 回填既有簽核列，回傳其所屬日
func backfillSignRows(db *gorm.DB, tz string) ([]string, error) {
	type legacyRow struct {
		ID         uint
		ReviewDate string
		CreatedAt  time.Time
	}
	var rows []legacyRow
	if err := db.Table("daily_review_logs").Select("id, review_date, created_at").Order("review_date").Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("讀取既有簽核紀錄失敗: %w", err)
	}
	dates := make([]string, 0, len(rows))
	for _, r := range rows {
		if _, ok := reviewcal.ParseDate(r.ReviewDate); !ok {
			return nil, fmt.Errorf("既有簽核紀錄 %d 的所屬日 %q 不是 YYYY-MM-DD", r.ID, r.ReviewDate)
		}
		start, end := reviewcal.DayWindow(r.ReviewDate, tz)
		due := reviewcal.DueAt(r.ReviewDate, tz)
		signedAt := r.CreatedAt
		if signedAt.IsZero() {
			// created_at 可空（baseline 未設 NOT NULL）；缺值時以該日結束為簽核時刻的上界
			signedAt = end
		}
		if err := db.Table("daily_review_logs").Where("id = ?", r.ID).Updates(map[string]any{
			"signed_at":         signedAt,
			"timezone":          tz,
			"timezone_inferred": true,
			"window_start":      start,
			"window_end":        end,
			"due_at":            due,
			"late":              !signedAt.Before(due),
			"coverage":          model.DailyReviewCoverageUntilSigned,
			"source_status":     model.DailyReviewSourceComplete,
			"enabled_basis":     model.DailyReviewBasisRecorded,
		}).Error; err != nil {
			return nil, fmt.Errorf("回填簽核紀錄 %d 失敗: %w", r.ID, err)
		}
		dates = append(dates, r.ReviewDate)
	}
	return dates, nil
}

// enabledEvent 一筆由審計重建的開關變更
type enabledEvent struct {
	at       time.Time
	old, new string
}

// historyRow 一筆待寫入的歷史列
type historyRow struct {
	at       time.Time
	old, new string
	source   string
	// order 同一時刻的排序：還原列 0、重建列 1、簽核列起點 2
	order int
	seq   int
}

// loadEnabledEvents 事件來源：政策變更審計列中 error_msg 完全符合
// `policy=daily_review_enabled old=(true|false) new=(true|false)` 者。
// 中介層為同一請求另寫的請求列沒有這個標記；old=new 與重複列不構成變更
func loadEnabledEvents(db *gorm.DB) ([]enabledEvent, error) {
	type auditRow struct {
		ID        uint
		CreatedAt time.Time
		ErrorMsg  string
	}
	var rows []auditRow
	if err := db.Table("audit_logs").Select("id, created_at, error_msg").
		Where("action = ? AND resource = ? AND status = ?", model.ActionUpdate, model.ResourceSecurityPolicy, model.StatusSuccess).
		Where("error_msg LIKE ?", "policy="+policyKeyDailyReviewEnabled+" old=%").
		Order("created_at, id").Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("讀取政策變更審計失敗: %w", err)
	}
	var out []enabledEvent
	seen := map[string]bool{}
	for _, r := range rows {
		key, oldV, newV, ok := model.ParsePolicyChangeAuditMessage(r.ErrorMsg)
		if !ok || key != policyKeyDailyReviewEnabled || !isBoolLiteral(oldV) || !isBoolLiteral(newV) || oldV == newV {
			continue
		}
		dedup := r.CreatedAt.UTC().Format(time.RFC3339Nano) + "|" + oldV + "|" + newV
		if seen[dedup] {
			continue
		}
		seen[dedup] = true
		out = append(out, enabledEvent{at: r.CreatedAt, old: oldV, new: newV})
	}
	return out, nil
}

func isBoolLiteral(v string) bool { return v == "true" || v == "false" }

// rebuildEnabledHistory 依設計的七步重建 daily_review_enabled 的歷史列
func rebuildEnabledHistory(db *gorm.DB, now time.Time, tz string, signedDates []string) ([]historyRow, error) {
	events, err := loadEnabledEvents(db)
	if err != nil {
		return nil, err
	}

	// 審計涵蓋區間的起點（a0）：保留水位；從未清除時為最早一列審計（安裝起點）
	var a0 time.Time
	hasWatermark := false
	var wm model.AuditRetentionWatermark
	switch err := db.Where("class = ?", model.RetentionClassAuditLog).First(&wm).Error; {
	case err == nil:
		a0, hasWatermark = wm.PurgedThroughAt, true
	case errors.Is(err, gorm.ErrRecordNotFound):
		var earliest []time.Time
		if err := db.Table("audit_logs").Order("created_at").Limit(1).Pluck("created_at", &earliest).Error; err != nil {
			return nil, fmt.Errorf("讀取最早審計列失敗: %w", err)
		}
		a0 = now
		if len(earliest) == 1 && !earliest[0].IsZero() {
			a0 = earliest[0]
		}
	default:
		return nil, fmt.Errorf("讀取保留水位失敗: %w", err)
	}
	// 水位之前的殘留列不完整，不作為證據（該段已整段推定為開）
	kept := events[:0]
	for _, e := range events {
		if !e.at.Before(a0) {
			kept = append(kept, e)
		}
	}
	events = kept

	// 安裝時刻 I：baseline 套用時刻。查無時（測試庫）不產生審計已清除的推定區段
	// （先確認追蹤表存在：pg 交易內查詢失敗會使整個交易作廢，不能以錯誤當探測）
	installAt := a0
	if db.Migrator().HasTable(&SchemaMigration{}) {
		var baseline SchemaMigration
		if err := db.Where("version = ?", BaselineVersion).First(&baseline).Error; err == nil {
			installAt = baseline.AppliedAt
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("讀取 baseline 套用時刻失敗: %w", err)
		}
	}

	// 政策現值 V 與政策列最後更新時刻
	current, rowUpdatedAt := "false", now
	var policyRow model.SecurityPolicy
	switch err := db.Where("key = ?", policyKeyDailyReviewEnabled).First(&policyRow).Error; {
	case err == nil:
		if isBoolLiteral(policyRow.Value) {
			current = policyRow.Value
		}
		if !policyRow.UpdatedAt.IsZero() {
			rowUpdatedAt = policyRow.UpdatedAt
		}
	case errors.Is(err, gorm.ErrRecordNotFound):
	default:
		return nil, fmt.Errorf("讀取政策現值失敗: %w", err)
	}

	var out []historyRow
	state, stateSource := "false", ""
	emit := func(at time.Time, value, source string) {
		if value == state && (value == "false" || source == stateSource) {
			return
		}
		out = append(out, historyRow{at: at, new: value, source: source, order: 1})
		state, stateSource = value, source
	}

	// 第 5 步：審計已清除的部分推定為開
	if hasWatermark && installAt.Before(a0) {
		emit(installAt, "true", model.PolicyHistorySourceMigrationPresumedPurged)
	}
	// 第 3 步：涵蓋起點 a0 時的狀態取第一筆事件的舊值；沒有事件時取現值
	if len(events) > 0 {
		emit(a0, events[0].old, model.PolicyHistorySourceMigrationAuditLog)
	} else {
		emit(a0, current, model.PolicyHistorySourceMigrationPolicyRow)
	}
	replayed := state
	if len(events) == 0 {
		replayed = current
	}
	for i, e := range events {
		// 相鄰兩筆銜接不上：兩筆之間推定為開
		if i > 0 && events[i-1].new != e.old {
			emit(events[i-1].at, "true", model.PolicyHistorySourceMigrationPresumedGap)
		}
		emit(e.at, e.new, model.PolicyHistorySourceMigrationAuditLog)
		replayed = e.new
	}
	// 第 4 步：末值與現值不符，最後一筆事件之後有未留審計的變更
	if replayed != current {
		tailStart := a0
		if len(events) > 0 {
			tailStart = events[len(events)-1].at
		}
		boundary := rowUpdatedAt
		if boundary.Before(tailStart) {
			boundary = tailStart
		}
		emit(tailStart, "true", model.PolicyHistorySourceMigrationPresumedTail)
		emit(boundary, current, model.PolicyHistorySourceMigrationPolicyRow)
	}

	// 第 6 步：簽核列優先。依據不是「有證據」的簽核日補一段 sign_record
	out = append(out, signRecordRows(out, signedDates, tz, now)...)
	for i := range out {
		out[i].seq = i
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].at.Equal(out[j].at) {
			return out[i].at.Before(out[j].at)
		}
		if out[i].order != out[j].order {
			return out[i].order < out[j].order
		}
		return out[i].seq < out[j].seq
	})
	prev := "false"
	for i := range out {
		out[i].old = prev
		prev = out[i].new
	}
	return out, nil
}

// signRecordRows 對依據不是 recorded 的簽核日（不在範圍或只與推定區段相交），
// 以連續日期為一段補上 [起點 true sign_record, 終點 還原為當時狀態]
func signRecordRows(rebuilt []historyRow, signedDates []string, tz string, now time.Time) []historyRow {
	if len(signedDates) == 0 {
		return nil
	}
	changes := toChanges(rebuilt)
	cal := reviewcal.Build(reviewcal.Inputs{Enabled: changes, CurrentTZ: tz}, now)
	var need []string
	for _, d := range signedDates {
		day, ok := cal.Lookup(d)
		if !ok || !day.InScope || day.Basis != reviewcal.BasisRecorded {
			need = append(need, d)
		}
	}
	var out []historyRow
	for i := 0; i < len(need); {
		j := i
		for j+1 < len(need) && need[j+1] == reviewcal.AddDays(need[j], 1) {
			j++
		}
		start, _ := reviewcal.DayWindow(need[i], tz)
		_, end := reviewcal.DayWindow(need[j], tz)
		if end.After(now) {
			// 升級當天已簽的日子：還原列不得寫在未來，否則會蓋過之後的正常變更
			end = now
		}
		value, source := stateAt(rebuilt, end)
		out = append(out,
			historyRow{at: start, new: "true", source: model.PolicyHistorySourceMigrationSignRecord, order: 2},
			historyRow{at: end, new: value, source: source, order: 0},
		)
		i = j + 1
	}
	return out
}

// stateAt 重建列在時刻 t（含）的狀態與來源
func stateAt(rows []historyRow, t time.Time) (string, string) {
	value, source := "false", model.PolicyHistorySourceMigrationAuditLog
	for _, r := range rows {
		if r.at.After(t) {
			break
		}
		value, source = r.new, r.source
	}
	return value, source
}

func toChanges(rows []historyRow) []reviewcal.Change {
	out := make([]reviewcal.Change, 0, len(rows))
	prev := "false"
	for _, r := range rows {
		out = append(out, reviewcal.Change{At: r.at, Old: prev, New: r.new, Source: r.source})
		prev = r.new
	}
	return out
}
