package asset

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// ErrReportScopeNotFound 範圍所指的節點或計劃不存在
var ErrReportScopeNotFound = errors.New("報告範圍不存在")

// GlobalMaxAgeDaysFunc 取全域「憑證最長使用天數」政策鍵的值（0＝未設定）。
//
// **以函式注入而非引用政策模組**：本模組為了一個純數字建立一條新的模組相依邊
// 不划算，且測試要能在不啟動政策服務的情況下窮舉「未設定」與各種天數。
type GlobalMaxAgeDaysFunc func() int

// RotationReportBuilder 報告資料集的唯一建構者。
type RotationReportBuilder struct {
	db     *gorm.DB
	plans  *ChangeSecretPlanService
	maxAge GlobalMaxAgeDaysFunc
}

// NewRotationReportBuilder 建構者。maxAge 為 nil 時視為全域未設定。
func NewRotationReportBuilder(db *gorm.DB, plans *ChangeSecretPlanService,
	maxAge GlobalMaxAgeDaysFunc) *RotationReportBuilder {
	return &RotationReportBuilder{db: db, plans: plans, maxAge: maxAge}
}

// Build 產生報告資料集。
//
// asOf 是所有派生值的基準時點；periodStart／periodEnd 只框住記錄明細
// （右開區間，使連續兩期首尾相接而不重複計入同一筆）。
func (b *RotationReportBuilder) Build(scope ReportScope, periodStart, periodEnd,
	asOf time.Time, lang string) (*RotationReport, error) {

	label, assetFilter, planFilter, err := b.resolveScope(scope)
	if err != nil {
		return nil, err
	}

	global := 0
	if b.maxAge != nil {
		global = b.maxAge()
	}

	rep := &RotationReport{
		Meta: ReportMeta{
			ScopeKind: scope.Kind, ScopeID: scope.ID, ScopeLabel: label,
			PeriodStart: periodStart, PeriodEnd: periodEnd, AsOf: asOf,
			GeneratedAt:      time.Now(),
			GlobalMaxAgeDays: global, DueSoonWindowDays: dueSoonWindowDays, Language: lang,
		},
		Truncation: ReportTruncation{RowsCap: ReportRowsCap, RecordsCap: ReportRecordsCap},
	}

	accounts, truncated, err := b.scopedAccounts(assetFilter, planFilter)
	if err != nil {
		return nil, err
	}
	rep.Truncation.RowsTruncated = truncated

	assets, err := b.assetsByID(accountAssetIDs(accounts))
	if err != nil {
		return nil, err
	}
	plans, err := b.plans.List()
	if err != nil {
		return nil, err
	}

	accountIDs := make([]uint, 0, len(accounts))
	for i := range accounts {
		accountIDs = append(accountIDs, accounts[i].ID)
	}
	lastSuccess, err := b.plans.LastSuccessByAccount(accountIDs, asOf)
	if err != nil {
		return nil, err
	}
	lastRecord, err := b.latestRecordStatus(accountIDs)
	if err != nil {
		return nil, err
	}
	candidates, err := b.candidateStates(accountIDs)
	if err != nil {
		return nil, err
	}

	cov := newPlanCoverage(plans, asOf)
	rep.Rows = make([]AccountRow, 0, len(accounts))
	for i := range accounts {
		row := b.buildRow(&accounts[i], assets[accounts[i].AssetID], cov, global,
			lastSuccess, lastRecord, candidates, asOf)
		rep.Rows = append(rep.Rows, row)
	}
	rep.Summary = summarize(rep.Rows)

	records, recTruncated, err := b.periodRecords(assetFilter, planFilter, plans,
		periodStart, periodEnd, asOf)
	if err != nil {
		return nil, err
	}
	rep.Records = records
	rep.Truncation.RecordsTruncated = recTruncated
	return rep, nil
}

// resolveScope 把範圍解析成「資產集合」與「帳號名集合」兩個篩選面。
//
// 回傳的 assetFilter 為 nil 代表不限資產（全系統）；planFilter 為 nil 代表不限帳號名。
func (b *RotationReportBuilder) resolveScope(scope ReportScope) (label string,
	assetFilter []uint, planFilter model.AccountScope, err error) {

	switch scope.Kind {
	case "", model.RotationScopeAll:
		return "", nil, nil, nil
	case model.RotationScopeNode:
		var node model.AssetGroup
		if e := b.db.First(&node, scope.ID).Error; e != nil {
			if errors.Is(e, gorm.ErrRecordNotFound) {
				return "", nil, nil, ErrReportScopeNotFound
			}
			return "", nil, nil, e
		}
		ids, e := descendantAssetIDs(b.db, scope.ID)
		if e != nil {
			return "", nil, nil, e
		}
		// 空子樹與「不限資產」必須可分辨：前者的母體是零個帳號
		if ids == nil {
			ids = []uint{}
		}
		return node.Name, ids, nil, nil
	case model.RotationScopePlan:
		plan, e := b.plans.Get(scope.ID)
		if e != nil {
			if errors.Is(e, ErrPlanNotFound) {
				return "", nil, nil, ErrReportScopeNotFound
			}
			return "", nil, nil, e
		}
		ids := AssetIDList(plan)
		if ids == nil {
			ids = []uint{}
		}
		return plan.Name, ids, PlanAccountScope(plan), nil
	default:
		return "", nil, nil, fmt.Errorf("未支援的報告範圍: %s", scope.Kind)
	}
}

// scopedAccounts 範圍內未刪除的帳號（依資產、帳號排序），超過上限即截斷。
//
// 母體＝掛在**未刪除資產**上的未刪除帳號。三種範圍同一個定義：節點範圍原本
// 靠 descendantAssetIDs 過濾掉已刪資產，全系統與計劃範圍不經過那條路，
// 少了這個 join 就會把已刪資產的帳號一併判桶、計入合規率、印進例外清單
// ——那些機器在資產管理頁看不到、連不上，也沒人能去改它的密碼。
func (b *RotationReportBuilder) scopedAccounts(assetFilter []uint,
	planFilter model.AccountScope) ([]model.AssetAccount, bool, error) {

	q := b.db.Model(&model.AssetAccount{}).
		Select("asset_accounts.*").
		Joins("JOIN assets ON assets.id = asset_accounts.asset_id AND assets.deleted_at IS NULL").
		Order("asset_accounts.asset_id asc, asset_accounts.id asc")
	if assetFilter != nil {
		if len(assetFilter) == 0 {
			return nil, false, nil
		}
		q = q.Where("asset_accounts.asset_id IN ?", assetFilter)
	}
	if names := explicitAccountNames(planFilter); names != nil {
		if len(names) == 0 {
			return nil, false, nil
		}
		q = q.Where("asset_accounts.username IN ?", names)
	}
	var rows []model.AssetAccount
	// 多取一筆用來分辨「恰好等於上限」與「已被截斷」
	if err := q.Limit(ReportRowsCap + 1).Find(&rows).Error; err != nil {
		return nil, false, err
	}
	if len(rows) > ReportRowsCap {
		return rows[:ReportRowsCap], true, nil
	}
	return rows, false, nil
}

// explicitAccountNames 計劃帳號範圍的明列名單；@ALL 或未設定回 nil（不限）。
func explicitAccountNames(scope model.AccountScope) []string {
	if len(scope) == 0 {
		return nil
	}
	names := make([]string, 0, len(scope))
	for _, s := range scope {
		if s == model.AccountScopeAll {
			return nil
		}
		names = append(names, s)
	}
	return names
}

func accountAssetIDs(accounts []model.AssetAccount) []uint {
	seen := map[uint]bool{}
	out := make([]uint, 0, len(accounts))
	for i := range accounts {
		if !seen[accounts[i].AssetID] {
			seen[accounts[i].AssetID] = true
			out = append(out, accounts[i].AssetID)
		}
	}
	return out
}

func (b *RotationReportBuilder) assetsByID(ids []uint) (map[uint]*model.Asset, error) {
	out := map[uint]*model.Asset{}
	if len(ids) == 0 {
		return out, nil
	}
	var rows []model.Asset
	if err := b.db.Unscoped().Where("id IN ?", ids).Find(&rows).Error; err != nil {
		return nil, err
	}
	for i := range rows {
		out[rows[i].ID] = &rows[i]
	}
	return out, nil
}

// latestRecordStatus 每個帳號最近一筆改密記錄的狀態（任意狀態）。
func (b *RotationReportBuilder) latestRecordStatus(accountIDs []uint) (map[uint]string, error) {
	out := map[uint]string{}
	if len(accountIDs) == 0 {
		return out, nil
	}
	for start := 0; start < len(accountIDs); start += recordAccountBatchSize {
		end := start + recordAccountBatchSize
		if end > len(accountIDs) {
			end = len(accountIDs)
		}
		var ids []uint
		if err := b.db.Model(&model.ChangeSecretRecord{}).
			Select("MAX(id)").
			Where("account_id IN ?", accountIDs[start:end]).
			Group("account_id").Scan(&ids).Error; err != nil {
			return nil, err
		}
		if len(ids) == 0 {
			continue
		}
		var rows []model.ChangeSecretRecord
		if err := b.db.Where("id IN ?", ids).Find(&rows).Error; err != nil {
			return nil, err
		}
		for i := range rows {
			out[rows[i].AccountID] = rows[i].Status
		}
	}
	return out, nil
}

// candidateStates 未驗證候選的三態。
func (b *RotationReportBuilder) candidateStates(accountIDs []uint) (map[uint]string, error) {
	out := map[uint]string{}
	if len(accountIDs) == 0 {
		return out, nil
	}
	for start := 0; start < len(accountIDs); start += recordAccountBatchSize {
		end := start + recordAccountBatchSize
		if end > len(accountIDs) {
			end = len(accountIDs)
		}
		var rows []model.ChangeSecretCandidate
		if err := b.db.Where("account_id IN ?", accountIDs[start:end]).
			Find(&rows).Error; err != nil {
			return nil, err
		}
		for i := range rows {
			state := CandidatePending
			if rows[i].Abandoned {
				state = CandidateAbandoned
			}
			out[rows[i].AccountID] = state
		}
	}
	return out, nil
}

// periodRecords 區間內的改密記錄明細。
//
// 母體以**未刪除與已刪除帳號皆計**取得：帳號在區間之後被刪除，其記錄仍是
// 這一期發生過的事實，抽掉它等於讓報告漏記一次改密。
//
// 實際區間為 [from, min(to, asOf))：截止時點之後發生的事不屬於這一份報告，
// 否則明細會列出派生值看不見的記錄，兩者互相矛盾。
func (b *RotationReportBuilder) periodRecords(assetFilter []uint, planFilter model.AccountScope,
	plans []model.ChangeSecretPlan, from, to, asOf time.Time) ([]RecordRow, bool, error) {

	if !asOf.IsZero() && asOf.Before(to) {
		to = asOf
	}
	if !from.Before(to) {
		return nil, false, nil
	}

	q := b.db.Unscoped().Model(&model.AssetAccount{}).Order("id asc")
	if assetFilter != nil {
		if len(assetFilter) == 0 {
			return nil, false, nil
		}
		q = q.Where("asset_id IN ?", assetFilter)
	}
	if names := explicitAccountNames(planFilter); names != nil {
		if len(names) == 0 {
			return nil, false, nil
		}
		q = q.Where("username IN ?", names)
	}
	var accounts []model.AssetAccount
	if err := q.Find(&accounts).Error; err != nil {
		return nil, false, err
	}
	if len(accounts) == 0 {
		return nil, false, nil
	}

	ids := make([]uint, 0, len(accounts))
	deleted := map[uint]bool{}
	assetIDs := make([]uint, 0, len(accounts))
	for i := range accounts {
		ids = append(ids, accounts[i].ID)
		deleted[accounts[i].ID] = accounts[i].DeletedAt.Valid
		assetIDs = append(assetIDs, accounts[i].AssetID)
	}
	assets, err := b.assetsByID(assetIDs)
	if err != nil {
		return nil, false, err
	}
	planNames := map[uint]string{}
	for i := range plans {
		planNames[plans[i].ID] = plans[i].Name
	}

	records, err := b.plans.RecordsByAccounts(ids, &from, &to, "")
	if err != nil {
		return nil, false, err
	}
	truncated := false
	if len(records) > ReportRecordsCap {
		records = records[:ReportRecordsCap]
		truncated = true
	}
	out := make([]RecordRow, 0, len(records))
	for i := range records {
		r := &records[i]
		assetName := ""
		if a := assets[r.AssetID]; a != nil {
			assetName = a.Name
		}
		out = append(out, RecordRow{
			RecordID: r.ID, ExecutedAt: r.ExecutedAt.In(from.Location()), PlanName: planNames[r.PlanID],
			AssetName: assetName, AccountUsername: r.AccountUsername,
			AccountDeleted: deleted[r.AccountID], SecretType: r.SecretType,
			Status: r.Status, ReasonCode: r.Error,
		})
	}
	return out, truncated, nil
}

// summarize 由已產出的列算摘要。
//
// **以列為準而非另查一次**：摘要與明細若各自查詢，截斷之後兩者就會對不上，
// 而讀者無從察覺。
func summarize(rows []AccountRow) ReportSummary {
	s := ReportSummary{TotalAccounts: len(rows)}
	for i := range rows {
		switch rows[i].Bucket {
		case BucketCompliant:
			s.Compliant++
		case BucketOverdue:
			s.Overdue++
		case BucketDueSoon:
			s.DueWithin30++
		case BucketNoRecord:
			s.NoRecord++
		case BucketUnverified:
			s.Unverified++
		case BucketNoPolicy:
			s.NoPolicy++
		}
		if rows[i].SharedCredential {
			s.SharedCredential++
		}
		if rows[i].MultiPlan {
			s.MultiPlan++
		}
	}
	base := s.TotalAccounts - s.NoPolicy - s.Unverified
	s.RateCountingNoRecord = ratio(s.Compliant, base)
	s.RateExcludingNoRecord = ratio(s.Compliant, base-s.NoRecord)
	return s
}

// ratio 分母為零時回 nil：輸出「不適用」而非 0%——後者會被讀成
// 「查過了，一個都不合規」。
func ratio(num, den int) *float64 {
	if den <= 0 {
		return nil
	}
	v := float64(num) / float64(den)
	return &v
}

// sortedNames 穩定的計劃名輸出順序。
func sortedNames(names []string) []string {
	out := append([]string(nil), names...)
	sort.Strings(out)
	return out
}
