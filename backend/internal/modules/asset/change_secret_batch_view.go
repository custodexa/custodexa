package asset

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 批次改密的讀取投影。
//
// 檢視者的資產範圍取帳號改密的讀取範圍（ChangeSecretScopePort.ViewScope）；不限範圍者
// （含未注入範圍判定）與現行逐欄相同。範圍化檢視者：
//   - 帳號名清單、目標列表只計範圍內資產上的帳號；
//   - 批次只列「授權脈絡的目標上界至少有一台在範圍內」者，判定在查詢內（先過濾再取上界筆數）；
//   - 詳情對範圍外批次與不存在同形；逐目標記錄只列範圍內資產，目標數與四種計數由範圍內重算。
//
// 目標上界在建立交易內寫入，所以剛建立、還沒有逐目標記錄的批次，建立者本人也看得到。

// batchViewScope 檢視者的資產範圍；判定器失敗一律視為授權不可用（不放寬）。
func (s *ChangeSecretBatchService) batchViewScope(ctx context.Context, actorID uint) (ChangeSecretAssetScope, error) {
	if s.scope == nil {
		return ChangeSecretAssetScope{}, nil
	}
	sc, err := s.scope.ViewScope(ctx, s.db, actorID, CredCapAccountRotate)
	if err != nil {
		return ChangeSecretAssetScope{}, fmt.Errorf("%w: %v", ErrCredentialAuthzUnavailable, err)
	}
	return sc, nil
}

// UsernamesFor 檢視者可見的帳號名清單（附範圍內資產數）。
func (s *ChangeSecretBatchService) UsernamesFor(ctx context.Context, actorID uint) ([]BatchUsername, error) {
	sc, err := s.batchViewScope(ctx, actorID)
	if err != nil {
		return nil, err
	}
	q := s.liveAccounts()
	if sc.Limited {
		q = q.Where("asset_accounts.asset_id IN (?)", sc.AssetIDs)
	}
	return usernamesOn(q)
}

// TargetsFor 檢視者可見的目標（範圍內資產上持有該帳號名者）。
func (s *ChangeSecretBatchService) TargetsFor(ctx context.Context, actorID uint, username string,
	asOf time.Time) ([]BatchTarget, error) {

	if _, err := normalizedUsername(username); err != nil {
		return nil, err
	}
	sc, err := s.batchViewScope(ctx, actorID)
	if err != nil {
		return nil, err
	}
	var filter []uint
	if sc.Limited {
		filter = []uint{}
		if err := s.db.Model(&model.Asset{}).Where("assets.id IN (?)", sc.AssetIDs).
			Order("assets.id").Pluck("assets.id", &filter).Error; err != nil {
			return nil, err
		}
		if filter == nil {
			filter = []uint{}
		}
	}
	var plans PlanFilter
	if s.scope != nil {
		// 涵蓋計畫、適用天數與排程只由檢視者可見的計畫彙總：不可見計畫的名稱與存在不出現在目標列上
		plans = func(all []model.ChangeSecretPlan) ([]model.ChangeSecretPlan, error) {
			visible, err := visiblePlanIDs(ctx, s.db, s.scope, actorID, all)
			if err != nil {
				return nil, err
			}
			return filterPlans(all, visible), nil
		}
	}
	return s.targetsIn(username, filter, plans, asOf)
}

// ListFor 檢視者可見的最近批次（新到舊，有界）。
func (s *ChangeSecretBatchService) ListFor(ctx context.Context, actorID uint) ([]model.ChangeSecretBatch, error) {
	sc, err := s.batchViewScope(ctx, actorID)
	if err != nil {
		return nil, err
	}
	if !sc.Limited {
		return s.List()
	}
	bound, err := targetBoundRows(s.db)
	if err != nil {
		return nil, err
	}
	var out []model.ChangeSecretBatch
	if err := s.db.Where("EXISTS (SELECT 1 FROM (?) tb "+
		"WHERE tb.auth_id = change_secret_batches.authorization_id AND tb.asset_id IN (?))", bound, sc.AssetIDs).
		Order("id desc").Limit(batchListLimit).Find(&out).Error; err != nil {
		return nil, err
	}
	if err := s.projectCounts(out, sc); err != nil {
		return nil, err
	}
	return out, nil
}

// DetailFor 檢視者可見的單一批次與其逐目標記錄；範圍外批次與不存在同為 ErrBatchNotFound。
func (s *ChangeSecretBatchService) DetailFor(ctx context.Context, actorID uint,
	id uint) (*model.ChangeSecretBatch, []model.ChangeSecretRecord, error) {

	sc, err := s.batchViewScope(ctx, actorID)
	if err != nil {
		return nil, nil, err
	}
	batch, err := s.Get(id)
	if err != nil {
		return nil, nil, err
	}
	if !sc.Limited {
		records, err := s.Records(batch.ID)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrBatchRecordsQuery, err)
		}
		return batch, records, nil
	}
	if batch.AuthorizationID == nil {
		return nil, nil, ErrBatchNotFound
	}
	bound, err := targetBoundRows(s.db)
	if err != nil {
		return nil, nil, err
	}
	var visible int64
	if err := s.db.Raw("SELECT COUNT(*) FROM (?) tb WHERE tb.auth_id = ? AND tb.asset_id IN (?)",
		bound, *batch.AuthorizationID, sc.AssetIDs).Scan(&visible).Error; err != nil {
		return nil, nil, err
	}
	if visible == 0 {
		return nil, nil, ErrBatchNotFound
	}
	var records []model.ChangeSecretRecord
	if err := s.db.Where("batch_id = ? AND asset_id IN (?)", batch.ID, sc.AssetIDs).
		Order("asset_id asc, id asc").Find(&records).Error; err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrBatchRecordsQuery, err)
	}
	out := []model.ChangeSecretBatch{*batch}
	if err := s.projectCounts(out, sc); err != nil {
		return nil, nil, err
	}
	return &out[0], records, nil
}

// projectCounts 以範圍內重算目標數與四種計數。
//
// 目標數＝目標上界中範圍內的資產數（批次只有一個帳號名，同一資產至多一個同名帳號）。
// 四種計數比照批次完成時才一次寫入的現行語義：執行中維持 0，完成後由範圍內記錄重算。
func (s *ChangeSecretBatchService) projectCounts(batches []model.ChangeSecretBatch, sc ChangeSecretAssetScope) error {
	if len(batches) == 0 {
		return nil
	}
	bound, err := targetBoundRows(s.db)
	if err != nil {
		return err
	}
	authIDs := make([]uint, 0, len(batches))
	batchIDs := make([]uint, 0, len(batches))
	for i := range batches {
		batchIDs = append(batchIDs, batches[i].ID)
		if batches[i].AuthorizationID != nil {
			authIDs = append(authIDs, *batches[i].AuthorizationID)
		}
	}
	targets := map[uint]int{}
	if len(authIDs) > 0 {
		var rows []struct {
			AuthID uint
			N      int
		}
		if err := s.db.Raw("SELECT tb.auth_id AS auth_id, COUNT(*) AS n FROM (?) tb "+
			"WHERE tb.auth_id IN ? AND tb.asset_id IN (?) GROUP BY tb.auth_id", bound, authIDs, sc.AssetIDs).
			Scan(&rows).Error; err != nil {
			return err
		}
		for _, r := range rows {
			targets[r.AuthID] = r.N
		}
	}
	var statusRows []struct {
		BatchID uint
		Status  string
		N       int
	}
	if err := s.db.Model(&model.ChangeSecretRecord{}).
		Select("batch_id, status, COUNT(*) AS n").
		Where("batch_id IN ? AND asset_id IN (?)", batchIDs, sc.AssetIDs).
		Group("batch_id, status").Scan(&statusRows).Error; err != nil {
		return err
	}
	counts := map[uint]map[string]int{}
	for _, r := range statusRows {
		if counts[r.BatchID] == nil {
			counts[r.BatchID] = map[string]int{}
		}
		counts[r.BatchID][r.Status] = r.N
	}
	for i := range batches {
		b := &batches[i]
		b.TargetCount = 0
		if b.AuthorizationID != nil {
			b.TargetCount = targets[*b.AuthorizationID]
		}
		b.SuccessCount, b.FailedCount, b.UnverifiedCount, b.SkippedCount = 0, 0, 0, 0
		if b.Status != model.ChangeSecretBatchCompleted {
			continue
		}
		c := counts[b.ID]
		b.SuccessCount = c[model.ChangeSecretSuccess]
		b.FailedCount = c[model.ChangeSecretFailed]
		b.UnverifiedCount = c[model.ChangeSecretUnverified]
		b.SkippedCount = c[model.ChangeSecretSkipped]
	}
	return nil
}

// ErrBatchRecordsQuery 詳情的逐目標記錄讀取失敗（handler 以記錄查詢的內部碼回應）
var ErrBatchRecordsQuery = errors.New("批次逐目標記錄讀取失敗")

// errTargetBoundDialect 目標上界展開不支援的資料庫方言（不退回記憶體過濾）。
var errTargetBoundDialect = errors.New("目標上界展開不支援此資料庫方言")

// targetBoundRows 把授權脈絡的目標上界（資產 id 的 JSON 陣列文字）展開成 (auth_id, asset_id) 列，
// 回子查詢供呼叫端以 (?) 嵌入。非陣列內容（含空字串）視為空陣列，不讓單一壞列使整個查詢失敗。
// 各方言的 SQL 皆為字面量，表名可被靜態解析；postgres 以逗號接集合回傳函式（FROM 內的函式可引用前項，
// 等同 LATERAL）。
func targetBoundRows(db *gorm.DB) (*gorm.DB, error) {
	switch db.Dialector.Name() {
	case "sqlite":
		return db.Raw("SELECT a.id AS auth_id, CAST(j.value AS INTEGER) AS asset_id " +
			"FROM credential_job_authorizations a, " +
			"json_each(CASE WHEN json_valid(a.target_bound) THEN " +
			"CASE WHEN json_type(a.target_bound) = 'array' THEN a.target_bound ELSE '[]' END " +
			"ELSE '[]' END) j"), nil
	case "postgres":
		return db.Raw("SELECT a.id AS auth_id, CAST(j.value AS BIGINT) AS asset_id " +
			"FROM credential_job_authorizations a, jsonb_array_elements_text(" +
			"CASE WHEN a.target_bound LIKE '[%' THEN CAST(a.target_bound AS jsonb) ELSE CAST('[]' AS jsonb) END" +
			") AS j(value)"), nil
	}
	return nil, fmt.Errorf("%w: %s", errTargetBoundDialect, db.Dialector.Name())
}
