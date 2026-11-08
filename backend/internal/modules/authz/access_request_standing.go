package authz

import (
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 申請流程的常設連線資格與帳號範圍上界。
//
// 常設連線權＝時效窗內、來源不是核准流的 connect 授權（含經使用者群組與資產節點取得者）。
// 資格與上界都由 StandingAccountScopesWithDB 的同一份結果導出：某（主體、資產）有任一列即持有資格，
// 各列帳號範圍的聯集即上界。零命中與「上界為全部帳號」是兩件事：model.AccountScope 的空值
// 被視為全部帳號，所以零命中一律以 found=false 表示，絕不以空範圍往下傳或寫入。

// standingKey 以（主體、資產）為鍵。
type standingKey struct{ subject, asset uint }

// standingBounds 每個命中的（主體、資產）對應其常設帳號範圍上界；查無的鍵不在表內。
type standingBounds map[standingKey]model.AccountScope

// unionStandingScope 把多筆授權列的帳號範圍取聯集。零列回 (nil, false)；任一列為全部帳號即回全部帳號。
func unionStandingScope(rows []model.AccountScope) (model.AccountScope, bool) {
	if len(rows) == 0 {
		return nil, false
	}
	var names []string
	for _, row := range rows {
		if row.IsAll() {
			return model.AccountScope{model.AccountScopeAll}, true
		}
		names = append(names, row...)
	}
	return model.NormalizeAccountScope(names), true
}

// standingBoundsOf 在指定 db/tx 內以單一查詢取得多個主體對多個資產的常設上界。
func (s *AccessRequestService) standingBoundsOf(tx *gorm.DB, subjectIDs, assetIDs []uint, now time.Time) (standingBounds, error) {
	rows, err := s.authzRepo.StandingAccountScopesWithDB(tx, subjectIDs, assetIDs, now)
	if err != nil {
		return nil, err
	}
	grouped := map[standingKey][]model.AccountScope{}
	for _, row := range rows {
		k := standingKey{row.SubjectID, row.AssetID}
		grouped[k] = append(grouped[k], row.Accounts)
	}
	out := make(standingBounds, len(grouped))
	for k, scopes := range grouped {
		if scope, ok := unionStandingScope(scopes); ok {
			out[k] = scope
		}
	}
	return out, nil
}

// withinBound 具名帳號是否全部落在上界內（上界為全部帳號時恆真）。
func withinBound(scope, bound model.AccountScope) bool {
	if bound.IsAll() {
		return true
	}
	if scope.IsAll() {
		return false
	}
	for _, name := range scope {
		if !bound.Contains(name) {
			return false
		}
	}
	return true
}

// requestPartyIDs 申請單的使用者側當事人：申請人，以及輔助模式的執行者。
func requestPartyIDs(requesterID uint, executorID *uint) []uint {
	if executorID == nil || *executorID == requesterID {
		return []uint{requesterID}
	}
	return []uint{requesterID, *executorID}
}

// recheckRequestParties 在交易內重判申請人（輔助模式另含執行者）對資產是否持有常設連線權。
// 申請人不符回 ErrRequestConnectRequired；執行者不符時，送單入口回既有的不存在封套（executorOpaque），
// 決定入口回 ErrRequestConnectRequired。回傳每個（主體、資產）的上界供呼叫端使用。
func (s *AccessRequestService) recheckRequestParties(tx *gorm.DB, requesterID uint, executorID *uint, assetIDs []uint, executorOpaque bool, now time.Time) (standingBounds, error) {
	bounds, err := s.standingBoundsOf(tx, requestPartyIDs(requesterID, executorID), assetIDs, now)
	if err != nil {
		return nil, err
	}
	for i, id := range assetIDs {
		if _, ok := bounds[standingKey{requesterID, id}]; !ok {
			return nil, &RequestConnectRequiredError{ItemIndex: i, AssetID: id}
		}
	}
	if executorID != nil {
		for i, id := range assetIDs {
			if _, ok := bounds[standingKey{*executorID, id}]; !ok {
				if executorOpaque {
					return nil, ErrAccessRequestNotFound
				}
				return nil, &RequestConnectRequiredError{ItemIndex: i, AssetID: id}
			}
		}
	}
	return bounds, nil
}
