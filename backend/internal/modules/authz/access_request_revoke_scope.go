package authz

import (
	"errors"
	"reflect"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
)

// 臨時授權撤銷資格的授權規則管理範圍：
//   - 粗閘（EvaluateRevokeRouteEligibility）只放寬進入條件：既有資格，或持授權規則管理能力的任一有效指派。
//     它不判範圍，也不是最終裁決。
//   - 完整資格在撤銷交易內逐項判定（RevokeItem → revokeQualifiedByScope）：持該能力、且本次判定集合的
//     每一項資產都經 Decide 落在範圍內者具撤銷資格；否則回到既有逐項判定，結果與放寬前相同。

// ErrRevokeWiringIncomplete 撤銷的範圍判定或交易內審計落地面未注入。
var ErrRevokeWiringIncomplete = errors.New("authz: access request revoke wiring incomplete")

// SetRevokeScope 注入撤銷資格的範圍判定（組裝時）。
func (s *AccessRequestService) SetRevokeScope(w *AuthorizationWriteScope) { s.revokeScope = w }

// SetAuditTxSink 注入交易內審計落地面（撤銷審計與撤銷同交易）。
func (s *AccessRequestService) SetAuditTxSink(sink port.TxSink) { s.txSink = sink }

// RequireRevokeWiring 組裝檢查：範圍判定與交易內審計落地面都已注入（含具型別的 nil），否則回錯誤。
func (s *AccessRequestService) RequireRevokeWiring() error {
	if s == nil || s.revokeScope == nil || isNilInterface(s.txSink) {
		return ErrRevokeWiringIncomplete
	}
	return nil
}

func isNilInterface(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Map, reflect.Func, reflect.Slice, reflect.Chan:
		return rv.IsNil()
	}
	return false
}

// factsOfUser 由使用者列取主體種類；agent 不因授權規則管理能力取得撤銷資格。
func factsOfUser(db *gorm.DB, userID uint) (TokenFacts, error) {
	var u model.User
	if err := db.Select("id", "kind").First(&u, userID).Error; err != nil {
		return TokenFacts{}, err
	}
	return TokenFacts{SubjectKind: u.Kind}, nil
}

// holdsAuthorizationManage 主體是否持授權規則管理能力的任一有效指派（空範圍或範圍節點全刪的指派不算）。
func holdsAuthorizationManage(db *gorm.DB, cat Catalogue, userID uint) (bool, error) {
	facts, err := factsOfUser(db, userID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if facts.SubjectKind == model.KindAgent {
		return false, nil
	}
	p, err := ResolveUserOnWithCatalogue(db, cat, userID, facts)
	if err != nil {
		return false, err
	}
	return p.Has(PermAuthorizationManage), nil
}

// AllAssetsInScope 主體對全部資產都持授權規則管理能力且在範圍內才為真；主體在 tx 內重解，
// 傳入的任何快取一律不用。資產不存在視為範圍外。空集合為假（沒有可判定的項目）。
func (w *AuthorizationWriteScope) AllAssetsInScope(tx *gorm.DB, userID uint, assetIDs []uint) (bool, error) {
	if w == nil || w.e == nil {
		return false, errAuthorizationScopeUnwired
	}
	if len(assetIDs) == 0 {
		return false, nil
	}
	facts, err := factsOfUser(tx, userID)
	if err != nil {
		return false, err
	}
	if facts.SubjectKind == model.KindAgent {
		return false, nil
	}
	p := &Principal{UserID: userID, Facts: facts}
	for _, id := range assetIDs {
		res, err := w.e.Decide(tx, p, PermAuthorizationManage, AuthorizationAssetObjectTarget(id))
		if err != nil {
			return false, err
		}
		if res.Outcome != ScopeAllow {
			return false, nil
		}
	}
	return true, nil
}

// revokeJudgedAssets 本次撤銷會變更狀態的任務項的資產：仍有有效票證的已核准項，加上整單撤銷
// 一併結束的待審項；已到期、票證已不存在或已撤銷而會被略過的項不計。單項撤銷只看該項。
func revokeJudgedAssets(tx *gorm.DB, items []model.AccessRequestItem, itemID uint, now time.Time) ([]uint, error) {
	seen := map[uint]bool{}
	var assets []uint
	add := func(id uint) {
		if !seen[id] {
			seen[id] = true
			assets = append(assets, id)
		}
	}
	for i := range items {
		item := &items[i]
		if itemID != 0 && item.ID != itemID {
			continue
		}
		switch {
		case item.Status == model.AccessRequestApproved && item.AuthorizationID != nil:
			var ticket model.AssetAuthorization
			if err := tx.First(&ticket, *item.AuthorizationID).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					continue
				}
				return nil, err
			}
			if ticket.DateExpired != nil && !ticket.DateExpired.After(now) {
				continue
			}
			add(item.AssetID)
		case itemID == 0 && item.Status == model.AccessRequestPending:
			add(item.AssetID)
		}
	}
	return assets, nil
}

// revokeQualifiedByScope 撤銷資格的授權規則管理範圍條件（寫入路徑與列級旗標共用的交易內資格函式）：
// 判定集合非空，且每一項資產都在操作者的授權規則管理範圍內。呼叫方須已取拓撲序列化鎖並在同交易內呼叫。
// 範圍化判定未注入、或集合為空時為假，由既有逐項資格裁決。
func (s *AccessRequestService) revokeQualifiedByScope(tx *gorm.DB, actorID uint, items []model.AccessRequestItem, itemID uint, now time.Time) (bool, error) {
	if s.revokeScope == nil {
		return false, nil
	}
	assets, err := revokeJudgedAssets(tx, items, itemID, now)
	if err != nil {
		return false, err
	}
	return s.revokeScope.AllAssetsInScope(tx, actorID, assets)
}

// itemRevokeEligible 既有的逐項撤銷資格（非超管且不具範圍化資格時）：原核准人，或無核准人時審核範圍涵蓋該項。
// 撤銷寫入與授權列表的列級旗標共用。
func (s *AccessRequestService) itemRevokeEligible(tx *gorm.DB, actorID uint, req *model.AccessRequest, item *model.AccessRequestItem) (bool, error) {
	if item.DecidedBy != nil {
		return *item.DecidedBy == actorID, nil
	}
	return s.authzRepo.ApproverScopeCoversRequestTx(tx, actorID, item.AssetID, req.RequesterID)
}

// revokeEligibleFor 非超管的操作者對整張申請單的撤銷資格（授權列表的列級旗標用，唯讀、不取鎖）。
// 判定與 RevokeItem 整單撤銷同序：範圍化資格成立則免逐項；否則每個已核准且有票證的項都須具逐項資格；
// 另回是否有可撤銷的票證（尚未到期者）。
func (s *AccessRequestService) revokeEligibleFor(db *gorm.DB, actorID, requestID uint, now time.Time) (eligible, revocable bool, err error) {
	var req model.AccessRequest
	if err := db.First(&req, requestID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, false, nil
		}
		return false, false, err
	}
	items, err := requestItems(db, &req)
	if err != nil {
		return false, false, err
	}
	qualified, err := s.revokeQualifiedByScope(db, actorID, items, 0, now)
	if err != nil {
		return false, false, err
	}
	eligible = true
	for i := range items {
		item := &items[i]
		if item.Status != model.AccessRequestApproved || item.AuthorizationID == nil {
			continue
		}
		if !qualified {
			ok, e := s.itemRevokeEligible(db, actorID, &req, item)
			if e != nil {
				return false, false, e
			}
			if !ok {
				eligible = false
			}
		}
		var ticket model.AssetAuthorization
		if e := db.First(&ticket, *item.AuthorizationID).Error; e != nil {
			if errors.Is(e, gorm.ErrRecordNotFound) {
				continue
			}
			return false, false, e
		}
		if ticket.DateExpired != nil && !ticket.DateExpired.After(now) {
			continue
		}
		revocable = true
	}
	return eligible, revocable, nil
}
