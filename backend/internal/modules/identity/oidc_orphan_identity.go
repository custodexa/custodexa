package identity

import (
	"errors"
	"log"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 登入時遇到「綁定仍有效、所屬帳號已刪除」的外部身分。
//
// 帳號刪除會在同一交易內作廢其綁定；本檔處理的是刪除路徑以外留下的此類綁定
// （例如較早版本刪除帳號時未作廢綁定）。處理方式：作廢該綁定並留痕，之後把這次
// 登入視為「無對應外部身分」，交回准入判定——不因曾有綁定而略過或放寬。

// ErrOIDCAccountRemoved 僅允許已綁定身分登入的模式下，此人過去的帳號已被管理者刪除。
//
// 與一般的准入不符分開：此人需要的行動是「請管理者重新建立帳號並綁定」，
// 而不是檢查自己的宣告是否符合規則
var ErrOIDCAccountRemoved = errors.New("您在本系統的帳號已被管理者刪除，請聯絡管理者重新建立帳號並綁定")

// loadBoundUser 讀取綁定所屬的帳號。
//
// 帳號查無（已刪除）即為懸空綁定：作廢並回 orphan=true，呼叫端將本次登入視為
// 無對應外部身分。其他讀取錯誤照常上拋，但留一筆流程失敗意向，不得無痕
func (s *OIDCLoginService) loadBoundUser(p *model.OIDCProvider, identity *model.UserExternalIdentity,
	trail *oidcAuditTrail) (*model.User, bool, error) {
	var user model.User
	err := s.db.Preload("Roles").First(&user, identity.UserID).Error
	if err == nil {
		return &user, false, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		trail.flowError(p.ID, "identity_lookup_failed")
		return nil, false, err
	}
	if s.orphanRevokeHook != nil {
		s.orphanRevokeHook()
	}
	if err := s.revokeOrphanIdentity(p, identity, trail); err != nil {
		trail.flowError(p.ID, "identity_lookup_failed")
		return nil, false, err
	}
	return nil, true, nil
}

// revokeOrphanIdentity 條件作廢懸空綁定（軟刪除，條件含 deleted_at IS NULL）。
//
// 受影響列數為 0 代表並發的另一個請求或刪除路徑已作廢，結果相同、不視為錯誤；
// 審計只由真正作廢到該列的一方寫出，否則一次雙開分頁會留下兩筆作廢紀錄
func (s *OIDCLoginService) revokeOrphanIdentity(p *model.OIDCProvider, identity *model.UserExternalIdentity,
	trail *oidcAuditTrail) error {
	res := s.db.Where("id = ?", identity.ID).Delete(&model.UserExternalIdentity{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return nil
	}
	previousUsername := ""
	var previous model.User
	if err := s.db.Unscoped().Select("id", "username").
		First(&previous, identity.UserID).Error; err == nil {
		previousUsername = previous.Username
	}
	trail.orphanRevoked(p, identity, previousUsername)
	log.Printf("[OIDC] 已作廢指向已刪帳號的外部身分 (identity=%d, previous_user=%d, provider=%d)",
		identity.ID, identity.UserID, p.ID)
	return nil
}

// removedAccountUserID 同一身分域三元組最近一筆「已作廢、且所屬帳號已刪除」的綁定
// 所屬的原帳號編號；無則回 0。
//
// 兩個用途：僅預綁模式下判定「此人過去的帳號已被刪除」，使每一次嘗試都得到同一個
// 專屬失敗原因；自動供應模式下標出重建帳號所取代的原帳號。兩者都只在不命中
// 有效綁定時執行，不影響既有身分的回訪
func (s *OIDCLoginService) removedAccountUserID(p *model.OIDCProvider, subject string) (uint, error) {
	var row struct{ UserID uint }
	err := s.db.Table("user_external_identities AS uei").
		Select("uei.user_id").
		Joins("LEFT JOIN users u ON u.id = uei.user_id").
		Where("uei.issuer = ? AND uei.client_id = ? AND uei.subject = ?", p.Issuer, p.ClientID, subject).
		Where("uei.deleted_at IS NOT NULL AND (u.id IS NULL OR u.deleted_at IS NOT NULL)").
		Order("uei.deleted_at DESC, uei.id DESC").
		Limit(1).Scan(&row).Error
	if err != nil {
		return 0, err
	}
	return row.UserID, nil
}

// orphanRevoked 懸空綁定作廢：帳號資料的修正，歸 user 資源。
//
// 列的帳號欄留空（作廢不是任何帳號的操作），原帳號放在 resource_id 與 Details；
// subject 記原值，供管理者與身分提供者端對照（subject 是不透明識別碼，不是憑證）
func (t *oidcAuditTrail) orphanRevoked(p *model.OIDCProvider, identity *model.UserExternalIdentity,
	previousUsername string) {
	prev := identity.UserID
	t.add(OIDCAuditEvent{
		Action: model.ActionDelete, Resource: model.ResourceUser, ResourceID: &prev,
		Status: model.StatusSuccess,
		Details: map[string]any{
			"event": "oidc_identity_orphan_revoked", "provider_id": p.ID,
			"provider_name": p.Name, "issuer": identity.Issuer, "subject": identity.Subject,
			"subject_fingerprint": sha256Hex(identity.Subject)[:16],
			"previous_user_id":    identity.UserID, "previous_username": previousUsername,
			"identity_id": identity.ID,
		},
	})
}

// accountRemoved 僅預綁模式下，此人過去的帳號已被刪除：身分成立但不准，記 denied
func (t *oidcAuditTrail) accountRemoved(p *model.OIDCProvider, subject string, previousUserID uint) {
	t.add(OIDCAuditEvent{
		Action: model.ActionLogin, Resource: model.ResourceAuth, Status: model.StatusDenied,
		Details: map[string]any{
			"event": "oidc_account_removed", "provider_id": p.ID,
			"provider_name": p.Name, "previous_user_id": previousUserID,
			"subject_fingerprint": sha256Hex(subject)[:16],
		},
	})
}

// userInactive 帳號已停用：身分成立且符合准入，但帳號不得登入，記 denied
func (t *oidcAuditTrail) userInactive(p *model.OIDCProvider, user *model.User) {
	t.add(OIDCAuditEvent{
		Action: model.ActionLogin, Resource: model.ResourceAuth, Status: model.StatusDenied,
		UserID: user.ID, Username: user.Username,
		Details: map[string]any{
			"event": "oidc_user_inactive", "provider_id": p.ID, "provider_name": p.Name,
		},
	})
}

// denyPrebound 僅預綁模式下查無有效綁定的拒絕：過去的帳號已被刪除者回專屬原因，
// 其餘維持「未預先綁定」
func (s *OIDCLoginService) denyPrebound(p *model.OIDCProvider, subject string, orphanUserID uint,
	trail *oidcAuditTrail) error {
	previous := orphanUserID
	if previous == 0 {
		id, err := s.removedAccountUserID(p, subject)
		if err != nil {
			trail.flowError(p.ID, "identity_lookup_failed")
			return err
		}
		previous = id
	}
	if previous > 0 {
		trail.accountRemoved(p, subject, previous)
		return ErrOIDCAccountRemoved
	}
	trail.admissionDenied(p, subject, "not_prebound")
	return ErrOIDCAdmissionDenied
}

// replacedUserID 自動供應前標出所取代的原帳號（剛作廢者優先，否則回查已作廢的綁定）。
// 只是審計註記，查詢失敗不阻斷供應
func (s *OIDCLoginService) replacedUserID(p *model.OIDCProvider, subject string, orphanUserID uint) uint {
	if orphanUserID > 0 {
		return orphanUserID
	}
	id, err := s.removedAccountUserID(p, subject)
	if err != nil {
		log.Printf("[OIDC] 查詢所取代的原帳號失敗（不阻斷供應）: provider=%d err=%v", p.ID, err)
		return 0
	}
	return id
}
