package api

import (
	"errors"

	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/gin-gonic/gin"
)

// 審核範圍的非超級管理者精簡 DTO：標量欄位同現行，巢狀物件只留 id 與顯示名稱。
// 列表每列與建立成功回應共用；顯示名稱取不到（關聯未載入）時巢狀物件只帶 id。

type idUsername struct {
	ID       uint   `json:"id"`
	Username string `json:"username,omitempty"`
}

type idName struct {
	ID   uint   `json:"id"`
	Name string `json:"name,omitempty"`
}

type approverScopeDTO struct {
	ID              uint        `json:"id"`
	ApproverID      *uint       `json:"approver_id"`
	ApproverGroupID *uint       `json:"approver_group_id"`
	AssetID         *uint       `json:"asset_id"`
	AssetGroupID    *uint       `json:"asset_group_id"`
	SubjectUserID   *uint       `json:"subject_user_id"`
	SubjectGroupID  *uint       `json:"subject_group_id"`
	GrantedBy       uint        `json:"granted_by"`
	CreatedAt       any         `json:"created_at"`
	Approver        *idUsername `json:"approver,omitempty"`
	ApproverGroup   *idName     `json:"approver_group,omitempty"`
	Asset           *idName     `json:"asset,omitempty"`
	AssetGroup      *idName     `json:"asset_group,omitempty"`
	SubjectUser     *idUsername `json:"subject_user,omitempty"`
	SubjectGroup    *idName     `json:"subject_group,omitempty"`
}

func toApproverScopeDTO(r *model.ApproverScope) approverScopeDTO {
	d := approverScopeDTO{ID: r.ID, ApproverID: r.ApproverID, ApproverGroupID: r.ApproverGroupID, AssetID: r.AssetID,
		AssetGroupID: r.AssetGroupID, SubjectUserID: r.SubjectUserID, SubjectGroupID: r.SubjectGroupID,
		GrantedBy: r.GrantedBy, CreatedAt: r.CreatedAt}
	user := func(id *uint, u *model.User) *idUsername {
		if id == nil {
			return nil
		}
		if u != nil && u.ID == *id {
			return &idUsername{ID: u.ID, Username: u.Username}
		}
		return &idUsername{ID: *id}
	}
	group := func(id *uint, g *model.UserGroup) *idName {
		if id == nil {
			return nil
		}
		if g != nil && g.ID == *id {
			return &idName{ID: g.ID, Name: g.Name}
		}
		return &idName{ID: *id}
	}
	d.Approver = user(r.ApproverID, r.Approver)
	d.SubjectUser = user(r.SubjectUserID, r.SubjectUser)
	d.ApproverGroup = group(r.ApproverGroupID, r.ApproverGroup)
	d.SubjectGroup = group(r.SubjectGroupID, r.SubjectGroup)
	if r.AssetID != nil {
		d.Asset = &idName{ID: *r.AssetID}
		if r.Asset != nil && r.Asset.ID == *r.AssetID {
			d.Asset.Name = r.Asset.Name
		}
	}
	if r.AssetGroupID != nil {
		d.AssetGroup = &idName{ID: *r.AssetGroupID}
		if r.AssetGroup != nil && r.AssetGroup.ID == *r.AssetGroupID {
			d.AssetGroup.Name = r.AssetGroup.Name
		}
	}
	return d
}

// respondApproverScopeScopeError 審核範圍寫入的能力拒絕與範圍拒絕；回傳 true 表示已寫出。
// 範圍外與不存在經同一出口、同一回應。
func respondApproverScopeScopeError(c *gin.Context, err error) bool {
	var denied *authz.ErrScopeDenied
	if errors.As(err, &denied) {
		middleware.RespondScopeDenied(c, denied)
		return true
	}
	var capDenied *authz.ApproverScopeCapabilityError
	if errors.As(err, &capDenied) {
		middleware.WriteCapabilityDenial(c, middleware.AllOfCapabilityDenial(capDenied.Required...))
		return true
	}
	return false
}
