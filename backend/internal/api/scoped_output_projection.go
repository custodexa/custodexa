package api

import (
	"context"
	"errors"
	"log"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/gin-gonic/gin"
)

// 範圍化輸出的集中投影：憑證相關的輸出一律先經此處的投影函式，再由 respondScoped 寫出。
// 投影取產生回應當下以請求主體重新解析的授權狀態，缺依賴時回錯誤，沒有退回全量的分支。

// scopedOutput 投影後的完整回應本文（外框鍵已含）。
type scopedOutput struct {
	body any
}

// respondScoped 範圍化輸出的唯一寫出點。
func respondScoped(c *gin.Context, status int, out scopedOutput) {
	c.JSON(status, out.body)
}

var (
	errRotationProjectionUnwired = errors.New("輪替成員投影未注入")
	errAccountProjectionUnwired  = errors.New("帳號列投影來源未注入，範圍化主體不得取得完整帳號列")
)

// RotationMemberProjection 輪替成員的可見投影（asset.CredentialRotationService 實作）。
type RotationMemberProjection interface {
	// MembersInView 請求主體可見的成員，與被省略成員所屬資產的去重台數（全量為 nil）。
	MembersInView(ctx context.Context, rotationID uint) ([]model.CredentialRotationMember, *int, error)
	// OutputScopeWired 輸出判定來源已注入。
	OutputScopeWired() bool
}

// SetRotationMemberProjection 注入輪替成員投影（組裝時）。
func (h *CredentialHandler) SetRotationMemberProjection(p RotationMemberProjection) {
	h.rotationProjection = p
}

// RotationProjectionInjected 輪替成員投影已注入（不含其輸出判定；組裝自檢用）。
func (h *CredentialHandler) RotationProjectionInjected() bool {
	return h != nil && h.rotationProjection != nil
}

// RotationProjectionWired 輪替投影已注入且其輸出判定已注入（組裝自檢用）。
func (h *CredentialHandler) RotationProjectionWired() bool {
	return h != nil && h.rotationProjection != nil && h.rotationProjection.OutputScopeWired()
}

// SetAccountRowProjector 以與帳號 handler 相同的兩個來源建立帳號列投影器（組裝時）。
func (h *CredentialHandler) SetAccountRowProjector(scope AccountCredentialScope, actions AccountRowActionSource) {
	h.accountRows = &accountRowProjector{credScope: scope, rowActions: actions}
}

// AccountRowProjectorWired 帳號列投影器已注入且憑證投影來源存在（組裝自檢用）。
func (h *CredentialHandler) AccountRowProjectorWired() bool {
	return h != nil && h.accountRows != nil && h.accountRows.credScope != nil
}

// rotationSupplement 補跑回應附在單一成員上的補充資料；只附在留下的成員上。
type rotationSupplement struct {
	MemberID     uint
	HostIdentity *asset.HostIdentityView
	Reason       string
}

// projectRotation 組出輪替的對外回應：成員只含請求主體可見者，受限時帶範圍外台數。
// 成員讀取或可見判定失敗、投影未注入都回錯誤，不出站任何成員。
// 聚合態、未收束輪次與候選旗標讀取失敗只記日誌（不含受保護內容）。
func (h *CredentialHandler) projectRotation(ctx context.Context, rot *model.CredentialRotation,
	sup rotationSupplement) (scopedOutput, error) {

	if !h.RotationProjectionWired() {
		return scopedOutput{}, errRotationProjectionUnwired
	}
	members, hidden, err := h.rotationProjection.MembersInView(ctx, rot.ID)
	if err != nil {
		return scopedOutput{}, err
	}
	aggregate, err := h.rotations.AggregateState(rot.CredentialID)
	if err != nil {
		log.Printf("[Credential] 查詢聚合態失敗: credential=%d err=%v", rot.CredentialID, err)
		aggregate = ""
	}
	out := newRotationDTO(rot, members, aggregate)
	if rot.Status == model.CredentialRotationAbandoned {
		unsettled, uerr := h.rotations.UnsettledRotationID(rot.CredentialID)
		if uerr != nil {
			log.Printf("[Credential] 查詢未收束輪替失敗: credential=%d err=%v", rot.CredentialID, uerr)
		}
		out.Unsettled = uerr == nil && unsettled == rot.ID
		if out.Unsettled {
			kept, kerr := h.rotations.CandidateKeptMembers(rot.ID)
			if kerr != nil {
				log.Printf("[Credential] 查詢成員候選失敗: rotation=%d err=%v", rot.ID, kerr)
			}
			for i := range out.Members {
				out.Members[i].CandidateKept = kept[out.Members[i].ID]
			}
		}
	}
	if sup.MemberID != 0 {
		for i := range out.Members {
			if out.Members[i].ID == sup.MemberID {
				out.Members[i].HostIdentity = sup.HostIdentity
				out.Members[i].Reason = sup.Reason
			}
		}
	}
	if hidden == nil {
		return scopedOutput{body: gin.H{"data": out}}, nil
	}
	row, err := withOutOfScopeCount(out, *hidden)
	if err != nil {
		return scopedOutput{}, err
	}
	return scopedOutput{body: gin.H{"data": row}}, nil
}

// accountRowProjector 帳號列投影：列表與五個寫入出口共用同一個判定。
type accountRowProjector struct {
	credScope  AccountCredentialScope
	rowActions AccountRowActionSource
}

// shape 以投影來源決定回應形狀與範圍化時 ids 中可見的憑證。
// 來源未注入（只存在於單元測試組裝）：欄位能力不成立回精簡；成立且請求主體是範圍化檢視者回錯誤；其餘完整。
func (p *accountRowProjector) shape(c *gin.Context, accounts []*asset.AssetAccountDTO) (authz.AccountCredentialShape, map[uint]bool, error) {
	if p == nil || p.credScope == nil {
		if !credentialFieldsVisible(c) {
			return authz.AccountCredentialSlim, nil, nil
		}
		if authz.IsCredentialScopedViewer(accountAuthzContext(c)) {
			return authz.AccountCredentialSlim, nil, errAccountProjectionUnwired
		}
		return authz.AccountCredentialFull, nil, nil
	}
	ids := make([]uint, 0, len(accounts))
	for _, a := range accounts {
		if a.CredentialID != 0 {
			ids = append(ids, a.CredentialID)
		}
	}
	return p.credScope.AccountCredentialProjection(accountAuthzContext(c), ids)
}

// row 單列依形狀轉成對外型別。
func (p *accountRowProjector) row(c *gin.Context, shape authz.AccountCredentialShape, inView map[uint]bool,
	a *asset.AssetAccountDTO) (any, error) {

	switch {
	case shape == authz.AccountCredentialSlim:
		return asset.SlimAssetAccountDTO(a), nil
	case shape == authz.AccountCredentialScoped && !inView[a.CredentialID]:
		row := asset.OutOfScopeAssetAccountDTO(a)
		if p != nil && p.rowActions != nil {
			actions, err := accountRowActions(p.rowActions.AccountRowChecks(accountContext(c), a.AssetID, a.ID, a.CredentialID))
			if err != nil {
				return nil, err
			}
			row.Actions = actions
		}
		return row, nil
	default:
		return a, nil
	}
}

// rows 列表回應（含 data 與 total 外框）。
func (p *accountRowProjector) rows(c *gin.Context, accounts []*asset.AssetAccountDTO) (scopedOutput, error) {
	shape, inView, err := p.shape(c, accounts)
	if err != nil {
		return scopedOutput{}, err
	}
	out := make([]any, 0, len(accounts))
	for _, a := range accounts {
		r, err := p.row(c, shape, inView, a)
		if err != nil {
			return scopedOutput{}, err
		}
		out = append(out, r)
	}
	return scopedOutput{body: gin.H{"data": out, "total": len(out)}}, nil
}

// one 寫入回應（單列本體，無外框）。
func (p *accountRowProjector) one(c *gin.Context, a *asset.AssetAccountDTO) (scopedOutput, error) {
	shape, inView, err := p.shape(c, []*asset.AssetAccountDTO{a})
	if err != nil {
		return scopedOutput{}, err
	}
	r, err := p.row(c, shape, inView, a)
	if err != nil {
		return scopedOutput{}, err
	}
	return scopedOutput{body: r}, nil
}

// respondAccountRow 帳號列寫入回應的統一出口（掛載與更換憑證）。
func (h *CredentialHandler) respondAccountRow(c *gin.Context, status int, dto *asset.AssetAccountDTO, code apierror.ErrCode) {
	out, err := h.accountRows.one(c, dto)
	if err != nil {
		respondCredentialError(c, code, err)
		return
	}
	respondScoped(c, status, out)
}
