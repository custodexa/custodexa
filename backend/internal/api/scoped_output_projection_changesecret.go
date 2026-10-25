package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz/disclosure"
)

// 改密輸出的集中投影：批次目標、改密紀錄（批次明細與計畫紀錄）與候選的來源計畫參照。
// 憑證識別能否出站只看憑證檢視集合（asset.CredentialOutputScope），改密入口與改密能力不參與。

var errChangeSecretOutputUnwired = errors.New("改密輸出判定未注入")

// SetCredentialOutputScope 注入輸出判定來源（組裝時）。
func (h *ChangeSecretHandler) SetCredentialOutputScope(src asset.CredentialOutputScopeSource) {
	h.output = src
}

// CredentialOutputScopeWired 輸出判定來源已注入（組裝自檢用）。
func (h *ChangeSecretHandler) CredentialOutputScopeWired() bool {
	return h != nil && h.output != nil
}

// CandidateScopeWired 候選服務的計畫範圍判定已注入（組裝自檢用）。
func (h *ChangeSecretHandler) CandidateScopeWired() bool {
	return h != nil && h.candidates.ScopeWired()
}

func (h *ChangeSecretHandler) outputScope(ctx context.Context) (asset.CredentialOutputScope, error) {
	if h == nil || h.output == nil {
		return nil, errChangeSecretOutputUnwired
	}
	scope, err := h.output.CredentialOutputScope(ctx)
	if err != nil {
		return nil, err
	}
	if scope == nil {
		return nil, errChangeSecretOutputUnwired
	}
	return scope, nil
}

// changeSecretRecordDTO 改密紀錄的對外表示。全量時鍵集與 model 序列化逐鍵相同；
// 憑證欄位為指標，範圍外憑證的列省略三欄並帶 credential_out_of_scope。
type changeSecretRecordDTO struct {
	ID              uint      `json:"id"`
	PlanID          uint      `json:"plan_id"`
	BatchID         uint      `json:"batch_id"`
	AssetID         uint      `json:"asset_id"`
	AccountID       uint      `json:"account_id"`
	AccountUsername string    `json:"account_username"`
	SecretType      string    `json:"secret_type"`
	CredentialID    *uint     `json:"credential_id,omitempty"`
	CredentialName  *string   `json:"credential_name,omitempty"`
	TargetVersionID *uint     `json:"target_version_id,omitempty"`
	Status          string    `json:"status"`
	Error           string    `json:"error"`
	ExecutedAt      time.Time `json:"executed_at"`

	CredentialOutOfScope bool `json:"credential_out_of_scope,omitempty"`
}

func newChangeSecretRecordDTO(r *model.ChangeSecretRecord, masked bool) changeSecretRecordDTO {
	d := changeSecretRecordDTO{
		ID: r.ID, PlanID: r.PlanID, BatchID: r.BatchID, AssetID: r.AssetID,
		AccountID: r.AccountID, AccountUsername: r.AccountUsername, SecretType: r.SecretType,
		Status: r.Status, Error: r.Error, ExecutedAt: r.ExecutedAt,
	}
	if masked {
		d.CredentialOutOfScope = true
		return d
	}
	cid, name, ver := r.CredentialID, r.CredentialName, r.TargetVersionID
	d.CredentialID, d.CredentialName, d.TargetVersionID = &cid, &name, &ver
	return d
}

// projectRecords 紀錄列的可見投影。以紀錄自身的憑證識別判定，不以帳號目前掛載的憑證代替。
// wrap 把投影後的列放入該出口的外框。判定失敗或來源未注入回錯誤。
func (h *ChangeSecretHandler) projectRecords(ctx context.Context, records []model.ChangeSecretRecord,
	wrap func(rows []changeSecretRecordDTO) any) (scopedOutput, error) {

	scope, err := h.outputScope(ctx)
	if err != nil {
		return scopedOutput{}, err
	}
	inView := map[uint]bool{}
	if !scope.Full() {
		ids := make([]uint, 0, len(records))
		for i := range records {
			if records[i].CredentialID != 0 {
				ids = append(ids, records[i].CredentialID)
			}
		}
		if inView, err = scope.CredentialsInView(ids); err != nil {
			return scopedOutput{}, err
		}
	}
	rows := make([]changeSecretRecordDTO, 0, len(records))
	for i := range records {
		masked := !scope.Full() && records[i].CredentialID != 0 && !inView[records[i].CredentialID]
		rows = append(rows, newChangeSecretRecordDTO(&records[i], masked))
	}
	return scopedOutput{body: wrap(rows)}, nil
}

// projectBatchTargets 批次目標的可見投影：不在憑證檢視集合內的列移除憑證名稱並帶範圍外標記。
// 全量時逐位元不變；判定失敗或來源未注入回錯誤。
func (h *ChangeSecretHandler) projectBatchTargets(ctx context.Context, targets []asset.BatchTarget,
	asOf time.Time) (scopedOutput, error) {

	scope, err := h.outputScope(ctx)
	if err != nil {
		return scopedOutput{}, err
	}
	frame := func(data any) scopedOutput {
		return scopedOutput{body: gin.H{"data": data, "total": len(targets), "as_of": asOf}}
	}
	if scope.Full() {
		return frame(targets), nil
	}
	ids := make([]uint, 0, len(targets))
	for i := range targets {
		if targets[i].CredentialID != 0 {
			ids = append(ids, targets[i].CredentialID)
		}
	}
	inView, err := scope.CredentialsInView(ids)
	if err != nil {
		return scopedOutput{}, err
	}
	rows := make([]json.RawMessage, 0, len(targets))
	for i := range targets {
		raw, err := json.Marshal(targets[i])
		if err != nil {
			return scopedOutput{}, err
		}
		if targets[i].CredentialID == 0 || inView[targets[i].CredentialID] {
			rows = append(rows, raw)
			continue
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			return scopedOutput{}, err
		}
		delete(m, "credential_name")
		m["credential_out_of_scope"] = json.RawMessage("true")
		masked, err := json.Marshal(m)
		if err != nil {
			return scopedOutput{}, err
		}
		rows = append(rows, masked)
	}
	return frame(rows), nil
}

// projectCandidates 候選清單的可見投影：來源計畫對請求主體不可見者，plan_id 輸出為 0
// （0 在模型上本就表示無計畫，檢視者無法區分沒有計畫與看不到的計畫）。
func (h *ChangeSecretHandler) projectCandidates(ctx context.Context, viewer uint,
	items []model.ChangeSecretCandidate) (scopedOutput, error) {

	planIDs := make([]uint, 0, len(items))
	seen := map[uint]bool{}
	for i := range items {
		if id := items[i].PlanID; id != 0 && !seen[id] {
			seen[id] = true
			planIDs = append(planIDs, id)
		}
	}
	visible, err := h.candidates.VisiblePlanRefs(ctx, viewer, planIDs)
	if err != nil {
		return scopedOutput{}, err
	}
	out := make([]changeSecretCandidateDTO, 0, len(items))
	for i := range items {
		dto := newCandidateDTO(&items[i])
		if visible != nil && dto.PlanID != 0 && !visible[dto.PlanID] {
			dto.PlanID = 0
		}
		out = append(out, dto)
	}
	return scopedOutput{body: gin.H{"data": out, "total": len(out)}}, nil
}

// maskPlans 計畫列的可見投影：目標憑證不在憑證檢視集合內者，目標憑證識別輸出為 null 並帶範圍外標記；
// 資產集合只留檢視集合內的資產，被省略的台數帶在 out_of_scope_asset_count。
// full 為真時不做任何改動（呼叫端直接輸出原計畫）。判定失敗或來源未注入回錯誤。
func (h *ChangeSecretHandler) maskPlans(ctx context.Context, plans []model.ChangeSecretPlan) (rows []json.RawMessage, full bool, err error) {
	scope, err := h.outputScope(ctx)
	if err != nil {
		return nil, false, err
	}
	if scope.Full() {
		return nil, true, nil
	}
	var credIDs, assetIDs []uint
	for i := range plans {
		if plans[i].TargetCredentialID != nil {
			credIDs = append(credIDs, *plans[i].TargetCredentialID)
		}
		assetIDs = append(assetIDs, asset.AssetIDList(&plans[i])...)
	}
	credInView, err := scope.CredentialsInView(credIDs)
	if err != nil {
		return nil, false, err
	}
	assetInView, err := scope.AssetsInView(assetIDs)
	if err != nil {
		return nil, false, err
	}
	rows = make([]json.RawMessage, 0, len(plans))
	for i := range plans {
		row, err := maskPlanRow(&plans[i], credInView, assetInView)
		if err != nil {
			return nil, false, err
		}
		rows = append(rows, row)
	}
	return rows, false, nil
}

func maskPlanRow(p *model.ChangeSecretPlan, credInView, assetInView map[uint]bool) (json.RawMessage, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	if p.TargetCredentialID != nil && !credInView[*p.TargetCredentialID] {
		m["target_credential_id"] = json.RawMessage("null")
		m["credential_out_of_scope"] = json.RawMessage("true")
	}
	all := asset.AssetIDList(p)
	kept := make([]uint, 0, len(all))
	for _, id := range all {
		if assetInView[id] {
			kept = append(kept, id)
		}
	}
	if len(kept) != len(all) {
		ids, err := json.Marshal(kept)
		if err != nil {
			return nil, err
		}
		quoted, err := json.Marshal(string(ids))
		if err != nil {
			return nil, err
		}
		m["asset_ids"] = json.RawMessage(quoted)
		m[disclosure.FieldOutOfScopeAssetCount] = disclosure.Count(disclosure.OutOfScopeAssetCount, len(all)-len(kept))
	}
	return json.Marshal(m)
}

// projectPlanList 計畫列表的可見投影；全量時輸出原計畫切片，形狀不變。
func (h *ChangeSecretHandler) projectPlanList(ctx context.Context, plans []model.ChangeSecretPlan) (scopedOutput, error) {
	rows, full, err := h.maskPlans(ctx, plans)
	if err != nil {
		return scopedOutput{}, err
	}
	if full {
		return scopedOutput{body: gin.H{"data": plans, "total": len(plans)}}, nil
	}
	return scopedOutput{body: gin.H{"data": rows, "total": len(rows)}}, nil
}

// projectPlan 單一計畫（建立與更新的回應）的可見投影；全量時輸出原計畫。
func (h *ChangeSecretHandler) projectPlan(ctx context.Context, plan *model.ChangeSecretPlan) (scopedOutput, error) {
	rows, full, err := h.maskPlans(ctx, []model.ChangeSecretPlan{*plan})
	if err != nil {
		return scopedOutput{}, err
	}
	if full {
		return scopedOutput{body: plan}, nil
	}
	return scopedOutput{body: rows[0]}, nil
}
