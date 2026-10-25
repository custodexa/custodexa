package asset

import (
	"context"
	"encoding/json"
	"errors"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 憑證目標計畫的掛載上界：範圍化發起者儲存該版時，伺服器把那一刻該憑證的全部掛載
// （資產帳號列）存成上界。每次執行在起始交易內、建立任何版本與成員之前，把當下掛載分成
// 「資產在發起者憑證改密範圍內」與其餘兩部分；只有範圍外部分不是上界子集時才整次停止，
// 範圍內新增的掛載照常執行。比對與成員快照用同一份交易內讀出的掛載，期間加掛也看得見。
// 經全系統來源持有憑證改密者依全域規則執行當下全部掛載，不比對上界。

// ErrRotationPlanBoundExceeded 憑證當下掛載的範圍外部分超出計畫該版的掛載上界（或計畫已在待重新確認，
// 而發起者只經節點範圍持有憑證改密）：不建立版本與成員，遠端零操作。
var ErrRotationPlanBoundExceeded = errors.New("憑證掛載的範圍外部分超出計畫的掛載上界")

// PlanMountBound 計畫路徑的整組起始條件。
type PlanMountBound struct {
	// Mounts 該版掛載上界（資產帳號列識別）；空＝沒有上界（以空集合比對）
	Mounts map[uint]bool
	// Reconfirming 計畫已在待重新確認：只經節點範圍持有憑證改密者一律停止，不因當下恰為子集而略過確認
	Reconfirming bool
	// PlanID 來源計畫；非 0 時起始交易在鎖後重讀計畫當下的暫停狀態與生效授權脈絡的掛載上界，
	// 呼叫端快照（Reconfirming、Mounts）只作為更嚴的下限，不能替已生效的暫停背書
	PlanID uint
}

// ParsePlanMountBound 讀授權脈絡的掛載上界欄；空值或無法解讀一律視為空集合（比對時只會更嚴）。
func ParsePlanMountBound(raw string) map[uint]bool {
	out := map[uint]bool{}
	var ids []uint
	if raw == "" || json.Unmarshal([]byte(raw), &ids) != nil {
		return out
	}
	for _, id := range ids {
		out[id] = true
	}
	return out
}

// StartForPlan 計畫路徑的整組改密起始：以掛載上界取代影響確認（確認已在計畫儲存時消費），
// 上界比對與成員快照在同一交易、同一份掛載。
func (s *CredentialRotationService) StartForPlan(ctx context.Context, credentialID uint,
	req StartRotationRequest, bound PlanMountBound) (*model.CredentialRotation, error) {
	return s.startGroupRotation(ctx, credentialID, req, &bound)
}

// enforcePlanMountBound 起始交易內（拓撲鎖、憑證列鎖、掛載讀取與整組判定之後）的上界比對。
func (s *CredentialRotationService) enforcePlanMountBound(ctx context.Context, tx *gorm.DB,
	bindings []model.AssetAccount, bound *PlanMountBound) error {

	// 不帶目標的憑證改密判定只認全系統來源：通過者依全域規則涵蓋當下全部掛載
	_, err := s.mgmt.require(ctx, tx, CredentialManagementRequest{
		Operation: CredOpRotate, Capabilities: []string{CredCapRotate},
	})
	if err == nil {
		return nil
	}
	var denied *CapabilityDeniedError
	if !errors.As(err, &denied) {
		return err
	}
	if bound.Reconfirming {
		return ErrRotationPlanBoundExceeded
	}
	mounts := bound.Mounts
	if bound.PlanID != 0 {
		current, err := planBoundInTx(tx, bound.PlanID)
		if err != nil {
			return err
		}
		if current.Reconfirming {
			return ErrRotationPlanBoundExceeded
		}
		mounts = current.Mounts
	}
	inScope := map[uint]bool{}
	for _, b := range bindings {
		in, seen := inScope[b.AssetID]
		if !seen {
			d, err := s.mgmt.require(ctx, tx, CredentialManagementRequest{
				Operation: CredOpRotate, Capabilities: []string{CredCapRotate}, AssetIDs: []uint{b.AssetID},
			})
			switch {
			case err == nil:
				in = true
			case d.ScopeDenial != nil:
				in = false
			default:
				return err
			}
			inScope[b.AssetID] = in
		}
		if !in && !mounts[b.ID] {
			return ErrRotationPlanBoundExceeded
		}
	}
	return nil
}

// planBoundInTx 起始交易內（拓撲鎖之後）重讀計畫當下的暫停狀態與生效授權脈絡的掛載上界。
// 計畫已刪除回 ErrPlanNotFound；授權脈絡讀不到時上界為空集合（比對只會更嚴）。
func planBoundInTx(tx *gorm.DB, planID uint) (PlanMountBound, error) {
	var plan model.ChangeSecretPlan
	if err := tx.Select("id", "authorization_id", "authorization_state").Where("id = ?", planID).
		First(&plan).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return PlanMountBound{}, ErrPlanNotFound
		}
		return PlanMountBound{}, err
	}
	out := PlanMountBound{Mounts: map[uint]bool{}, PlanID: planID,
		Reconfirming: plan.AuthorizationState == model.PlanAuthNeedsReconfirmation}
	if auth, err := loadJobAuthorization(tx, plan.AuthorizationID); err == nil {
		out.Mounts = ParsePlanMountBound(auth.TargetMountBound)
	}
	return out, nil
}
