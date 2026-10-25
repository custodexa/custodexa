package asset

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 批次的執行時重驗。
//
// 建立批次時確認的是模式決定的能力：所有批次都要帳號改密；整批同一組另要建立與掛入；
// 每台各自隨機遇到共用憑證的成員另要脫離與憑證改密。這組能力連同選定的資產存成批次的
// 授權脈絡。背景執行時對每一台重驗**同一組**能力（對象是這一台的資產與帳號），只重驗帳號改密
// 的話，建立後被撤回的掛入或脫離能力在執行時不起作用。

// errBatchAuthzStop 批次授權重驗未通過：呼叫端停止該批（或該組）派送並記原因碼。
type errBatchAuthzStop struct {
	reason string
	cause  error
}

func (e *errBatchAuthzStop) Error() string {
	return fmt.Sprintf("批次授權重驗未通過: reason=%s: %v", e.reason, e.cause)
}

func (e *errBatchAuthzStop) Unwrap() error { return e.cause }

// batchRunCapabilities 批次執行時重驗的能力集合：批次授權脈絡保存的能力，聯集由模式推導的下限。
// 升級前沒有授權脈絡的批次只用下限；脈絡存在卻讀不出來回原因碼（fail closed）。
func (r *ChangeSecretRunner) batchRunCapabilities(job rotationJob) ([]string, string) {
	return r.batchRunCapabilitiesIn(r.db, job)
}

// batchRunCapabilitiesIn 同 batchRunCapabilities，以呼叫端給的連線讀授權脈絡（判定短交易內傳 tx）。
func (r *ChangeSecretRunner) batchRunCapabilitiesIn(db *gorm.DB, job rotationJob) ([]string, string) {
	floor := []string{CredCapAccountRotate}
	if job.sharedCredentialID != 0 {
		floor = append(floor, CredCapCreate, CredCapBind)
	}
	if job.authorizationID == 0 {
		return floor, ""
	}
	id := job.authorizationID
	auth, err := loadJobAuthorization(db, &id)
	if err != nil {
		return nil, jobAuthReason(err)
	}
	caps, err := strictAuthorizationCapabilities(auth)
	if err != nil {
		return nil, jobAuthReason(err)
	}
	return unionCapabilities(caps, floor), ""
}

// revalidateBatch 批次逐台派送前的重驗（呼叫端已取得該帳號的互斥鎖）：以批次的能力集合判定這一台的
// 資產與帳號；整批同一組另以掛入能力判定本批次新建的共用憑證與這一台——新憑證歸屬或目標資產不在發起者
// 當下的掛入範圍內即停止，遠端不被觸碰、不改綁。
// 回判定關卡的原始錯誤（nil＝通過）；能力欄讀不出來回 errBatchAuthzStop（不是目標範圍拒絕）。
func (r *ChangeSecretRunner) revalidateBatch(ctx context.Context, db *gorm.DB, job rotationJob, assetIDs, accountIDs []uint) error {
	caps, reason := r.batchRunCapabilitiesIn(db, job)
	if reason != "" {
		return &errBatchAuthzStop{reason: reason, cause: ErrJobAuthorizationUnreadable}
	}
	if _, err := r.mgmt.require(ctx, db, CredentialManagementRequest{
		Operation: CredOpRun, Capabilities: caps, AssetIDs: assetIDs, AccountIDs: accountIDs,
	}); err != nil {
		return err
	}
	if job.sharedCredentialID == 0 {
		return nil
	}
	_, err := r.mgmt.require(ctx, db, CredentialManagementRequest{
		Operation: CredOpBind, Capabilities: []string{CredCapBind},
		CredentialIDs: []uint{job.sharedCredentialID}, AssetIDs: assetIDs, AccountIDs: accountIDs,
	})
	return err
}

// unionCapabilities 保序去重的能力聯集（base 在前）。
func unionCapabilities(base, extra []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(base))
	for _, list := range [][]string{base, extra} {
		for _, c := range list {
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	return out
}

// splitAssetBound 由批次發起的拆分沿用的資產上界：起始交易與每次派送前，對選定成員所在的資產以
// caps 重驗（帳號改密與拆分所需能力），並把選定資產存進輪替的授權脈絡。nil＝一般拆分（只以憑證歸屬判定）。
type splitAssetBound struct {
	caps []string
}

// authorizationTargetBound 授權脈絡的目標上界；空字串、null 與空陣列都是「無上界」。
func authorizationTargetBound(auth *model.CredentialJobAuthorization) ([]uint, error) {
	raw := strings.TrimSpace(auth.TargetBound)
	if raw == "" || raw == "null" {
		return nil, nil
	}
	var ids []uint
	if err := json.Unmarshal([]byte(raw), &ids); err != nil {
		return nil, fmt.Errorf("%w: 目標上界無法解析", ErrJobAuthorizationUnreadable)
	}
	return ids, nil
}

// boundedSplitFloor 由批次發起的拆分（帶資產上界）在執行時的最低能力：帳號改密，加上拆分本身要的
// 憑證改密與脫離。持久化的能力陣列只能往上加，缺項不降低要求（與整批同一組模式的下限同一做法）。
func boundedSplitFloor() []string {
	return []string{CredCapAccountRotate, CredCapRotate, CredCapDetach}
}

// boundedRotationCapabilities 帶資產上界的輪替逐台重驗的能力：本輪授權脈絡的能力聯集拆分模式下限。
// 能力欄空白、null、空陣列或無法解析＝脈絡不完整，回錯誤（fail closed），不退回只剩憑證改密的預設。
func boundedRotationCapabilities(auth *model.CredentialJobAuthorization) ([]string, error) {
	caps, err := strictAuthorizationCapabilities(auth)
	if err != nil {
		return nil, err
	}
	if len(caps) == 0 {
		return nil, fmt.Errorf("%w: 帶上界的輪替缺能力記載", ErrJobAuthorizationUnreadable)
	}
	return unionCapabilities(caps, boundedSplitFloor()), nil
}

// revalidateAssetBound 帶資產上界的輪替（由批次發起的拆分）在每次派送前的重驗：成員所在資產不在上界內即停止；
// 在上界內者，以本輪能力聯集拆分模式下限對該資產與帳號判定，不以來源共用憑證的歸屬判定（拆分只改所選掛載，
// 起始交易同一口徑）。判定對象依序為本輪發起者、手動補跑的點擊者、重排者（與前兩者不同時）。
// 回原因碼與發起者通過時的權限世代版本（寫進 dispatch claim）。
func (s *CredentialRotationService) revalidateAssetBound(ctx context.Context, db *gorm.DB, auth *model.CredentialJobAuthorization,
	member *model.CredentialRotationMember, bound []uint) (string, int64) {

	caps, err := boundedRotationCapabilities(auth)
	if err != nil {
		return jobAuthReason(err), 0
	}
	inBound := false
	for _, id := range bound {
		if id == member.AssetID {
			inBound = true
			break
		}
	}
	if !inBound {
		return model.ChangeSecretReasonAuthzRevoked, 0
	}
	req := CredentialManagementRequest{
		Operation: CredOpRun, Capabilities: caps,
		AssetIDs: []uint{member.AssetID}, AccountIDs: []uint{member.AccountID},
	}
	actors := []context.Context{initiatorContext(auth)}
	callerID := uint(0)
	if ctx != nil {
		if uid, _ := model.UserFromContext(ctx); uid != 0 && uid != auth.ActorID {
			callerID = uid
			actors = append(actors, ctx)
		}
	}
	if member.RequeuedBy != 0 && member.RequeuedBy != auth.ActorID && member.RequeuedBy != callerID {
		actors = append(actors, contextWithInitiator(context.Background(), member.RequeuedBy, member.RequeuedByName))
	}
	var version int64
	for i, actor := range actors {
		decision, err := s.mgmt.require(actor, db, req)
		if err != nil {
			return revalidationReason(err), 0
		}
		if i == 0 {
			version = decision.AuthzVersion
		}
	}
	return "", version
}

// batchStopReason 拆分起始失敗是否為批次授權重驗未通過；是則回原因碼。
func batchStopReason(err error) (string, bool) {
	var stop *errBatchAuthzStop
	if errors.As(err, &stop) {
		return stop.reason, true
	}
	return "", false
}
