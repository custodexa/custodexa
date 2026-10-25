package asset

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
)

// 主機身分的人工承接入口（骨架）。
//
// 本檔只做兩件事：把請求收斂成固定形狀，以及在任何寫入與網路之前判定「誰在確認、確認的是不是這個目標」。
// 授權是純判定：只讀，不建立也不改任何授權列，不重新授權整輪工作；
// 通過判定後建立承接紀錄（短交易，見 hostkey_identity_takeover_create.go）；
// 單次驗證、消耗與就位轉移尚未接上，所以成功建立紀錄後仍回 ErrHostIdentityConfirmIncomplete。

// 承接的工作種類。
const (
	takeoverKindCandidate = "candidate"
	takeoverKindMember    = "member"
)

var (
	// ErrHostIdentityConfirmInvalid 確認請求的形狀不合法（傳輸值域、身分欄位或多餘欄位）。
	ErrHostIdentityConfirmInvalid = errors.New("主機身分確認請求不合法")
	// ErrHostIdentityConfirmTargetChanged 工作建立之後目標已改變：訊息即對外原因碼。
	ErrHostIdentityConfirmTargetChanged = errors.New(model.ChangeSecretReasonAuthzTargetChanged)
	// ErrHostIdentityConfirmIncomplete 通過授權與目標判定，但承接流程尚未接上。
	ErrHostIdentityConfirmIncomplete = errors.New("主機身分承接流程尚未完成")
)

// HostIdentityConfirmRequest 呼叫者明示確認的主機身分。
// 不含任何主體或授權欄位：確認者只來自伺服器端 context。
type HostIdentityConfirmRequest struct {
	// Transport ssh 或 winrm；winrm 時四個身分欄必須省略
	Transport          string `json:"transport"`
	RecordID           uint   `json:"record_id"`
	Algorithm          string `json:"algorithm"`
	Fingerprint        string `json:"fingerprint"`
	Generation         int64  `json:"generation"`
	AcceptDifferentKey bool   `json:"accept_different_key"`
}

// DecodeHostIdentityConfirmRequest 嚴格解碼：多餘欄位（例如自稱的操作者）一律拒絕，並做形狀驗證。
func DecodeHostIdentityConfirmRequest(raw []byte) (*HostIdentityConfirmRequest, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var req HostIdentityConfirmRequest
	if err := dec.Decode(&req); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHostIdentityConfirmInvalid, err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: 多餘內容", ErrHostIdentityConfirmInvalid)
	}
	if err := req.validate(); err != nil {
		return nil, err
	}
	return &req, nil
}

// validate 傳輸值域與身分欄位的對應：ssh 四欄齊全，winrm 四欄全空。
func (r *HostIdentityConfirmRequest) validate() error {
	identityEmpty := r.RecordID == 0 && r.Algorithm == "" && r.Fingerprint == "" && r.Generation == 0
	switch r.Transport {
	case model.HostKeyTransportSSH:
		if r.RecordID == 0 || strings.TrimSpace(r.Algorithm) == "" || strings.TrimSpace(r.Fingerprint) == "" || r.Generation <= 0 {
			return fmt.Errorf("%w: ssh 必須帶完整的記錄、演算法、指紋與世代", ErrHostIdentityConfirmInvalid)
		}
	case model.HostKeyTransportWinRM:
		if !identityEmpty {
			return fmt.Errorf("%w: winrm 不得帶身分欄位", ErrHostIdentityConfirmInvalid)
		}
	default:
		return fmt.Errorf("%w: transport 值域錯誤", ErrHostIdentityConfirmInvalid)
	}
	return nil
}

// HostIdentityTakeoverService 人工承接服務。
type HostIdentityTakeoverService struct {
	db   *gorm.DB
	mgmt credentialManagementGate
	sink port.TxSink
	// createTxBarrier 測試掛點：建立交易提交前呼叫，回錯誤即中止（模擬行程在提交前結束）
	createTxBarrier func(tx *gorm.DB) error
	// crashAfterRecord 測試掛點：紀錄與審計已提交、驗證尚未開始時呼叫，回錯誤即原樣返回
	// （模擬行程在此點結束：不寫任何結果、不撥號）
	crashAfterRecord func() error
	// candidateRunner 一般候選的驗證與轉正執行器；nil＝承接停在建立紀錄
	candidateRunner *ChangeSecretRetryRunner
	// memberRunner 輪替成員的驗證與就位執行器；nil＝成員承接停在建立紀錄
	memberRunner *CredentialRotationService
}

// NewHostIdentityTakeoverService 建立承接服務；authorizer 缺席時所有確認 fail closed。
func NewHostIdentityTakeoverService(db *gorm.DB, authorizer CredentialManagementAuthorizer) *HostIdentityTakeoverService {
	return &HostIdentityTakeoverService{db: db, mgmt: credentialManagementGate{authorizer: authorizer}}
}

// WiringGaps 回報完整承接流程所必需、但尚未注入的依賴名稱（全部就緒則為空）。
//
// 缺任一項時，帶確認的請求會在建立紀錄之後停在「流程未完成」，或在授權判定處一律拒絕；
// 組裝根在排程啟動之前呼叫它，缺口直接讓啟動失敗，不留到有人按下確認才發現。
func (s *HostIdentityTakeoverService) WiringGaps() []string {
	if s == nil {
		return []string{"hostIdentityTakeover"}
	}
	var gaps []string
	if s.db == nil {
		gaps = append(gaps, "db")
	}
	if s.mgmt.authorizer == nil {
		gaps = append(gaps, "authorizer")
	}
	if s.sink == nil {
		gaps = append(gaps, "auditSink")
	}
	if s.candidateRunner == nil {
		gaps = append(gaps, "candidateRunner")
	}
	if s.memberRunner == nil {
		gaps = append(gaps, "memberRunner")
	}
	return gaps
}

// takeoverSubject 工作列在授權與目標判定上需要的事實。
type takeoverSubject struct {
	assetID, accountID, credentialID uint
	storedFingerprint                string
	// capabilities 確認者必須具備的能力：基本鍵加上工作授權脈絡記下的整組能力
	// （與不帶確認的手動重試、補跑同一判準）；沒有授權脈絡時只有基本鍵。
	capabilities []string
	// auth 工作的授權脈絡（唯讀）；升級前的工作為 nil
	auth *model.CredentialJobAuthorization
	// authID 入口判權時工作引用的授權脈絡；建立交易鎖內須仍是同一個
	authID *uint
}

// ConfirmHostIdentityAndVerify 確認者明示承接某個停止中的工作。
// 一般候選（注入執行器時）做完整流程並在成功時回 nil；其餘種類仍停在建立紀錄。
func (s *HostIdentityTakeoverService) ConfirmHostIdentityAndVerify(ctx context.Context, kind string, jobID uint,
	req HostIdentityConfirmRequest) error {

	if err := req.validate(); err != nil {
		return err
	}
	// 背景呼叫沒有伺服器端主體：任何情形都拒絕，也不以系統呼叫標記放行
	if uid, _ := model.UserFromContext(ctx); uid == 0 {
		return ErrCredentialBindForbidden
	}
	subject, err := s.loadSubject(kind, jobID)
	if err != nil {
		return err
	}
	// 純判定：只讀，不寫授權列、不重新授權整輪工作
	decision, err := s.mgmt.require(ctx, s.db, CredentialManagementRequest{
		Operation:     CredOpRun,
		Capabilities:  subject.capabilities,
		CredentialIDs: nonZeroIDs(subject.credentialID),
		AssetIDs:      []uint{subject.assetID},
		AccountIDs:    []uint{subject.accountID},
	})
	if err != nil {
		return err
	}
	// 原發起者仍有權時另驗其能力（兩者都要通過）；失權或授權脈絡留自還原之前則只以確認者放行
	if err := s.revalidateInitiator(subject); err != nil {
		return err
	}
	// 目標可證實：當下的目標指紋必須等於工作建立時記下的
	// 查無目標列、工作無可證實指紋、指紋確實不同才是目標變更；其他讀取失敗無法判定（fail closed，保留原因）
	binding, err := loadConfirmedTargetBinding(s.db, subject.accountID)
	if err != nil {
		return err
	}
	var targetAsset model.Asset
	if err := s.db.Where("id = ?", binding.AssetID).First(&targetAsset).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrHostIdentityConfirmTargetChanged
		}
		return fmt.Errorf("%w: %v", ErrCredentialAuthzUnavailable, err)
	}
	// 輪替成員的目標指紋只在建立時寫入；指紋欄位出現之前建立的成員為空，目標已在上面證實仍存在，
	// 空值在建立承接紀錄的同一交易內補記（見 pinMemberTargetInTx），一般候選維持原判準
	pinMember := kind == takeoverKindMember && subject.storedFingerprint == ""
	if !pinMember && (subject.storedFingerprint == "" || targetFingerprintOf(&targetAsset, binding) != subject.storedFingerprint) {
		return ErrHostIdentityConfirmTargetChanged
	}
	rec, err := s.createConfirmation(ctx, kind, jobID, req, subject, decision)
	if err != nil {
		return err
	}
	if s.crashAfterRecord != nil {
		if err := s.crashAfterRecord(); err != nil {
			return err
		}
	}
	if kind == takeoverKindCandidate && s.candidateRunner != nil {
		return s.runCandidate(ctx, rec)
	}
	if kind == takeoverKindMember && s.memberRunner != nil {
		return s.memberRunner.verifyConfirmedMember(ctx, rec)
	}
	return ErrHostIdentityConfirmIncomplete
}

// loadSubject 載入工作列。找不到與無權同一回應，不讓無權者探測工作是否存在。
func (s *HostIdentityTakeoverService) loadSubject(kind string, jobID uint) (*takeoverSubject, error) {
	switch kind {
	case takeoverKindCandidate:
		var c model.ChangeSecretCandidate
		if err := s.db.Where("id = ?", jobID).First(&c).Error; err != nil {
			return nil, takeoverLoadError(err)
		}
		caps, auth, err := s.confirmerCapabilities(c.AuthorizationID, CredCapAccountRotate)
		if err != nil {
			return nil, err
		}
		return &takeoverSubject{assetID: c.AssetID, accountID: c.AccountID, credentialID: c.CredentialID,
			storedFingerprint: c.TargetFingerprint, capabilities: caps, auth: auth, authID: c.AuthorizationID}, nil
	case takeoverKindMember:
		var m model.CredentialRotationMember
		if err := s.db.Where("id = ?", jobID).First(&m).Error; err != nil {
			return nil, takeoverLoadError(err)
		}
		var rot model.CredentialRotation
		if err := s.db.Where("id = ?", m.RotationID).First(&rot).Error; err != nil {
			return nil, takeoverLoadError(err)
		}
		caps, auth, err := s.confirmerCapabilities(rot.AuthorizationID, CredCapRotate)
		if err != nil {
			return nil, err
		}
		return &takeoverSubject{assetID: m.AssetID, accountID: m.AccountID, credentialID: rot.CredentialID,
			storedFingerprint: m.TargetFingerprint, capabilities: caps, auth: auth, authID: rot.AuthorizationID}, nil
	}
	return nil, fmt.Errorf("%w: 未知的工作種類", ErrHostIdentityConfirmInvalid)
}

func takeoverLoadError(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrCredentialBindForbidden
	}
	return fmt.Errorf("%w: %v", ErrCredentialAuthzUnavailable, err)
}

// confirmerCapabilities 確認者的能力集合：基本鍵 ∪ 工作授權脈絡記下的能力。
// 沒有授權脈絡（升級前的工作）退回基本鍵；脈絡存在卻讀不出來時 fail closed。
// 只讀，不寫任何授權列。
func (s *HostIdentityTakeoverService) confirmerCapabilities(authID *uint, base string) ([]string,
	*model.CredentialJobAuthorization, error) {

	auth, err := loadJobAuthorization(s.db, authID)
	if errors.Is(err, ErrJobAuthorizationMissing) {
		return []string{base}, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrCredentialAuthzUnavailable, err)
	}
	ctxCaps, err := strictAuthorizationCapabilities(auth)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrCredentialAuthzUnavailable, err)
	}
	caps := []string{base}
	for _, c := range ctxCaps {
		if c != base {
			caps = append(caps, c)
		}
	}
	return caps, auth, nil
}

// revalidateInitiator 原發起者仍有權時，以脈絡記下的能力另驗其當下權限。
// 通過＝繼續（兩者都通過）；明確失權或脈絡留自還原之前＝不阻擋（只以確認者放行，紀錄另寫）；
// 無法判定（含世代讀取失敗）fail closed。不寫授權列。
func (s *HostIdentityTakeoverService) revalidateInitiator(subject *takeoverSubject) error {
	if subject.auth == nil {
		return nil
	}
	mismatch, err := s.mgmt.restoreMismatch(s.db, subject.auth.RestoreGeneration)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCredentialAuthzUnavailable, err)
	}
	if mismatch {
		return nil
	}
	initiatorCaps, err := strictAuthorizationCapabilities(subject.auth)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCredentialAuthzUnavailable, err)
	}
	if len(initiatorCaps) == 0 {
		initiatorCaps = subject.capabilities[:1]
	}
	_, err = s.mgmt.require(initiatorContext(subject.auth), s.db, CredentialManagementRequest{
		Operation:     CredOpRun,
		Capabilities:  initiatorCaps,
		CredentialIDs: nonZeroIDs(subject.credentialID),
		AssetIDs:      []uint{subject.assetID},
		AccountIDs:    []uint{subject.accountID},
	})
	if err == nil || errors.Is(err, ErrCredentialBindForbidden) {
		return nil
	}
	return err
}
