package asset

import (
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 憑證的對外投影：從 model 到 DTO 的轉換，與「哪些欄位可以出站」這件事的單一落點。
//
// # 為什麼投影自成一檔
//
// 密文不出站是安全紅線，而紅線最容易在「順手多回一個欄位」時被跨過。把全部轉換
// 收在一處，回應形狀的每一次變動都在同一個 diff 裡看得見；散在各服務方法內時，
// 一個新增欄位的 commit 會看起來像在改業務邏輯。
//
// # 專用憑證的顯示名是計算值
//
// 「資產名 / 帳號名」不落庫：資產改名後顯示名必須跟著改，落庫的副本會在改名那一刻
// 開始說謊，而說謊的方向正好是「憑證庫上看到的那台機器」與「實際掛著的那台」不同。

// CredentialDTO 憑證的對外表示：密文絕不出站，只投影「是否持有」兩個布林。
type CredentialDTO struct {
	ID uint `json:"id"`
	// Name 共用＝落庫的名稱；專用＝「資產名 / 帳號名」計算值（不落庫、不可編輯）
	Name           string `json:"name"`
	Scope          string `json:"scope"`
	Username       string `json:"username"`
	SecretType     string `json:"secret_type"`
	AuthMethod     string `json:"auth_method"`
	ProtocolFamily string `json:"protocol_family"`
	Note           string `json:"note"`

	HasPassword   bool `json:"has_password"`
	HasPrivateKey bool `json:"has_private_key"`
	// BindingCount 掛載此憑證的資產數
	BindingCount int `json:"binding_count"`
	// CurrentVersionNo 現行版本序號；0＝尚無任何密文
	CurrentVersionNo int `json:"current_version_no"`
	// RotationActive 輪替進行中（聚合態的五值投影屬輪替狀態機的射程，不在此）
	RotationActive bool `json:"rotation_active"`
	// ActiveRotationID 進行中那一輪的識別；0＝沒有進行中的輪替。
	//
	// 進度端點以輪替識別定址，少了這一欄，逐台進度就只有「發起那一次操作」的
	// 呼叫端看得到——重新整理或換一台電腦打開，同一筆憑證只剩「輪替中」與
	// 被擋住的動作，而看不出還差哪幾台。
	ActiveRotationID uint `json:"active_rotation_id"`

	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// CredentialBindingDTO 掛載列的對外表示（憑證詳情的右側清單）。
type CredentialBindingDTO struct {
	AccountID uint   `json:"account_id"`
	AssetID   uint   `json:"asset_id"`
	AssetName string `json:"asset_name"`
	Username  string `json:"username"`
	IsDefault bool   `json:"is_default"`
	// Privileged 逐掛載獨立：同一組秘密在不同主機上的特權性可以不同
	Privileged bool   `json:"privileged"`
	Note       string `json:"note"`
	// EffectiveVersionNo 該台當下用以連線的版本序號；0＝尚未取得任何密文
	EffectiveVersionNo int `json:"effective_version_no"`
	// UpToDate 就位版本即憑證的現行版本
	UpToDate bool `json:"up_to_date"`
}

// CredentialDetailDTO 憑證詳情：基本資料＋掛載清單。
type CredentialDetailDTO struct {
	CredentialDTO
	Bindings []*CredentialBindingDTO `json:"bindings"`
}

// --- 投影面 ---

// credentialDTO 由 model 轉出對外表示（密文只轉成布林）。
func (s *CredentialService) credentialDTO(db *gorm.DB, cred *model.Credential) (*CredentialDTO, error) {
	return credentialDTOFrom(db, cred)
}

// credentialDTOFrom 憑證投影。專用憑證的顯示名為「資產名 / 帳號名」計算值。
func credentialDTOFrom(db *gorm.DB, cred *model.Credential) (*CredentialDTO, error) {
	count, err := credentialBindingCount(db, cred.ID)
	if err != nil {
		return nil, err
	}
	dto := &CredentialDTO{
		ID:             cred.ID,
		Scope:          cred.Scope,
		Username:       cred.Username,
		SecretType:     cred.SecretType,
		AuthMethod:     cred.AuthMethod,
		ProtocolFamily: cred.ProtocolFamily,
		Note:           cred.Note,
		BindingCount:   int(count),
		RotationActive: cred.ActiveRotationID != nil,
		CreatedAt:      cred.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:      cred.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
	if cred.ActiveRotationID != nil {
		dto.ActiveRotationID = *cred.ActiveRotationID
	}
	if cred.Scope == model.CredentialScopeShared {
		if cred.Name != nil {
			dto.Name = *cred.Name
		}
	} else {
		name, derr := dedicatedDisplayName(db, cred)
		if derr != nil {
			return nil, derr
		}
		dto.Name = name
	}
	if cred.CurrentVersionID != nil {
		version, verr := loadCredentialVersion(db, cred.ID, *cred.CurrentVersionID)
		if verr != nil && !errors.Is(verr, ErrCredentialVersionNotFound) {
			return nil, verr
		}
		if version != nil {
			dto.CurrentVersionNo = version.VersionNo
		}
		flags, ferr := versionSecretFlags(db, []uint{*cred.CurrentVersionID})
		if ferr != nil {
			return nil, ferr
		}
		f := flags[*cred.CurrentVersionID]
		dto.HasPassword, dto.HasPrivateKey = f.HasPassword, f.HasPrivateKey
	}
	return dto, nil
}

// dedicatedDisplayName 專用憑證的計算顯示名：「資產名 / 帳號名」。
//
// **不落庫**：資產改名後顯示名必須跟著改，落庫的副本會在改名那一刻開始說謊。
// 掛載尚未建立（建立與掛載之間的交易中間態）時退為帳號名本身。
func dedicatedDisplayName(db *gorm.DB, cred *model.Credential) (string, error) {
	var binding model.AssetAccount
	err := db.Where("credential_id = ?", cred.ID).Order("id ASC").First(&binding).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return cred.Username, nil
		}
		return "", fmt.Errorf("查詢憑證掛載失敗: %w", err)
	}
	var asset model.Asset
	if err := db.Where("id = ?", binding.AssetID).First(&asset).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return cred.Username, nil
		}
		return "", fmt.Errorf("查詢資產失敗: %w", err)
	}
	return asset.Name + " / " + cred.Username, nil
}

// credentialBindingDTOs 憑證的掛載清單（每台帶就位版本與特權標記）。
func credentialBindingDTOs(db *gorm.DB, cred *model.Credential) ([]*CredentialBindingDTO, error) {
	var bindings []model.AssetAccount
	if err := db.Where("credential_id = ?", cred.ID).
		Order("asset_id ASC, id ASC").Find(&bindings).Error; err != nil {
		return nil, fmt.Errorf("查詢憑證掛載失敗: %w", err)
	}
	out := make([]*CredentialBindingDTO, 0, len(bindings))
	for i := range bindings {
		b := &bindings[i]
		dto := &CredentialBindingDTO{
			AccountID:  b.ID,
			AssetID:    b.AssetID,
			Username:   cred.Username,
			IsDefault:  b.IsDefault,
			Privileged: b.Privileged,
			Note:       b.Note,
		}
		var asset model.Asset
		if err := db.Where("id = ?", b.AssetID).First(&asset).Error; err == nil {
			dto.AssetName = asset.Name
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("查詢資產失敗: %w", err)
		}
		if b.EffectiveVersionID != nil {
			version, verr := loadCredentialVersion(db, cred.ID, *b.EffectiveVersionID)
			if verr != nil && !errors.Is(verr, ErrCredentialVersionNotFound) {
				return nil, verr
			}
			if version != nil {
				dto.EffectiveVersionNo = version.VersionNo
			}
			dto.UpToDate = cred.CurrentVersionID != nil && *cred.CurrentVersionID == *b.EffectiveVersionID
		}
		out = append(out, dto)
	}
	return out, nil
}
