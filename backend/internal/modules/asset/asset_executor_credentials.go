package asset

import (
	"bytes"
	"context"
	"errors"
	"strings"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/model"
)

// 以堡壘機專用帳號（執行身分）登入目標機時唯一的取密途徑。
//
// 只讀某資產用途為執行身分的掛載，以開工時釘住的版本解封；不經 GetWithCredentialsForAccount、
// ResolveAccountIdentity、VerifyAccountBinding 這些人員連線出口，也不放寬它們對執行身分
// 「與不存在相同」的判定。

var (
	// ErrExecutorChanged 開工後專用帳號被清除、更換，或就位版本與釘住值不同
	ErrExecutorChanged = errors.New("堡壘機專用帳號已被變更")
	// ErrExecutorBusy 專用帳號的憑證正在整組輪替，或其掛載有未驗證的候選秘密
	ErrExecutorBusy = errors.New("堡壘機專用帳號正在改密")
	// ErrExecutorUnavailable 專用帳號沒有可用秘密、無法解封，或帳號名與秘密含不允許的字元
	ErrExecutorUnavailable = errors.New("堡壘機專用帳號沒有可用的秘密")
)

// ExecutorPin 改密工作展開某資產目標時記下的專用帳號釘住值。
type ExecutorPin struct {
	// AccountID 執行身分掛載識別
	AccountID uint
	// Username 掛載上的帳號名（登入一律取這個，不取憑證上的名字）
	Username     string
	CredentialID uint
	// EffectiveVersionID 該掛載就位的密文版本；0＝掛載在、沒有就位版本
	EffectiveVersionID uint
	// SecretType 就位版本的秘密型別（password／ssh_key）；無就位版本時為空
	SecretType string
}

// ExecutorCredentials 解封後的專用帳號登入材料。呼叫端 Destroy。
type ExecutorCredentials struct {
	AccountID    uint
	Username     string
	CredentialID uint
	VersionID    uint
	SecretType   string
	Password     *material.Secret
	PrivateKey   *material.Secret
}

// Destroy 抹除秘密。
func (c *ExecutorCredentials) Destroy() {
	if c == nil {
		return
	}
	c.Password.Destroy()
	c.PrivateKey.Destroy()
}

// readExecutorPin 讀該資產的執行身分掛載並記下釘住值；沒有執行身分回 nil。
func readExecutorPin(db *gorm.DB, assetID uint) (*ExecutorPin, error) {
	var mount model.AssetAccount
	err := db.Where("asset_id = ? AND purpose = ?", assetID, model.AccountPurposeExecutor).Limit(1).Find(&mount).Error
	if err != nil {
		return nil, err
	}
	if mount.ID == 0 {
		return nil, nil
	}
	pin := &ExecutorPin{AccountID: mount.ID, Username: mount.Username, CredentialID: mount.CredentialID}
	if mount.EffectiveVersionID != nil && *mount.EffectiveVersionID != 0 {
		pin.EffectiveVersionID = *mount.EffectiveVersionID
		if version, verr := loadCredentialVersion(db, mount.CredentialID, pin.EffectiveVersionID); verr == nil {
			pin.SecretType = version.SecretType
		}
	}
	return pin, nil
}

// executorMountState 判定專用帳號掛載此刻能不能用：憑證整組輪替中或掛載有未驗證候選回 ErrExecutorBusy，
// 讀不到憑證、沒有就位版本回 ErrExecutorUnavailable。不解封。取密與發起前的前置檢查共用這一份判定，
// 兩處對同一輸入的分類因此必然相同。
func executorMountState(db *gorm.DB, mount *model.AssetAccount) error {
	cred, err := loadCredential(db, mount.CredentialID)
	if err != nil {
		return ErrExecutorUnavailable
	}
	if cred.ActiveRotationID != nil {
		return ErrExecutorBusy
	}
	var pending int64
	if err := db.Model(&model.ChangeSecretCandidate{}).Where("account_id = ?", mount.ID).Count(&pending).Error; err != nil {
		return ErrExecutorUnavailable
	}
	if pending > 0 {
		return ErrExecutorBusy
	}
	if mount.EffectiveVersionID == nil || *mount.EffectiveVersionID == 0 {
		return ErrExecutorUnavailable
	}
	return nil
}

// ResolveExecutorCredentials 依釘住值取該資產專用帳號的登入材料。
//
// 判定順序：掛載與釘住值一致 → 就位版本一致 → 憑證不在輪替且掛載無未驗證候選 → 有就位版本 → 解封 →
// 控制字元檢查。每一步失敗都回專屬哨兵錯誤，錯誤不帶任何秘密；回傳的秘密由呼叫端 Destroy。
func (s *AssetService) ResolveExecutorCredentials(ctx context.Context, assetID uint, pin ExecutorPin) (*ExecutorCredentials, error) {
	db := database.DB
	var mount model.AssetAccount
	if err := db.Where("asset_id = ? AND purpose = ?", assetID, model.AccountPurposeExecutor).Limit(1).Find(&mount).Error; err != nil {
		return nil, ErrExecutorUnavailable
	}
	if mount.ID == 0 || mount.ID != pin.AccountID || mount.CredentialID != pin.CredentialID {
		return nil, ErrExecutorChanged
	}
	var effective uint
	if mount.EffectiveVersionID != nil {
		effective = *mount.EffectiveVersionID
	}
	if effective != pin.EffectiveVersionID {
		return nil, ErrExecutorChanged
	}
	if err := executorMountState(db, &mount); err != nil {
		return nil, err
	}
	resolved, err := s.resolver.ResolveVersion(ctx, pin.CredentialID, pin.EffectiveVersionID)
	if err != nil {
		return nil, ErrExecutorUnavailable
	}
	// 帳號名取掛載的帳號名，不取憑證上的名字
	out := &ExecutorCredentials{
		AccountID: mount.ID, Username: pin.Username, CredentialID: pin.CredentialID,
		VersionID: resolved.VersionID, SecretType: resolved.SecretType,
		Password: resolved.Password, PrivateKey: resolved.PrivateKey,
	}
	if strings.ContainsAny(out.Username, "\n\r\x00:") || out.Username == "" {
		out.Destroy()
		return nil, ErrExecutorUnavailable
	}
	if !out.Password.IsEmpty() {
		bad, _ := material.Use(out.Password, func(raw []byte) (bool, error) {
			return bytes.ContainsAny(raw, "\n\r\x00"), nil
		})
		if bad {
			out.Destroy()
			return nil, ErrExecutorUnavailable
		}
	}
	if out.Password.IsEmpty() && out.PrivateKey.IsEmpty() {
		out.Destroy()
		return nil, ErrExecutorUnavailable
	}
	return out, nil
}
