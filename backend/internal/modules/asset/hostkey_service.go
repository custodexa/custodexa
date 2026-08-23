package asset

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/custodexa/backend/internal/model"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

// ErrHostKeyChanged 指紋不符：可能的中間人攻擊，硬拒線
var ErrHostKeyChanged = errors.New("主機金鑰已變更，連線已拒絕；若主機確實重灌，請聯繫管理員重置 host key")

// HostKeyService SSH host key 的 TOFU 記錄與驗證（host-key-verification）
type HostKeyService struct {
	db *gorm.DB
}

// NewHostKeyService 建立 host key 服務
func NewHostKeyService(db *gorm.DB) *HostKeyService {
	return &HostKeyService{db: db}
}

// Callback 產生指定資產的 ssh.HostKeyCallback：
// 無記錄→TOFU 記錄；相符→放行；不符→ErrHostKeyChanged；DB 故障→fail-closed
func (s *HostKeyService) Callback(assetID uint) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fingerprint := ssh.FingerprintSHA256(key)

		var rec model.AssetHostKey
		err := s.db.Where("asset_id = ?", assetID).First(&rec).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			rec = model.AssetHostKey{
				AssetID:     assetID,
				Algorithm:   key.Type(),
				Fingerprint: fingerprint,
				PublicKey:   base64.StdEncoding.EncodeToString(key.Marshal()),
			}
			if createErr := s.db.Create(&rec).Error; createErr != nil {
				log.Printf("[HostKey] TOFU 記錄失敗: assetID=%d err=%v", assetID, createErr)
				return fmt.Errorf("host key 記錄失敗")
			}
			log.Printf("[HostKey] TOFU 首連記錄: assetID=%d %s %s", assetID, key.Type(), fingerprint)
			return nil
		}
		if err != nil {
			log.Printf("[HostKey] 查詢失敗（fail-closed）: assetID=%d err=%v", assetID, err)
			return fmt.Errorf("host key 驗證暫時不可用")
		}

		if rec.Fingerprint != fingerprint {
			log.Printf("[HostKey] 指紋不符: assetID=%d 記錄=%s 來者=%s（可能 MITM）",
				assetID, rec.Fingerprint, fingerprint)
			return ErrHostKeyChanged
		}
		return nil
	}
}

// Get 取得資產的 host key 記錄
func (s *HostKeyService) Get(assetID uint) (*model.AssetHostKey, error) {
	var rec model.AssetHostKey
	if err := s.db.Where("asset_id = ?", assetID).First(&rec).Error; err != nil {
		return nil, err
	}
	return &rec, nil
}

// Reset 刪除記錄（admin 重置；回傳是否存在）
func (s *HostKeyService) Reset(assetID uint) (bool, error) {
	result := s.db.Where("asset_id = ?", assetID).Delete(&model.AssetHostKey{})
	if result.Error != nil {
		return false, result.Error
	}
	return result.RowsAffected > 0, nil
}
