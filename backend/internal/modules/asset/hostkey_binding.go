package asset

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/custodexa/backend/internal/model"
)

// HostKeyBindTarget 綁定回呼要寫入主機身分快照的工作列：一般改密候選，或輪替成員。
// 兩者擇一（另一個為 0）。
type HostKeyBindTarget struct {
	CandidateID uint
	MemberID    uint
}

// hostKeyBinder 有狀態的綁定回呼：第一次放行時把當下的主機身分寫進工作列，
// 其後同一物件的每次握手只以自己的快照做純讀比對（同一派送的重撥與立即驗證都經它）。
type hostKeyBinder struct {
	svc    *HostKeyService
	dc     HostKeyDialContext
	target HostKeyBindTarget
	base   ssh.HostKeyCallback
	result *HostKeyDialResult

	mu     sync.Mutex
	pinned ssh.HostKeyCallback // 非 nil＝已綁定，之後只做純讀比對
}

// CallbackForBinding 產生綁定回呼與結果物件。呼叫端須先確認工作列具綁定資格
// （一般候選為 pending；成員見 classifyMemberDelivery），資格為否時不得建立本回呼。
//
// 首次握手：沿用 CallbackFor 的判定與寫入分支（首次信任、沿用建列、重置後重錄、不符留痕與拒絕），
// 判定可放行之後、回 nil 之前，在主機金鑰信任鎖內的短交易重讀自身列，確認它仍等於本次握手的金鑰，
// 再條件式更新工作列為 bound 並寫入四個快照欄；任何一步失敗回 ErrHostKeyCheckFailed，
// 連線在送出任何認證之前中止。綁定成功後，本物件改為只比對自己的快照，不再寫入。
func (s *HostKeyService) CallbackForBinding(dc HostKeyDialContext, target HostKeyBindTarget) (ssh.HostKeyCallback, *HostKeyDialResult) {
	base, result := s.CallbackFor(dc)
	b := &hostKeyBinder{svc: s, dc: dc, target: target, base: base, result: result}
	return b.callback, result
}

func (b *hostKeyBinder) callback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pinned != nil {
		return b.pinned(hostname, remote, key)
	}
	if err := b.base(hostname, remote, key); err != nil {
		return err
	}
	if b.result.Mismatch() {
		// 互動路徑的不符會放行；綁定只用於背景派送，不把不符的金鑰綁成預期身分
		return ErrHostKeyCheckFailed
	}
	pin, err := b.svc.bindWorkRow(b.dc.AssetID, b.target, key)
	if err != nil {
		log.Printf("[HostKey] 綁定主機身分失敗（fail-closed）: assetID=%d err=%v", b.dc.AssetID, err)
		return ErrHostKeyCheckFailed
	}
	b.pinned = b.svc.CallbackForPinned(b.dc, pin)
	return nil
}

// bindWorkRow 在信任鎖內重讀自身列並條件式更新工作列，回傳寫入的快照。
func (s *HostKeyService) bindWorkRow(assetID uint, target HostKeyBindTarget, key ssh.PublicKey) (HostKeyPin, error) {
	pin := HostKeyPin{Algorithm: key.Type(), Fingerprint: ssh.FingerprintSHA256(key)}
	if (target.CandidateID == 0) == (target.MemberID == 0) {
		return pin, errors.New("綁定目標須恰為候選或成員其一")
	}
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := lockAssetHostKey(tx, assetID); err != nil {
			return err
		}
		q := tx.Where("asset_id = ?", assetID)
		if tx.Dialector.Name() == "postgres" {
			q = q.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		var own model.AssetHostKey
		if err := q.First(&own).Error; err != nil {
			return fmt.Errorf("讀取自身列失敗: %w", err)
		}
		if own.ResetPending || own.Algorithm != pin.Algorithm || own.Fingerprint != pin.Fingerprint {
			return errors.New("自身列已不等於本次握手的金鑰")
		}
		if s.bindTxBarrier != nil {
			s.bindTxBarrier(tx)
		}
		fields := map[string]any{
			"host_key_binding": model.HostKeyBindingBound, "host_key_transport": model.HostKeyTransportSSH,
			"host_key_record_id": own.ID, "host_key_algorithm": own.Algorithm,
			"host_key_fingerprint": own.Fingerprint, "host_key_generation": own.TrustGeneration,
			"host_key_bound_at": s.now(),
		}
		var res *gorm.DB
		if target.CandidateID != 0 {
			res = tx.Model(&model.ChangeSecretCandidate{}).
				Where("id = ? AND host_key_binding = ?", target.CandidateID, model.HostKeyBindingPending).
				Updates(fields)
		} else {
			res = tx.Model(&model.CredentialRotationMember{}).
				Where("id = ? AND "+memberBindEligibleSQL, target.MemberID).
				Updates(fields)
		}
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 1 {
			return fmt.Errorf("工作列已不具綁定資格（受影響 %d 列）", res.RowsAffected)
		}
		return nil
	})
	return pin, err
}

// BindWinRM WinRM 首次派送在 Rotate 之前的綁定：WinRM 沒有金鑰交換，只寫「自始為 WinRM」的持久證據
// （傳輸 winrm、記錄 ID 與快照欄為零值）。條件與 SSH 綁定相同：一般候選須為 pending，
// 成員須滿足 memberBindEligibleSQL；受影響列不為 1 或任何錯誤回 ErrHostKeyCheckFailed，呼叫端不得派送。
func (s *HostKeyService) BindWinRM(target HostKeyBindTarget) error {
	if (target.CandidateID == 0) == (target.MemberID == 0) {
		return ErrHostKeyCheckFailed
	}
	fields := map[string]any{
		"host_key_binding": model.HostKeyBindingBound, "host_key_transport": model.HostKeyTransportWinRM,
		"host_key_record_id": 0, "host_key_algorithm": "", "host_key_fingerprint": "",
		"host_key_generation": 0, "host_key_bound_at": s.now(),
	}
	var res *gorm.DB
	if target.CandidateID != 0 {
		res = s.db.Model(&model.ChangeSecretCandidate{}).
			Where("id = ? AND host_key_binding = ?", target.CandidateID, model.HostKeyBindingPending).
			Updates(fields)
	} else {
		res = s.db.Model(&model.CredentialRotationMember{}).
			Where("id = ? AND "+memberBindEligibleSQL, target.MemberID).
			Updates(fields)
	}
	if res.Error != nil {
		log.Printf("[HostKey] WinRM 綁定失敗（fail-closed）: err=%v", res.Error)
		return ErrHostKeyCheckFailed
	}
	if res.RowsAffected != 1 {
		log.Printf("[HostKey] WinRM 綁定失敗（fail-closed）: 受影響 %d 列", res.RowsAffected)
		return ErrHostKeyCheckFailed
	}
	return nil
}
