package asset

import (
	"errors"
	"fmt"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 撥號前查庫（hostIdentityVerdict）回報的停止細節。空字串＝放行。
const (
	// hostIdentityUnboundLegacy 升級前建立、沒有歷史身分，且秘密已送出或結果未知
	hostIdentityUnboundLegacy = "unbound_legacy"
	// hostIdentityTransportChanged 工作綁定的傳輸種類與資產當下有效通道不同
	hostIdentityTransportChanged = "transport_changed"
	// hostIdentityRecordMissing 該資產的主機金鑰自身列不存在
	hostIdentityRecordMissing = "record_missing"
	// hostIdentityResetPending 自身列正等待重置後的重新記錄
	hostIdentityResetPending = "reset_pending"
	// hostIdentityGenerationChanged 自身列 id 或信任世代與綁定快照不同
	hostIdentityGenerationChanged = "generation_changed"
	// hostIdentityFingerprintChanged 世代相同但指紋或演算法與快照不同（只可能是壞資料）
	hostIdentityFingerprintChanged = "fingerprint_changed"
	// hostIdentityLookupFailed 讀取自身列失敗，無從核對（fail-closed）
	hostIdentityLookupFailed = "lookup_failed"
)

// hostIdentityJob 工作列（改密候選或輪替成員）上與主機身分守衛有關的欄位。
// 欄位語義與兩種工作列的 host_key_* 欄位一致；legacy 是否已送出由呼叫端依派送證據算出。
type hostIdentityJob struct {
	AssetID    uint
	Binding    string
	Transport  string
	RecordID   uint
	Generation int64
	Pin        HostKeyPin
	// BoundAt 綁定時刻（唯讀檢視用；未綁定為 nil）
	BoundAt *time.Time
	// IsMember 輪替成員（有派送標記）；一般候選為 false
	IsMember bool
	// SecretSent 成員的派送標記 secret_sent_at 非空
	SecretSent bool
	// LegacySentOrUnknown legacy 工作的秘密已送出或結果未知：一般候選為列存在；
	// 成員為派送標記非空，或整組模式且該帳號有候選列（拆分模式只看標記）
	LegacySentOrUnknown bool
}

// hostIdentityExpected 提交前比對的預期身分：來自工作列快照，或人工承接紀錄。
type hostIdentityExpected struct {
	RecordID   uint
	Generation int64
	Pin        HostKeyPin
}

// hostIdentityJobOfCandidate 一般候選的守衛視圖：列存在即視為秘密已送出或結果未知。
func hostIdentityJobOfCandidate(c *model.ChangeSecretCandidate) hostIdentityJob {
	return hostIdentityJob{
		AssetID: c.AssetID, Binding: c.HostKeyBinding, Transport: c.HostKeyTransport,
		RecordID: c.HostKeyRecordID, Generation: c.HostKeyGeneration,
		Pin:                 HostKeyPin{Algorithm: c.HostKeyAlgorithm, Fingerprint: c.HostKeyFingerprint},
		BoundAt:             c.HostKeyBoundAt,
		LegacySentOrUnknown: true,
	}
}

// hostIdentityJobOfMember 輪替成員的守衛視圖。groupCandidateExists 為整組模式下該帳號的候選列是否存在
// （拆分模式傳 false：只看派送標記）。
func hostIdentityJobOfMember(m *model.CredentialRotationMember, groupCandidateExists bool) hostIdentityJob {
	sent := m.SecretSentAt != nil
	return hostIdentityJob{
		AssetID: m.AssetID, Binding: m.HostKeyBinding, Transport: m.HostKeyTransport,
		RecordID: m.HostKeyRecordID, Generation: m.HostKeyGeneration,
		Pin:      HostKeyPin{Algorithm: m.HostKeyAlgorithm, Fingerprint: m.HostKeyFingerprint},
		BoundAt:  m.HostKeyBoundAt,
		IsMember: true, SecretSent: sent, LegacySentOrUnknown: sent || groupCandidateExists,
	}
}

// expected 工作列自身綁定的預期身分。
func (j hostIdentityJob) expected() *hostIdentityExpected {
	return &hostIdentityExpected{RecordID: j.RecordID, Generation: j.Generation, Pin: j.Pin}
}

// rotationTransportOf 資產當下有效輪替通道對應的主機身分傳輸種類。
func rotationTransportOf(asset *model.Asset) string {
	if asset.EffectiveRotationChannel() == model.RotationChannelWindowsWinRM {
		return model.HostKeyTransportWinRM
	}
	return model.HostKeyTransportSSH
}

// hostIdentityVerdict 撥號前查庫：回空字串＝可進入撥號（含「重新首次派送」與「WinRM 無主機金鑰可比」）；
// 否則回停止細節。只讀不寫，對查詢失敗一律回 lookup_failed（fail-closed）。
func hostIdentityVerdict(db *gorm.DB, job hostIdentityJob, asset *model.Asset) string {
	switch job.Binding {
	case model.HostKeyBindingLegacy:
		if job.LegacySentOrUnknown {
			return hostIdentityUnboundLegacy
		}
		return "" // 未標記的升級前成員：照常首次派送並綁定
	case model.HostKeyBindingPending:
		return "" // 握手前中斷、未送出：以綁定回呼重新首次派送
	case model.HostKeyBindingBound:
		if job.IsMember && !job.SecretSent {
			return "" // 歷次派送都是乾淨失敗：重新首次派送
		}
	default:
		return hostIdentityUnboundLegacy // 無法辨識的綁定狀態不放行
	}

	if job.Transport != rotationTransportOf(asset) {
		return hostIdentityTransportChanged
	}
	if job.Transport == model.HostKeyTransportWinRM {
		return "" // 沒有主機金鑰可比
	}

	var own model.AssetHostKey
	if err := db.Where("asset_id = ?", asset.ID).First(&own).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return hostIdentityRecordMissing
		}
		return hostIdentityLookupFailed
	}
	if own.ResetPending {
		return hostIdentityResetPending
	}
	if own.ID != job.RecordID || own.TrustGeneration != job.Generation {
		return hostIdentityGenerationChanged
	}
	if own.Fingerprint != job.Pin.Fingerprint || own.Algorithm != job.Pin.Algorithm {
		return hostIdentityFingerprintChanged
	}
	return ""
}

// assertHostIdentityUnchangedTx 提交前同交易再比一次主機身分：呼叫端須已取得資產帳號集鎖，
// 且在取任何憑證列之前呼叫。重新取得主機金鑰信任鎖後重讀自身列，id、世代、重置旗標、指紋與演算法
// 全部等於預期才放行，否則回 ErrHostIdentityChanged（呼叫端交易回滾、候選保留）。
//
//   - transport 為 winrm 的工作沒有記錄可比，直接放行。
//   - expected 為 nil 時以工作列自身快照為預期；工作列非 bound 又沒有外部預期（承接紀錄）時，
//     狀態不一致，回 ErrHostKeyCheckFailed（fail-closed，不是身分變更）。
func assertHostIdentityUnchangedTx(tx *gorm.DB, job hostIdentityJob, expected *hostIdentityExpected) error {
	if job.Transport == model.HostKeyTransportWinRM {
		return nil
	}
	exp := expected
	if exp == nil {
		if job.Binding != model.HostKeyBindingBound {
			return ErrHostKeyCheckFailed
		}
		exp = job.expected()
	}
	if err := lockAssetHostKey(tx, job.AssetID); err != nil {
		return fmt.Errorf("%w: %v", ErrHostKeyCheckFailed, err)
	}
	var own model.AssetHostKey
	if err := tx.Where("asset_id = ?", job.AssetID).First(&own).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrHostIdentityChanged
		}
		return fmt.Errorf("%w: %v", ErrHostKeyCheckFailed, err)
	}
	if own.ResetPending || own.ID != exp.RecordID || own.TrustGeneration != exp.Generation ||
		own.Fingerprint != exp.Pin.Fingerprint || own.Algorithm != exp.Pin.Algorithm {
		return ErrHostIdentityChanged
	}
	return nil
}

// hostIdentityRecoveryReason 把撥號前查庫的停止細節對應到失權有限驗證記錄的原因碼。
// 讀取失敗沿用既有的無法判定；其餘身分類細節一律歸主機身分變更。
func hostIdentityRecoveryReason(detail string) string {
	switch detail {
	case "":
		return ""
	case hostIdentityLookupFailed:
		return model.ChangeSecretReasonAuthzUnavailable
	default:
		return model.ChangeSecretReasonHostIdentityChanged
	}
}
