package audit

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"sync"

	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 權限狀態事件的逐列完整性驗證碼。
//
// 事件的 Digest／PrevDigest 是公開演算法算出的雜湊鏈：只持資料庫帳密的人照格式補一筆
// 事件，鏈照樣接得上。逐列 HMAC 用的是與 audit_logs 同一組完整性密鑰（同一條版本鏈、
// 同一個解封閘），沒有密鑰就算不出來；重放時驗不過的列一律視為不可信，
// 其帶來的狀態計為無來源變動（含偽造的確認事件，它不得清掉先前的無來源變動）。
//
// 不新增秘密種類，密鑰與驗證碼都不進日誌。

// permissionEventIntegrityKind 驗證碼的固定域：與審計列、工具呼叫帳本的驗證碼互不可移貼。
const permissionEventIntegrityKind = "permission_state_event_v1"

// permissionEventIntegrityPayload 驗證碼涵蓋的內容（固定 struct＝固定鍵序）。
// Digest 一律由欄位重算（涵蓋序號、種類、操作、版本、前後摘要與差集），不採信列上存的值；
// AfterBody 不在 Digest 內，另以其雜湊納入。
type permissionEventIntegrityPayload struct {
	Kind            string `json:"kind"`
	Seq             int64  `json:"seq"`
	Digest          string `json:"digest"`
	StoredDigest    string `json:"stored_digest"`
	AfterBodyDigest string `json:"after_body_digest"`
	ActivatedSeq    *int64 `json:"activated_seq"`
	KeyVersion      int    `json:"key_version"`
}

func permissionEventSignBytes(e *model.PermissionStateEvent) []byte {
	b, err := json.Marshal(permissionEventIntegrityPayload{
		Kind: permissionEventIntegrityKind, Seq: e.Seq, Digest: permissionEventDigest(e), StoredDigest: e.Digest,
		AfterBodyDigest: stateHash([]byte(e.AfterBody)), ActivatedSeq: e.ActivatedSeq, KeyVersion: e.KeyVersion,
	})
	if err != nil {
		return nil
	}
	return b
}

func computePermissionEventHMAC(key []byte, e *model.PermissionStateEvent) string {
	if len(key) == 0 {
		return ""
	}
	b := permissionEventSignBytes(e)
	if b == nil {
		return ""
	}
	m := hmac.New(sha256.New, key)
	m.Write(b)
	return hex.EncodeToString(m.Sum(nil))
}

// StampPermissionEvent 以現行完整性密鑰為事件列填驗證碼（寫入前呼叫）。
// 取不到密鑰時清空並回錯；呼叫端不擋寫入，該列在對帳時即視為不可信。
func (s *AuditIntegrityService) StampPermissionEvent(e *model.PermissionStateEvent) (err error) {
	if s == nil || s.activeFn == nil {
		return errors.New("permission event integrity unavailable")
	}
	if s.gate != nil {
		lease, e2 := s.gate.Borrow()
		if e2 != nil {
			e.IntegrityHMAC, e.KeyVersion = "", 0
			return e2
		}
		defer lease.Finish(func(valid bool) {
			if !valid {
				e.IntegrityHMAC, e.KeyVersion = "", 0
				err = errors.New("permission event key lease revoked")
			}
		})
	}
	v, key := s.activeFn()
	if s.gate != nil {
		defer material.Wipe(key)
	}
	e.KeyVersion = v
	e.IntegrityHMAC = computePermissionEventHMAC(key, e)
	if e.IntegrityHMAC == "" {
		e.KeyVersion = 0
		return errors.New("permission event integrity key unavailable")
	}
	return nil
}

// VerifyPermissionEvent 依列的 key_version 取鑰重算比對。空驗證碼、未知版本、取不到密鑰一律回 false。
func (s *AuditIntegrityService) VerifyPermissionEvent(e *model.PermissionStateEvent) (valid bool) {
	if s == nil || s.keyFn == nil || e.IntegrityHMAC == "" {
		return false
	}
	if s.gate != nil {
		lease, err := s.gate.Borrow()
		if err != nil {
			return false
		}
		defer lease.Finish(func(ok bool) {
			if !ok {
				valid = false
			}
		})
	}
	key := s.keyFn(e.KeyVersion)
	if s.gate != nil {
		defer material.Wipe(key)
	}
	want := computePermissionEventHMAC(key, e)
	return want != "" && hmac.Equal([]byte(want), []byte(e.IntegrityHMAC))
}

// permissionEventTrusted 事件列的驗證碼是否有效。完整性服務未就緒＝無法證明，視為不可信。
func permissionEventTrusted(e *model.PermissionStateEvent) bool {
	return GetAuditIntegrity().VerifyPermissionEvent(e)
}

// 段 2 之前寫入的事件（還原完成時的 restore 事件，寫在完整性服務建立之前）由同一行程記下
// 自己寫的內容，待完整性服務就緒後補章。只補「本行程寫過、內容逐位元相同、仍未蓋章」的列：
// 他人插入或改動過的列對不上記錄，維持不可信。行程在補章前結束，該列即保持不可信並告警。
const pendingPermissionStampCap = 64

var (
	pendingPermissionStampMu sync.Mutex
	pendingPermissionStamps  = map[int64][]byte{}
)

func rememberUnstampedPermissionEvent(e *model.PermissionStateEvent) {
	pendingPermissionStampMu.Lock()
	defer pendingPermissionStampMu.Unlock()
	if len(pendingPermissionStamps) >= pendingPermissionStampCap {
		return
	}
	cp := *e
	cp.KeyVersion = 0
	pendingPermissionStamps[e.Seq] = permissionEventSignBytes(&cp)
}

// stampPermissionEvent 寫入前蓋章。不擋寫入：取不到密鑰時該列留空，對帳時計為無來源變動並告警。
func stampPermissionEvent(e *model.PermissionStateEvent) {
	svc := GetAuditIntegrity()
	if svc == nil {
		e.IntegrityHMAC, e.KeyVersion = "", 0
		rememberUnstampedPermissionEvent(e)
		return
	}
	if err := svc.StampPermissionEvent(e); err != nil {
		log.Printf("[PermissionState] 事件 seq=%d 未能蓋完整性章，對帳時將視為不可信: %v", e.Seq, err)
	}
}

// StampPendingPermissionEvents 完整性服務就緒後補章（InitAuditIntegrityVersioned 內呼叫）。
// 失敗只記日誌：未補上的列維持不可信，經對帳告警，由超級管理員確認。
func StampPendingPermissionEvents(db *gorm.DB) {
	pendingPermissionStampMu.Lock()
	pending := pendingPermissionStamps
	pendingPermissionStamps = map[int64][]byte{}
	pendingPermissionStampMu.Unlock()
	if len(pending) == 0 || db == nil || !permissionEventsTableExists(db) {
		return
	}
	svc := GetAuditIntegrity()
	for seq, want := range pending {
		var row model.PermissionStateEvent
		if err := db.Where("seq = ?", seq).Limit(1).Find(&row).Error; err != nil || row.ID == 0 {
			continue
		}
		cp := row
		cp.KeyVersion = 0
		if row.IntegrityHMAC != "" || !bytes.Equal(permissionEventSignBytes(&cp), want) {
			log.Printf("[PermissionState] 事件 seq=%d 與本行程寫入的內容不同或已有驗證碼，不補章", seq)
			continue
		}
		if err := svc.StampPermissionEvent(&row); err != nil {
			log.Printf("[PermissionState] 事件 seq=%d 補章失敗，對帳時將視為不可信: %v", seq, err)
			continue
		}
		if err := db.Model(&model.PermissionStateEvent{}).Where("id = ? AND integrity_hmac = ''", row.ID).
			Updates(map[string]any{"integrity_hmac": row.IntegrityHMAC, "key_version": row.KeyVersion}).Error; err != nil {
			log.Printf("[PermissionState] 事件 seq=%d 補章寫回失敗: %v", seq, err)
		}
	}
}
