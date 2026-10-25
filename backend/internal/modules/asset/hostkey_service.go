package asset

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

// ErrHostKeyChanged 指紋不符且本次撥號屬背景作業（改密、改密重試、憑證輪替）：
// 留痕之後拒絕撥號，不向目標送出任何憑證或新秘密。互動路徑不符時不回這個錯誤（放行並留痕）。
var ErrHostKeyChanged = errors.New("主機金鑰與記錄不符，背景作業已拒絕撥號；請確認主機後在資產設定採用新指紋或重置主機金鑰")

// ErrHostKeyCheckFailed 主機金鑰查核失敗：讀不到記錄，或不符時審計、觀察紀錄、告警任一寫不進去。
// 連線在送出憑證之前中止（fail-closed）。
var ErrHostKeyCheckFailed = errors.New("主機金鑰查核失敗，連線已中止")

// HostKeyOutcome 一次指紋判定的結果。
type HostKeyOutcome string

const (
	// HostKeyRecorded 沒有任何可比對的記錄（或本資產已標為重置待記錄）：記錄當次指紋。
	HostKeyRecorded HostKeyOutcome = "recorded"
	// HostKeyMatched 與本資產自身記錄相符。
	HostKeyMatched HostKeyOutcome = "matched"
	// HostKeyAdopted 本資產尚無自身記錄，與同位址的既有記錄相符：複製為自身記錄。
	HostKeyAdopted HostKeyOutcome = "adopted"
	// HostKeyMismatch 與應比對的記錄不符。處置由撥號路徑決定（見 HostKeyPath）：
	// 互動路徑留痕後放行，背景路徑留痕後拒絕。
	HostKeyMismatch HostKeyOutcome = "mismatch"
)

// HostKeyRecordSource 比對所依據的記錄來源。
type HostKeyRecordSource string

const (
	HostKeyRecordOwn     HostKeyRecordSource = "own"
	HostKeyRecordAddress HostKeyRecordSource = "address"
)

// HostKeyDecision 一次指紋判定的結果與比對依據。
type HostKeyDecision struct {
	Outcome HostKeyOutcome
	// Source 比對依據的記錄來源；Recorded 時為空。
	Source HostKeyRecordSource
	// RecordedFingerprint 被比對的記錄指紋；Recorded 時為空。
	RecordedFingerprint string
	// ObservedFingerprint 本次連線取得的指紋。
	ObservedFingerprint string
}

// HostKeyPath SSH 撥號路徑。處置由服務依路徑決定，呼叫端不能另行指定：
// 互動路徑（有人在場）不符時放行並留痕；背景路徑（無人在場）不符時留痕後拒絕，
// 因為放行會把登入憑證或新秘密送到可能是冒充的主機上。
type HostKeyPath string

const (
	HostKeyPathTerminal           HostKeyPath = "terminal"
	HostKeyPathFileTransfer       HostKeyPath = "file_transfer"
	HostKeyPathConnectionTest     HostKeyPath = "connection_test"
	HostKeyPathCredentialChange   HostKeyPath = "credential_change"
	HostKeyPathCredentialRotation HostKeyPath = "credential_rotation"
	// HostKeyPathAgentTerminal 自動化代理（agent token 主體）經 MCP 開的終端會話：無人即時在場，
	// 屬背景路徑，不符時拒絕
	HostKeyPathAgentTerminal HostKeyPath = "agent_terminal"
)

// Interactive 回報此路徑不符時是否放行。未知路徑一律視為背景路徑（拒絕），不預設放行。
func (p HostKeyPath) Interactive() bool {
	switch p {
	case HostKeyPathTerminal, HostKeyPathFileTransfer, HostKeyPathConnectionTest:
		return true
	default:
		return false
	}
}

// 不符審計與告警的處置值。
const (
	hostKeyOutcomeAllowed = "allowed"
	hostKeyOutcomeRefused = "refused"
)

// HostKeyDialContext 一次 SSH 撥號的脈絡：不符時的審計、觀察紀錄與告警都由此取值。
//
// UserID／Username 是連線使用者（互動路徑為發起連線的人，背景路徑為作業發起者），由呼叫端解析後帶入；
// 系統告警要求操作者非零值，零值的脈絡在不符時會讓查核失敗、連線中止（fail-close，不補假名）。
// ConnectionRef 是連線識別：終端為會話公開識別、檔案傳輸為會話主鍵或空、
// 連線測試為空、改密與輪替為「種類:ID」。
type HostKeyDialContext struct {
	AssetID       uint
	Path          HostKeyPath
	UserID        uint
	Username      string
	AccountID     uint
	ClientIP      string
	ConnectionRef string
}

// HostKeyDialResult 撥號後可讀的判定結果：呼叫端據此得知「這次是否不符」，以便在連線建立後送出警示。
type HostKeyDialResult struct {
	mu       sync.Mutex
	mismatch bool
	decision HostKeyDecision
	// correlationID 不符留痕的關聯識別；憑證送出後的補記審計沿用
	correlationID string
	dc            HostKeyDialContext
}

func (r *HostKeyDialResult) set(dec HostKeyDecision) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.decision = dec
	r.mismatch = dec.Outcome == HostKeyMismatch
}

// 憑證曝露語義（不符審計的 credentials 欄）：放行＝回呼返回後 SSH 立刻送出登入憑證；拒絕＝未送出
const (
	hostKeyCredentialsAboutToBeSent = "about_to_be_sent"
	hostKeyCredentialsNotSent       = "not_sent"
)

// 認證結果（host_key_cred_sent 審計的 auth_result 欄）
const (
	HostKeyAuthSucceeded = "succeeded"
	HostKeyAuthFailed    = "failed"
	HostKeyAuthUnknown   = "unknown"
)

// Mismatch 本次撥號的主機金鑰是否與記錄不符（互動路徑放行後為真）。
func (r *HostKeyDialResult) Mismatch() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.mismatch
}

// Decision 本次撥號的判定（未走到回呼時為零值）。
func (r *HostKeyDialResult) Decision() HostKeyDecision {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.decision
}

// HostKeyActor 執行採用或重置的超級管理者。
type HostKeyActor struct {
	UserID   uint
	Username string
	ClientIP string
}

// HostKeyService SSH host key 的 TOFU 記錄與驗證（host-key-verification）
type HostKeyService struct {
	db *gorm.DB
	// auditSink 不符審計與採用審計的交易內落地面；alertSink 系統告警落地面。
	// **nil 即 fail-close**：不符時任一缺席都回 ErrHostKeyCheckFailed、連線中止，採用回錯。
	auditSink port.TxSink
	alertSink port.SystemAlertSink
	now       func() time.Time
	// adoptTxBarrier 測試用：在採用交易開始前呼叫（交錯測試以此模擬在途請求）
	adoptTxBarrier func()
	// evalWriteBarrier 測試用：在 Evaluate 讀完記錄、進入信任變更交易之前呼叫
	// （重置後首連與同位址沿用建列兩處），交錯測試以此讓採用或重置在此窗口提交。
	evalWriteBarrier func()
	// resetTxBarrier 測試用：在 Reset 讀完前置資料、進入信任變更交易之前呼叫
	resetTxBarrier func()
	// bindTxBarrier 測試用：在綁定交易重讀自身列之後、條件式更新工作列之前呼叫
	bindTxBarrier func(tx *gorm.DB)
}

// NewHostKeyService 建立 host key 服務
func NewHostKeyService(db *gorm.DB) *HostKeyService {
	return &HostKeyService{db: db, now: time.Now}
}

// SetAuditTxSink 注入交易內審計落地面（組裝根呼叫；必須晚於落地面建構與自檢）。
func (s *HostKeyService) SetAuditTxSink(sink port.TxSink) { s.auditSink = sink }

// SetSystemAlertSink 注入交易內系統告警落地面（組裝根呼叫；必須晚於落地面建構與自檢）。
func (s *HostKeyService) SetSystemAlertSink(sink port.SystemAlertSink) { s.alertSink = sink }

// dialAddress 由 ssh 回呼收到的 hostname（實際撥號目標，host:port）取得正規化位址；
// 解析不出時回 ok=false（此時只做本資產自身記錄的比對，不讀寫位址）。
func dialAddress(hostname string) (host string, port int, ok bool) {
	h, p, err := net.SplitHostPort(hostname)
	if err != nil {
		return "", 0, false
	}
	n, err := strconv.Atoi(p)
	if err != nil || n <= 0 {
		return "", 0, false
	}
	h = model.NormalizeHostKeyHost(h)
	if h == "" {
		return "", 0, false
	}
	return h, n, true
}

// CallbackFor 產生一次撥號的 ssh.HostKeyCallback 與結果物件。撥號位址取自 ssh 回呼的 hostname
// 參數（即實際撥號目標），與 model.Asset.HostKeyAddress 的推導同源。
//
// 回呼在 SSH 金鑰交換時執行，早於使用者認證：回呼回錯即憑證未送出，回 nil 接著就送憑證。
// 判定見 Evaluate；查核失敗一律 fail-closed（ErrHostKeyCheckFailed）。指紋不符時先在同一交易
// 寫入觀察紀錄、審計與（首次出現時的）系統告警，再依路徑放行（互動）或回 ErrHostKeyChanged（背景）；
// 留痕任一步失敗即回 ErrHostKeyCheckFailed，連線中止。
func (s *HostKeyService) CallbackFor(dc HostKeyDialContext) (ssh.HostKeyCallback, *HostKeyDialResult) {
	result := &HostKeyDialResult{}
	cb := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		host, port, _ := dialAddress(hostname)
		dec, err := s.Evaluate(dc.AssetID, host, port, key)
		if err != nil {
			log.Printf("[HostKey] 判定失敗（fail-closed）: assetID=%d path=%s err=%v", dc.AssetID, dc.Path, err)
			return ErrHostKeyCheckFailed
		}
		switch dec.Outcome {
		case HostKeyMismatch:
			allowed := dc.Path.Interactive()
			corr, err := s.traceMismatch(dc, host, port, key, dec, allowed)
			if err != nil {
				log.Printf("[HostKey] 不符留痕失敗（fail-closed）: assetID=%d path=%s err=%v", dc.AssetID, dc.Path, err)
				if failure := audit.GetAuditFailure(); failure != nil {
					failure.Report(model.MechanismAuditWrite, model.CauseHostKeyMismatchRecordFailed, map[string]string{
						"asset_id": strconv.FormatUint(uint64(dc.AssetID), 10),
						"path":     string(dc.Path),
					})
				}
				return ErrHostKeyCheckFailed
			}
			result.set(dec)
			result.mu.Lock()
			result.correlationID, result.dc = corr, dc
			result.mu.Unlock()
			log.Printf("[HostKey] 指紋不符: assetID=%d path=%s 來源=%s 記錄=%s 來者=%s 放行=%v",
				dc.AssetID, dc.Path, dec.Source, dec.RecordedFingerprint, dec.ObservedFingerprint, allowed)
			if allowed {
				return nil
			}
			return ErrHostKeyChanged
		case HostKeyRecorded:
			log.Printf("[HostKey] TOFU 記錄: assetID=%d %s %s", dc.AssetID, key.Type(), dec.ObservedFingerprint)
		case HostKeyAdopted:
			log.Printf("[HostKey] 沿用同位址既有指紋: assetID=%d %s", dc.AssetID, dec.ObservedFingerprint)
		}
		result.set(dec)
		return nil
	}
	return cb, result
}

// ErrHostIdentityChanged 背景作業握手時的實際金鑰與工作列綁定的主機身分不同，但並非真正的指紋不符
// （例如管理員已採用新指紋、記錄已被重置）：撥號在送出任何憑證之前中止，不寫不符觀察，不改寫記錄。
var ErrHostIdentityChanged = errors.New("主機身分已變更，背景作業已拒絕撥號")

// HostKeyPin 工作列綁定的主機金鑰快照：演算法與 SHA256 指紋。
type HostKeyPin struct {
	Algorithm   string
	Fingerprint string
}

// classifyHostKey 純讀分類：只讀自身列與同位址記錄，不寫入任何東西。port 為 0 表示位址未知。
// 回傳的記錄是判定所依據的列：Source 為 own 時是自身列（可能 ResetPending），為 address 時是同位址記錄，
// 首次信任時為 nil。次序：
//  1. 自身列標為重置待記錄 → Outcome=Recorded、記錄為該自身列（由寫入分支記錄當次指紋）。
//  2. 自身列有指紋 → 相符 Matched、不符 Mismatch（Source=own）。
//  3. 無自身列 → 同位址最近一筆可比對的記錄（依更新時間與 ID 由新到舊）：相符 Adopted、不符 Mismatch（Source=address）。
//  4. 同位址也無記錄 → Outcome=Recorded、記錄為 nil（首次信任）。
//
// error 非 nil 時回傳的 decision 無效，呼叫端不得依其 Outcome 判定，一律視為查核失敗。
func (s *HostKeyService) classifyHostKey(assetID uint, host string, port int, key ssh.PublicKey) (HostKeyDecision, *model.AssetHostKey, error) {
	fp := ssh.FingerprintSHA256(key)
	dec := HostKeyDecision{ObservedFingerprint: fp}
	haveAddr := host != "" && port > 0

	var own model.AssetHostKey
	err := s.db.Where("asset_id = ?", assetID).First(&own).Error
	switch {
	case err == nil:
		if own.ResetPending {
			dec.Outcome = HostKeyRecorded
			return dec, &own, nil
		}
		dec.Source, dec.RecordedFingerprint = HostKeyRecordOwn, own.Fingerprint
		if own.Fingerprint != fp {
			dec.Outcome = HostKeyMismatch
		} else {
			dec.Outcome = HostKeyMatched
		}
		return dec, &own, nil
	case !errors.Is(err, gorm.ErrRecordNotFound):
		return dec, nil, fmt.Errorf("host key 查詢失敗: %w", err)
	}

	if haveAddr {
		var addr model.AssetHostKey
		aerr := s.db.Where("host = ? AND port = ? AND reset_pending = ? AND fingerprint <> ?", host, port, false, "").
			Order("updated_at DESC, id DESC").First(&addr).Error
		switch {
		case aerr == nil:
			dec.Source, dec.RecordedFingerprint = HostKeyRecordAddress, addr.Fingerprint
			if addr.Fingerprint != fp {
				dec.Outcome = HostKeyMismatch
			} else {
				dec.Outcome = HostKeyAdopted
			}
			return dec, &addr, nil
		case !errors.Is(aerr, gorm.ErrRecordNotFound):
			return dec, nil, fmt.Errorf("host key 位址查詢失敗: %w", aerr)
		}
	}
	dec.Outcome = HostKeyRecorded
	return dec, nil, nil
}

// CallbackForPinned 產生以工作列快照（pin）為預期身分的 ssh.HostKeyCallback：只分類、不寫入、不開交易
// （不符留痕除外，它自開交易）。實際金鑰等於 pin 即放行；不等時以 classifyHostKey 讀當下記錄：
//   - 與當下自身記錄相符（遠端已是新身分）、自身列缺、重置待記錄：ErrHostIdentityChanged，
//     不寫不符觀察、不告警、不改寫記錄、不 TOFU；
//   - 與當下自身記錄也不符：走既有不符留痕並拒絕（ErrHostKeyChanged）；
//   - 讀取失敗，或判定為同位址沿用／首次信任：ErrHostKeyCheckFailed 或 ErrHostIdentityChanged，一律拒絕不建列。
func (s *HostKeyService) CallbackForPinned(dc HostKeyDialContext, pin HostKeyPin) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if key.Type() == pin.Algorithm && ssh.FingerprintSHA256(key) == pin.Fingerprint {
			return nil
		}
		host, port, _ := dialAddress(hostname)
		dec, rec, err := s.classifyHostKey(dc.AssetID, host, port, key)
		if err != nil {
			log.Printf("[HostKey] 判定失敗（fail-closed）: assetID=%d path=%s err=%v", dc.AssetID, dc.Path, err)
			return ErrHostKeyCheckFailed
		}
		if dec.Source != HostKeyRecordOwn || rec == nil || rec.ResetPending || dec.Outcome != HostKeyMismatch {
			return ErrHostIdentityChanged
		}
		if _, err := s.traceMismatch(dc, host, port, key, dec, false); err != nil {
			log.Printf("[HostKey] 不符留痕失敗（fail-closed）: assetID=%d path=%s err=%v", dc.AssetID, dc.Path, err)
			if failure := audit.GetAuditFailure(); failure != nil {
				failure.Report(model.MechanismAuditWrite, model.CauseHostKeyMismatchRecordFailed, map[string]string{
					"asset_id": strconv.FormatUint(uint64(dc.AssetID), 10),
					"path":     string(dc.Path),
				})
			}
			return ErrHostKeyCheckFailed
		}
		return ErrHostKeyChanged
	}
}

// Evaluate 依撥號位址與觀察到的金鑰判定，並做對應的記錄寫入。port 為 0 表示位址未知。
// 判定本身是純讀的 classifyHostKey（次序見該函式）；本函式只負責其後的寫入分支：
// 重置待記錄 → recordAfterReset；自身列相符而位址不同或未記 → 更新為目前位址；
// 同位址相符 → 複製為自身列；首次信任 → 建列。
//
// 不符的處置（放行或拒絕）與留痕不在本函式；查詢或寫入失敗回 error，呼叫端一律拒線（fail-closed）。
// error 非 nil 時回傳的 decision 無效，呼叫端不得依其 Outcome 判定。
func (s *HostKeyService) Evaluate(assetID uint, host string, port int, key ssh.PublicKey) (HostKeyDecision, error) {
	dec, rec, err := s.classifyHostKey(assetID, host, port, key)
	if err != nil {
		return dec, err
	}
	haveAddr := host != "" && port > 0
	switch dec.Outcome {
	case HostKeyMismatch:
		return dec, nil
	case HostKeyMatched:
		if haveAddr && (rec.Host != host || rec.Port != port) {
			if updErr := s.db.Model(&model.AssetHostKey{}).Where("id = ?", rec.ID).
				Updates(map[string]any{"host": host, "port": port}).Error; updErr != nil {
				return dec, fmt.Errorf("host key 位址更新失敗: %w", updErr)
			}
		}
		return dec, nil
	case HostKeyAdopted:
		if s.evalWriteBarrier != nil {
			s.evalWriteBarrier()
		}
		raced := false
		if txErr := s.db.Transaction(func(tx *gorm.DB) error {
			if err := lockAssetHostKey(tx, assetID); err != nil {
				return err
			}
			var cnt int64
			if err := tx.Model(&model.AssetHostKey{}).Where("asset_id = ?", assetID).Count(&cnt).Error; err != nil {
				return err
			}
			if cnt > 0 {
				raced = true // 鎖等待期間他人已建立自身列：放棄建列，依當下狀態重新分類
				return nil
			}
			adopted := model.AssetHostKey{
				AssetID: assetID, Algorithm: rec.Algorithm, Fingerprint: rec.Fingerprint,
				PublicKey: rec.PublicKey, Host: host, Port: port, TrustGeneration: 1,
			}
			return tx.Create(&adopted).Error
		}); txErr != nil {
			return dec, fmt.Errorf("host key 沿用記錄失敗: %w", txErr)
		}
		if raced {
			return s.Evaluate(assetID, host, port, key)
		}
		return dec, nil
	}

	// HostKeyRecorded：重置待記錄（記錄為自身列）或首次信任（記錄為 nil）
	if rec != nil {
		return s.recordAfterReset(assetID, host, port, key, dec)
	}
	newRec := model.AssetHostKey{
		AssetID:         assetID,
		Algorithm:       key.Type(),
		Fingerprint:     dec.ObservedFingerprint,
		PublicKey:       base64.StdEncoding.EncodeToString(key.Marshal()),
		TrustGeneration: 1,
	}
	if haveAddr {
		newRec.Host, newRec.Port = host, port
	}
	if createErr := s.db.Create(&newRec).Error; createErr != nil {
		return dec, fmt.Errorf("host key 記錄失敗: %w", createErr)
	}
	return dec, nil
}

// errHostKeyStateMoved 鎖內重讀發現記錄狀態已被他人改變，呼叫端須依當下狀態重新分類。
var errHostKeyStateMoved = errors.New("host key 記錄狀態已改變")

// recordAfterReset 重置後首連的記錄寫入：取得資產級鎖後重讀自身列，仍為重置待記錄才以欄位更新寫入；
// 指紋或演算法改變時世代在同一個 UPDATE 內加一，同一把金鑰重新記錄不推進。
// 重讀發現採用已清除旗標（或列已不存在）時不寫入，改依當下狀態重新分類，不用鎖前讀到的內容覆寫。
func (s *HostKeyService) recordAfterReset(assetID uint, host string, port int, key ssh.PublicKey,
	dec HostKeyDecision) (HostKeyDecision, error) {
	fp := dec.ObservedFingerprint
	haveAddr := host != "" && port > 0
	if s.evalWriteBarrier != nil {
		s.evalWriteBarrier()
	}
	txErr := s.db.Transaction(func(tx *gorm.DB) error {
		if err := lockAssetHostKey(tx, assetID); err != nil {
			return err
		}
		var cur model.AssetHostKey
		if err := tx.Where("asset_id = ?", assetID).First(&cur).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return errHostKeyStateMoved
			}
			return fmt.Errorf("host key 查詢失敗: %w", err)
		}
		if !cur.ResetPending {
			return errHostKeyStateMoved
		}
		changes := map[string]any{
			"algorithm":     key.Type(),
			"fingerprint":   fp,
			"public_key":    base64.StdEncoding.EncodeToString(key.Marshal()),
			"reset_pending": false,
		}
		if haveAddr {
			changes["host"], changes["port"] = host, port
		}
		if cur.Fingerprint != fp || cur.Algorithm != key.Type() {
			changes["trust_generation"] = gorm.Expr("trust_generation + 1")
		}
		res := tx.Model(&model.AssetHostKey{}).Where("id = ? AND reset_pending = ?", cur.ID, true).Updates(changes)
		if res.Error != nil {
			return fmt.Errorf("host key 重置後記錄失敗: %w", res.Error)
		}
		if res.RowsAffected != 1 {
			return errHostKeyStateMoved
		}
		return clearHostKeyObservations(tx, assetID)
	})
	if errors.Is(txErr, errHostKeyStateMoved) {
		return s.Evaluate(assetID, host, port, key)
	}
	if txErr != nil {
		return dec, txErr
	}
	dec.Outcome = HostKeyRecorded
	return dec, nil
}

// hostKeyLockNamespace 資產信任變更的交易級諮詢鎖命名空間（PG pg_advisory_xact_lock 的高位 key）
const hostKeyLockNamespace = 0x484B // "HK"

// lockAssetHostKey 對同一資產的信任變更（採用、重置、重置後首連）取交易級鎖，交易結束自動釋放。
// PostgreSQL 以諮詢鎖實作（自身列可能尚不存在，列鎖鎖不住「無列」的情形）；SQLite 的寫入本就單一寫者序列化。
func lockAssetHostKey(tx *gorm.DB, assetID uint) error {
	if tx.Dialector.Name() != "postgres" {
		return nil
	}
	if err := tx.Exec("SELECT pg_advisory_xact_lock(?, ?)", hostKeyLockNamespace, int64(assetID)).Error; err != nil {
		return fmt.Errorf("取得主機金鑰信任變更鎖失敗: %w", err)
	}
	return nil
}

// clearHostKeyObservations 刪除資產的全部觀察紀錄（採用或重新記錄時，與記錄改寫同交易）。
func clearHostKeyObservations(tx *gorm.DB, assetID uint) error {
	if err := tx.Where("asset_id = ?", assetID).Delete(&model.AssetHostKeyMismatch{}).Error; err != nil {
		return fmt.Errorf("清除主機金鑰觀察紀錄失敗: %w", err)
	}
	return nil
}

// hostKeyMismatchDetails 不符審計列的 details（不含任何秘密；指紋與演算法是主機的公開身分）。
type hostKeyMismatchDetails struct {
	RecordedFingerprint string `json:"recorded_fingerprint"`
	ObservedFingerprint string `json:"observed_fingerprint"`
	ObservedAlgorithm   string `json:"observed_algorithm"`
	RecordSource        string `json:"record_source"`
	Host                string `json:"host"`
	Port                int    `json:"port"`
	Path                string `json:"path"`
	Outcome             string `json:"outcome"`
	Credentials         string `json:"credentials"`
	AccountID           uint   `json:"account_id"`
	ConnectionRef       string `json:"connection_ref,omitempty"`
	CorrelationID       string `json:"correlation_id"`
}

// hostKeyCredSentDetails 憑證實際送出後的補記審計 details。
type hostKeyCredSentDetails struct {
	Path                string `json:"path"`
	AuthResult          string `json:"auth_result"`
	ObservedFingerprint string `json:"observed_fingerprint"`
	RecordedFingerprint string `json:"recorded_fingerprint"`
	AccountID           uint   `json:"account_id"`
	ConnectionRef       string `json:"connection_ref,omitempty"`
	CorrelationID       string `json:"correlation_id"`
}

// RecordCredentialSent 不符放行且撥號已越過主機金鑰回呼之後補記：登入憑證已實際送到該主機，
// 以及認證結果（成功、失敗、未知）。與不符審計同 correlation_id。
//
// 寫在自己的交易內：這時憑證已經送出，留痕失敗無法再保護任何東西，所以不中止連線；
// 失敗寫日誌並上報審計失效事件，不靜默。未發生不符（或被拒絕）時不寫。
func (s *HostKeyService) RecordCredentialSent(res *HostKeyDialResult, authResult string) {
	if res == nil || !res.Mismatch() {
		return
	}
	res.mu.Lock()
	dc, dec, corr := res.dc, res.decision, res.correlationID
	res.mu.Unlock()
	if !dc.Path.Interactive() {
		return
	}
	details, err := json.Marshal(hostKeyCredSentDetails{
		Path: string(dc.Path), AuthResult: authResult,
		ObservedFingerprint: dec.ObservedFingerprint, RecordedFingerprint: dec.RecordedFingerprint,
		AccountID: dc.AccountID, ConnectionRef: dc.ConnectionRef, CorrelationID: corr,
	})
	if err != nil {
		log.Printf("[HostKey] 序列化憑證送出審計失敗: %v", err)
		return
	}
	assetID := dc.AssetID
	txErr := s.db.Transaction(func(tx *gorm.DB) error {
		return port.WriteInTx(s.auditSink, tx, gatewayapi.AuditEvent{
			OccurredAt: s.now(),
			Actor:      gatewayapi.Actor{UserID: dc.UserID, Username: dc.Username},
			Action:     string(model.ActionHostKeyCredSent),
			Resource:   string(model.ResourceAsset),
			ResourceID: &assetID,
			Status:     string(model.StatusSuccess),
			AssetID:    &assetID,
			Request:    gatewayapi.RequestMeta{ClientIP: dc.ClientIP},
			Details:    string(details),
		})
	})
	if txErr != nil {
		log.Printf("[HostKey] 憑證送出審計寫入失敗: assetID=%d path=%s err=%v", assetID, dc.Path, txErr)
		if failure := audit.GetAuditFailure(); failure != nil {
			failure.Report(model.MechanismAuditWrite, model.CauseHostKeyMismatchRecordFailed, map[string]string{
				"asset_id": strconv.FormatUint(uint64(assetID), 10),
				"path":     string(dc.Path),
				"stage":    "credentials_sent",
			})
		}
	}
}

// traceMismatch 在同一交易內寫入觀察紀錄、不符審計與（需要時的）系統告警。
//
// 告警條件：此指紋第一次出現（觀察列是這次新建的），或處置為放行且這次是此觀察第一次寫入
// first_allowed_at（此指紋先前只在背景路徑被拒絕過，登入憑證這時才第一次送出）。
// 同一指紋的併發首次出現由（資產、指紋）唯一索引決定由誰新建；first_allowed_at 以「為空才寫入」
// 的條件更新，影響列數為 1 的那條發告警。任一步失敗整筆回滾，呼叫端回 ErrHostKeyCheckFailed。
func (s *HostKeyService) traceMismatch(dc HostKeyDialContext, host string, dialPort int, key ssh.PublicKey,
	dec HostKeyDecision, allowed bool) (string, error) {
	outcome, credentials := hostKeyOutcomeRefused, hostKeyCredentialsNotSent
	if allowed {
		outcome, credentials = hostKeyOutcomeAllowed, hostKeyCredentialsAboutToBeSent
	}
	corr, err := newAssetCorrelationID()
	if err != nil {
		return "", err
	}
	now := s.now()
	return corr, s.db.Transaction(func(tx *gorm.DB) error {
		created, firstAllowed, err := upsertHostKeyObservation(tx, dc.AssetID, host, dialPort, key, dec, allowed, now)
		if err != nil {
			return err
		}
		details, err := json.Marshal(hostKeyMismatchDetails{
			RecordedFingerprint: dec.RecordedFingerprint, ObservedFingerprint: dec.ObservedFingerprint,
			ObservedAlgorithm: key.Type(), RecordSource: string(dec.Source), Host: host, Port: dialPort,
			Path: string(dc.Path), Outcome: outcome, Credentials: credentials, AccountID: dc.AccountID,
			ConnectionRef: dc.ConnectionRef, CorrelationID: corr,
		})
		if err != nil {
			return fmt.Errorf("序列化主機金鑰不符審計失敗: %w", err)
		}
		assetID := dc.AssetID
		if err := port.WriteInTx(s.auditSink, tx, gatewayapi.AuditEvent{
			OccurredAt: now,
			Actor:      gatewayapi.Actor{UserID: dc.UserID, Username: dc.Username},
			Action:     string(model.ActionHostKeyMismatch),
			Resource:   string(model.ResourceAsset),
			ResourceID: &assetID,
			Status:     string(model.StatusSuccess),
			AssetID:    &assetID,
			Request:    gatewayapi.RequestMeta{ClientIP: dc.ClientIP},
			Details:    string(details),
		}); err != nil {
			return fmt.Errorf("寫入主機金鑰不符審計失敗: %w", err)
		}
		if !created && !firstAllowed {
			return nil
		}
		params := map[string]string{
			"path":                 string(dc.Path),
			"outcome":              outcome,
			"record_source":        string(dec.Source),
			"recorded_fingerprint": dec.RecordedFingerprint,
			"observed_fingerprint": dec.ObservedFingerprint,
			"observed_algorithm":   key.Type(),
		}
		if dc.ConnectionRef != "" {
			params["connection_ref"] = dc.ConnectionRef
		}
		if _, err := port.RaiseInTx(s.alertSink, tx, port.SystemAlertEvent{
			Type:          port.SystemAlertHostKeyMismatch,
			Actor:         port.SystemAlertActor{UserID: dc.UserID, Username: dc.Username},
			ClientIP:      dc.ClientIP,
			OccurredAt:    now,
			Target:        port.SystemAlertTarget{Kind: port.SystemAlertTargetAsset, ID: strconv.FormatUint(uint64(assetID), 10)},
			AssetID:       &assetID,
			CorrelationID: corr,
			Params:        params,
		}); err != nil {
			return fmt.Errorf("產生主機金鑰不符系統告警失敗: %w", err)
		}
		return nil
	})
}

// upsertHostKeyObservation 以（資產、出示指紋）為鍵寫入或累計觀察紀錄。
// 回傳 created（這次新建）與 firstAllowed（這次第一次寫入 first_allowed_at）。
func upsertHostKeyObservation(tx *gorm.DB, assetID uint, host string, dialPort int, key ssh.PublicKey,
	dec HostKeyDecision, allowed bool, now time.Time) (created, firstAllowed bool, err error) {
	bump := func() (int64, error) {
		res := tx.Model(&model.AssetHostKeyMismatch{}).
			Where("asset_id = ? AND observed_fingerprint = ?", assetID, dec.ObservedFingerprint).
			Updates(map[string]any{"last_seen_at": now, "seen_count": gorm.Expr("seen_count + 1")})
		return res.RowsAffected, res.Error
	}
	n, err := bump()
	if err != nil {
		return false, false, fmt.Errorf("累計主機金鑰觀察紀錄失敗: %w", err)
	}
	if n == 0 {
		row := model.AssetHostKeyMismatch{
			AssetID: assetID, Host: host, Port: dialPort,
			RecordedFingerprint: dec.RecordedFingerprint,
			ObservedAlgorithm:   key.Type(), ObservedFingerprint: dec.ObservedFingerprint,
			ObservedPublicKey: base64.StdEncoding.EncodeToString(key.Marshal()),
			FirstSeenAt:       now, LastSeenAt: now, SeenCount: 1,
		}
		if allowed {
			t := now
			row.FirstAllowedAt = &t
		}
		if cerr := tx.Create(&row).Error; cerr == nil {
			return true, allowed, nil
		}
		// 新建失敗：多半是同一指紋的另一條連線剛搶先新建（唯一索引）；再累計一次，仍為 0 列才算失敗
		n, err = bump()
		if err != nil || n == 0 {
			return false, false, fmt.Errorf("寫入主機金鑰觀察紀錄失敗: 新建被唯一索引拒絕後累計仍無列（err=%v）", err)
		}
	}
	if !allowed {
		return false, false, nil
	}
	res := tx.Model(&model.AssetHostKeyMismatch{}).
		Where("asset_id = ? AND observed_fingerprint = ? AND first_allowed_at IS NULL", assetID, dec.ObservedFingerprint).
		Update("first_allowed_at", now)
	if res.Error != nil {
		return false, false, fmt.Errorf("寫入主機金鑰觀察首次放行時刻失敗: %w", res.Error)
	}
	return false, res.RowsAffected == 1, nil
}

// Observations 資產尚未確認的不符指紋（最近出現者在前），最多 limit 筆；limit 不大於 0 時不設上限。
func (s *HostKeyService) Observations(assetID uint, limit int) ([]model.AssetHostKeyMismatch, error) {
	var rows []model.AssetHostKeyMismatch
	q := s.db.Where("asset_id = ?", assetID).Order("last_seen_at DESC, id DESC")
	if limit > 0 {
		q = q.Limit(limit)
	}
	if err := q.Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("查詢主機金鑰觀察紀錄失敗: %w", err)
	}
	return rows, nil
}

// assetAddress 讀取資產的 SSH 撥號位址；資產不存在或沒有 SSH 撥號回 ok=false。
func (s *HostKeyService) assetAddress(assetID uint) (host string, port int, ok bool) {
	var a model.Asset
	if err := s.db.Where("id = ?", assetID).First(&a).Error; err != nil {
		return "", 0, false
	}
	return a.HostKeyAddress()
}

// addressRecord 同位址最近一筆可沿用的記錄（排除重置待記錄與無指紋者）。
func (s *HostKeyService) addressRecord(host string, port int) (*model.AssetHostKey, error) {
	var rec model.AssetHostKey
	err := s.db.Where("host = ? AND port = ? AND reset_pending = ? AND fingerprint <> ?", host, port, false, "").
		Order("updated_at DESC, id DESC").First(&rec).Error
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

// LookupAddress 依撥號位址取最近一筆可比對的記錄（含公鑰本體），供不經平台撥號的通道
// （VNC 檔案傳輸側車）把已記錄的主機金鑰交給外部元件驗證。只讀，不記錄、不做首次信任；
// 無記錄回 gorm.ErrRecordNotFound。
func (s *HostKeyService) LookupAddress(host string, port int) (*model.AssetHostKey, error) {
	h := model.NormalizeHostKeyHost(host)
	if h == "" || port <= 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return s.addressRecord(h, port)
}

// Get 取得資產的 host key 記錄：自身列有指紋照舊回傳；本資產已標為重置待記錄視同無記錄；
// 無自身列時回傳可沿用的同位址記錄（Inherited 為真、ID 為 0、AssetID 為被查資產）；皆無回 gorm.ErrRecordNotFound。
func (s *HostKeyService) Get(assetID uint) (*model.AssetHostKey, error) {
	var rec model.AssetHostKey
	err := s.db.Where("asset_id = ?", assetID).First(&rec).Error
	if err == nil {
		if rec.ResetPending {
			return nil, gorm.ErrRecordNotFound
		}
		return &rec, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	host, port, ok := s.assetAddress(assetID)
	if !ok {
		return nil, gorm.ErrRecordNotFound
	}
	src, err := s.addressRecord(host, port)
	if err != nil {
		return nil, err
	}
	return &model.AssetHostKey{
		AssetID: assetID, Algorithm: src.Algorithm, Fingerprint: src.Fingerprint,
		CreatedAt: src.CreatedAt, UpdatedAt: src.UpdatedAt, Inherited: true,
	}, nil
}

// 採用與重置告警的 previous_fingerprint／adopted_fingerprint 佔位值。
const (
	hostKeyFingerprintNone         = "none"
	hostKeyFingerprintResetPending = "reset_pending"
)

// raiseRecordChanged 在 tx 內產生 host_key_record_changed 系統告警（採用與重置共用）。
func (s *HostKeyService) raiseRecordChanged(tx *gorm.DB, assetID uint, actor HostKeyActor,
	change, previous, adopted, correlationID string) error {
	id := assetID
	_, err := port.RaiseInTx(s.alertSink, tx, port.SystemAlertEvent{
		Type:          port.SystemAlertHostKeyRecordChanged,
		Actor:         port.SystemAlertActor{UserID: actor.UserID, Username: actor.Username},
		ClientIP:      actor.ClientIP,
		OccurredAt:    s.now(),
		Target:        port.SystemAlertTarget{Kind: port.SystemAlertTargetAsset, ID: strconv.FormatUint(uint64(id), 10)},
		AssetID:       &id,
		CorrelationID: correlationID,
		Params: map[string]string{
			"change":               change,
			"previous_fingerprint": previous,
			"adopted_fingerprint":  adopted,
		},
	})
	if err != nil {
		return fmt.Errorf("產生主機金鑰記錄變更系統告警失敗: %w", err)
	}
	return nil
}

// HostKeyResetResult 重置的服務層結果：是否有可重置的記錄，與生效時世代的前後值
// （無自身列、新建自身列時前值為 0）。世代不進一般 API 回應，也不新增審計類型。
type HostKeyResetResult struct {
	Reset            bool
	GenerationBefore int64
	GenerationAfter  int64
}

// Reset 將本資產標為重置待記錄（超管保留操作；回傳是否有可重置的記錄）。世代前後值見 MarkResetWithGeneration。
func (s *HostKeyService) Reset(assetID uint, actor HostKeyActor) (bool, error) {
	res, err := s.MarkResetWithGeneration(assetID, actor)
	return res.Reset, err
}

// MarkResetWithGeneration 將本資產標為重置待記錄，並回傳信任世代的前後值。
//
//   - 自身列有指紋 → 標記重置待記錄並使世代加一（不刪列、不動他人或已刪資產的列）。
//   - 無自身列但資產撥號位址有可沿用的記錄 → 新建世代為 1 的自身列並標記重置待記錄。
//   - 兩者皆無，或本資產已是重置待記錄 → Reset 為 false（無可重置，不改任何東西、不發告警、世代不變）。
//
// 重置只影響本資產：位址記錄仍可供日後重建的資產沿用。生效的重置與一則
// host_key_record_changed 系統告警（change=reset）同交易；告警寫不進去，重置不生效。
// 取得資產級鎖之後才重讀自身列並判定，不使用鎖前讀到的內容。
func (s *HostKeyService) MarkResetWithGeneration(assetID uint, actor HostKeyActor) (HostKeyResetResult, error) {
	var out HostKeyResetResult
	var srcHost string
	var srcPort int
	var src *model.AssetHostKey
	var pre model.AssetHostKey
	err := s.db.Where("asset_id = ?", assetID).First(&pre).Error
	switch {
	case err == nil:
		if pre.ResetPending {
			return out, nil
		}
	case errors.Is(err, gorm.ErrRecordNotFound):
		host, port, ok := s.assetAddress(assetID)
		if !ok {
			return out, nil
		}
		rec, aerr := s.addressRecord(host, port)
		if errors.Is(aerr, gorm.ErrRecordNotFound) {
			return out, nil
		}
		if aerr != nil {
			return out, aerr
		}
		srcHost, srcPort, src = host, port, rec
	default:
		return out, err
	}
	corr, err := newAssetCorrelationID()
	if err != nil {
		return out, err
	}
	if s.resetTxBarrier != nil {
		s.resetTxBarrier()
	}
	txErr := s.db.Transaction(func(tx *gorm.DB) error {
		out = HostKeyResetResult{}
		if err := lockAssetHostKey(tx, assetID); err != nil {
			return err
		}
		var own model.AssetHostKey
		oerr := tx.Where("asset_id = ?", assetID).First(&own).Error
		switch {
		case oerr == nil:
			if own.ResetPending {
				return nil
			}
			res := tx.Model(&model.AssetHostKey{}).Where("id = ? AND reset_pending = ?", own.ID, false).
				Updates(map[string]any{"reset_pending": true, "trust_generation": gorm.Expr("trust_generation + 1")})
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected != 1 {
				return nil
			}
			var after model.AssetHostKey
			if err := tx.Where("id = ?", own.ID).First(&after).Error; err != nil {
				return err
			}
			out = HostKeyResetResult{Reset: true, GenerationBefore: own.TrustGeneration, GenerationAfter: after.TrustGeneration}
			return s.raiseRecordChanged(tx, assetID, actor, "reset", own.Fingerprint, hostKeyFingerprintNone, corr)
		case errors.Is(oerr, gorm.ErrRecordNotFound):
			if src == nil {
				return nil // 鎖前有自身列、鎖內已不存在：無可重置
			}
			pending := model.AssetHostKey{
				AssetID: assetID, Algorithm: src.Algorithm, Fingerprint: src.Fingerprint, PublicKey: src.PublicKey,
				Host: srcHost, Port: srcPort, ResetPending: true, TrustGeneration: 1,
			}
			if err := tx.Create(&pending).Error; err != nil {
				return err
			}
			out = HostKeyResetResult{Reset: true, GenerationBefore: 0, GenerationAfter: 1}
			return s.raiseRecordChanged(tx, assetID, actor, "reset", src.Fingerprint, hostKeyFingerprintNone, corr)
		default:
			return oerr
		}
	})
	if txErr != nil {
		return HostKeyResetResult{}, txErr
	}
	return out, nil
}

// ErrHostKeyObservationNotFound 要採用的指紋不在該資產的觀察紀錄中。
var ErrHostKeyObservationNotFound = errors.New("這個指紋不在待確認清單中")

// hostKeyAdoptDetails 採用審計列的 details。
type hostKeyAdoptDetails struct {
	PreviousFingerprint string `json:"previous_fingerprint"`
	PreviousAlgorithm   string `json:"previous_algorithm"`
	AdoptedFingerprint  string `json:"adopted_fingerprint"`
	AdoptedAlgorithm    string `json:"adopted_algorithm"`
	FirstSeenAt         string `json:"first_seen_at"`
	LastSeenAt          string `json:"last_seen_at"`
	SeenCount           int    `json:"seen_count"`
	EverAllowed         bool   `json:"ever_allowed"`
	Host                string `json:"host"`
	Port                int    `json:"port"`
	CorrelationID       string `json:"correlation_id"`
	// TrustGenerationBefore／After 採用前後的信任世代；新建自身記錄時前值為 0
	TrustGenerationBefore int64 `json:"trust_generation_before"`
	TrustGenerationAfter  int64 `json:"trust_generation_after"`
}

// Adopt 把資產觀察紀錄中的一個指紋採用為自身記錄（超管保留操作）。
//
// 同一交易內：以觀察的演算法、指紋、公鑰與撥號位址 upsert 自身記錄並清除重置待記錄旗標；
// 刪除該資產全部觀察紀錄；寫採用審計；產生 host_key_record_changed 告警（change=adopted）。
// 指紋不在觀察紀錄中回 ErrHostKeyObservationNotFound 且不寫任何東西；任一步失敗整筆回滾。
// 只影響本資產，不改寫其他資產或已刪除資產留下的同位址記錄。
func (s *HostKeyService) Adopt(assetID uint, fingerprint string, actor HostKeyActor) (*model.AssetHostKey, error) {
	corr, err := newAssetCorrelationID()
	if err != nil {
		return nil, err
	}
	if s.adoptTxBarrier != nil {
		s.adoptTxBarrier()
	}
	now := s.now()
	var adopted model.AssetHostKey
	txErr := s.db.Transaction(func(tx *gorm.DB) error {
		// 同一資產的信任變更（採用、重置、重置後首連）序列化：先取資產級鎖，再讀觀察列並原子消耗。
		// 在途或並行的採用請求若在另一次採用／重置提交之後才進來，這裡讀不到該觀察列，回查無，
		// 不會把已失效的指紋寫回信任
		if err := lockAssetHostKey(tx, assetID); err != nil {
			return err
		}
		var obs model.AssetHostKeyMismatch
		if err := tx.Where("asset_id = ? AND observed_fingerprint = ?", assetID, fingerprint).First(&obs).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrHostKeyObservationNotFound
			}
			return fmt.Errorf("查詢主機金鑰觀察紀錄失敗: %w", err)
		}
		consumed := tx.Where("id = ?", obs.ID).Delete(&model.AssetHostKeyMismatch{})
		if consumed.Error != nil {
			return fmt.Errorf("消耗主機金鑰觀察紀錄失敗: %w", consumed.Error)
		}
		if consumed.RowsAffected != 1 {
			return ErrHostKeyObservationNotFound
		}
		previousFP, previousAlgo := hostKeyFingerprintNone, ""
		var genBefore int64
		var own model.AssetHostKey
		err := tx.Where("asset_id = ?", assetID).First(&own).Error
		switch {
		case err == nil:
			previousFP, previousAlgo, genBefore = own.Fingerprint, own.Algorithm, own.TrustGeneration
			if own.ResetPending {
				previousFP = hostKeyFingerprintResetPending
			}
			changes := map[string]any{
				"algorithm":     obs.ObservedAlgorithm,
				"fingerprint":   obs.ObservedFingerprint,
				"public_key":    obs.ObservedPublicKey,
				"reset_pending": false,
			}
			if obs.Host != "" && obs.Port > 0 {
				changes["host"], changes["port"] = obs.Host, obs.Port
			}
			// 指紋或演算法改變才推進；採用與自身列相同的指紋只清除重置旗標（世代已由重置推進）
			if own.Fingerprint != obs.ObservedFingerprint || own.Algorithm != obs.ObservedAlgorithm {
				changes["trust_generation"] = gorm.Expr("trust_generation + 1")
			}
			if err := tx.Model(&model.AssetHostKey{}).Where("id = ?", own.ID).Updates(changes).Error; err != nil {
				return fmt.Errorf("寫入採用的主機金鑰記錄失敗: %w", err)
			}
			if err := tx.Where("id = ?", own.ID).First(&own).Error; err != nil {
				return fmt.Errorf("重讀採用的主機金鑰記錄失敗: %w", err)
			}
		case errors.Is(err, gorm.ErrRecordNotFound):
			own = model.AssetHostKey{
				AssetID: assetID, Algorithm: obs.ObservedAlgorithm, Fingerprint: obs.ObservedFingerprint,
				PublicKey: obs.ObservedPublicKey, Host: obs.Host, Port: obs.Port, TrustGeneration: 1,
			}
			if err := tx.Create(&own).Error; err != nil {
				return fmt.Errorf("建立採用的主機金鑰記錄失敗: %w", err)
			}
		default:
			return fmt.Errorf("查詢主機金鑰記錄失敗: %w", err)
		}
		adopted = own
		if err := clearHostKeyObservations(tx, assetID); err != nil {
			return err
		}
		details, err := json.Marshal(hostKeyAdoptDetails{
			PreviousFingerprint: previousFP, PreviousAlgorithm: previousAlgo,
			AdoptedFingerprint: obs.ObservedFingerprint, AdoptedAlgorithm: obs.ObservedAlgorithm,
			FirstSeenAt: obs.FirstSeenAt.UTC().Format(time.RFC3339), LastSeenAt: obs.LastSeenAt.UTC().Format(time.RFC3339),
			SeenCount: obs.SeenCount, EverAllowed: obs.FirstAllowedAt != nil,
			Host: obs.Host, Port: obs.Port, CorrelationID: corr,
			TrustGenerationBefore: genBefore, TrustGenerationAfter: own.TrustGeneration,
		})
		if err != nil {
			return fmt.Errorf("序列化採用審計失敗: %w", err)
		}
		id := assetID
		if err := port.WriteInTx(s.auditSink, tx, gatewayapi.AuditEvent{
			OccurredAt: now,
			Actor:      gatewayapi.Actor{UserID: actor.UserID, Username: actor.Username},
			Action:     string(model.ActionHostKeyAdopt),
			Resource:   string(model.ResourceAsset),
			ResourceID: &id,
			Status:     string(model.StatusSuccess),
			AssetID:    &id,
			Request:    gatewayapi.RequestMeta{ClientIP: actor.ClientIP},
			Details:    string(details),
		}); err != nil {
			return fmt.Errorf("寫入採用審計失敗: %w", err)
		}
		return s.raiseRecordChanged(tx, assetID, actor, "adopted", previousFP, obs.ObservedFingerprint, corr)
	})
	if txErr != nil {
		return nil, txErr
	}
	return &adopted, nil
}
