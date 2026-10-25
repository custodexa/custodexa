package asset

import (
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 輪替成員的狀態機。
//
// # 為什麼轉移要有一張表
//
// 成員狀態決定的是「這台主機此刻該用哪一版秘密登入」。任何一條沒有被想過的轉移
// ——例如從「遠端結果不明」直接跳到「已就位」——都會讓系統以一組可能根本沒生效的
// 秘密去連線，而那台機器連不上的原因在畫面上看不出來。轉移集合寫成資料而非散在
// 各個 if，是為了讓「有哪些轉移」這件事可以被一支測試逐格比對，而不是靠讀完全部
// 呼叫點去推。
//
// # 對就位版本的唯一影響點
//
// **只有轉入 applied 會改寫掛載的就位版本**，其餘六個狀態一律不動。遠端是否收下
// 新秘密未知時，提前改指等於謊稱新版已生效：該台既連不上，畫面上也看不出原因。
// 這條不變式由本檔的 transitionMember 單一入口承擔，呼叫端不得繞過它直接下 Update。

// 成員狀態的合法轉移。鍵為目前狀態，值為允許轉入的狀態集合。
//
// 「放棄本輪但成員停在 changed_unverified」不是轉移——該成員維持原狀態，
// 由輪替列的 status 表達本輪已被放棄，故表中沒有這條邊。
var credentialMemberTransitions = map[string][]string{
	// 已排入本輪：被執行器領取即開始動遠端；本輪被放棄且從未動過遠端則收束
	model.CredentialMemberQueued: {
		model.CredentialMemberChanging,
		model.CredentialMemberAbandoned,
	},
	// 正在對遠端下達：成功即進入待驗證；乾淨失敗依是否達上限分流；
	// 待生效版本被操作者宣告的密文取代時收束（本輪的目標已無人要，不再推進）
	model.CredentialMemberChanging: {
		model.CredentialMemberChangedUnverified,
		model.CredentialMemberRetryWait,
		model.CredentialMemberTerminalFailed,
		model.CredentialMemberAbandoned,
	},
	// 遠端已下達但未以新值驗證成功：驗證通過即就位，逾期即終局失敗，
	// 待生效版本被取代時收束
	model.CredentialMemberChangedUnverified: {
		model.CredentialMemberApplied,
		model.CredentialMemberTerminalFailed,
		model.CredentialMemberAbandoned,
	},
	// 本輪終態
	model.CredentialMemberApplied: {},
	// 可重試的失敗：到期重新下達、達上限終局失敗、放棄本輪則收束
	model.CredentialMemberRetryWait: {
		model.CredentialMemberChanging,
		model.CredentialMemberTerminalFailed,
		model.CredentialMemberAbandoned,
	},
	// 終局失敗：只有逐台補跑能把它重新排入
	model.CredentialMemberTerminalFailed: {
		model.CredentialMemberQueued,
	},
	// 已收束：逐台補跑可重新排入（本輪的目標版本仍是憑證要收斂到的那一版時才准）
	model.CredentialMemberAbandoned: {
		model.CredentialMemberQueued,
	},
}

// credentialMemberStates 全部成員狀態（供逐格檢查與值域判定使用）。
var credentialMemberStates = []string{
	model.CredentialMemberQueued,
	model.CredentialMemberChanging,
	model.CredentialMemberChangedUnverified,
	model.CredentialMemberApplied,
	model.CredentialMemberRetryWait,
	model.CredentialMemberTerminalFailed,
	model.CredentialMemberAbandoned,
}

// ErrMemberTransitionNotAllowed 轉移不在允許集合內。
//
// **不靜默略過**：一條沒被想過的轉移代表呼叫端對成員此刻的狀態有錯誤認知，
// 讓它安靜地不生效只會把錯誤延後到「這台為什麼連不上」那一刻才被發現。
var ErrMemberTransitionNotAllowed = errors.New("輪替成員的狀態轉移不被允許")

// ErrMemberWithoutTargetVersion 成員缺少目標版本卻要就位。
var ErrMemberWithoutTargetVersion = errors.New("輪替成員沒有目標版本，無法就位")

// isMemberTransitionAllowed 回報一次轉移是否落在轉移表內。
func isMemberTransitionAllowed(from, to string) bool {
	for _, next := range credentialMemberTransitions[from] {
		if next == to {
			return true
		}
	}
	return false
}

// memberTransition 一次轉移要一併寫入的附帶欄位。
//
// 全部為選填：不帶 LastError 就不動既有值（重試成功後仍保留上一次的原因碼會誤導，
// 故成功路徑一律顯式帶空字串）。
type memberTransition struct {
	// LastError 機器可讀的失敗原因碼；空字串＝清除既有值
	LastError string
	// BumpAttempt true＝嘗試次數加一
	BumpAttempt bool
	// NextAttemptAt 下次嘗試時刻（retry_wait 用）
	NextAttemptAt *time.Time
	// Verified 人工承接的邏輯驗證成功結果。逾期（終局失敗或已收束）成員轉入已就位
	// 只接受帶它的轉移；其他轉移忽略此欄
	Verified *verifiedConfirmation
}

// verifiedConfirmation 一次人工承接的「驗證成功」結果。
//
// 套件內未匯出；正式碼只有承接服務在單次邏輯驗證回 nil 之後的一處會建構它，
// 未驗證、驗證失敗與驗證進行中都拿不到。transitionMember 只能核對紀錄身分與未消耗，
// 分不出驗證是否成功，所以「驗證成功」完全由那唯一的建構點承擔。
type verifiedConfirmation struct {
	kind           string
	jobID          uint
	confirmationID uint
	revision       int64
	transport      string
	algorithm      string
	fingerprint    string
}

// ErrVerifiedConfirmationRequired 逾期成員轉入已就位卻沒有驗證成功的結果。
var ErrVerifiedConfirmationRequired = errors.New("逾期的輪替成員只能經人工承接驗證成功後就位")

// ErrVerifiedConfirmationInvalid 驗證結果與成員或承接紀錄對不上（零值身分、錯誤工作或次序、已消耗）。
var ErrVerifiedConfirmationInvalid = errors.New("人工承接的驗證結果與承接紀錄不符")

// isExpiredMemberState 逾期後停在終局的成員狀態：就位只能走人工承接。
func isExpiredMemberState(state string) bool {
	return state == model.CredentialMemberTerminalFailed || state == model.CredentialMemberAbandoned
}

// admitVerifiedApply 逾期成員轉入已就位的放行檢查：結果物件的身分欄不得為零值、須指向本成員，
// 並在交易內重讀承接紀錄確認仍未消耗。不碰消耗本身，消耗在狀態更新成功之後。
func admitVerifiedApply(tx *gorm.DB, member *model.CredentialRotationMember, opt memberTransition) error {
	if opt.Verified == nil {
		return ErrVerifiedConfirmationRequired
	}
	if opt.Verified.confirmationID == 0 || opt.Verified.jobID == 0 || opt.Verified.revision <= 0 ||
		opt.Verified.kind != takeoverKindMember || opt.Verified.jobID != member.ID {
		return ErrVerifiedConfirmationInvalid
	}
	var n int64
	if err := tx.Model(&model.CredentialHostIdentityConfirmation{}).
		Where("id = ? AND kind = ? AND job_id = ? AND revision = ? AND consumed_at IS NULL AND outcome = ''",
			opt.Verified.confirmationID, opt.Verified.kind, opt.Verified.jobID, opt.Verified.revision).Count(&n).Error; err != nil {
		return fmt.Errorf("重讀承接紀錄失敗: %w", err)
	}
	if n != 1 {
		return ErrVerifiedConfirmationInvalid
	}
	return nil
}

// consumeVerifiedApply 同交易條件式消耗承接紀錄；受影響列數不為 1 即失敗，呼叫端整筆回滾。
func consumeVerifiedApply(tx *gorm.DB, opt memberTransition) error {
	res := tx.Model(&model.CredentialHostIdentityConfirmation{}).
		Where("id = ? AND kind = ? AND job_id = ? AND revision = ? AND consumed_at IS NULL AND outcome = ''",
			opt.Verified.confirmationID, opt.Verified.kind, opt.Verified.jobID, opt.Verified.revision).
		Updates(map[string]any{"consumed_at": time.Now(), "outcome": takeoverOutcomeVerified})
	if res.Error != nil {
		return fmt.Errorf("消耗承接紀錄失敗: %w", res.Error)
	}
	if res.RowsAffected != 1 {
		return ErrConfirmationNotConsumable
	}
	return nil
}

// transitionMember 於交易內套用一次成員狀態轉移。
//
// **就位版本的唯一寫入點**：轉入 applied 時，且僅在此時，把該掛載的就位版本改寫
// 為成員的目標版本；其餘六個狀態一律不動就位版本。改寫走 setBindingEffectiveVersion
// （它以 credential_id 為 WHERE 條件強制版本歸屬），故跨憑證的版本識別寫不進去。
//
// 呼叫端須已在交易內取得該掛載所屬資產的列鎖與憑證列鎖（次序：先資產、後憑證）。
func transitionMember(tx *gorm.DB, member *model.CredentialRotationMember,
	to string, opt memberTransition) error {

	if member == nil {
		return ErrCredentialRotationMemberNotFound
	}
	// 逾期成員轉入已就位：不在轉移表內，唯一的入口是帶驗證成功結果的轉移
	verifiedApply := to == model.CredentialMemberApplied && isExpiredMemberState(member.State)
	if verifiedApply {
		if err := admitVerifiedApply(tx, member, opt); err != nil {
			return err
		}
	} else if !isMemberTransitionAllowed(member.State, to) {
		return fmt.Errorf("%w: %s -> %s", ErrMemberTransitionNotAllowed, member.State, to)
	}

	updates := map[string]any{
		"state":      to,
		"last_error": opt.LastError,
	}
	if opt.BumpAttempt {
		updates["attempt_count"] = member.AttemptCount + 1
	}
	updates["next_attempt_at"] = opt.NextAttemptAt

	now := time.Now()
	// 派送標記（單調）：轉入 changed_unverified 或 applied，或由 changing 直接收束
	// （放棄）時，同一個 UPDATE 內把「第一次可能已生效或結果不可知」的時刻寫下。
	// COALESCE 保證只由 NULL 寫成時刻、不覆寫既有值；乾淨失敗（changing 轉
	// retry_wait／terminal_failed）與 queued 之類其餘轉移不寫，也沒有任何路徑寫回 NULL
	writesSentMark := memberTransitionMarksSent(member.State, to)
	if writesSentMark {
		updates["secret_sent_at"] = gorm.Expr("COALESCE(secret_sent_at, ?)", now)
	}

	var appliedAt *time.Time
	if to == model.CredentialMemberApplied {
		if member.TargetVersionID == nil || *member.TargetVersionID == 0 {
			return ErrMemberWithoutTargetVersion
		}
		account, err := resolveAssetAccount(tx, member.AssetID, member.AccountID)
		if err != nil {
			return err
		}
		if account == nil {
			return ErrAssetAccountNotFound
		}
		if err := setBindingEffectiveVersion(tx, account, *member.TargetVersionID); err != nil {
			return err
		}
		appliedAt = &now
		updates["applied_at"] = appliedAt
	}

	res := tx.Model(&model.CredentialRotationMember{}).
		Where("id = ? AND state = ?", member.ID, member.State).
		Updates(updates)
	if res.Error != nil {
		return fmt.Errorf("更新輪替成員狀態失敗: %w", res.Error)
	}
	// 零列＝本成員的狀態在本交易可見範圍內已被別人改掉。**不得當成功**：
	// 就位版本可能已在上面被改寫，而成員狀態停在舊值，兩者從此互相矛盾
	if res.RowsAffected == 0 {
		return ErrMemberTransitionNotAllowed
	}
	if verifiedApply {
		if err := consumeVerifiedApply(tx, opt); err != nil {
			return err
		}
	}

	member.State = to
	member.LastError = opt.LastError
	if opt.BumpAttempt {
		member.AttemptCount++
	}
	member.NextAttemptAt = opt.NextAttemptAt
	if appliedAt != nil {
		member.AppliedAt = appliedAt
	}
	if writesSentMark && member.SecretSentAt == nil {
		member.SecretSentAt = &now
	}
	return nil
}

// memberTransitionMarksSent 一次轉移是否同時寫派送標記。
//
// 寫：轉入 changed_unverified、轉入 applied、由 changing 轉入 abandoned。
// 不寫：由 changing 轉入 retry_wait／terminal_failed（乾淨失敗，遠端確定不是新秘密）、
// 由其他狀態轉入 abandoned（從未下達或標記早已寫下）、轉入 queued／changing。
func memberTransitionMarksSent(from, to string) bool {
	switch to {
	case model.CredentialMemberChangedUnverified, model.CredentialMemberApplied:
		return true
	case model.CredentialMemberAbandoned:
		return from == model.CredentialMemberChanging
	}
	return false
}

// memberBackoffTransition 依嘗試次數與本輪起始時刻決定「還能重試」或「終局失敗」。
//
// 退避節奏沿用候選憑證的既有上限（candidateBackoff／candidateRetryDeadline）：
// 兩條路徑對同一台目標機下手，各有一套節奏就等於兩套鎖帳風險。
func memberBackoffTransition(member *model.CredentialRotationMember, startedAt time.Time) (string, *time.Time) {
	if time.Since(startedAt) >= candidateRetryDeadline {
		return model.CredentialMemberTerminalFailed, nil
	}
	next := time.Now().Add(candidateBackoff(member.AttemptCount + 1))
	return model.CredentialMemberRetryWait, &next
}
