package asset

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"gorm.io/gorm"
)

// ChangeSecretRetryRunner 未驗證候選憑證的重試執行器。
//
// 重試只做一件事：**以候選秘密登入目標機**。成功即代表遠端確實已是新秘密，
// 於是提交為帳號憑證並刪除候選列；失敗則退避並等下一輪。
//
// 刻意**不**以舊秘密回探來分辨「遠端沒改成」——那會對目標機多打一輪認證，
// 而分辨出來也不改變處置（不採自動回滾）。
type ChangeSecretRetryRunner struct {
	db         *gorm.DB
	candidates *ChangeSecretCandidateService
	assets     *AssetService
	hostKeys   *HostKeyService
	notifier   *audit.AlertNotifier

	// batchSize 單輪上界；重試會對外建線，無界批次會讓一輪跑到下一輪還沒結束
	batchSize int

	// executors 依通道取執行器（與改密執行器同一組工廠）。
	// **重試必須走同一條驗證路徑**：兩邊分岔即會出現「手動能過、自動不能」
	executors func(channel string) rotationExecutor
}

// NewChangeSecretRetryRunner 建立重試執行器
func NewChangeSecretRetryRunner(db *gorm.DB, candidates *ChangeSecretCandidateService,
	assets *AssetService, hostKeys *HostKeyService, notifier *audit.AlertNotifier) *ChangeSecretRetryRunner {
	return &ChangeSecretRetryRunner{
		db: db, candidates: candidates, assets: assets,
		hostKeys: hostKeys, notifier: notifier, batchSize: 25,
		executors: rotationExecutorFor,
	}
}

// RunDue 處理本輪到期的候選，回傳（轉正筆數, 仍失敗筆數）
func (r *ChangeSecretRetryRunner) RunDue() (int, int) {
	due, err := r.candidates.DueForRetry(r.batchSize)
	if err != nil {
		log.Printf("[ChangeSecretRetry] 取候選清單失敗: %v", err)
		return 0, 0
	}
	var promoted, failed int
	for i := range due {
		cand := due[i]
		if r.RetryOne(&cand) {
			promoted++
			continue
		}
		failed++
	}
	if promoted > 0 || failed > 0 {
		log.Printf("[ChangeSecretRetry] 本輪完成: 轉正=%d 仍未驗=%d", promoted, failed)
	}
	return promoted, failed
}

// RetryOne 單筆重試；true＝已轉正。管理員手動觸發與排程共用同一路徑——
// 兩條路徑分岔即會出現「手動能過、自動不能」的行為差異
func (r *ChangeSecretRetryRunner) RetryOne(cand *model.ChangeSecretCandidate) bool {
	ctx := context.Background()
	secret, err := r.candidates.Secret(ctx, cand)
	if err != nil {
		r.noteFailure(cand, model.ChangeSecretReasonRetrySecretUnavailable, err)
		return false
	}
	asset, err := r.assets.GetByID(cand.AssetID)
	if err != nil {
		r.noteFailure(cand, model.ChangeSecretReasonAssetLookupFailed, err)
		return false
	}
	// 通道在此重新推導而非存在候選列上：候選是「這個秘密可能已經在遠端了」的
	// 待辦，不是連線設定的快照。管理員在等待期間修好通道設定，下一輪就該用新的
	channel := asset.EffectiveRotationChannel()
	rt := rotationTarget{
		asset:      asset,
		channel:    channel,
		username:   cand.AccountUsername,
		secretType: cand.SecretType,
		addr:       rotationAddr(asset, channel),
		hostKeyCB:  r.hostKeys.Callback(cand.AssetID),
	}
	newSecret := secret.Password
	if cand.SecretType == model.ChangeSecretTypeSSHKey {
		newSecret = secret.PrivateKey
	}
	if err := r.executors(channel).Verify(ctx, rt, newSecret); err != nil {
		r.noteFailure(cand, model.ChangeSecretReasonRetryLoginFailed, err)
		return false
	}

	if err := r.candidates.Promote(ctx, cand); err != nil {
		r.noteFailure(cand, model.ChangeSecretReasonPromoteFailed, err)
		return false
	}
	noteCredentialGroupLeft(r.db, cand.AccountID)
	r.recordPromotion(cand)
	return true
}

// noteFailure 累計失敗並在轉為已放棄時推送高等級告警。
//
// 安全紅線：last_error 只存原因碼。cause 可能挾帶目標機回吐的攻擊者可控字串
// （SSH 交握訊息），而 last_error 未加密落庫並經 API 反射——原文只進後端 log
func (r *ChangeSecretRetryRunner) noteFailure(cand *model.ChangeSecretCandidate, reason string, cause error) {
	log.Printf("[ChangeSecretRetry] 重試失敗 id=%d asset=%d account=%s reason=%s cause=%s",
		cand.ID, cand.AssetID, cand.AccountUsername, reason, sanitizeRemoteMessage(cause.Error()))
	abandoned, err := r.candidates.RecordFailure(cand, reason)
	if err != nil {
		log.Printf("[ChangeSecretRetry] 更新候選失敗狀態失敗: id=%d err=%v", cand.ID, err)
		return
	}
	if abandoned {
		r.alert("改密候選憑證已放棄重試",
			fmt.Sprintf("asset_id=%d account=%s 已逾重試期限仍無法驗證，需管理員以帶外途徑處置",
				cand.AssetID, cand.AccountUsername))
	}
}

// recordPromotion 轉正時補一筆成功記錄——否則「後來自己好了」這件事在記錄上看不見，
// 使用者只會看到當初那筆 unverified 而以為問題還在
func (r *ChangeSecretRetryRunner) recordPromotion(cand *model.ChangeSecretCandidate) {
	rec := model.ChangeSecretRecord{
		PlanID:          cand.PlanID,
		AssetID:         cand.AssetID,
		AccountID:       cand.AccountID,
		AccountUsername: cand.AccountUsername,
		SecretType:      cand.SecretType,
		Status:          model.ChangeSecretSuccess,
		Error:           model.ChangeSecretReasonRetryPromoted,
		ExecutedAt:      time.Now(),
	}
	if err := r.db.Create(&rec).Error; err != nil {
		log.Printf("[ChangeSecretRetry] 轉正記錄入庫失敗: id=%d err=%v", cand.ID, err)
	}
}

func (r *ChangeSecretRetryRunner) alert(rule, msg string) {
	if r.notifier == nil {
		return
	}
	r.notifier.Enqueue(model.CommandAlert{RuleName: rule, Command: msg, Severity: "high"})
}
