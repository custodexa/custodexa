package asset

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
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
	// crashAfterVerify 測試掛點：人工承接的單次驗證成功之後、本地提交之前呼叫，
	// 回錯誤即原樣返回（模擬行程在此點結束：不寫任何結果）
	crashAfterVerify func() error

	// rotations 輪替引擎；nil＝尚未接線。
	//
	// **本欄決定候選的歸屬分流**：屬於某個輪替成員的候選一律交回成員路徑，
	// 未接線時寧可略過也不走單帳號轉正——後者會在共用憑證上多開版本、
	// 繞過成員轉移表改寫就位版本，拆分模式下還會把唯一的新秘密寫回原共用憑證
	rotations *CredentialRotationService

	// mgmt 候選重試前的授權重驗關卡；判定器未注入時不重驗（未接線的測試組裝），
	// 生產組裝必須注入。無授權脈絡的舊候選維持可重試：候選是「秘密可能已在遠端」的
	// 唯一副本，擋住它只會讓狀態永遠不明
	mgmt credentialManagementGate

	// auditTx 失權後有限驗證成功的留痕落地面（組裝根注入）；nil＝只寫日誌
	auditTx port.TxSink
}

// WithAuditSink 注入有限驗證的審計落地面。
func (r *ChangeSecretRetryRunner) WithAuditSink(sink port.TxSink) *ChangeSecretRetryRunner {
	r.auditTx = sink
	return r
}

// WithManagementAuthorizer 接上授權重驗：候選若帶授權脈絡，重試前以發起者當下的能力重驗
// （手動觸發另驗點擊者）；失權即記失敗原因並退避，不對遠端發出新的認證。
func (r *ChangeSecretRetryRunner) WithManagementAuthorizer(a CredentialManagementAuthorizer) *ChangeSecretRetryRunner {
	r.mgmt = credentialManagementGate{authorizer: a}
	return r
}

// RevalidationWired 授權重驗判定器是否已注入（組裝根自檢用：未注入時重試一律拒絕）。
func (r *ChangeSecretRetryRunner) RevalidationWired() bool {
	return r != nil && r.mgmt.authorizer != nil && r.mgmt.restoreGenerationWired() && r.auditTx != nil
}

// WithRotationService 接上輪替引擎（組裝根注入）。
func (r *ChangeSecretRetryRunner) WithRotationService(rotations *CredentialRotationService) *ChangeSecretRetryRunner {
	r.rotations = rotations
	return r
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

// RunDue 處理本輪到期的候選與到期的輪替成員，回傳（轉正筆數, 仍失敗筆數）。
//
// **兩種來源、一套節奏**：候選列與輪替成員列各自帶著下次嘗試時刻，但退避與期限
// 沿用同一組常數，且同一個掛載只會被其中一條路徑推進——兩套排程對同一台目標機
// 下手就是兩套帳號鎖定風險。
func (r *ChangeSecretRetryRunner) RunDue() (int, int) {
	handled := r.advanceRotationMembers()

	due, err := r.candidates.DueForRetry(r.batchSize)
	if err != nil {
		log.Printf("[ChangeSecretRetry] 取候選清單失敗: %v", err)
		return 0, 0
	}
	var promoted, failed int
	for i := range due {
		cand := due[i]
		if handled[cand.AccountID] {
			continue
		}
		member, merr := rotationMemberForAccount(r.db, cand.AccountID)
		if merr != nil {
			// 查不出歸屬時一律不走單帳號轉正：誤把輪替候選轉正的代價是共用憑證
			// 多開版本、就位版本繞過轉移表被改寫；少推進一輪只是晚一個退避週期
			log.Printf("[ChangeSecretRetry] 查詢候選歸屬失敗 id=%d err=%v", cand.ID, merr)
			continue
		}
		if member != nil {
			if !r.advanceMember(member) {
				// 成員此刻不歸背景推進（最終失敗、已收束，或成員自己的退避未到）：候選列
				// 不能留在「已到期」，否則每一輪都撈到它、還會佔掉批次裡其他候選的位置
				r.deferCandidate(&cand)
			}
			continue
		}
		held, herr := abandonedRotationHoldsCandidate(r.db, &cand)
		if herr != nil {
			log.Printf("[ChangeSecretRetry] 查詢候選是否屬於已放棄輪替失敗 id=%d err=%v", cand.ID, herr)
			continue
		}
		if held {
			// 已放棄、仍在憑證詳情等逐台補跑的那一輪留下的候選：只由補跑推進。走單帳號
			// 路徑只會以「授權失效」停下並告警，原因不對，處置也不在候選清單上
			r.deferCandidate(&cand)
			continue
		}
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

// advanceRotationMembers 推進到期的輪替成員，回傳本輪已處理的掛載集合。
//
// 先於候選掃描執行：乾淨失敗的成員已無候選列，只掃候選會讓它永遠等不到下一次。
func (r *ChangeSecretRetryRunner) advanceRotationMembers() map[uint]bool {
	handled := map[uint]bool{}
	if r.rotations == nil {
		return handled
	}
	members, err := r.rotations.DueMembers(r.batchSize)
	if err != nil {
		log.Printf("[ChangeSecretRetry] 取到期輪替成員失敗: %v", err)
		return handled
	}
	for i := range members {
		handled[members[i].AccountID] = true
		r.advanceMember(&members[i])
	}
	return handled
}

// advanceMember 把一個成員交回輪替引擎做背景推進（失敗只留 log：狀態與原因碼由引擎
// 自己落庫）。回傳 true＝確實推進了一步。
//
// 走 AdvanceMemberInBackground 而非 RunMember：後者會把最終失敗與已收束的成員重新排入，
// 等於無人在場時再對遠端下達一次改密。
func (r *ChangeSecretRetryRunner) advanceMember(member *DueRotationMember) bool {
	advanced, err := r.rotations.AdvanceMemberInBackground(context.Background(), member.RotationID, member.MemberID)
	if err != nil {
		log.Printf("[ChangeSecretRetry] 輪替成員推進失敗 rotation=%d member=%d err=%v",
			member.RotationID, member.MemberID, err)
	}
	return advanced
}

// deferCandidate 背景不推進的候選往後挪一個退避上限：不累計次數、不改原因碼、不觸發逾期
// 放棄（那些是嘗試過才有的事實，這裡沒有嘗試）。
func (r *ChangeSecretRetryRunner) deferCandidate(cand *model.ChangeSecretCandidate) {
	if err := r.candidates.Defer(cand.ID, time.Now().Add(candidateRetryMax)); err != nil {
		log.Printf("[ChangeSecretRetry] 候選延後失敗 id=%d err=%v", cand.ID, err)
	}
}

// RetryOne 單筆重試；true＝已轉正。管理員手動觸發與排程共用同一路徑——
// 兩條路徑分岔即會出現「手動能過、自動不能」的行為差異
func (r *ChangeSecretRetryRunner) RetryOne(cand *model.ChangeSecretCandidate) bool {
	return r.RetryOneAs(context.Background(), cand)
}

// RetryOneAs 同 RetryOne；ctx 帶有伺服器端主體時視為手動觸發，點擊者與原發起者都要通過重驗。
func (r *ChangeSecretRetryRunner) RetryOneAs(caller context.Context, cand *model.ChangeSecretCandidate) bool {
	return r.RetryOneAsResult(caller, cand).Promoted
}

// RetryOneAsResult 同 RetryOneAs，並在被主機身分守衛擋下時帶回唯讀檢視（不含秘密、公鑰本體與來源資產）。
func (r *ChangeSecretRetryRunner) RetryOneAsResult(caller context.Context, cand *model.ChangeSecretCandidate) RetryResult {
	// 屬於輪替成員的候選不走本路徑（含 admin 手動觸發）：單帳號轉正會繞過成員
	// 轉移表這個就位版本的唯一寫入點
	if member, merr := rotationMemberForAccount(r.db, cand.AccountID); merr != nil || member != nil {
		log.Printf("[ChangeSecretRetry] 候選屬於輪替成員，不走單帳號轉正 id=%d account=%d",
			cand.ID, cand.AccountID)
		return RetryResult{}
	}
	ctx := context.Background()
	recovery := false
	var identityView *HostIdentityView
	if reason := r.revalidateCandidate(caller, cand); reason != "" {
		if reason == model.ChangeSecretReasonAuthzRevoked {
			// 失權：遠端變更若已確認下達，僅在目標未被改動時開放「只驗證、只提交本地」的有限收斂
			if verdict := recoveryVerdict(r.db, r.hostKeys, cand.Applied, cand.CreatedAt,
				cand.TargetFingerprint, cand.AccountID, hostIdentityJobOfCandidate(cand)); verdict != "" {
				reason = verdict
				if verdict == model.ChangeSecretReasonHostIdentityChanged {
					identityView = r.recordRecoveryIdentityStop(cand)
				}
			} else {
				recovery = true
				if r.notifier != nil && claimRecoveryAlert(r.db, &model.ChangeSecretCandidate{}, cand.ID) {
					r.alert("改密工作於授權失效後進入有限驗證",
						fmt.Sprintf("candidate=%d asset_id=%d account=%s 發起者已失權，因遠端變更已送出，僅做驗證與本地提交（不再下達新變更），請具權者知悉",
							cand.ID, cand.AssetID, cand.AccountUsername))
				}
			}
		}
		if !recovery {
			if reason != model.ChangeSecretReasonHostIdentityChanged {
				// 主機身分停止有自己的停止審計與通知（每個身分狀態一次），不套授權失效的告警
				r.alertStopOnce(cand, reason)
			}
			r.noteFailure(cand, reason, fmt.Errorf("授權重驗未通過"))
			return RetryResult{HostIdentity: identityView}
		}
	}
	secret, err := r.candidates.Secret(ctx, cand)
	if err != nil {
		r.noteFailure(cand, model.ChangeSecretReasonRetrySecretUnavailable, err)
		return RetryResult{}
	}
	defer secret.Destroy()
	asset, err := r.assets.GetByID(cand.AssetID)
	if err != nil {
		r.noteFailure(cand, model.ChangeSecretReasonAssetLookupFailed, err)
		return RetryResult{}
	}
	// 通道在此重新推導而非存在候選列上：候選是「這個秘密可能已經在遠端了」的
	// 待辦，不是連線設定的快照。管理員在等待期間修好通道設定，下一輪就該用新的
	channel := asset.EffectiveRotationChannel()
	// 主機金鑰回呼帶撥號脈絡：重試屬背景路徑，不符時留痕後拒絕；連線使用者為候選的授權脈絡發起者
	var initiatorID uint
	var initiatorName string
	if auth, aerr := loadJobAuthorization(r.db, cand.AuthorizationID); aerr == nil {
		initiatorID, initiatorName = auth.ActorID, auth.ActorName
	}
	guard := r.retryIdentityGuard(cand, initiatorID, initiatorName)
	hostKeyCB, gerr := r.retryHostKeyCallback(guard, asset)
	if errors.Is(gerr, ErrCandidateNotFound) {
		log.Printf("[ChangeSecretRetry] 候選已不存在，略過 id=%d asset=%d account=%s",
			cand.ID, cand.AssetID, cand.AccountUsername)
		return RetryResult{}
	}
	if gerr != nil {
		// 撥號前查庫不放行：任何 I/O 之前停下，候選保留
		log.Printf("[ChangeSecretRetry] 主機身分守衛擋下重試 id=%d asset=%d: %v", cand.ID, cand.AssetID, gerr)
		if errors.Is(gerr, ErrHostIdentityChanged) {
			guard.recordStop(asset)
		}
		r.noteFailure(cand, retryVerifyFailureReason(gerr), gerr)
		return RetryResult{HostIdentity: guard.lastView()}
	}
	rt := rotationTarget{
		asset:      asset,
		channel:    channel,
		username:   cand.AccountUsername,
		secretType: cand.SecretType,
		addr:       rotationAddr(asset, channel),
		hostKeyCB:  hostKeyCB,
	}
	newSecret := secret.Password
	if cand.SecretType == model.ChangeSecretTypeSSHKey {
		newSecret = secret.PrivateKey
	}
	if err := withProtocolSecret(newSecret, func(next []byte) error { return r.executors(channel).Verify(ctx, rt, next) }); err != nil {
		if recovery {
			_ = r.recoveryAudit(cand, "verify_failed", false)
		}
		if errors.Is(err, ErrHostIdentityChanged) {
			guard.recordStop(asset)
		}
		r.noteFailure(cand, retryVerifyFailureReason(err), err)
		return RetryResult{HostIdentity: guard.lastView()}
	}

	secret.Destroy()
	if recovery {
		// 在發起者已失權的狀態下代為完成本地提交：留痕寫不進去就不提交，候選保留
		if err := r.recoveryAudit(cand, "verified", cand.SecretType == model.ChangeSecretTypeSSHKey && cand.PreviousPublicKey != ""); err != nil {
			r.noteFailure(cand, model.ChangeSecretReasonAuthzUnavailable, fmt.Errorf("有限驗證留痕失敗"))
			return RetryResult{}
		}
	}
	if err := r.candidates.Promote(ctx, cand); err != nil {
		if errors.Is(err, ErrCandidateNotFound) {
			// 候選列在這次重試的讀取與提交之間已不在（另一條路徑先轉正，或管理員清除）：
			// 沒有東西可提交、也沒有列可記失敗，不累計次數、不發放棄告警
			log.Printf("[ChangeSecretRetry] 候選已不存在，略過 id=%d asset=%d account=%s",
				cand.ID, cand.AssetID, cand.AccountUsername)
			return RetryResult{}
		}
		if errors.Is(err, ErrHostIdentityChanged) {
			guard.recordCommitStop(asset)
		}
		r.noteFailure(cand, promoteFailureReason(err), err)
		return RetryResult{HostIdentity: guard.lastView()}
	}
	if cand.CredentialID != 0 && cand.TargetVersionID != 0 {
		// 批次可能早已結束、當時因仍有待驗證候選而未評估；本候選轉正後掛載數若
		// 仍少於 2 且再無待驗證候選，該轉回專用就在此刻
		settleBatchSharedCredential(r.db, cand.CredentialID)
	}
	r.recordPromotion(cand, recovery)
	return RetryResult{Promoted: true}
}

// alertStopOnce 授權停止的告警每個候選只發一次：同一原因已記在候選上就不隨退避週期重複。
// 逾期放棄時由 noteFailure 另發一次（沿用原放棄告警）。
func (r *ChangeSecretRetryRunner) alertStopOnce(cand *model.ChangeSecretCandidate, reason string) {
	if cand.LastError == reason {
		return
	}
	if reason == model.ChangeSecretReasonAuthzRestored {
		r.auditRestoredStop(cand)
	}
	r.alert("改密工作因授權失效停止",
		fmt.Sprintf("retry candidate=%d reason=%s（遠端未被新增變更，候選保留，需具權者處置）", cand.ID, reason))
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
func (r *ChangeSecretRetryRunner) recordPromotion(cand *model.ChangeSecretCandidate, recovery bool) {
	reason := model.ChangeSecretReasonRetryPromoted
	cleanupPending := recovery && cand.SecretType == model.ChangeSecretTypeSSHKey && cand.PreviousPublicKey != ""
	if cleanupPending {
		// 失權後不再替原發起者刪舊鑰：新鑰已驗證並提交，舊公鑰留在目標機上待人清理
		reason = model.ChangeSecretReasonRecoveredCleanupPending
	}
	rec := model.ChangeSecretRecord{
		PlanID:          cand.PlanID,
		BatchID:         cand.BatchID,
		AssetID:         cand.AssetID,
		AccountID:       cand.AccountID,
		AccountUsername: cand.AccountUsername,
		SecretType:      cand.SecretType,
		CredentialID:    cand.CredentialID,
		CredentialName:  cand.CredentialName,
		TargetVersionID: committedVersionID(r.db, cand.AccountID, cand.TargetVersionID),
		Status:          model.ChangeSecretSuccess,
		Error:           reason,
		ExecutedAt:      time.Now(),
	}
	if err := r.db.Create(&rec).Error; err != nil {
		log.Printf("[ChangeSecretRetry] 轉正記錄入庫失敗: id=%d err=%v", cand.ID, err)
	}
	if recovery {
		if cleanupPending {
			r.alert("改密候選已驗證但舊公鑰待清理",
				fmt.Sprintf("asset_id=%d account=%s 已於失權後完成有限驗證，目標機上的舊公鑰尚未清除，請具權者手動處置",
					cand.AssetID, cand.AccountUsername))
		}
	}
}

func (r *ChangeSecretRetryRunner) alert(rule, msg string) {
	if r.notifier == nil {
		return
	}
	r.notifier.Enqueue(model.CommandAlert{RuleName: rule, Command: msg, Severity: "high"})
}

// recoveryAudit 有限驗證的結果留痕（發起者取自候選的授權脈絡）。
func (r *ChangeSecretRetryRunner) recoveryAudit(cand *model.ChangeSecretCandidate, result string, cleanupPending bool) error {
	in := recoveryAuditInput{
		resource: model.ResourceChangeSecretPlan, resourceID: cand.PlanID, assetID: cand.AssetID,
		accountID: cand.AccountID, authorizationID: cand.AuthorizationID, cleanupPending: cleanupPending,
		source: "candidate", result: result, fingerprint: cand.TargetFingerprint,
	}
	if auth, err := loadJobAuthorization(r.db, cand.AuthorizationID); err == nil {
		in.initiatorID, in.initiatorName = auth.ActorID, auth.ActorName
	}
	return writeRecoveryVerifyAudit(r.auditTx, r.db, in)
}

// auditRestoredStop 還原世代不符而停止的候選留痕（與告警同一個每候選一次的去重）。
// 落地面缺席或寫入失敗只留日誌，不阻擋停止。
func (r *ChangeSecretRetryRunner) auditRestoredStop(cand *model.ChangeSecretCandidate) {
	if r.auditTx == nil {
		return
	}
	var initiatorID uint
	var initiatorName string
	if auth, err := loadJobAuthorization(r.db, cand.AuthorizationID); err == nil {
		initiatorID, initiatorName = auth.ActorID, auth.ActorName
	}
	details, _ := json.Marshal(map[string]any{
		"resource": string(model.ResourceChangeSecretPlan), "operation": "authorization_stop",
		"plan_id": cand.PlanID, "batch_id": cand.BatchID, "candidate_id": cand.ID, "account_id": cand.AccountID,
		"reason": model.ChangeSecretReasonAuthzRestored, "initiator_id": initiatorID,
	})
	assetID := cand.AssetID
	var resourceID *uint
	if cand.PlanID != 0 {
		id := cand.PlanID
		resourceID = &id
	}
	err := r.db.Transaction(func(tx *gorm.DB) error {
		return port.WriteInTx(r.auditTx, tx, port.AuditEvent{
			OccurredAt: time.Now(),
			Actor:      gatewayapi.Actor{UserID: initiatorID, Username: initiatorName},
			Action:     string(model.ActionUpdate),
			Resource:   string(model.ResourceChangeSecretPlan),
			ResourceID: resourceID,
			AssetID:    &assetID,
			Status:     string(model.StatusDenied),
			Details:    string(details),
		})
	})
	if err != nil {
		log.Printf("[ChangeSecretRetry] 授權停止事件審計寫入失敗 candidate=%d: %v", cand.ID, err)
	}
}
