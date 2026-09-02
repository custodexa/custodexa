package asset

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/custodexa/backend/internal/branding"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

const changeSecretDialTimeout = 10 * time.Second

// ChangeSecretRunner 改密執行器。
//
// 執行單位是**帳號**而非資產：計劃的（資產集 × 帳號範圍）展開為帳號清單，
// 逐帳號隔離錯誤。兩種秘密型別共用同一套可靠性語義——
// 候選先落庫 → 動遠端 → 驗證 → 驗證成功才提交本地憑證。
type ChangeSecretRunner struct {
	db           *gorm.DB
	assetService *AssetService
	candidates   *ChangeSecretCandidateService
	hostKeys     *HostKeyService
	notifier     *audit.AlertNotifier

	// accountLocks per-account 行程內互斥。本產品現為單實例部署，
	// 候選表的 account_id 唯一索引是最終防線，此鎖只是避免無謂的遠端往返
	accountLocks sync.Map
}

// NewChangeSecretRunner 建立執行器
func NewChangeSecretRunner(db *gorm.DB, assetService *AssetService,
	candidates *ChangeSecretCandidateService, hostKeys *HostKeyService, notifier *audit.AlertNotifier) *ChangeSecretRunner {
	return &ChangeSecretRunner{
		db: db, assetService: assetService,
		candidates: candidates, hostKeys: hostKeys, notifier: notifier,
	}
}

// changeSecretTarget 單一改密目標（資產 × 帳號）
type changeSecretTarget struct {
	assetID   uint
	accountID uint
	username  string
}

// RunPlan 執行計劃：逐帳號隔離錯誤，單一失敗不中斷批次
func (r *ChangeSecretRunner) RunPlan(plan *model.ChangeSecretPlan) []model.ChangeSecretRecord {
	var records []model.ChangeSecretRecord
	for _, assetID := range AssetIDList(plan) {
		targets, skipRec := r.resolveTargets(plan, assetID)
		if skipRec != nil {
			records = append(records, r.save(*skipRec))
			continue
		}
		for _, tgt := range targets {
			rec := r.runTarget(plan, tgt)
			records = append(records, rec)
			if rec.Status == model.ChangeSecretFailed || rec.Status == model.ChangeSecretUnverified {
				r.alertFailure(plan, rec)
			}
		}
	}
	return records
}

// resolveTargets 把（資產 × 帳號範圍）展開為帳號清單。
// 回傳非 nil 的 record 代表整台資產層級即被跳過（非 SSH、無帳號、讀取失敗）
func (r *ChangeSecretRunner) resolveTargets(plan *model.ChangeSecretPlan, assetID uint) ([]changeSecretTarget, *model.ChangeSecretRecord) {
	base := model.ChangeSecretRecord{
		PlanID: plan.ID, AssetID: assetID,
		SecretType: normalizeSecretType(plan.SecretType), ExecutedAt: time.Now(),
	}
	asset, err := r.assetService.GetByID(assetID)
	if err != nil {
		base.Status = model.ChangeSecretFailed
		base.Error = model.ChangeSecretReasonAssetLookupFailed
		return nil, &base
	}
	if asset.Protocol != model.ProtocolSSH {
		base.Status = model.ChangeSecretSkipped
		base.Error = model.ChangeSecretReasonProtocolUnsupported
		return nil, &base
	}
	var accounts []model.AssetAccount
	if err := r.db.Where("asset_id = ?", assetID).
		Order("is_default DESC, username ASC, id ASC").Find(&accounts).Error; err != nil {
		base.Status = model.ChangeSecretFailed
		base.Error = model.ChangeSecretReasonAccountLookupFailed
		return nil, &base
	}
	scope := model.AccountScope(PlanAccountScope(plan))
	var targets []changeSecretTarget
	for _, acc := range accounts {
		if !scope.Contains(acc.Username) {
			continue
		}
		targets = append(targets, changeSecretTarget{assetID: assetID, accountID: acc.ID, username: acc.Username})
	}
	if len(targets) == 0 {
		base.Status = model.ChangeSecretSkipped
		base.Error = model.ChangeSecretReasonNoAccountInScope
		return nil, &base
	}
	return targets, nil
}

// runTarget 單帳號改密；任何錯誤僅入 record 不上拋
func (r *ChangeSecretRunner) runTarget(plan *model.ChangeSecretPlan, tgt changeSecretTarget) model.ChangeSecretRecord {
	// per-account 互斥：同一帳號的兩次改密同時跑，會有兩個候選互相覆蓋遠端狀態
	lockAny, _ := r.accountLocks.LoadOrStore(tgt.accountID, &sync.Mutex{})
	lock := lockAny.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()

	rec := model.ChangeSecretRecord{
		PlanID: plan.ID, AssetID: tgt.assetID,
		AccountID: tgt.accountID, AccountUsername: tgt.username,
		SecretType: normalizeSecretType(plan.SecretType), ExecutedAt: time.Now(),
	}
	finish := func(status, errMsg string) model.ChangeSecretRecord {
		rec.Status = status
		rec.Error = errMsg
		return r.save(rec)
	}

	// 該帳號已有未驗證候選：不疊加第二個未知狀態
	existing, err := r.candidates.FindByAccount(tgt.accountID)
	if err != nil {
		return finish(model.ChangeSecretFailed, model.ChangeSecretReasonCandidateQueryFailed)
	}
	if existing != nil {
		return finish(model.ChangeSecretSkipped, model.ChangeSecretReasonCandidatePending)
	}

	// 開頭解析帳號憑證一次並**釘住 AccountID**：其後讀憑證、動遠端、憑證寫回
	// 全程作用於同一帳號。若結尾改以 assetID 重解析 default，執行期間管理員切換
	// default 就會把新秘密寫進另一個帳號——遠端已改的那台留著舊憑證（鎖死），
	// 另一台的憑證則被無聲覆蓋
	creds, err := r.assetService.GetWithCredentialsForAccount(tgt.assetID, tgt.accountID)
	if err != nil {
		return finish(model.ChangeSecretFailed, model.ChangeSecretReasonCredentialLoadFailed)
	}
	if creds.AccountID != tgt.accountID || creds.Username != tgt.username {
		return finish(model.ChangeSecretFailed, model.ChangeSecretReasonAccountChanged)
	}
	if creds.Password == "" && creds.PrivateKey == "" {
		return finish(model.ChangeSecretSkipped, model.ChangeSecretReasonNoCredential)
	}

	addr := fmt.Sprintf("%s:%d", creds.Asset.Host, creds.Asset.Port)
	hostKeyCB := r.hostKeys.Callback(tgt.assetID)

	if normalizeSecretType(plan.SecretType) == model.ChangeSecretTypeSSHKey {
		return r.rotateKey(plan, tgt, creds, addr, hostKeyCB, finish)
	}
	return r.rotatePassword(plan, tgt, creds, addr, hostKeyCB, finish)
}

// rotatePassword 密碼輪替：chpasswd（憑證經 stdin，不進 argv）
func (r *ChangeSecretRunner) rotatePassword(plan *model.ChangeSecretPlan, tgt changeSecretTarget,
	creds *AssetCredentials, addr string, hostKeyCB ssh.HostKeyCallback,
	finish func(string, string) model.ChangeSecretRecord) model.ChangeSecretRecord {

	if creds.Password == "" {
		return finish(model.ChangeSecretSkipped, model.ChangeSecretReasonNoPasswordCredential)
	}
	newPassword, err := GeneratePassword(PolicyFromPlan(plan))
	if err != nil {
		log.Printf("[ChangeSecret] 產生新密碼失敗 asset=%d account=%d err=%v", tgt.assetID, tgt.accountID, err)
		return finish(model.ChangeSecretFailed, model.ChangeSecretReasonPasswordGenerateFailed)
	}

	ctx := context.Background()
	// 候選先於遠端落庫
	cand, err := r.candidates.Create(ctx, CandidateInput{
		AssetID: tgt.assetID, AccountID: tgt.accountID, AccountUsername: tgt.username,
		PlanID: plan.ID, SecretType: model.ChangeSecretTypePassword, Password: newPassword,
	})
	if err != nil {
		if errors.Is(err, ErrCandidateExists) {
			return finish(model.ChangeSecretSkipped, model.ChangeSecretReasonCandidatePending)
		}
		return finish(model.ChangeSecretFailed, model.ChangeSecretReasonCandidatePersistFailed)
	}

	client, err := dialSSHPassword(addr, tgt.username, creds.Password, hostKeyCB)
	if err != nil {
		// 尚未動遠端，候選可安全清除
		_ = r.candidates.Discard(cand.ID)
		logRemoteCause(tgt, "舊憑證登入失敗", err)
		return finish(model.ChangeSecretFailed, model.ChangeSecretReasonOldCredentialLoginFailed)
	}
	err = runChpasswd(client, tgt.username, creds.Password, newPassword)
	client.Close()
	if err != nil {
		logRemoteCause(tgt, "改密指令失敗", err)
		// 本地前置驗證失敗＝完全未接觸遠端，遠端狀態並非不可知：清候選走乾淨失敗。
		// 若誤歸為 unverified，候選會一直卡著並擋住該帳號後續全部改密
		var localErr *localPreconditionError
		if errors.As(err, &localErr) {
			_ = r.candidates.Discard(cand.ID)
			return finish(model.ChangeSecretFailed, localErr.reason)
		}
		// 指令跑完但非零退出＝遠端確定未變更，清候選走乾淨失敗；
		// 其他錯誤（連線中斷／逾時）＝遠端狀態不可知，保留候選交給重試
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			_ = r.candidates.Discard(cand.ID)
			return finish(model.ChangeSecretFailed, model.ChangeSecretReasonRemoteRejected)
		}
		return finish(model.ChangeSecretUnverified, model.ChangeSecretReasonRemoteStateUnknown)
	}
	_ = r.candidates.MarkApplied(cand.ID)

	verify, err := dialSSHPassword(addr, tgt.username, newPassword, hostKeyCB)
	if err != nil {
		// 本地憑證**不動**，候選保留待重試。硬提交是在猜遠端狀態，
		// 猜錯就把還能用的憑證改壞
		logRemoteCause(tgt, "新密驗證失敗", err)
		_, _ = r.candidates.RecordFailure(cand, model.ChangeSecretReasonVerifyFailed)
		return finish(model.ChangeSecretUnverified, model.ChangeSecretReasonVerifyFailed)
	}
	verify.Close()

	cand.Applied = true
	if err := r.candidates.Promote(ctx, cand); err != nil {
		logRemoteCause(tgt, "憑證提交失敗", err)
		_, _ = r.candidates.RecordFailure(cand, model.ChangeSecretReasonPromoteFailed)
		return finish(model.ChangeSecretUnverified, model.ChangeSecretReasonPromoteFailed)
	}
	noteCredentialGroupLeft(r.db, tgt.accountID)
	return finish(model.ChangeSecretSuccess, "")
}

// rotateKey SSH 金鑰輪替：加新 → 驗新 → 刪舊
func (r *ChangeSecretRunner) rotateKey(plan *model.ChangeSecretPlan, tgt changeSecretTarget,
	creds *AssetCredentials, addr string, hostKeyCB ssh.HostKeyCallback,
	finish func(string, string) model.ChangeSecretRecord) model.ChangeSecretRecord {

	comment := fmt.Sprintf(branding.Slug + "-change-secret-%d-%d", tgt.assetID, tgt.accountID)
	newPrivate, newLine, err := GenerateSSHKeyPair(comment)
	if err != nil {
		return finish(model.ChangeSecretFailed, model.ChangeSecretReasonKeypairGenerateFailed)
	}
	// 舊的「本系統推送鑰」：僅當帳號現以私鑰認證時存在
	previousLine := ""
	if creds.PrivateKey != "" {
		if line, err := PublicLineFromPrivateKey(creds.PrivateKey); err == nil {
			previousLine = line
		}
	}

	ctx := context.Background()
	cand, err := r.candidates.Create(ctx, CandidateInput{
		AssetID: tgt.assetID, AccountID: tgt.accountID, AccountUsername: tgt.username,
		PlanID: plan.ID, SecretType: model.ChangeSecretTypeSSHKey,
		PrivateKey: newPrivate, PublicKey: newLine, PreviousPublicKey: previousLine,
	})
	if err != nil {
		if errors.Is(err, ErrCandidateExists) {
			return finish(model.ChangeSecretSkipped, model.ChangeSecretReasonCandidatePending)
		}
		return finish(model.ChangeSecretFailed, model.ChangeSecretReasonCandidatePersistFailed)
	}

	client, err := dialSSHCredentials(addr, tgt.username, creds, hostKeyCB)
	if err != nil {
		_ = r.candidates.Discard(cand.ID)
		logRemoteCause(tgt, "舊憑證登入失敗", err)
		return finish(model.ChangeSecretFailed, model.ChangeSecretReasonOldCredentialLoginFailed)
	}
	defer client.Close()

	sc, err := openSFTP(client)
	if err != nil {
		_ = r.candidates.Discard(cand.ID)
		logRemoteCause(tgt, "開啟 SFTP 失敗", err)
		return finish(model.ChangeSecretFailed, model.ChangeSecretReasonSFTPOpenFailed)
	}
	defer sc.Close()

	current, err := ReadAuthorizedKeys(sc)
	if err != nil {
		_ = r.candidates.Discard(cand.ID)
		logRemoteCause(tgt, "讀取 authorized_keys 失敗", err)
		return finish(model.ChangeSecretFailed, model.ChangeSecretReasonAuthorizedKeysReadFailed)
	}

	// 加新：預設策略下既有金鑰（含使用者自放的）全部保留
	next := AppendKeyLine(current.Original, newLine)
	if plan.KeyStrategy == model.KeyStrategyExclusive {
		next = newLine + "\n"
	}
	if err := WriteAuthorizedKeys(sc, next); err != nil {
		_ = r.candidates.Discard(cand.ID)
		logRemoteCause(tgt, "寫入 authorized_keys 失敗", err)
		return finish(model.ChangeSecretFailed, model.ChangeSecretReasonAuthorizedKeysWriteFailed)
	}
	_ = r.candidates.MarkApplied(cand.ID)

	// 驗新：以新私鑰對同一目標實連。此步同時是 AuthorizedKeysFile 指向他處、
	// 檔案唯讀等狀況的偵測手段——加了鑰卻登不進去即代表該檔未被 sshd 採用
	verifyClient, err := dialSSHPrivateKey(addr, tgt.username, newPrivate, hostKeyCB)
	if err != nil {
		logRemoteCause(tgt, "新鑰驗證失敗", err)
		// 還原：在**同一條已認證的 SFTP 連線**上回寫（不重新撥號，故與舊憑證是否
		// 仍有效無關）；移除剛加入的那一行，exclusive 則回填原始內容
		restore := RemoveKeyLine(next, newLine)
		if plan.KeyStrategy == model.KeyStrategyExclusive {
			restore = current.Original
		}
		if rErr := WriteAuthorizedKeys(sc, restore); rErr != nil {
			logRemoteCause(tgt, "新鑰驗證失敗後還原 authorized_keys 失敗", rErr)
			_, _ = r.candidates.RecordFailure(cand, model.ChangeSecretReasonKeyVerifyFailedRestoreFailed)
			return finish(model.ChangeSecretUnverified, model.ChangeSecretReasonKeyVerifyFailedRestoreFailed)
		}
		_ = r.candidates.Discard(cand.ID)
		return finish(model.ChangeSecretFailed, model.ChangeSecretReasonKeyVerifyFailedRestored)
	}
	verifyClient.Close()

	// 刪舊：只刪本系統先前推送的那一行，使用者自放的鑰一律不動
	if previousLine != "" && plan.KeyStrategy != model.KeyStrategyExclusive {
		pruned := RemoveKeyLine(next, previousLine)
		if pruned != next {
			if err := WriteAuthorizedKeys(sc, pruned); err != nil {
				// 新鑰已驗證可用，舊鑰沒刪掉不影響可用性；記錄但仍提交
				log.Printf("[ChangeSecret] 舊公鑰移除失敗 asset=%d account=%d: %v",
					tgt.assetID, tgt.accountID, err)
			}
		}
	}

	cand.Applied = true
	if err := r.candidates.Promote(ctx, cand); err != nil {
		logRemoteCause(tgt, "憑證提交失敗", err)
		_, _ = r.candidates.RecordFailure(cand, model.ChangeSecretReasonPromoteFailed)
		return finish(model.ChangeSecretUnverified, model.ChangeSecretReasonPromoteFailed)
	}
	noteCredentialGroupLeft(r.db, tgt.accountID)
	return finish(model.ChangeSecretSuccess, "")
}

// save 落庫記錄；入庫失敗只記 log（記錄失敗不應改變改密結果）
func (r *ChangeSecretRunner) save(rec model.ChangeSecretRecord) model.ChangeSecretRecord {
	if err := r.db.Create(&rec).Error; err != nil {
		log.Printf("[ChangeSecret] record 入庫失敗: plan=%d asset=%d account=%d err=%v",
			rec.PlanID, rec.AssetID, rec.AccountID, err)
	}
	return rec
}

// normalizeSecretType 空值視為密碼（既有計劃無此欄）
func normalizeSecretType(t string) string {
	if t == model.ChangeSecretTypeSSHKey {
		return model.ChangeSecretTypeSSHKey
	}
	return model.ChangeSecretTypePassword
}

// dialSSHPassword 以密碼建立輕量 exec 用連線（不開 PTY）
func dialSSHPassword(addr, user, password string, hostKey ssh.HostKeyCallback) (*ssh.Client, error) {
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: hostKey,
		Timeout:         changeSecretDialTimeout,
	})
}

// dialSSHPrivateKey 以私鑰建立連線（金鑰輪替的驗證步驟）
func dialSSHPrivateKey(addr, user, privatePEM string, hostKey ssh.HostKeyCallback) (*ssh.Client, error) {
	signer, err := ssh.ParsePrivateKey([]byte(privatePEM))
	if err != nil {
		return nil, fmt.Errorf("解析私鑰失敗: %w", err)
	}
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKey,
		Timeout:         changeSecretDialTimeout,
	})
}

// dialSSHCredentials 以帳號現行憑證登入（私鑰優先，其次密碼）
func dialSSHCredentials(addr, user string, creds *AssetCredentials, hostKey ssh.HostKeyCallback) (*ssh.Client, error) {
	var methods []ssh.AuthMethod
	if creds.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(creds.PrivateKey))
		if err == nil {
			methods = append(methods, ssh.PublicKeys(signer))
		}
	}
	if creds.Password != "" {
		methods = append(methods, ssh.Password(creds.Password))
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("帳號無可用憑證")
	}
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            methods,
		HostKeyCallback: hostKey,
		Timeout:         changeSecretDialTimeout,
	})
}

// runChpasswd 執行改密：root 直接 chpasswd；非 root 以 sudo -S 餵舊密提權。
//
// **憑證一律經 session stdin 投遞**，SHALL NOT 進入命令列——目標機的 ps 與
// /proc/<pid>/cmdline 因此看不到任何密碼。後端側亦無子程序（全程行程內 SSH
// 客戶端），故本地 argv／environ 同樣不持有憑證。
func runChpasswd(client *ssh.Client, user, oldPassword, newPassword string) error {
	// chpasswd 自 stdin 逐行讀 user:password；user/新密含換行會拆出額外條目
	// 改到非目標帳號（stdin 注入），故在組裝 entry 前嚴格拒絕控制字元
	//
	// 本地前置驗證在**完全未接觸遠端**時失敗，故以專屬型別回傳：呼叫端據此走
	// 乾淨 failed，不得落入「狀態不可知」分支（那會留下擋住該帳號的候選）
	if strings.ContainsAny(user, "\n\r\x00:") {
		return &localPreconditionError{reason: model.ChangeSecretReasonInvalidAccountName}
	}
	if strings.ContainsAny(newPassword, "\n\r\x00") {
		return &localPreconditionError{reason: model.ChangeSecretReasonInvalidNewSecret}
	}

	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	entry := fmt.Sprintf("%s:%s", user, newPassword)
	var cmd string
	var stdin string
	if user == "root" {
		cmd = "chpasswd"
		stdin = entry + "\n"
	} else {
		// sudo -S 自 stdin 讀密碼；chpasswd 條目為 stdin 的第二行
		cmd = "sudo -S -p '' sh -c 'chpasswd'"
		stdin = oldPassword + "\n" + entry + "\n"
	}

	sess.Stdin = strings.NewReader(stdin)
	var stderr bytes.Buffer
	sess.Stderr = &stderr
	if err := sess.Run(cmd); err != nil {
		// 保留 *ssh.ExitError 型別供可知性分流；只在有 stderr 時附上訊息
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return fmt.Errorf("%s: %w", sanitizeRemoteMessage(msg), err)
		}
		return err
	}
	return nil
}

// sanitizeRemoteMessage 遠端 stderr 只取首行並截長（避免把整段輸出寫進記錄欄）
func sanitizeRemoteMessage(msg string) string {
	if idx := strings.IndexAny(msg, "\r\n"); idx > 0 {
		msg = msg[:idx]
	}
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return msg
}

// localPreconditionError 本地前置驗證失敗（完全未接觸遠端）。
// reason 為 model 的原因碼常數，直接落 record.error
type localPreconditionError struct{ reason string }

func (e *localPreconditionError) Error() string { return e.reason }

// logRemoteCause 遠端／庫原文的**唯一**出口：只進後端 log，不落庫、不外送。
//
// 安全紅線：err 可能挾帶目標機回吐的攻擊者可控字串（stderr、SSH 交握訊息），
// 其中可能夾帶本輪產生的新秘密（目標機把收到的 stdin 回吐即可）。這條字串
// SHALL NOT 進入 record.error／candidate.last_error／告警通道。
func logRemoteCause(tgt changeSecretTarget, stage string, err error) {
	log.Printf("[ChangeSecret] %s asset=%d account=%d user=%s cause=%s",
		stage, tgt.assetID, tgt.accountID, tgt.username, sanitizeRemoteMessage(err.Error()))
}

// alertFailure 失敗推送告警通道（復用 CommandAlert 通道格式）。
//
// 告警離開產品邊界（webhook／Slack），故內容一律是機器碼＋固定文案；
// 遠端原文只留在後端 log
func (r *ChangeSecretRunner) alertFailure(plan *model.ChangeSecretPlan, rec model.ChangeSecretRecord) {
	if r.notifier == nil {
		return
	}
	r.notifier.Enqueue(model.CommandAlert{
		RuleName: "改密計劃失敗",
		Command: fmt.Sprintf("plan=%s asset_id=%d account=%s reason=%s（詳細遠端訊息見伺服器日誌）",
			plan.Name, rec.AssetID, rec.AccountUsername, rec.Error),
		Severity: "high",
	})
}
