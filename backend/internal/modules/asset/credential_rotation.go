package asset

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/branding"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
)

// 共用憑證的整組改密：一次輪替、逐掛載成員、部分成功與收斂。
//
// # 為什麼共用憑證要有自己的輪替實體
//
// 一組秘密掛在多台主機上時，「換掉它」不是一個動作而是 n 個——每一台各自可能成功、
// 失敗或結果不明，而它們之間沒有相依性。把這 n 個結果壓成單一的成功／失敗，等於
// 在「三台裡有一台沒換成」時只能二選一：宣稱整批成功（那台留著舊密而沒人知道），
// 或宣稱整批失敗（另外兩台明明已經換好）。輪替列與逐掛載的成員列就是為了讓這件事
// 有地方被完整表達。
//
// # 為什麼不採「任一失敗即全組停止」
//
// 成員之間無相依性，停下來只是讓已經可以改的主機也不改。單一成員失敗不中斷其他成員，
// 未就位的成員也不被禁止連線——各台以自己的就位版本維持可用。
//
// # 期間鎖定
//
// 輪替進行中，該憑證的掛載、卸載、直接寫入密文、更換掛載所引用的憑證、範圍轉換與
// 再次輪替一律拒絕：操作者宣告密文的路徑會立即改寫全部掛載的就位版本，與進行中的
// 逐台驗證互斥。判定入口是 assertNoActiveRotation，且一律先取憑證列鎖再讀該欄。

// 憑證的聚合輪替狀態。**純投影、不落欄**：事實來源是逐成員狀態，
// 另設一個會與之漂移的欄位只會製造第二個真相。
const (
	// CredentialAggregateIdle 無進行中的輪替且無待生效版本
	CredentialAggregateIdle = "idle"
	// CredentialAggregateQueued 有進行中的輪替且全部成員仍在排隊
	CredentialAggregateQueued = "queued"
	// CredentialAggregateChanging 有進行中的輪替且已有成員在動或等待重試
	CredentialAggregateChanging = "changing"
	// CredentialAggregatePartial 有進行中的輪替且同時存在已就位與未就位的成員
	CredentialAggregatePartial = "partial"
	// CredentialAggregateOutOfSync 輪替已結束但待生效版本仍在、成員未全部就位。
	// 後續只能逐台補跑至收斂，收斂前不允許啟動新一輪
	CredentialAggregateOutOfSync = "out_of_sync"
)

// 憑證審計的輪替類操作分類。
//
// 與 credential_binding.go 的 credentialOpBind／Unbind／Scope／Rebind 同一組值域，
// 落在本檔是因為它們只由輪替路徑產生——分開放使「誰會寫出這個分類」一眼可查。
const (
	credentialOpRotate  = "rotate"
	credentialOpAbandon = "abandon"
	credentialOpDetach  = "detach"
)

var (
	// ErrCredentialRotationNotFound 輪替不存在
	ErrCredentialRotationNotFound = errors.New("輪替不存在")
	// ErrCredentialRotationMemberNotFound 輪替成員不存在或不屬於該輪替
	ErrCredentialRotationMemberNotFound = errors.New("輪替成員不存在或不屬於該輪替")
	// ErrCredentialRotationNotRunning 輪替已結束，不接受推進或放棄
	ErrCredentialRotationNotRunning = errors.New("輪替已結束")
	// ErrCredentialRotationNoBinding 憑證零掛載，無可輪替的目標。
	// 零掛載的共用憑證是合法的待用狀態，但「對它發起改密」沒有任何遠端可動
	ErrCredentialRotationNoBinding = errors.New("憑證沒有任何掛載，無可改密的目標")
	// ErrCredentialOutOfSync 上一輪未收斂（RULE_CREDENTIAL_OUT_OF_SYNC）。
	// 收斂前啟動新一輪會讓「遠端到底是哪一版」永遠答不出來
	ErrCredentialOutOfSync = errors.New("憑證的上一輪改密尚未收斂，請先逐台補跑")
	// ErrCredentialAuthzUnavailable 資產權限判定器缺席。
	//
	// **裝配缺陷，不是使用者錯誤**：對外收斂為一般內部錯誤（成因只落伺服端日誌），
	// 對內則保證「無從判定權限」不會以放行收場
	ErrCredentialAuthzUnavailable = errors.New("資產權限判定不可用")
)

// rotationAccountLocks per-account 行程內互斥，計劃／批次改密與整組輪替**共用同一組**。
//
// 兩套引擎對同一個掛載同時下手，會有兩個候選互相覆蓋遠端狀態；各自持有一份鎖表
// 等於沒有互斥。候選表的 account_id 唯一索引仍是最終防線，此鎖只是避免無謂的遠端往返。
var rotationAccountLocks sync.Map

// lockRotationAccount 取某掛載的行程內互斥鎖，回傳解鎖函式。
func lockRotationAccount(accountID uint) func() {
	lockAny, _ := rotationAccountLocks.LoadOrStore(accountID, &sync.Mutex{})
	lock := lockAny.(*sync.Mutex)
	lock.Lock()
	return lock.Unlock
}

// StartRotationRequest 發起一次輪替。
//
// 金鑰型別沒有對應的策略欄：整組輪替一律保留既有金鑰（含使用者自放的），
// 只換本系統推送的那一把——多一個開關等於多一條「把別人的鑰清掉」的路徑。
type StartRotationRequest struct {
	// Policy 密碼型別的生成策略；語義與改密計劃相同
	Policy PasswordPolicy
}

// CredentialRotationService 共用憑證的輪替引擎。
//
// 執行面完全重用改密執行器：rotationExecutor 介面、四類錯誤分流契約、
// rotationExecutorFor 的通道選路與 per-account 互斥逐條沿用。狀態機不認識任何
// 遠端協定，新通道不必為輪替再寫一次候選與失敗三態的處理。
type CredentialRotationService struct {
	db         *gorm.DB
	assets     *AssetService
	candidates *ChangeSecretCandidateService
	hostKeys   *HostKeyService
	crypto     crypto.ColumnCodec
	auditTx    port.TxSink

	// authz 受影響資產的權限判定。發起改密會改掉遠端主機上的登入秘密，射程是該
	// 憑證當下的**全部掛載**——只驗其中一台等於讓權限最寬的那一台替其餘各台決定。
	//
	// **建構期必填**：設為可選欄位＋nil 時放行，等於留一個「忘記注入就退回無驗權」
	// 的開關，而那個開關沒有任何機器盯著。萬一仍以 nil 到達（顯式傳 nil），
	// 驗權面一律 fail-close 拒絕，不以放行收場
	authz assetViewPermissionChecker

	// executors 依通道取執行器（與改密執行器同一組工廠）。**可換**是為了讓狀態機的
	// 測試不必真的連上任何目標機——選路與三態處理是本結構的責任，遠端協定不是
	executors func(channel string) rotationExecutor

	// keyApplier 金鑰型別的遠端三段式（加新 → 驗新 → 刪舊）。可換的理由同 executors：
	// 三段式需要一條跨越「動遠端」與「驗證」的已認證 SFTP 連線，表達不進 executors 介面
	keyApplier sshKeyApplier
}

// sshKeyApplier 金鑰三段式的遠端段簽名（見 applySSHKeyOnTarget）。
type sshKeyApplier func(ctx context.Context, exec rotationExecutor, rt rotationTarget,
	tgt changeSecretTarget, oldPassword, oldPrivateKey, newPrivate, newLine, previousLine,
	keyStrategy string, onDelivered func()) error

// NewCredentialRotationService 建立輪替服務。
//
// codec SHALL 與資產服務、憑證服務同一個實例：兩份 codec 會讓待生效版本寫得進去卻讀不回來。
// authz 為建構期必填（見同名欄註解）。
func NewCredentialRotationService(db *gorm.DB, assets *AssetService,
	candidates *ChangeSecretCandidateService, hostKeys *HostKeyService,
	codec crypto.ColumnCodec, auditTx port.TxSink,
	authz assetViewPermissionChecker) *CredentialRotationService {

	return &CredentialRotationService{
		db: db, assets: assets, candidates: candidates, hostKeys: hostKeys,
		crypto: codec, auditTx: auditTx, authz: authz,
		executors:  rotationExecutorFor,
		keyApplier: applySSHKeyOnTarget,
	}
}

// assertAssetPermission 單一受影響資產的權限檢核。
//
// 判準與掛載面同一條（`credential_binding.go` 的同名方法）：以資產權限階梯的上限
// 判定——能連上那台機器的人才談得上改掉它的登入秘密。回的是與「憑證不存在」
// 共用的收斂哨兵，分流即製造存在性探測器。
//
// 判定器缺席時拒絕而非放行：無從判定「這個人管不管得到這幾台」時改掉遠端秘密，
// 與判定為無權在後果上相同。
func (s *CredentialRotationService) assertAssetPermission(ctx context.Context, assetID uint) error {
	if s.authz == nil {
		return ErrCredentialAuthzUnavailable
	}
	operatorID, _ := model.UserFromContext(ctx)
	allowed, err := s.authz.CheckPermission(ctx, operatorID, assetID, model.PermissionConnect)
	if err != nil {
		return fmt.Errorf("判定資產權限失敗: %w", err)
	}
	if !allowed {
		return ErrCredentialBindForbidden
	}
	return nil
}

// assertBoundAssetsPermission 逐台驗操作者對該憑證全部掛載資產的權限。
//
// 於呼叫端的交易與憑證列鎖之內讀取掛載集合，避免「驗過之後又被掛上一台」。
func (s *CredentialRotationService) assertBoundAssetsPermission(ctx context.Context,
	db *gorm.DB, credentialID uint) error {

	if s.authz == nil {
		return ErrCredentialAuthzUnavailable
	}
	assetIDs, err := credentialBoundAssetIDs(db, credentialID)
	if err != nil {
		return err
	}
	for _, assetID := range assetIDs {
		if err := s.assertAssetPermission(ctx, assetID); err != nil {
			return err
		}
	}
	return nil
}

// Rotation 取一筆輪替並確認它屬於該憑證。
//
// **憑證識別是判定的一部分而非裝飾**：只依 rotation id 取列會讓任何持有識別的人
// 讀到別筆憑證的輪替進度，而進度含逐台的資產名與失敗原因。
func (s *CredentialRotationService) Rotation(credentialID, rotationID uint) (*model.CredentialRotation, error) {
	rot, err := loadRotation(s.db, rotationID)
	if err != nil {
		return nil, err
	}
	if rot.CredentialID != credentialID {
		return nil, ErrCredentialRotationNotFound
	}
	return rot, nil
}

// Start 發起整組改密：全部掛載換到同一組新秘密，共用關係維持。
//
// 同一交易內：取憑證列鎖 → 檢查無進行中的輪替且未處於未收斂狀態 → 遞增輪替代數
// → 建立待生效版本（整組同一組秘密）→ 快照全部掛載為成員列 → 寫入進行中的輪替識別。
//
// **待生效版本在動任何遠端之前就落庫**：後端在「已下達、尚未驗證」的窗口被砍時，
// 新秘密若只在記憶體即永久遺失，而遠端可能已經換過去了。
func (s *CredentialRotationService) Start(ctx context.Context, credentialID uint,
	req StartRotationRequest) (*model.CredentialRotation, error) {

	userID, operator := model.UserFromContext(ctx)
	var out *model.CredentialRotation
	err := s.db.Transaction(func(tx *gorm.DB) error {
		cred, err := lockCredentialRow(tx, credentialID)
		if err != nil {
			return err
		}
		if err := assertNoActiveRotation(cred); err != nil {
			return err
		}
		if err := assertCredentialConverged(tx, cred); err != nil {
			return err
		}
		bindings, err := credentialBindingRows(tx, cred.ID)
		if err != nil {
			return err
		}
		if len(bindings) == 0 {
			return ErrCredentialRotationNoBinding
		}
		// 逐台驗權在列鎖與掛載讀取之後：本輪要動的就是這一組主機
		if err := s.assertBoundAssetsPermission(ctx, tx, cred.ID); err != nil {
			return err
		}

		version, err := s.buildRotationVersion(ctx, tx, cred, req)
		if err != nil {
			return err
		}
		rot := &model.CredentialRotation{
			CredentialID:             cred.ID,
			Epoch:                    cred.RotationEpoch + 1,
			Mode:                     model.CredentialRotationModeGroup,
			TargetVersionID:          &version.ID,
			Status:                   model.CredentialRotationRunning,
			RequestedBy:              userID,
			RequestedByName:          operator,
			PasswordLength:           req.Policy.Length,
			PasswordIncludeSymbol:    req.Policy.IncludeSymbol,
			PasswordExcludeAmbiguous: req.Policy.ExcludeAmbiguous,
			StartedAt:                time.Now(),
		}
		if err := tx.Create(rot).Error; err != nil {
			return fmt.Errorf("建立輪替失敗: %w", err)
		}
		if err := snapshotRotationMembers(tx, rot, bindings, &version.ID); err != nil {
			return err
		}
		if err := tx.Model(&model.Credential{}).Where("id = ?", cred.ID).
			Updates(map[string]any{
				"pending_version_id": version.ID,
				"active_rotation_id": rot.ID,
				"rotation_epoch":     rot.Epoch,
			}).Error; err != nil {
			return fmt.Errorf("寫入輪替狀態失敗: %w", err)
		}
		out = rot
		return writeCredentialAudit(s.auditTx, tx, credentialAudit{
			CredentialID: cred.ID,
			Operation:    credentialOpRotate,
			Scope:        cred.Scope,
			Fields:       []string{"pending_version_id", "active_rotation_id"},
		}, userID, operator)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// buildRotationVersion 產生本輪的新秘密並落成一筆待生效版本。
//
// 未被本次更動的那一欄自現行版本原樣帶過來（密文原樣搬、不解密）：金鑰輪替不得
// 順手清掉密碼備援入口，密碼輪替對私鑰同理。
func (s *CredentialRotationService) buildRotationVersion(ctx context.Context, tx *gorm.DB,
	cred *model.Credential, req StartRotationRequest) (*model.CredentialSecretVersion, error) {

	var passwordEnc, privateKeyEnc string
	switch cred.SecretType {
	case model.ChangeSecretTypeSSHKey:
		comment := fmt.Sprintf("%s-credential-%d", branding.Slug, cred.ID)
		newPrivate, _, err := GenerateSSHKeyPair(comment)
		if err != nil {
			return nil, fmt.Errorf("產生金鑰對失敗: %w", err)
		}
		enc, err := s.crypto.EncryptFor(ctx, keyvault.RefCredentialVersionPrivateKey, newPrivate)
		if err != nil {
			return nil, fmt.Errorf("加密私鑰失敗: %w", err)
		}
		privateKeyEnc = enc
	default:
		password, err := GeneratePassword(normalizeRotationPolicy(req.Policy))
		if err != nil {
			return nil, fmt.Errorf("產生新密碼失敗: %w", err)
		}
		enc, err := s.crypto.EncryptFor(ctx, keyvault.RefCredentialVersionPassword, password)
		if err != nil {
			return nil, fmt.Errorf("加密密碼失敗: %w", err)
		}
		passwordEnc = enc
	}

	if cred.CurrentVersionID != nil {
		var err error
		passwordEnc, privateKeyEnc, err = carryOverVersionCiphertext(tx, cred.ID,
			*cred.CurrentVersionID, passwordEnc, privateKeyEnc)
		if err != nil {
			return nil, err
		}
	}
	return appendCredentialVersion(tx, cred.ID, cred.SecretType,
		passwordEnc, privateKeyEnc, model.CredentialVersionReasonRotation)
}

// normalizeRotationPolicy 長度為 0（未設）時取預設值，讀取端不因缺欄生出長度 0 的密碼。
func normalizeRotationPolicy(p PasswordPolicy) PasswordPolicy {
	if p.Length == 0 {
		p.Length = model.PasswordLengthDefault
	}
	return p
}

// snapshotRotationMembers 把當下的全部掛載快照成成員列。
//
// **四個快照欄是刻意的冗餘**：拆分收斂後掛載列會改指向別的憑證，歷史查詢若只靠
// 掛載識別回頭 join，讀到的是「現在」的憑證與帳號名，而不是那一輪動的是誰。
//
// targetVersionID 為 nil＝拆分模式（每台目標不同，於各自成功時才知道）。
func snapshotRotationMembers(tx *gorm.DB, rot *model.CredentialRotation,
	bindings []model.AssetAccount, targetVersionID *uint) error {

	for i := range bindings {
		binding := bindings[i]
		var asset model.Asset
		if err := tx.Where("id = ?", binding.AssetID).First(&asset).Error; err != nil {
			return fmt.Errorf("查詢掛載所屬資產失敗: %w", err)
		}
		member := &model.CredentialRotationMember{
			RotationID:      rot.ID,
			AccountID:       binding.ID,
			CredentialID:    rot.CredentialID,
			Username:        binding.Username,
			AssetID:         binding.AssetID,
			AssetName:       asset.Name,
			FromVersionID:   binding.EffectiveVersionID,
			TargetVersionID: targetVersionID,
			State:           model.CredentialMemberQueued,
		}
		if err := tx.Create(member).Error; err != nil {
			return fmt.Errorf("建立輪替成員失敗: %w", err)
		}
	}
	return nil
}

// credentialBindings 取某憑證當下的全部掛載（依掛載識別排序，使成員順序可重現）。
func credentialBindingRows(db *gorm.DB, credentialID uint) ([]model.AssetAccount, error) {
	var out []model.AssetAccount
	if err := db.Where("credential_id = ?", credentialID).
		Order("id ASC").Find(&out).Error; err != nil {
		return nil, fmt.Errorf("查詢憑證掛載失敗: %w", err)
	}
	return out, nil
}

// rotationMembers 取某輪替的全部成員。
func rotationMembers(db *gorm.DB, rotationID uint) ([]model.CredentialRotationMember, error) {
	var out []model.CredentialRotationMember
	if err := db.Where("rotation_id = ?", rotationID).
		Order("id ASC").Find(&out).Error; err != nil {
		return nil, fmt.Errorf("查詢輪替成員失敗: %w", err)
	}
	return out, nil
}

// loadRotation 取輪替列。
func loadRotation(db *gorm.DB, rotationID uint) (*model.CredentialRotation, error) {
	var rot model.CredentialRotation
	if err := db.Where("id = ?", rotationID).First(&rot).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrCredentialRotationNotFound
		}
		return nil, fmt.Errorf("查詢輪替失敗: %w", err)
	}
	return &rot, nil
}

// loadRotationMember 取成員列並確認歸屬。
//
// 歸屬條件寫進查詢而不是查完再比：查完再比一旦漏掉那個 if，就是一條
// 「給我任意成員識別，我照著推進」的路徑。
func loadRotationMember(db *gorm.DB, rotationID, memberID uint) (*model.CredentialRotationMember, error) {
	var member model.CredentialRotationMember
	err := db.Where("id = ? AND rotation_id = ?", memberID, rotationID).First(&member).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrCredentialRotationMemberNotFound
		}
		return nil, fmt.Errorf("查詢輪替成員失敗: %w", err)
	}
	return &member, nil
}

// AggregateState 憑證的聚合輪替狀態（純投影）。
func (s *CredentialRotationService) AggregateState(credentialID uint) (string, error) {
	return credentialAggregateState(s.db, credentialID)
}

// credentialAggregateState 由憑證的輪替指標與逐成員狀態投影出聚合態。
//
// **partial 先於 changing**：一旦出現「有的已就位、有的還沒」，那就是操作者最需要
// 看見的事實；把它蓋成 changing 會讓「部分成功」這件事只能靠逐台展開才看得出來。
func credentialAggregateState(db *gorm.DB, credentialID uint) (string, error) {
	cred, err := loadCredential(db, credentialID)
	if err != nil {
		return "", err
	}
	if cred.ActiveRotationID == nil || *cred.ActiveRotationID == 0 {
		if cred.PendingVersionID != nil && *cred.PendingVersionID != 0 {
			return CredentialAggregateOutOfSync, nil
		}
		return CredentialAggregateIdle, nil
	}
	members, err := rotationMembers(db, *cred.ActiveRotationID)
	if err != nil {
		return "", err
	}
	if len(members) == 0 {
		return CredentialAggregateQueued, nil
	}
	applied, queued, inflight := 0, 0, 0
	for i := range members {
		switch members[i].State {
		case model.CredentialMemberApplied:
			applied++
		case model.CredentialMemberQueued:
			queued++
		case model.CredentialMemberChanging, model.CredentialMemberChangedUnverified,
			model.CredentialMemberRetryWait:
			inflight++
		}
	}
	switch {
	case applied > 0 && applied < len(members):
		return CredentialAggregatePartial, nil
	case queued == len(members):
		return CredentialAggregateQueued, nil
	case queued == 0 && inflight == 0:
		// 全部成員都停在終局失敗或已收束：沒有任何一台還在動，也沒有一台就位。
		// 報成 changing 會讓操作者一直等一個永遠不會發生的進展——這裡要看見的
		// 事實是「本輪停住了，接下來只能逐台補跑」
		return CredentialAggregateOutOfSync, nil
	default:
		return CredentialAggregateChanging, nil
	}
}

// assertCredentialConverged 上一輪未收斂時拒絕啟動新一輪。
func assertCredentialConverged(db *gorm.DB, cred *model.Credential) error {
	if cred == nil {
		return ErrCredentialNotFound
	}
	if (cred.ActiveRotationID == nil || *cred.ActiveRotationID == 0) &&
		cred.PendingVersionID != nil && *cred.PendingVersionID != 0 {
		return ErrCredentialOutOfSync
	}
	return nil
}

// openRotationForPendingVersion 取產生此待生效版本、且尚未收斂的那一輪（無則 nil, nil）。
//
// 以目標版本而非進行中識別定位：未同步狀態的定義就是「輪替已結束、待生效版本還在」，
// 那時憑證的進行中識別已經清空，只有版本識別連得回那一輪。
func openRotationForPendingVersion(db *gorm.DB, cred *model.Credential) (*model.CredentialRotation, error) {
	if cred == nil || cred.PendingVersionID == nil || *cred.PendingVersionID == 0 {
		return nil, nil
	}
	var rots []model.CredentialRotation
	err := db.Where("credential_id = ? AND target_version_id = ? AND status IN ?",
		cred.ID, *cred.PendingVersionID, rotationOpenStatuses).
		Order("id DESC").Limit(1).Find(&rots).Error
	if err != nil {
		return nil, fmt.Errorf("查詢未收斂的輪替失敗: %w", err)
	}
	if len(rots) == 0 {
		return nil, nil
	}
	return &rots[0], nil
}

// convergeCredentialAfterBindingRemoval 掛載被移除之後重評本輪是否已收斂。
//
// 卸載是未同步狀態的出口之一（死主機移得掉）。移除的若正是最後一台未就位的主機，
// 沒有任何後續動作會再去看一眼——憑證會永遠停在未同步，而已經沒有東西要收斂了。
func convergeCredentialAfterBindingRemoval(tx *gorm.DB, cred *model.Credential) error {
	rot, err := openRotationForPendingVersion(tx, cred)
	if err != nil || rot == nil {
		return err
	}
	return convergeRotationIfComplete(tx, rot, cred)
}

// supersedePendingRotation 操作者宣告的密文**取代**尚未收斂的待生效版本。
//
// 兩者並存是矛盾的：宣告的密文說「這組秘密現在長這樣」並立即改寫全部掛載的
// 就位版本，而未收斂的那一輪仍握著另一組待生效秘密與可補跑的成員。留著它，
// 一次補跑就會把遠端改回上一輪的秘密、收斂時再把它提升為現行版本，
// 於是操作者剛剛宣告的那一組在沒有任何提示的情況下被蓋掉。
//
// terminal_failed 的成員刻意不動：它已是終態，且「這台確定改不動」比「本輪收束」
// 更具體，改寫只會抹掉資訊；它同樣推不動，因為補跑入口已由
// assertRotationTargetStillPending 擋下。
func supersedePendingRotation(tx *gorm.DB, cred *model.Credential) error {
	if cred == nil || cred.PendingVersionID == nil || *cred.PendingVersionID == 0 {
		return nil
	}
	rot, err := openRotationForPendingVersion(tx, cred)
	if err != nil {
		return err
	}
	if rot != nil {
		members, merr := rotationMembers(tx, rot.ID)
		if merr != nil {
			return merr
		}
		for i := range members {
			switch members[i].State {
			case model.CredentialMemberApplied, model.CredentialMemberAbandoned,
				model.CredentialMemberTerminalFailed:
				continue
			}
			if err := transitionMember(tx, &members[i], model.CredentialMemberAbandoned,
				memberTransition{LastError: members[i].LastError}); err != nil {
				return err
			}
		}
		now := time.Now()
		if err := tx.Model(&model.CredentialRotation{}).
			Where("id = ? AND status = ?", rot.ID, model.CredentialRotationRunning).
			Updates(map[string]any{
				"status":      model.CredentialRotationAbandoned,
				"finished_at": &now,
			}).Error; err != nil {
			return fmt.Errorf("收束被取代的輪替失敗: %w", err)
		}
	}
	if err := tx.Model(&model.Credential{}).Where("id = ?", cred.ID).
		Update("pending_version_id", nil).Error; err != nil {
		return fmt.Errorf("清除待生效版本失敗: %w", err)
	}
	cred.PendingVersionID = nil
	return nil
}

// assertRotationTargetStillPending 整組輪替的目標版本必須仍是憑證的待生效版本。
//
// 待生效版本被操作者宣告的密文取代之後，本輪的目標已經不是憑證要收斂到的那一版。
// 再推進一台，等於把一組沒有人要的秘密推上遠端，並在收斂時把它提升為現行版本。
//
// 拆分模式沒有整組的目標版本（每台不同），不適用本判定。
func assertRotationTargetStillPending(db *gorm.DB, rot *model.CredentialRotation) error {
	if rot == nil || rot.Mode != model.CredentialRotationModeGroup {
		return nil
	}
	cred, err := loadCredential(db, rot.CredentialID)
	if err != nil {
		return err
	}
	if rot.TargetVersionID == nil || *rot.TargetVersionID == 0 ||
		cred.PendingVersionID == nil || *cred.PendingVersionID != *rot.TargetVersionID {
		return ErrCredentialRotationNotRunning
	}
	return nil
}

// Abandon 放棄本輪：**只表示停止自動化，不回滾**。
//
// 已就位者不改回舊密、不刪候選、不強制提升待生效版本，且對遠端零額外操作——
// 回滾要先登入那台機器，而「放棄」這個動作的意思正是不再對它下手。
//
// 兩條出口：
//   - 無任何成員動過遠端（全部仍在排隊或等待重試，且無已下達的候選）：待生效版本
//     直接丟棄、清除進行中的輪替識別，憑證回到 idle。這一輪等於沒發生過，
//     不該讓憑證背著一個永遠收斂不了的狀態。
//   - 否則：保留待生效版本與成員證據，憑證進入 out_of_sync，後續只能逐台補跑至收斂。
func (s *CredentialRotationService) Abandon(ctx context.Context, rotationID uint) error {
	userID, operator := model.UserFromContext(ctx)
	return s.db.Transaction(func(tx *gorm.DB) error {
		rot, err := loadRotation(tx, rotationID)
		if err != nil {
			return err
		}
		if rot.Status != model.CredentialRotationRunning {
			return ErrCredentialRotationNotRunning
		}
		cred, err := lockCredentialRow(tx, rot.CredentialID)
		if err != nil {
			return err
		}
		// **取鎖後重讀，且要確認本輪仍是憑證進行中的那一輪**：等鎖期間本輪可能
		// 已經收斂完成，而下一輪已經發起。以取鎖前的快照續走，清掉的會是別人
		// 那一輪的進行中識別——那一輪從此沒有任何路徑推得動，畫面上卻只看到
		// 一個回到閒置的憑證與幾台停在未就位的主機
		rot, err = loadRotation(tx, rot.ID)
		if err != nil {
			return err
		}
		if rot.Status != model.CredentialRotationRunning {
			return ErrCredentialRotationNotRunning
		}
		if cred.ActiveRotationID == nil || *cred.ActiveRotationID != rot.ID {
			return ErrCredentialRotationNotRunning
		}
		members, err := rotationMembers(tx, rot.ID)
		if err != nil {
			return err
		}

		touched := false
		for i := range members {
			member := members[i]
			switch member.State {
			case model.CredentialMemberApplied, model.CredentialMemberChangedUnverified,
				model.CredentialMemberChanging, model.CredentialMemberTerminalFailed:
				// changing／terminal_failed 也算動過：前者的遠端結果此刻未知，
				// 後者可能是「已下達但確定失敗」，兩者都不該讓本輪被當成沒發生過
				touched = true
				continue
			}
			delivered, cerr := memberHasDeliveredCandidate(tx, member.AccountID)
			if cerr != nil {
				return cerr
			}
			if delivered {
				touched = true
				continue
			}
			if err := transitionMember(tx, &member, model.CredentialMemberAbandoned,
				memberTransition{}); err != nil {
				return err
			}
			// 收束的定義就是「從未動過遠端」，故它的候選必然不在任何主機上生效。
			// 留著它會靜默擋住這個掛載後續全部的改密請求（候選存在即記為略過），
			// 而那條候選對誰都不再有意義
			if err := deleteAccountCandidate(tx, member.AccountID); err != nil {
				return err
			}
		}

		now := time.Now()
		// 兩次寫入都帶條件並檢查影響列數：列鎖在 sqlite 是無操作（靠單寫者序列化），
		// 條件更新才是兩種方言共通的那一道防線
		res := tx.Model(&model.CredentialRotation{}).
			Where("id = ? AND status = ?", rot.ID, model.CredentialRotationRunning).
			Updates(map[string]any{
				"status":      model.CredentialRotationAbandoned,
				"finished_at": &now,
			})
		if res.Error != nil {
			return fmt.Errorf("更新輪替狀態失敗: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			return ErrCredentialRotationNotRunning
		}

		updates := map[string]any{"active_rotation_id": nil}
		if !touched {
			updates["pending_version_id"] = nil
		}
		res = tx.Model(&model.Credential{}).
			Where("id = ? AND active_rotation_id = ?", cred.ID, rot.ID).
			Updates(updates)
		if res.Error != nil {
			return fmt.Errorf("清除輪替狀態失敗: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			return ErrCredentialRotationNotRunning
		}
		return writeCredentialAudit(s.auditTx, tx, credentialAudit{
			CredentialID: cred.ID,
			Operation:    credentialOpAbandon,
			Scope:        cred.Scope,
			Fields:       []string{"active_rotation_id"},
		}, userID, operator)
	})
}

// memberHasDeliveredCandidate 該掛載是否留著**已下達**的候選秘密。
//
// 判定用「已下達」而非「候選存在」：拆分模式的候選在起始交易就備妥，那時候還沒有
// 任何遠端被觸碰過。已下達的候選才是「那把可能已在遠端生效的秘密」，它還在就代表
// 遠端狀態不可知，本輪不能被當成沒發生過。
func memberHasDeliveredCandidate(db *gorm.DB, accountID uint) (bool, error) {
	var count int64
	if err := db.Model(&model.ChangeSecretCandidate{}).
		Where("account_id = ? AND applied = ?", accountID, true).Count(&count).Error; err != nil {
		return false, fmt.Errorf("查詢未決候選失敗: %w", err)
	}
	return count > 0, nil
}

// ActiveRotationFor 取憑證進行中的輪替（無則回 nil, nil）。
func (s *CredentialRotationService) ActiveRotationFor(credentialID uint) (*model.CredentialRotation, error) {
	cred, err := loadCredential(s.db, credentialID)
	if err != nil {
		return nil, err
	}
	if cred.ActiveRotationID == nil || *cred.ActiveRotationID == 0 {
		return nil, nil
	}
	return loadRotation(s.db, *cred.ActiveRotationID)
}

// Members 取某輪替的全部成員（供呈現面與逐台補跑挑選目標）。
func (s *CredentialRotationService) Members(rotationID uint) ([]model.CredentialRotationMember, error) {
	return rotationMembers(s.db, rotationID)
}

// DueRotationMember 一筆待推進的輪替成員（推進者只需要這三個識別）。
type DueRotationMember struct {
	RotationID uint
	MemberID   uint
	AccountID  uint
}

// memberPendingStates 尚未收束、仍可被推進的成員狀態。
//
// applied 是本輪終態；queued 由發起端的推進負責；abandoned／terminal_failed 要由
// 操作者顯式補跑（自動重排會讓一台確定改不動的機器被無限期地反覆嘗試）。
var memberPendingStates = []string{
	model.CredentialMemberRetryWait,
	model.CredentialMemberChangedUnverified,
}

// rotationOpenStatuses 仍可推進成員的輪替狀態。
//
// 含 abandoned：放棄不回滾，未就位的成員要能逐台補跑至收斂，那是未同步狀態的唯一出口。
var rotationOpenStatuses = []string{
	model.CredentialRotationRunning,
	model.CredentialRotationAbandoned,
}

// rotationCaptureStatuses 會**捕獲候選**的輪替狀態。
//
// **只有進行中的那一輪**，刻意窄於 rotationOpenStatuses：放棄之後憑證的
// 進行中識別已清空，該掛載對計劃與批次重新開放，此後建立的候選屬於那些路徑。
// 若連放棄的輪替也捕獲候選，新候選會被永久攔在單帳號轉正之外——遠端密碼已經
// 改掉、就位版本卻永遠不更新，而畫面上什麼異常也看不到。
// 放棄後仍未就位的成員以逐台補跑收斂（顯式的成員推進），不經候選排程。
var rotationCaptureStatuses = []string{model.CredentialRotationRunning}

// MemberForAccount 該掛載當下是否屬於某個**進行中**輪替的成員。
//
// **候選重試排程的分流依據**：輪替引擎建立的候選一律交回成員路徑推進，不得走
// 單帳號的轉正——後者會在共用憑證上多開一個版本、在成員轉移表之外改寫就位版本，
// 拆分模式下更會把那台唯一的新秘密寫回原本要脫離的共用憑證。
func (s *CredentialRotationService) MemberForAccount(accountID uint) (*DueRotationMember, error) {
	return rotationMemberForAccount(s.db, accountID)
}

func rotationMemberForAccount(db *gorm.DB, accountID uint) (*DueRotationMember, error) {
	if accountID == 0 {
		return nil, nil
	}
	// 成員表不存在＝這個裝配裡沒有輪替引擎，故不可能有輪替建立的候選。
	// （生產一律有表；本判定只讓不涉及輪替的裝配不必攜帶整組輪替結構）
	if db.Migrator() != nil && !db.Migrator().HasTable(&model.CredentialRotationMember{}) {
		return nil, nil
	}
	var rows []DueRotationMember
	err := db.Model(&model.CredentialRotationMember{}).
		Select("credential_rotation_members.rotation_id AS rotation_id,"+
			" credential_rotation_members.id AS member_id,"+
			" credential_rotation_members.account_id AS account_id").
		Joins("JOIN credential_rotations ON credential_rotations.id = credential_rotation_members.rotation_id").
		Where("credential_rotation_members.account_id = ?", accountID).
		Where("credential_rotation_members.state <> ?", model.CredentialMemberApplied).
		Where("credential_rotations.status IN ?", rotationCaptureStatuses).
		Order("credential_rotation_members.id DESC").Limit(1).Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("查詢掛載所屬的輪替成員失敗: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &rows[0], nil
}

// DueMembers 到期待推進的輪替成員（有界批次）。
//
// **與候選列並列掃描而非取而代之**：乾淨失敗時候選會被清掉，成員卻停在等待重試；
// 只掃候選就永遠不會回頭看它，那台機器會一直停在「等下一次」而沒有下一次。
//
// **只掃進行中的那一輪**（同 rotationCaptureStatuses）：放棄之後那些成員不再由
// 排程自動推進，否則排程會反覆把上一輪的待生效秘密推向已被別條路徑改過密的主機。
// 補跑改由操作者顯式逐台推進，那正是放棄這個動作的語義——停止自動化。
func (s *CredentialRotationService) DueMembers(limit int) ([]DueRotationMember, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var rows []DueRotationMember
	err := s.db.Model(&model.CredentialRotationMember{}).
		Select("credential_rotation_members.rotation_id AS rotation_id,"+
			" credential_rotation_members.id AS member_id,"+
			" credential_rotation_members.account_id AS account_id").
		Joins("JOIN credential_rotations ON credential_rotations.id = credential_rotation_members.rotation_id").
		Where("credential_rotation_members.state IN ?", memberPendingStates).
		Where("credential_rotation_members.next_attempt_at IS NOT NULL").
		Where("credential_rotation_members.next_attempt_at <= ?", time.Now()).
		Where("credential_rotations.status IN ?", rotationCaptureStatuses).
		Order("credential_rotation_members.next_attempt_at ASC").
		Limit(limit).Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("查詢到期的輪替成員失敗: %w", err)
	}
	return rows, nil
}
