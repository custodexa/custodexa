package asset

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
)

// 每台各自隨機的拆分，與單台脫離共用。
//
// # 兩者是同一條流程
//
// 「每台各自隨機」與「單台脫離共用」的差別只有兩個：成員數，以及新秘密可不可以由
// 操作者指定。內部走同一條可恢復的分段流程，故不重寫第二套狀態機——兩套會在
// 「失敗了要怎麼收」這件事上慢慢長出差異，而那正是最不該有差異的地方。
//
// # 為什麼不先解除關聯再逐台改密
//
// 先拆再改的做法把第二步交給人：拆離後忘記改密的主機留著一組已知的共用密碼，
// 而系統此刻已經不記得它們曾經共用。故一律**先改成功、再拆離**，失敗者留在原憑證上。
//
// # 對外不得宣稱整批原子成功
//
// 跨多台遠端系統無法構成單一資料庫交易。對外是一個受審計的操作，內部是可恢復的
// 分段流程；放棄後已成功的成員維持已拆離，**不重新掛回**——遠端已不再使用共用秘密，
// 掛回是製造一個「群組成員但密碼不一致」的更糟狀態。

var (
	// ErrCredentialNotShared 拆分與脫離只對共用憑證成立
	ErrCredentialNotShared = errors.New("此操作僅適用於共用憑證")
	// ErrCredentialDetachSourceInvalid 新秘密來源不在值域內
	ErrCredentialDetachSourceInvalid = errors.New("新秘密來源僅允許 random 或 custom")
)

// 單台脫離的新秘密來源。
const (
	// DetachSourceRandom 由系統依密碼策略隨機產生
	DetachSourceRandom = "random"
	// DetachSourceCustom 由操作者自訂
	DetachSourceCustom = "custom"
)

// DetachCredentialRequest 單台脫離共用。
type DetachCredentialRequest struct {
	// Source 見 DetachSource* 常數
	Source string `json:"source"`
	// Policy Source=random 時的生成策略
	Policy PasswordPolicy `json:"policy"`
	// Password／PrivateKey Source=custom 時的新秘密（二擇一，依憑證型別）
	Password   string `json:"password"`
	PrivateKey string `json:"private_key"`
}

// CredentialDetachFailedError 脫離未完成：該掛載仍在原共用憑證上。
//
// 帶回成員的終態與機器可讀原因碼——「失敗了」與「遠端結果不明」對操作者的下一步
// 完全不同：前者可以直接再試，後者要先確認那台機器現在到底吃哪一組秘密。
type CredentialDetachFailedError struct {
	State  string
	Reason string
}

func (e *CredentialDetachFailedError) Error() string {
	return fmt.Sprintf("脫離共用未完成: state=%s reason=%s", e.State, e.Reason)
}

// StartSplit 發起「每台各自隨機」：各台改為互不相同的新秘密，改完即解除共用關係。
//
// 起始交易內鎖定該憑證與全部掛載、快照成員，並為每台各建一筆不同的候選秘密；
// **不先解除關聯**。逐台的遠端修改與驗證由 Run 推進。
func (s *CredentialRotationService) StartSplit(ctx context.Context, credentialID uint,
	req StartRotationRequest) (*model.CredentialRotation, error) {

	bindings, err := s.currentBindingsForSplit(credentialID)
	if err != nil {
		return nil, err
	}
	// 拆分會動到全部掛載的遠端秘密，逐台驗權。
	// **只在操作者直接發起的入口驗**：批次入口（StartSplitFor）的權限判定屬批次的
	// 目標選取面，在此重驗會用到與批次不同的身分上下文
	if err := s.assertBoundAssetsPermission(ctx, s.db, credentialID); err != nil {
		return nil, err
	}
	return s.startSplitRotation(ctx, credentialID, bindings, req.Policy, nil)
}

// StartSplitFor 只對指定的幾個掛載發起拆分（批次以帳號名為軸時，選中的目標可能
// 只是該共用憑證的一部分）。
//
// **未選中的掛載不動**：它們的主機沒有被觸碰，仍以原憑證的就位版本連線。
// 收尾規則不變——原憑證剩一個掛載即轉為專用，零掛載且無未決候選即回收。
func (s *CredentialRotationService) StartSplitFor(ctx context.Context, credentialID uint,
	accountIDs []uint, req StartRotationRequest) (*model.CredentialRotation, error) {

	all, err := s.currentBindingsForSplit(credentialID)
	if err != nil {
		return nil, err
	}
	wanted := make(map[uint]bool, len(accountIDs))
	for _, id := range accountIDs {
		wanted[id] = true
	}
	selected := make([]model.AssetAccount, 0, len(accountIDs))
	for i := range all {
		if wanted[all[i].ID] {
			selected = append(selected, all[i])
		}
	}
	if len(selected) == 0 {
		return nil, ErrCredentialRotationNoBinding
	}
	return s.startSplitRotation(ctx, credentialID, selected, req.Policy, nil)
}

// currentBindingsForSplit 取拆分的成員母體並檢核憑證範圍。
func (s *CredentialRotationService) currentBindingsForSplit(credentialID uint) ([]model.AssetAccount, error) {
	cred, err := loadCredential(s.db, credentialID)
	if err != nil {
		return nil, err
	}
	if cred.Scope != model.CredentialScopeShared {
		return nil, ErrCredentialNotShared
	}
	bindings, err := credentialBindingRows(s.db, credentialID)
	if err != nil {
		return nil, err
	}
	if len(bindings) == 0 {
		return nil, ErrCredentialRotationNoBinding
	}
	return bindings, nil
}

// startSplitRotation 拆分與脫離共用的共同起始交易。
//
// fixedSecret 非 nil＝單台脫離且操作者自訂新秘密；nil＝每台各自隨機。
func (s *CredentialRotationService) startSplitRotation(ctx context.Context, credentialID uint,
	bindings []model.AssetAccount, policy PasswordPolicy,
	fixedSecret *CandidateSecret) (*model.CredentialRotation, error) {

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
		rot := &model.CredentialRotation{
			CredentialID: cred.ID,
			Epoch:        cred.RotationEpoch + 1,
			Mode:         model.CredentialRotationModeSplit,
			// 拆分沒有整組的目標版本：每台目標不同，且只有各自成功時才知道是哪一版
			TargetVersionID:          nil,
			Status:                   model.CredentialRotationRunning,
			RequestedBy:              userID,
			RequestedByName:          operator,
			PasswordLength:           policy.Length,
			PasswordIncludeSymbol:    policy.IncludeSymbol,
			PasswordExcludeAmbiguous: policy.ExcludeAmbiguous,
			StartedAt:                time.Now(),
		}
		if err := tx.Create(rot).Error; err != nil {
			return fmt.Errorf("建立輪替失敗: %w", err)
		}
		if err := snapshotRotationMembers(tx, rot, bindings, nil); err != nil {
			return err
		}
		for i := range bindings {
			if err := s.seedSplitCandidate(ctx, tx, cred, &bindings[i], policy, fixedSecret); err != nil {
				return err
			}
		}
		if err := tx.Model(&model.Credential{}).Where("id = ?", cred.ID).
			Updates(map[string]any{
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
			Fields:       []string{"active_rotation_id"},
		}, userID, operator)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// seedSplitCandidate 為單一掛載建立它自己的候選秘密。
//
// **候選先於任何遠端動作落庫**：拆分的每一台各有一組秘密，那組秘密在候選列上是
// 唯一副本——它若只在記憶體，行程被砍時該台就沒有任何一組已知的秘密可以登入。
func (s *CredentialRotationService) seedSplitCandidate(ctx context.Context, tx *gorm.DB,
	cred *model.Credential, binding *model.AssetAccount, policy PasswordPolicy,
	fixedSecret *CandidateSecret) error {

	in := CandidateInput{
		AssetID:      binding.AssetID,
		AccountID:    binding.ID,
		SecretType:   cred.SecretType,
		CredentialID: cred.ID,
	}
	in.AccountUsername = cred.Username
	switch {
	case fixedSecret != nil:
		in.Password = fixedSecret.Password
		in.PrivateKey = fixedSecret.PrivateKey
	case cred.SecretType == model.ChangeSecretTypeSSHKey:
		private, _, err := GenerateSSHKeyPair(fmt.Sprintf("credential-%d-binding-%d", cred.ID, binding.ID))
		if err != nil {
			return fmt.Errorf("產生金鑰對失敗: %w", err)
		}
		in.PrivateKey = private
	default:
		password, err := GeneratePassword(normalizeRotationPolicy(policy))
		if err != nil {
			return fmt.Errorf("產生新密碼失敗: %w", err)
		}
		in.Password = password
	}
	if _, err := s.candidates.CreateInTx(ctx, tx, in); err != nil {
		return err
	}
	return nil
}

// commitSplitApplied 單台成功的交易：建專用憑證與其 v1、改綁掛載、就位、刪候選、
// 寫審計、標記成員已就位，並在**同一交易**內對原憑證收尾。
//
// **掛載識別保持不變**：改綁只換 credential_id，既有記錄與授權範圍因此不斷鏈。
func (s *CredentialRotationService) commitSplitApplied(ctx context.Context,
	rot *model.CredentialRotation, member *model.CredentialRotationMember, mc *memberContext) error {

	userID, operator := model.UserFromContext(ctx)
	passwordEnc, privateKeyEnc, err := s.encryptRotationSecret(ctx, mc)
	if err != nil {
		return err
	}

	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := lockAssetForAccountMutation(tx, member.AssetID); err != nil {
			return err
		}
		source, err := lockCredentialRow(tx, member.CredentialID)
		if err != nil {
			return err
		}
		account, err := resolveAssetAccount(tx, member.AssetID, member.AccountID)
		if err != nil {
			return err
		}
		if account == nil {
			return ErrAssetAccountNotFound
		}
		if account.CredentialID != source.ID {
			// 本成員已被改綁到別的憑證：本輪對它的認知已過時，不得再動
			return ErrCredentialBindingNotFound
		}

		dedicated, err := createDedicatedCredential(tx, source.Username, source.SecretType,
			source.AuthMethod, source.ProtocolFamily)
		if err != nil {
			return err
		}
		// 未被本次更動的那一欄自原就位版本原樣帶過來（同一張表的同一欄，密文原樣搬、
		// 不解密）：只換密碼不得順手清掉私鑰備援入口
		pwEnc, keyEnc := passwordEnc, privateKeyEnc
		if account.EffectiveVersionID != nil {
			pwEnc, keyEnc, err = carryOverVersionCiphertext(tx, source.ID,
				*account.EffectiveVersionID, pwEnc, keyEnc)
			if err != nil {
				return err
			}
		}
		version, err := appendCredentialVersion(tx, dedicated.ID, mc.secretType,
			pwEnc, keyEnc, model.CredentialVersionReasonDetach)
		if err != nil {
			return err
		}
		if err := setCredentialCurrentVersion(tx, dedicated.ID, version.ID); err != nil {
			return err
		}

		// 改綁：掛載識別不變，就位版本暫清空，由成員轉入已就位時寫入（唯一寫入點）
		res := tx.Model(&model.AssetAccount{}).
			Where("id = ? AND credential_id = ?", account.ID, source.ID).
			Updates(map[string]any{
				"credential_id":        dedicated.ID,
				"effective_version_id": nil,
			})
		if res.Error != nil {
			return fmt.Errorf("改綁掛載失敗: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			return ErrCredentialBindingNotFound
		}
		if err := tx.Model(&model.CredentialRotationMember{}).Where("id = ?", member.ID).
			Update("target_version_id", version.ID).Error; err != nil {
			return fmt.Errorf("寫入成員目標版本失敗: %w", err)
		}

		m, err := loadRotationMember(tx, rot.ID, member.ID)
		if err != nil {
			return err
		}
		if err := transitionMember(tx, m, model.CredentialMemberApplied, memberTransition{}); err != nil {
			return err
		}
		if err := deleteAccountCandidate(tx, m.AccountID); err != nil {
			return err
		}
		if err := writeCredentialAudit(s.auditTx, tx, credentialAudit{
			CredentialID: dedicated.ID,
			Operation:    credentialOpDetach,
			Scope:        dedicated.Scope,
			Fields:       []string{"credential_id", "effective_version_id"},
			AssetID:      m.AssetID,
			AccountID:    m.AccountID,
		}, userID, operator); err != nil {
			return err
		}
		member.State = m.State
		member.TargetVersionID = m.TargetVersionID
		member.AppliedAt = m.AppliedAt

		if err := s.convergeIfComplete(tx, rot, source); err != nil {
			return err
		}
		return settleSourceCredential(tx, source)
	})
}

// encryptRotationSecret 把本成員的新秘密加密成憑證版本欄的密文。
//
// **不自候選列原樣搬**：信封的附加驗證資料綁「表｜欄」，候選列與版本列是不同的表與欄，
// 原樣搬過去會解不開。同表同欄之間的原樣搬（未更動的那一欄）另由
// carryOverVersionCiphertext 承擔，那條路徑確實不解密。
func (s *CredentialRotationService) encryptRotationSecret(ctx context.Context,
	mc *memberContext) (string, string, error) {

	if mc.secretType == model.ChangeSecretTypeSSHKey {
		enc, err := s.crypto.EncryptFor(ctx, keyvault.RefCredentialVersionPrivateKey, mc.newPrivateKey)
		if err != nil {
			return "", "", fmt.Errorf("加密私鑰失敗: %w", err)
		}
		return "", enc, nil
	}
	enc, err := s.crypto.EncryptFor(ctx, keyvault.RefCredentialVersionPassword, mc.newPassword)
	if err != nil {
		return "", "", fmt.Errorf("加密密碼失敗: %w", err)
	}
	return enc, "", nil
}

// settleSourceCredential 拆離之後對原憑證的收尾。
//
// 剩一個掛載＝共用關係已不存在，轉為專用並清空名稱（一個人的「共用」不是共用，
// 留著會讓憑證庫持續標示一個已經不存在的共用關係）；零掛載且無未決候選則軟刪。
// **共用憑證零掛載本身是合法的待用狀態**，故只在確定是拆離造成的孤兒時才刪。
func settleSourceCredential(tx *gorm.DB, cred *model.Credential) error {
	count, err := credentialBindingCount(tx, cred.ID)
	if err != nil {
		return err
	}
	if count == 0 {
		pending, perr := credentialPendingCandidates(tx, cred.ID)
		if perr != nil {
			return perr
		}
		if pending > 0 {
			return nil
		}
		if err := tx.Delete(&model.Credential{}, cred.ID).Error; err != nil {
			return fmt.Errorf("刪除零掛載的原憑證失敗: %w", err)
		}
		return nil
	}
	if count == 1 && cred.Scope == model.CredentialScopeShared {
		if err := tx.Model(&model.Credential{}).Where("id = ?", cred.ID).
			Updates(map[string]any{
				"scope": model.CredentialScopeDedicated,
				"name":  nil,
			}).Error; err != nil {
			return fmt.Errorf("原憑證轉為專用失敗: %w", err)
		}
		cred.Scope = model.CredentialScopeDedicated
		cred.Name = nil
	}
	return nil
}

// Detach 單台脫離共用：以該掛載的就位版本登入、套用新秘密、以新秘密驗證，
// **通過才**建立專用憑證並改綁。
//
// 驗證失敗或遠端結果不明時維持共用關係，原憑證與其他掛載不受影響；結果不明者
// 保留候選供補跑。脫離與卸載是兩件事——卸載只移除掛載、主機上的秘密不動；
// 脫離會改變主機上的秘密。
func (s *CredentialRotationService) Detach(ctx context.Context, credentialID, accountID uint,
	req DetachCredentialRequest) (*model.CredentialRotation, error) {

	cred, err := loadCredential(s.db, credentialID)
	if err != nil {
		return nil, err
	}
	if cred.Scope != model.CredentialScopeShared {
		return nil, ErrCredentialNotShared
	}
	binding, err := detachBinding(s.db, credentialID, accountID)
	if err != nil {
		return nil, err
	}
	// 脫離只動這一台的遠端秘密，故只驗這一台
	if err := s.assertAssetPermission(ctx, binding.AssetID); err != nil {
		return nil, err
	}
	fixed, err := detachFixedSecret(cred, req)
	if err != nil {
		return nil, err
	}

	rot, err := s.startSplitRotation(ctx, credentialID,
		[]model.AssetAccount{*binding}, req.Policy, fixed)
	if err != nil {
		return nil, err
	}
	if err := s.Run(ctx, rot.ID); err != nil {
		return nil, err
	}

	members, err := rotationMembers(s.db, rot.ID)
	if err != nil {
		return nil, err
	}
	if len(members) == 1 && members[0].State == model.CredentialMemberApplied {
		return rot, nil
	}
	state, reason := "", ""
	if len(members) == 1 {
		state, reason = members[0].State, members[0].LastError
	}
	return rot, &CredentialDetachFailedError{State: state, Reason: reason}
}

// detachBinding 取要脫離的掛載並確認它掛在該憑證上。
func detachBinding(db *gorm.DB, credentialID, accountID uint) (*model.AssetAccount, error) {
	var binding model.AssetAccount
	err := db.Where("id = ? AND credential_id = ?", accountID, credentialID).First(&binding).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrCredentialBindingNotFound
		}
		return nil, fmt.Errorf("查詢掛載失敗: %w", err)
	}
	return &binding, nil
}

// detachFixedSecret 自訂新密的檢核；隨機來源回 nil（由起始交易依策略產生）。
//
// **空值一律拒絕**：新秘密的來源是二擇一，不是三選一。把未填欄位讀成「隨機」等於
// 替操作者決定要改掉那台主機的密碼——脫離共用會動遠端，這個選擇必須是明示的。
func detachFixedSecret(cred *model.Credential, req DetachCredentialRequest) (*CandidateSecret, error) {
	switch req.Source {
	case DetachSourceRandom:
		return nil, nil
	case DetachSourceCustom:
		if cred.SecretType == model.ChangeSecretTypeSSHKey {
			if req.PrivateKey == "" {
				return nil, ErrCredentialSecretRequired
			}
			return &CandidateSecret{PrivateKey: req.PrivateKey}, nil
		}
		if req.Password == "" {
			return nil, ErrCredentialSecretRequired
		}
		return &CandidateSecret{Password: req.Password}, nil
	default:
		return nil, ErrCredentialDetachSourceInvalid
	}
}
