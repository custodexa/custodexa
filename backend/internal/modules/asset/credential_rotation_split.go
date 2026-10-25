package asset

import (
	"context"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/material"
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

	if err := s.requireManagement(ctx, nil, CredOpSplit, splitGateWhole().caps,
		[]uint{credentialID}, nil, nil); err != nil {
		return nil, err
	}
	bindings, err := s.currentBindingsForSplit(credentialID)
	if err != nil {
		return nil, err
	}
	return s.startSplitRotation(ctx, credentialID, bindings, req.Policy, nil, splitGateWhole(), &req.ImpactConfirmationID, nil)
}

// StartSplitFor 只對指定的幾個掛載發起拆分（批次以帳號名為軸時，選中的目標可能
// 只是該共用憑證的一部分）。
//
// **未選中的掛載不動**：它們的主機沒有被觸碰，仍以原憑證的就位版本連線。
// 收尾規則不變——原憑證剩一個掛載即轉為專用，零掛載且無未決候選即回收。
func (s *CredentialRotationService) StartSplitFor(ctx context.Context, credentialID uint,
	accountIDs []uint, req StartRotationRequest) (*model.CredentialRotation, error) {
	return s.startSplitForBatch(ctx, credentialID, accountIDs, req, nil)
}

// startSplitForBatch 同 StartSplitFor；bound 非 nil＝由批次發起，起始交易內另對選定資產重驗批次能力，
// 並把選定資產存成輪替授權脈絡的上界（每次派送前據此重驗，見 revalidateAssetBound）。
func (s *CredentialRotationService) startSplitForBatch(ctx context.Context, credentialID uint,
	accountIDs []uint, req StartRotationRequest, bound *splitAssetBound) (*model.CredentialRotation, error) {

	// 由批次發起（bound 非 nil）只以選定資產判定，判定在起始交易內；不先以來源憑證歸屬預檢
	if bound == nil {
		if err := s.requireManagement(ctx, nil, CredOpSplit, splitGateWhole().caps,
			[]uint{credentialID}, nil, accountIDs); err != nil {
			return nil, err
		}
	}
	all, err := s.currentBindingsForSplit(credentialID)
	if err != nil {
		return nil, err
	}
	byID := make(map[uint]model.AssetAccount, len(all))
	for i := range all {
		byID[all[i].ID] = all[i]
	}
	// 逐 ID 檢查來源：混入不存在或不屬於本憑證的識別，整筆拒絕而不是悄悄略過——
	// 略過會讓呼叫端以為自己選的每一台都被處理了
	selected := make([]model.AssetAccount, 0, len(accountIDs))
	seen := make(map[uint]bool, len(accountIDs))
	for _, id := range accountIDs {
		binding, ok := byID[id]
		if !ok {
			return nil, ErrCredentialRotationNoBinding
		}
		if !seen[id] {
			seen[id] = true
			selected = append(selected, binding)
		}
	}
	if len(selected) == 0 {
		return nil, ErrCredentialRotationNoBinding
	}
	return s.startSplitRotation(ctx, credentialID, selected, req.Policy, nil, splitGateWhole(), nil, bound)
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

// splitGate 拆分類入口所需的管理能力：整組或指定掛載拆分需來源輪替加脫離，
// 單台脫離需脫離能力。
type splitGate struct {
	op   CredentialOperation
	caps []string
}

func splitGateWhole() splitGate {
	return splitGate{op: CredOpSplit, caps: []string{CredCapRotate, CredCapDetach}}
}

func splitGateDetach() splitGate {
	return splitGate{op: CredOpDetach, caps: []string{CredCapDetach}}
}

// splitManagementRequest 拆分與脫離起始交易的管理授權請求；帳號列的脫離旗標以同一形狀判定。
// 影響集合取自本次要動的掛載列（單台脫離為該台，拆分為選定成員）；單台脫離的選定掛載須在範圍內，
// 整組拆分的成員只以憑證歸屬判定。
func splitManagementRequest(gate splitGate, credentialID uint, bindings []model.AssetAccount) CredentialManagementRequest {
	assetIDs := make([]uint, 0, len(bindings))
	accountIDs := make([]uint, 0, len(bindings))
	for i := range bindings {
		assetIDs = append(assetIDs, bindings[i].AssetID)
		accountIDs = append(accountIDs, bindings[i].ID)
	}
	req := CredentialManagementRequest{
		Operation: gate.op, Capabilities: gate.caps, CredentialIDs: []uint{credentialID},
		MountedAssetIDs: assetIDs, AccountIDs: accountIDs,
	}
	if gate.op == CredOpDetach {
		req.AssetIDs = assetIDs
	}
	return req
}

// startSplitRotation 拆分與脫離共用的共同起始交易。
//
// fixedSecret 非 nil＝單台脫離且操作者自訂新秘密；nil＝每台各自隨機。
func (s *CredentialRotationService) startSplitRotation(ctx context.Context, credentialID uint,
	bindings []model.AssetAccount, policy PasswordPolicy,
	fixedSecret *CandidateSecret, gate splitGate, impactID *string, bound *splitAssetBound) (*model.CredentialRotation, error) {

	userID, operator := model.UserFromContext(ctx)
	var out *model.CredentialRotation
	err := s.db.Transaction(func(tx *gorm.DB) error {
		// 第一個動作取拓撲序列化鎖，其後才取來源憑證列鎖（不新增資產列鎖）
		if err := s.lockTopologyTx(tx); err != nil {
			return err
		}
		cred, err := lockCredentialRow(tx, credentialID)
		if err != nil {
			return err
		}
		// 能力檢核在起始交易內、列鎖之後：三個入口（整組拆分、指定掛載拆分、單台脫離）
		// 共用同一道關卡，直接呼叫服務的路徑同樣經過，不再有免驗入口。由批次發起者改在重讀掛載後
		// 以選定資產判定（拆分只改所選掛載、不改來源憑證的秘密，不要求來源憑證歸屬在範圍內）
		var decision CredentialManagementDecision
		if bound == nil {
			if decision, err = s.mgmt.require(ctx, tx, splitManagementRequest(gate, credentialID, bindings)); err != nil {
				return err
			}
		}
		// 整組拆分是遠端輪替的一種：範圍外掛載同樣須先確認（impactID 為 nil 的入口不涉範圍外確認）
		var impact *impactOutcome
		if impactID != nil {
			if impact, err = (impactGuard{scope: s.scope}).enforce(ctx, tx, cred.ID,
				model.CredentialImpactOpRotate, *impactID); err != nil {
				return err
			}
		}
		// 查驗之後可能有人改綁或卸載：在列鎖之內重讀，選定的每一台都必須仍掛在本憑證
		// 同一台資產上，否則整筆不建立輪替與候選
		current, cerr := credentialBindingRows(tx, credentialID)
		if cerr != nil {
			return cerr
		}
		fresh := make(map[uint]model.AssetAccount, len(current))
		for i := range current {
			fresh[current[i].ID] = current[i]
		}
		for i := range bindings {
			now, ok := fresh[bindings[i].ID]
			if !ok || now.AssetID != bindings[i].AssetID {
				return ErrCredentialRotationNoBinding
			}
			bindings[i] = now
		}
		// 由批次發起：選定成員所在的資產以批次能力重驗（同一交易、拓撲鎖之後），範圍外或失權即整筆不建立
		var boundAssets []uint
		authCaps := gate.caps
		if bound != nil {
			boundAssets = bindingAssetIDs(bindings)
			authCaps = unionCapabilities(bound.caps, boundedSplitFloor())
			if decision, err = s.mgmt.require(ctx, tx, CredentialManagementRequest{
				Operation: CredOpRun, Capabilities: authCaps,
				AssetIDs: boundAssets, AccountIDs: bindingAccountIDs(bindings),
			}); err != nil {
				return &errBatchAuthzStop{reason: revalidationReason(err), cause: err}
			}
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
		// 帶上界者存完整的批次能力集合（含帳號改密），派送前重驗依此聯集拆分模式下限
		if err := createRotationRow(s.mgmt, tx, rot, decision, authCaps, boundAssets); err != nil {
			return err
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
		audit := credentialAudit{
			CredentialID: cred.ID,
			Operation:    credentialOpRotate,
			Scope:        cred.Scope,
			Fields:       []string{"active_rotation_id"},
			RotationID:   rot.ID,
			Extra:        impact.auditDetails(),
		}
		if gate.op != CredOpDetach {
			// 隨機拆分沒有人決定的秘密值：維持原服務審計，不產生自訂秘密事件
			return writeCredentialAudit(s.auditTx, tx, audit, userID, operator)
		}
		// 單台脫離：意圖（審計與系統告警）與工作、候選同一交易先提交，之後才可能有遠端 I/O；
		// 審計或告警落地失敗整筆回滾，沒有工作、沒有候選、沒有遠端副作用
		corr, cerr := newAssetCorrelationID()
		if cerr != nil {
			return cerr
		}
		audit.CorrelationID = corr
		audit.SecretSource = secretSourceRandom
		if fixedSecret != nil {
			audit.SecretSource = secretSourceCustom
		}
		if err := writeCredentialAudit(s.auditTx, tx, audit, userID, operator); err != nil {
			return err
		}
		var assetID uint
		if len(bindings) == 1 {
			assetID = bindings[0].AssetID
		}
		return raiseCustomSecretUsed(s.alerts, tx, customSecretEvent{
			Entry: customSecretEntryFor(gate.op), CredentialID: cred.ID, AssetID: assetID,
			CorrelationID: corr, UserID: userID, Username: operator,
		})
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
		_, err := s.candidates.createOwnedInTx(ctx, tx, in, fixedSecret.Password, fixedSecret.PrivateKey)
		return err
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
	rot *model.CredentialRotation, member *model.CredentialRotationMember, mc *memberContext,
	confirm *model.CredentialHostIdentityConfirmation, applied memberTransition) error {

	userID, operator := model.UserFromContext(ctx)
	passwordEnc, privateKeyEnc, err := s.encryptRotationSecret(ctx, mc)
	if err != nil {
		return err
	}

	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := lockAssetForAccountMutation(tx, member.AssetID); err != nil {
			return err
		}
		// 主機身分比對在資產列鎖之後、任何憑證列之前（拆分模式只看派送標記，不看整組候選）
		fresh, err := loadRotationMember(tx, rot.ID, member.ID)
		if err != nil {
			return err
		}
		if err := assertMemberHostIdentityTx(tx, fresh, false, confirm); err != nil {
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
		consumedByTransition := isExpiredMemberState(m.State)
		if err := transitionMember(tx, m, model.CredentialMemberApplied, applied); err != nil {
			return err
		}
		if err := deleteAccountCandidate(tx, m.AccountID); err != nil {
			return err
		}
		if err := consumeConfirmationHooked(tx, confirm, consumedByTransition, s.confirmedCommitHook); err != nil {
			return err
		}
		if err := writeCredentialAudit(s.auditTx, tx, credentialAudit{
			CredentialID: dedicated.ID,
			Operation:    credentialOpDetach,
			Scope:        dedicated.Scope,
			Fields:       []string{"credential_id", "effective_version_id"},
			AssetID:      m.AssetID,
			AccountID:    m.AccountID,
			RotationID:   rot.ID,
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
		enc, err := material.Use(mc.newPrivateKey, func(raw []byte) (string, error) {
			return s.assets.bytesCrypto.EncryptBytesFor(ctx, keyvault.RefCredentialVersionPrivateKey, raw)
		})
		if err != nil {
			return "", "", fmt.Errorf("加密私鑰失敗: %w", err)
		}
		return "", enc, nil
	}
	enc, err := material.Use(mc.newPassword, func(raw []byte) (string, error) {
		return s.assets.bytesCrypto.EncryptBytesFor(ctx, keyvault.RefCredentialVersionPassword, raw)
	})
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
		// 收斂成專用時歸屬同筆改為隨資產（遠端已完成後的本地收斂，不新增授權或序列化點）
		updates := ownershipColumns(dedicatedOwnership())
		updates["scope"] = model.CredentialScopeDedicated
		updates["name"] = nil
		if err := tx.Model(&model.Credential{}).Where("id = ?", cred.ID).
			Updates(updates).Error; err != nil {
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

	// 無權者先被擋下：憑證不是共用、掛載不存在等狀態錯誤不得成為存在性探測器
	if err := s.requireManagement(ctx, nil, CredOpDetach, splitGateDetach().caps,
		[]uint{credentialID}, nil, []uint{accountID}); err != nil {
		return nil, err
	}
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
	// 脫離只動這一台的遠端秘密；能力檢核在 startSplitRotation 的起始交易內
	fixed, err := detachFixedSecret(cred, req)
	if err != nil {
		return nil, err
	}

	defer fixed.Destroy()
	rot, err := s.startSplitRotation(ctx, credentialID,
		[]model.AssetAccount{*binding}, req.Policy, fixed, splitGateDetach(), nil, nil)
	if err != nil {
		// 範圍外資產上的掛載與不存在的掛載同形
		return nil, assetScopeDenialAsBindingNotFound(err)
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
			// 操作者貼上的私鑰：先擋下解析不了的，免得進了改密流程才在遠端操作途中失敗
			if err := ValidatePrivateKey(req.PrivateKey); err != nil {
				return nil, err
			}
			return &CandidateSecret{PrivateKey: material.Adopt([]byte(req.PrivateKey))}, nil
		}
		if req.Password == "" {
			return nil, ErrCredentialSecretRequired
		}
		return &CandidateSecret{Password: material.Adopt([]byte(req.Password))}, nil
	default:
		return nil, ErrCredentialDetachSourceInvalid
	}
}

// bindingAssetIDs 掛載列所在的資產（去重保序）。
func bindingAssetIDs(bindings []model.AssetAccount) []uint {
	seen := make(map[uint]bool, len(bindings))
	out := make([]uint, 0, len(bindings))
	for i := range bindings {
		if !seen[bindings[i].AssetID] {
			seen[bindings[i].AssetID] = true
			out = append(out, bindings[i].AssetID)
		}
	}
	return out
}

// bindingAccountIDs 掛載列識別。
func bindingAccountIDs(bindings []model.AssetAccount) []uint {
	out := make([]uint, 0, len(bindings))
	for i := range bindings {
		out = append(out, bindings[i].ID)
	}
	return out
}
