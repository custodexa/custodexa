package asset

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 掛載與卸載：把既有共用憑證接到資產上，或把它拿下來。
//
// # 兩者都不觸碰目標主機
//
// 掛載是操作者的宣告「這台從現在起以此憑證登入」，卸載是「這台不再由本系統以此
// 憑證登入」。兩者都只動掛載列——**遠端主機上的密碼不會因此改變**。這條界線必須
// 在介面上就地說明，否則管理者會把卸載當成「把這台的密碼收回來」，而實際上那台
// 機器仍然接受同一組秘密，只是本系統不再記得它。改遠端是「脫離共用」的事。
//
// # 權限的檢核面跟著動作的影響面走
//
// 掛載本身即改變秘密的影響面：把一組已經用在生產核心機上的共用憑證掛到自己的
// 資產上，就取得了以該秘密登入的能力。故除路由級授權點外，服務層另驗操作者對
// 該動作**實際影響到的每一台資產**都有權限。
//
// 掛載、卸載、改綁各只動一筆掛載列，受影響的就是那一台，驗那一台
// （assertAssetPermission）；改秘密、換範圍、刪憑證動的是憑證本身，後果落在它
// 當下的全部掛載上，故逐台驗（assertBoundAssetsPermission）。逐台而非取聯集：
// 只驗其中一台，等於讓操作者拿一台他管得到的機器，決定另外幾台他管不到的機器
// 怎麼登入。
//
// # 全域鎖次序固定「先資產列、後憑證列」
//
// 掛載同時動資產的帳號集合與憑證的掛載集合，兩者各有互斥點。次序反過來寫的那一
// 條路徑會與其餘路徑交錯死鎖，而死鎖只在並行時出現、單測永遠看不到。
//
// 這是**全套件唯一的次序**，不是本檔的區域慣例。持久列鎖只有兩個入口：
// 資產列＝`lockAssetForAccountMutation`（asset_account_service.go），
// 憑證列＝`lockCredentialRow`（credential_resolver.go）。同時取兩者的路徑一律：
//
//	Bind／Unbind／Rebind（本檔）、removeAssetBindings（本檔，經
//	lockCredentialsForBindingRemoval）、CredentialService.Update（credential_service.go，
//	經 lockAssetsOfCredential 先取）、commitGroupApplied（credential_rotation_run.go）、
//	commitSplitApplied／Detach（credential_rotation_split.go）、
//	appendDeclaredSecret（credential_resolver.go，呼叫端已持資產列鎖）
//
// 只取憑證列鎖的路徑（Start／Abandon／SetSecret／ConvertScope／Delete／
// startSplitRotation）不參與次序問題。多筆憑證一次鎖時另按憑證識別升冪
// （lockCredentialRowsOrdered），否則兩條方向相反的改綁會各持對方要的那一列。
// 守衛：credential_rotation_race_test.go 的 TestRowLockOrderAssetBeforeCredential。

// 憑證審計的操作分類（帳號側的 model.AccountOp* 之外，憑證獨有的三個）。
const (
	credentialOpBind   = "bind"
	credentialOpUnbind = "unbind"
	credentialOpScope  = "scope"
	credentialOpRebind = "rebind"
)

var (
	// ErrCredentialBindForbidden 操作者對受影響的資產無權限。
	// 與「憑證不存在」共用收斂的對外回應：分流即製造存在性探測器
	ErrCredentialBindForbidden = errors.New("操作者對受影響的資產無管理權限")
	// ErrCredentialBindingExists 同一資產已掛載同一憑證（CONFLICT_CREDENTIAL_BINDING）
	ErrCredentialBindingExists = errors.New("該資產已掛載此憑證")
	// ErrCredentialBindingNotFound 掛載不存在或不屬於該憑證（NOTFOUND_CREDENTIAL_BINDING）
	ErrCredentialBindingNotFound = errors.New("掛載不存在或不屬於該憑證")
	// ErrCredentialProtocolMismatch 憑證協定族與資產協定不相容
	// （RULE_CREDENTIAL_PROTOCOL_MISMATCH）
	ErrCredentialProtocolMismatch = errors.New("憑證的協定族與資產協定不相容")
	// ErrCredentialDedicatedSingleBinding 專用憑證恰一掛載，不可另行掛載
	// （RULE_CREDENTIAL_DEDICATED_SINGLE_BINDING）
	ErrCredentialDedicatedSingleBinding = errors.New("專用憑證恰有一個掛載，不可掛到其他資產")
	// ErrBindingWithoutCredential 掛載列沒有憑證識別。
	//
	// **硬前提，大聲失敗**：存量轉換已保證每一筆掛載都有憑證，此狀態只可能來自
	// 繞過服務層的資料層寫入。就地補一筆憑證看似體貼，實際是讓一個不該存在的
	// 狀態靜默延續下去，而它下一次出現時仍然沒有人知道它是怎麼來的
	ErrBindingWithoutCredential = errors.New("掛載列缺少憑證識別，資料狀態異常")
)

// BindCredentialRequest 把既有共用憑證掛到資產上。
type BindCredentialRequest struct {
	AssetID    uint   `json:"asset_id"`
	IsDefault  bool   `json:"is_default"`
	Privileged bool   `json:"privileged"`
	Note       string `json:"note"`
}

// Bind 把共用憑證掛到資產上，**對目標主機零寫入**。
//
// 新掛載的就位版本於同一交易設為該憑證當下的現行版本（操作者宣告的密文立即生效）。
// 這不宣稱該秘密在那台機器上必定有效——有效與否由後續連線或改密揭露；設定它只是把
// 「未經驗證」從「連不上」降級為「連得上或連不上，兩者都看得見」。
func (s *CredentialService) Bind(ctx context.Context, credentialID uint, req *BindCredentialRequest) (*AssetAccountDTO, error) {
	if req == nil || req.AssetID == 0 {
		return nil, ErrAssetNotFound
	}
	if err := validateAccountNote(req.Note); err != nil {
		return nil, err
	}
	asset, err := s.assets.GetByID(req.AssetID)
	if err != nil {
		return nil, err
	}
	if err := s.assertAssetPermission(ctx, asset.ID); err != nil {
		return nil, err
	}

	userID, operator := model.UserFromContext(ctx)
	account := &model.AssetAccount{
		AssetID:    asset.ID,
		Privileged: req.Privileged,
		Note:       req.Note,
	}
	txErr := database.DB.Transaction(func(tx *gorm.DB) error {
		if err := lockAssetForAccountMutation(tx, asset.ID); err != nil {
			return err
		}
		cred, err := lockCredentialRow(tx, credentialID)
		if err != nil {
			return err
		}
		if err := assertNoActiveRotation(cred); err != nil {
			return err
		}
		// 待生效版本尚未收斂時不得掛上新的一台：新掛載的就位版本會設成**現行**版本，
		// 而現行版本正是上一輪要換掉的那一組。它不在該輪的成員快照裡，補跑收斂時
		// 也不會被帶上，於是憑證顯示已收斂、這一台卻永遠停在舊版而畫面上看不出來
		if err := assertCredentialConverged(tx, cred); err != nil {
			return err
		}
		if cred.Scope != model.CredentialScopeShared {
			return ErrCredentialDedicatedSingleBinding
		}
		if err := assertProtocolFamilyMatch(cred, asset); err != nil {
			return err
		}
		if err := assertCredentialNotBound(tx, asset.ID, cred.ID); err != nil {
			return err
		}
		if err := assertUsernameFreeOnAsset(tx, asset.ID, cred.Username, 0); err != nil {
			return err
		}

		count, err := liveAccountCount(tx, asset.ID)
		if err != nil {
			return err
		}
		account.IsDefault = req.IsDefault || count == 0
		if account.IsDefault {
			if err := clearDefaultAccounts(tx, asset.ID, 0); err != nil {
				return err
			}
		}
		account.Username = cred.Username
		account.AuthMethod = cred.AuthMethod
		account.CredentialID = cred.ID
		// 掛載本身不建新密文版本：就位版本設為目標憑證當下的現行版本
		account.EffectiveVersionID = cred.CurrentVersionID
		if err := tx.Create(account).Error; err != nil {
			return accountUniqueViolation(err, "掛載憑證失敗")
		}
		if account.IsDefault {
			if err := mirrorDefaultAccountToAsset(tx, account); err != nil {
				return err
			}
		}
		return writeCredentialAudit(s.auditTx, tx, credentialAudit{
			CredentialID: cred.ID,
			Operation:    credentialOpBind,
			Scope:        cred.Scope,
			AssetID:      asset.ID,
			AccountID:    account.ID,
		}, userID, operator)
	})
	if txErr != nil {
		return nil, txErr
	}
	return newAccountDTO(database.DB, account)
}

// Unbind 卸載某筆掛載：只移除掛載列與其就位版本，**不更動目標主機上的密碼**。
//
// 卸載專用憑證的唯一掛載時同一交易刪除該憑證——零掛載的專用憑證是孤兒，
// 它既沒有顯示名（顯示名由掛載算出）也沒有任何人能用它。
func (s *CredentialService) Unbind(ctx context.Context, credentialID, accountID uint) error {
	if accountID == 0 {
		return ErrCredentialBindingNotFound
	}
	userID, operator := model.UserFromContext(ctx)
	return database.DB.Transaction(func(tx *gorm.DB) error {
		var binding model.AssetAccount
		if err := tx.Where("id = ? AND credential_id = ?", accountID, credentialID).
			First(&binding).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrCredentialBindingNotFound
			}
			return fmt.Errorf("查詢掛載失敗: %w", err)
		}
		if err := s.assertAssetPermission(ctx, binding.AssetID); err != nil {
			return err
		}
		if err := lockAssetForAccountMutation(tx, binding.AssetID); err != nil {
			return err
		}
		cred, err := lockCredentialRow(tx, credentialID)
		if err != nil {
			return err
		}
		if err := assertNoActiveRotation(cred); err != nil {
			return err
		}
		count, err := liveAccountCount(tx, binding.AssetID)
		if err != nil {
			return err
		}
		if binding.IsDefault && count > 1 {
			// 「有帳號必有預設」：先指定新的預設再卸載，否則該資產會落入
			// 有掛載卻無預設的破損態，系統路徑將無身分可用
			return ErrAssetAccountDefaultRequired
		}
		res := tx.Delete(&model.AssetAccount{}, binding.ID)
		if res.Error != nil {
			return fmt.Errorf("卸載憑證失敗: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			return ErrCredentialBindingNotFound
		}
		if binding.IsDefault {
			if err := clearAssetIdentityMirror(tx, binding.AssetID); err != nil {
				return err
			}
		}
		// 移除的可能正是最後一台未就位的主機：卸載是未同步狀態的出口，
		// 而一個沒有任何後續動作會再去看的出口，走完仍停在未同步
		if err := convergeCredentialAfterBindingRemoval(tx, cred); err != nil {
			return err
		}
		if err := deleteDedicatedIfOrphaned(tx, cred); err != nil {
			return err
		}
		return writeCredentialAudit(s.auditTx, tx, credentialAudit{
			CredentialID: cred.ID,
			Operation:    credentialOpUnbind,
			Scope:        cred.Scope,
			AssetID:      binding.AssetID,
			AccountID:    binding.ID,
		}, userID, operator)
	})
}

// Rebind 更換某筆掛載所引用的憑證。
//
// 就位版本於同一交易改寫為新憑證當下的現行版本——掛載列的就位版本**必須屬於它
// 引用的憑證**，改綁而不改就位會讓這台機器指向一個不屬於自己憑證的版本，
// 取密路徑會拿到另一組秘密。舊憑證若因此成為零掛載的專用憑證，同交易刪除。
func (s *CredentialService) Rebind(ctx context.Context, assetID, accountID, credentialID uint) (*AssetAccountDTO, error) {
	if accountID == 0 {
		return nil, ErrAssetAccountNotFound
	}
	asset, err := s.assets.GetByID(assetID)
	if err != nil {
		return nil, err
	}
	if err := s.assertAssetPermission(ctx, asset.ID); err != nil {
		return nil, err
	}

	userID, operator := model.UserFromContext(ctx)
	var result *model.AssetAccount
	txErr := database.DB.Transaction(func(tx *gorm.DB) error {
		if err := lockAssetForAccountMutation(tx, asset.ID); err != nil {
			return err
		}
		binding, err := resolveAssetAccount(tx, asset.ID, accountID)
		if err != nil {
			return err
		}
		if binding == nil {
			return ErrAssetAccountNotFound
		}
		if binding.CredentialID == credentialID {
			result = binding
			return nil
		}
		// 兩筆憑證按識別升冪取鎖：兩條互為來源與去向的改綁若各按自己的順序取，
		// 會各持對方要的那一列
		locked, err := lockCredentialRowsOrdered(tx, binding.CredentialID, credentialID)
		if err != nil {
			return err
		}
		oldCred, cred := locked[binding.CredentialID], locked[credentialID]
		for _, c := range []*model.Credential{oldCred, cred} {
			if err := assertNoActiveRotation(c); err != nil {
				return err
			}
			// 待生效版本尚未收斂時不得改綁：改綁會把就位版本改寫成新憑證的現行版本，
			// 等於在上一輪的目標集合底下抽走一台，而那一台的成員列還留在該輪裡
			if err := assertCredentialConverged(tx, c); err != nil {
				return err
			}
		}
		if cred.Scope != model.CredentialScopeShared {
			return ErrCredentialDedicatedSingleBinding
		}
		if err := assertProtocolFamilyMatch(cred, asset); err != nil {
			return err
		}
		if err := assertCredentialNotBound(tx, asset.ID, cred.ID); err != nil {
			return err
		}
		if err := assertUsernameFreeOnAsset(tx, asset.ID, cred.Username, binding.ID); err != nil {
			return err
		}

		updates := map[string]interface{}{
			"credential_id": cred.ID,
			"username":      cred.Username,
			"auth_method":   cred.AuthMethod,
		}
		if cred.CurrentVersionID != nil {
			updates["effective_version_id"] = *cred.CurrentVersionID
		} else {
			updates["effective_version_id"] = nil
		}
		res := tx.Model(&model.AssetAccount{}).Where("id = ?", binding.ID).Updates(updates)
		if res.Error != nil {
			return accountUniqueViolation(res.Error, "更換掛載憑證失敗")
		}
		if res.RowsAffected == 0 {
			return ErrAssetAccountNotFound
		}
		binding.CredentialID = cred.ID
		binding.Username = cred.Username
		binding.AuthMethod = cred.AuthMethod
		binding.EffectiveVersionID = cred.CurrentVersionID
		if binding.IsDefault {
			if err := mirrorDefaultAccountToAsset(tx, binding); err != nil {
				return err
			}
		}
		if err := deleteDedicatedIfOrphaned(tx, oldCred); err != nil {
			return err
		}
		result = binding
		return writeCredentialAudit(s.auditTx, tx, credentialAudit{
			CredentialID: cred.ID,
			Operation:    credentialOpRebind,
			Scope:        cred.Scope,
			AssetID:      asset.ID,
			AccountID:    binding.ID,
		}, userID, operator)
	})
	if txErr != nil {
		return nil, txErr
	}
	return newAccountDTO(database.DB, result)
}

// --- 不變式的共同判定 ---

// assertProtocolFamilyMatch 掛載時資產協定必須屬於憑證的協定族。
func assertProtocolFamilyMatch(cred *model.Credential, asset *model.Asset) error {
	if cred.ProtocolFamily != model.ProtocolFamilyForAsset(asset) {
		return ErrCredentialProtocolMismatch
	}
	return nil
}

// assertCredentialNotBound 同一憑證不得在同一資產上掛兩次。
//
// 服務層先判一次而不是只等 (asset_id, credential_id) 的唯一索引：索引違反回來的是
// 一個要靠字串比對才分得出成因的錯誤，而這裡要回的是一個管理者看得懂的規則。
func assertCredentialNotBound(tx *gorm.DB, assetID, credentialID uint) error {
	var dup int64
	if err := tx.Model(&model.AssetAccount{}).
		Where("asset_id = ? AND credential_id = ?", assetID, credentialID).
		Count(&dup).Error; err != nil {
		return fmt.Errorf("檢查既有掛載失敗: %w", err)
	}
	if dup > 0 {
		return ErrCredentialBindingExists
	}
	return nil
}

// assertUsernameFreeOnAsset 同一資產上同一登入帳號名只允許存在一個掛載。
//
// **這條不變式沒有 DB 唯一鍵**：帳號名的真相在憑證表，「同資產同帳號名」是跨表
// 條件，單一 unique index 表達不了。序列化由呼叫端的資產列鎖承擔——本函式必須
// 在該鎖之內呼叫，否則兩個並行的掛載會各自讀到「沒有撞名」然後雙雙寫入。
//
// 判定以**憑證的帳號名**為準：掛載列上的同名欄位是過渡期的顯示副本，兩者於改名
// 時同步，但真相只有一個。
func assertUsernameFreeOnAsset(tx *gorm.DB, assetID uint, username string, exceptAccountID uint) error {
	if username == "" {
		// 空帳號名合法（VNC／Redis／K8s 等無 username 協議），且無從撞名
		return nil
	}
	q := tx.Model(&model.AssetAccount{}).
		Joins("JOIN credentials ON credentials.id = asset_accounts.credential_id AND credentials.deleted_at IS NULL").
		Where("asset_accounts.asset_id = ? AND credentials.username = ?", assetID, username)
	if exceptAccountID != 0 {
		q = q.Where("asset_accounts.id <> ?", exceptAccountID)
	}
	var dup int64
	if err := q.Count(&dup).Error; err != nil {
		return fmt.Errorf("檢查同名掛載失敗: %w", err)
	}
	if dup > 0 {
		return ErrAssetAccountUsernameExists
	}
	return nil
}

// setBindingEffectiveVersion 改寫某掛載的就位版本，並強制它屬於該掛載的憑證。
//
// 歸屬條件以查詢確認而非查完再比：查完再比的寫法一旦漏掉那個 if，就是一條
// 「把任意版本識別寫進就位指標」的路徑，而取密會照著它去解一組不屬於這台的秘密。
func setBindingEffectiveVersion(tx *gorm.DB, account *model.AssetAccount, versionID uint) error {
	if account == nil {
		return ErrAssetAccountNotFound
	}
	if account.CredentialID == 0 {
		return ErrBindingWithoutCredential
	}
	if _, err := loadCredentialVersion(tx, account.CredentialID, versionID); err != nil {
		return err
	}
	res := tx.Model(&model.AssetAccount{}).
		Where("id = ? AND credential_id = ?", account.ID, account.CredentialID).
		Update("effective_version_id", versionID)
	if res.Error != nil {
		return fmt.Errorf("更新就位版本失敗: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrAssetAccountNotFound
	}
	account.EffectiveVersionID = &versionID
	return nil
}

// requireBindingCredential 掛載必有憑證的硬前提。
//
// 存量轉換已保證 credential_id 非空；此處大聲失敗而不就地補憑證——補一筆會讓一個
// 只可能來自繞過服務層的狀態靜默延續，而下一次它出現時仍然沒有人知道它從哪來。
func requireBindingCredential(account *model.AssetAccount) error {
	if account == nil {
		return ErrAssetAccountNotFound
	}
	if account.CredentialID == 0 {
		return ErrBindingWithoutCredential
	}
	return nil
}

// deleteDedicatedIfOrphaned 專用憑證失去最後一個掛載時同交易刪除。
//
// 只對專用憑證成立：共用憑證零掛載是合法的待用狀態（憑證庫可先建好再掛），
// 順手刪掉它等於讓一次卸載悄悄毀掉一筆管理者刻意保留的憑證。
func deleteDedicatedIfOrphaned(tx *gorm.DB, cred *model.Credential) error {
	if cred == nil || cred.Scope != model.CredentialScopeDedicated {
		return nil
	}
	count, err := credentialBindingCount(tx, cred.ID)
	if err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	if err := tx.Delete(&model.Credential{}, cred.ID).Error; err != nil {
		return fmt.Errorf("刪除孤兒專用憑證失敗: %w", err)
	}
	return nil
}

// lockCredentialsForBindingRemoval 掛載被移除之前，先取其憑證列鎖並擋下改密進行中的憑證。
//
// **鎖與拒絕都必須發生在刪除之前**：回收與否要先數過掛載才算得出來（零掛載才回收），
// 若等到那時才發現改密進行中，掛載列已經不在了，而改密的目標集合正是「當下的全部
// 掛載」——中途抽掉一台，那一台會停在沒有人會再去收斂的狀態。
//
// 同一批掛載可能引用同一筆憑證，去重後每筆只鎖一次；憑證已不在（只可能來自繞過
// 服務層的寫入）則跳過該筆，不讓一筆早已消失的憑證擋住掛載的移除。
func lockCredentialsForBindingRemoval(tx *gorm.DB, bindings []model.AssetAccount) ([]*model.Credential, error) {
	seen := make(map[uint]bool, len(bindings))
	locked := make([]*model.Credential, 0, len(bindings))
	for i := range bindings {
		credentialID := bindings[i].CredentialID
		if credentialID == 0 || seen[credentialID] {
			continue
		}
		seen[credentialID] = true
		cred, err := lockCredentialRow(tx, credentialID)
		if err != nil {
			if errors.Is(err, ErrCredentialNotFound) {
				continue
			}
			return nil, err
		}
		if err := assertNoActiveRotation(cred); err != nil {
			return nil, err
		}
		locked = append(locked, cred)
	}
	return locked, nil
}

// reclaimDedicatedCredentials 掛載移除之後，回收因此失去全部掛載的專用憑證。
//
// 與卸載端點共用同一條判定（deleteDedicatedIfOrphaned）而不是各寫一份：掛載消失的
// 入口不只一個（卸載、刪帳號、刪資產），判定各寫一份的那幾條路徑會逐條漂移，
// 而漏掉回收的那一條在畫面上看不出任何差別——只是憑證庫裡多一筆沒有顯示名、
// 沒有人能用、也沒有掛載可以把它帶走的列。
func reclaimDedicatedCredentials(tx *gorm.DB, creds []*model.Credential) error {
	for _, cred := range creds {
		if err := deleteDedicatedIfOrphaned(tx, cred); err != nil {
			return err
		}
	}
	return nil
}

// removeAssetBindings 資產刪除時同交易移除其全部掛載，並回收隨之孤兒的專用憑證。
//
// 專用憑證的生滅綁在它唯一的掛載上，掛載的生滅綁在資產上。資產沒了卻留著掛載，
// 憑證庫會持續顯示一筆指向已不存在的主機的掛載，而該憑證從此刪不掉——引用檢查
// 數得到掛載、卻查不到資產名，操作者拿到的是一句沒有對象的「還有人在用」。
func removeAssetBindings(tx *gorm.DB, assetID uint) error {
	if err := lockAssetForAccountMutation(tx, assetID); err != nil {
		return err
	}
	var bindings []model.AssetAccount
	if err := tx.Where("asset_id = ?", assetID).Find(&bindings).Error; err != nil {
		return fmt.Errorf("查詢資產掛載失敗: %w", err)
	}
	if len(bindings) == 0 {
		return nil
	}
	creds, err := lockCredentialsForBindingRemoval(tx, bindings)
	if err != nil {
		return err
	}
	if err := tx.Where("asset_id = ?", assetID).Delete(&model.AssetAccount{}).Error; err != nil {
		return fmt.Errorf("移除資產掛載失敗: %w", err)
	}
	return reclaimDedicatedCredentials(tx, creds)
}

// clearAssetIdentityMirror 掛載清空後同步資產的顯示欄。
//
// username 若留舊值，列表與審計 diff 會顯示一個已不存在的身分。
func clearAssetIdentityMirror(tx *gorm.DB, assetID uint) error {
	if err := tx.Model(&model.Asset{}).Where("id = ?", assetID).
		UpdateColumns(map[string]interface{}{
			"username":        "",
			"has_password":    false,
			"has_private_key": false,
		}).Error; err != nil {
		return fmt.Errorf("同步資產顯示欄失敗: %w", err)
	}
	return nil
}

// assertAssetPermission 單一受影響資產的權限檢核（掛載、卸載、改綁各只動一台）。
//
// 判定用的是資產權限階梯的**上限**（兩階為 view < connect）：能連上那台機器的人
// 才談得上決定它用哪一組秘密登入。authz 為 nil＝未注入判定（僅供不涉及跨資產
// 後果的既有單測建構），生產組裝一律注入。
func (s *CredentialService) assertAssetPermission(ctx context.Context, assetID uint) error {
	if s.authz == nil {
		return nil
	}
	operatorID, _ := model.UserFromContext(ctx)
	allowed, err := s.authz.CheckPermission(ctx, operatorID, assetID, model.PermissionConnect)
	if err != nil {
		return fmt.Errorf("判定資產權限失敗: %w", err)
	}
	if !allowed {
		log.Printf("[Credential] 受影響資產不可管理，拒絕操作: operator=%d assetID=%d", operatorID, assetID)
		return ErrCredentialBindForbidden
	}
	return nil
}

// assertBoundAssetsPermission 影響全部掛載的動作：逐台驗操作者對受影響資產的權限。
//
// 改秘密、換範圍、刪憑證的後果不落在單一台上——新秘密會同時就位到每一台，範圍換了
// 改變的是整組的管理語義，刪除則讓整組失去登入身分。逐台驗而非「有一台有權就放行」：
// 權限是每一台各自的事實，取聯集會讓最寬的那一台替其餘各台決定。
//
// 掛載集合於呼叫端的交易與憑證列鎖之內讀取，避免「驗過之後又被掛上一台」。
func (s *CredentialService) assertBoundAssetsPermission(ctx context.Context, db *gorm.DB, credentialID uint) error {
	if s.authz == nil {
		return nil
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

// credentialBoundAssetIDs 掛載此憑證的資產識別（去重、序穩定）。
//
// 同一台資產可以掛同一憑證兩次以上嗎——不行（掛載唯一性擋著），但去重仍留著：
// 判定的成本與正確性都不該押在另一條不變式沒有破的前提上。
func credentialBoundAssetIDs(db *gorm.DB, credentialID uint) ([]uint, error) {
	var ids []uint
	if err := db.Model(&model.AssetAccount{}).
		Where("credential_id = ?", credentialID).
		Order("asset_id ASC").Pluck("asset_id", &ids).Error; err != nil {
		return nil, fmt.Errorf("查詢憑證掛載資產失敗: %w", err)
	}
	out := make([]uint, 0, len(ids))
	seen := make(map[uint]bool, len(ids))
	for _, id := range ids {
		if id == 0 || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out, nil
}

// --- 審計 ---

// credentialAudit 憑證操作的審計輸入。
type credentialAudit struct {
	CredentialID uint
	Operation    string
	Scope        string
	Fields       []string
	// AssetID 受影響的資產（掛載類操作）；0＝與單一資產無關
	AssetID uint
	// AccountID 受影響的掛載列
	AccountID uint
}

// credentialAuditDetails 審計詳情的序列化形狀。
//
// **只帶識別而不帶名稱**：憑證名與資產名合起來就是一張共用拓撲圖，審計列的讀者
// 比憑證庫頁廣，投影面收窄到識別即可回答「動了哪一筆」。密文與任何秘密材料一律不入。
type credentialAuditDetails struct {
	Resource     string   `json:"resource"`
	CredentialID uint     `json:"credential_id"`
	Operation    string   `json:"operation"`
	Scope        string   `json:"scope,omitempty"`
	Fields       []string `json:"fields,omitempty"`
	AccountID    uint     `json:"account_id,omitempty"`
}

// writeCredentialAudit 記錄憑證操作審計（交易內落地，失敗即回滾）。
//
// Resource 用 credential＋ResourceID＝憑證 id：憑證是獨立的管理實體，掛在資產下
// 會讓零掛載的憑證（建好待用、剛卸載完）根本沒有可掛的主體。掛載類操作另帶
// AssetID，使它同時出現在該台資產的時間線上——主體只有產生點知道，落地器不得推導。
func writeCredentialAudit(sink port.TxSink, tx *gorm.DB, a credentialAudit, userID uint, operator string) error {
	details := credentialAuditDetails{
		Resource:     string(model.ResourceCredential),
		CredentialID: a.CredentialID,
		Operation:    a.Operation,
		Scope:        a.Scope,
		Fields:       a.Fields,
		AccountID:    a.AccountID,
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		log.Printf("序列化憑證變更詳情失敗: %v", err)
		detailsJSON = []byte("{}")
	}
	credentialID := a.CredentialID
	// 受影響資產於字面量之前算好：主體鍵是產生點的一部分，事後才補上的欄位
	// 在「哪些產生點填了主體鍵」的機械盤點上看不見
	var assetID *uint
	if a.AssetID != 0 {
		id := a.AssetID
		assetID = &id
	}
	return port.WriteInTx(sink, tx, port.AuditEvent{
		OccurredAt: time.Now(),
		Actor:      gatewayapi.Actor{UserID: userID, Username: operator},
		Action:     string(auditActionForAccountOp(a.Operation)),
		Resource:   string(model.ResourceCredential),
		ResourceID: &credentialID,
		AssetID:    assetID,
		Status:     string(model.StatusSuccess),
		Details:    string(detailsJSON),
	})
}
