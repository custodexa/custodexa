package asset

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 憑證快照：改密記錄、候選列與報告列共用的「執行當下這台用的是哪一筆憑證、哪一版」。
//
// # 為什麼要快照而不是回頭 join
//
// 掛載可以被改綁到另一筆憑證（拆分收斂、脫離共用、更換掛載憑證）。事後以掛載識別
// 回頭 join 讀到的是**現在**的憑證，而不是那一次執行動的是誰——歷史記錄會被現況汙染，
// 而稽核要問的正好是「當時」。故記錄與候選各自帶著憑證識別、名稱與目標版本。

// credentialSnapshot 一筆憑證在某一刻的可外露事實（不含任何密文）。
type credentialSnapshot struct {
	CredentialID uint
	// Name 共用＝落庫名稱；專用＝「資產名 / 帳號名」計算值
	Name string
	// Shared 憑證範圍為共用
	Shared bool
	// EffectiveVersionNo 該掛載當下用以連線的版本序號；0＝尚未取得任何密文
	EffectiveVersionNo int
	// EffectiveVersionID 該掛載當下的就位版本識別；0＝尚未取得任何密文
	EffectiveVersionID uint
}

// bindingCredentialSnapshot 取單一掛載的憑證快照。
func bindingCredentialSnapshot(db *gorm.DB, account *model.AssetAccount) (credentialSnapshot, error) {
	out := credentialSnapshot{}
	if account == nil || account.CredentialID == 0 {
		return out, nil
	}
	byAccount, err := accountsCredentialSnapshots(db, []model.AssetAccount{*account})
	if err != nil {
		return out, err
	}
	return byAccount[account.ID], nil
}

// accountsCredentialSnapshots 批次取一組掛載的憑證快照，鍵為掛載識別。
//
// **批次而非逐筆**：報告的範圍可達全系統，逐帳號查會把一次報告產出變成上萬次往返。
func accountsCredentialSnapshots(db *gorm.DB, accounts []model.AssetAccount) (map[uint]credentialSnapshot, error) {
	out := make(map[uint]credentialSnapshot, len(accounts))
	if len(accounts) == 0 {
		return out, nil
	}
	credIDs := make([]uint, 0, len(accounts))
	versionIDs := make([]uint, 0, len(accounts))
	seenCred := map[uint]bool{}
	for i := range accounts {
		if id := accounts[i].CredentialID; id != 0 && !seenCred[id] {
			seenCred[id] = true
			credIDs = append(credIDs, id)
		}
		if v := accounts[i].EffectiveVersionID; v != nil && *v != 0 {
			versionIDs = append(versionIDs, *v)
		}
	}
	creds, err := credentialsByID(db, credIDs)
	if err != nil {
		return nil, err
	}
	versionNos, err := versionNumbers(db, versionIDs)
	if err != nil {
		return nil, err
	}
	// 專用憑證的顯示名需要它唯一掛載所屬的資產名；本批的掛載列已在手上，
	// 先以它們湊出「憑證 → 資產」，湊不到的才回查（憑證掛在本批之外的掛載上）
	assetNames, err := assetNamesFor(db, accounts)
	if err != nil {
		return nil, err
	}
	for i := range accounts {
		acc := &accounts[i]
		snap := credentialSnapshot{CredentialID: acc.CredentialID}
		if v := acc.EffectiveVersionID; v != nil && *v != 0 {
			snap.EffectiveVersionID = *v
			snap.EffectiveVersionNo = versionNos[*v]
		}
		cred := creds[acc.CredentialID]
		if cred == nil {
			out[acc.ID] = snap
			continue
		}
		snap.Shared = cred.Scope == model.CredentialScopeShared
		if snap.Shared {
			if cred.Name != nil {
				snap.Name = *cred.Name
			}
		} else if name := assetNames[acc.AssetID]; name != "" {
			snap.Name = name + " / " + cred.Username
		} else {
			snap.Name = cred.Username
		}
		out[acc.ID] = snap
	}
	return out, nil
}

// credentialsByID 批次取憑證列（含軟刪：記錄要指得回一筆已刪的憑證）。
func credentialsByID(db *gorm.DB, ids []uint) (map[uint]*model.Credential, error) {
	out := map[uint]*model.Credential{}
	if len(ids) == 0 {
		return out, nil
	}
	var rows []model.Credential
	if err := db.Unscoped().Where("id IN ?", ids).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("查詢憑證失敗: %w", err)
	}
	for i := range rows {
		out[rows[i].ID] = &rows[i]
	}
	return out, nil
}

// versionNumbers 批次取密文版本的序號（版本列不可變，故序號可安全快取於呼叫端）。
func versionNumbers(db *gorm.DB, ids []uint) (map[uint]int, error) {
	out := map[uint]int{}
	if len(ids) == 0 {
		return out, nil
	}
	type row struct {
		ID        uint
		VersionNo int
	}
	var rows []row
	if err := db.Model(&model.CredentialSecretVersion{}).
		Select("id, version_no").Where("id IN ?", ids).Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("查詢憑證密文版本失敗: %w", err)
	}
	for _, r := range rows {
		out[r.ID] = r.VersionNo
	}
	return out, nil
}

// assetNamesFor 取這批掛載所屬資產的名稱（含已刪除資產：記錄要讀得出當時的機器名）。
func assetNamesFor(db *gorm.DB, accounts []model.AssetAccount) (map[uint]string, error) {
	ids := make([]uint, 0, len(accounts))
	seen := map[uint]bool{}
	for i := range accounts {
		if id := accounts[i].AssetID; id != 0 && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	out := map[uint]string{}
	if len(ids) == 0 {
		return out, nil
	}
	type row struct {
		ID   uint
		Name string
	}
	var rows []row
	if err := db.Unscoped().Model(&model.Asset{}).
		Select("id, name").Where("id IN ?", ids).Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("查詢資產失敗: %w", err)
	}
	for _, r := range rows {
		out[r.ID] = r.Name
	}
	return out, nil
}

// credentialNameSnapshot 取單一憑證的顯示名快照（共用＝落庫名稱，專用＝計算名）。
//
// 讀不到憑證時回空字串而不是報錯：快照是記錄上的說明欄位，取不到名字不該把
// 一次已經完成的改密翻成失敗。
func credentialNameSnapshot(db *gorm.DB, credentialID uint) string {
	if credentialID == 0 {
		return ""
	}
	var cred model.Credential
	if err := db.Unscoped().Where("id = ?", credentialID).First(&cred).Error; err != nil {
		return ""
	}
	if cred.Scope == model.CredentialScopeShared {
		if cred.Name != nil {
			return *cred.Name
		}
		return ""
	}
	name, err := dedicatedDisplayName(db, &cred)
	if err != nil {
		return cred.Username
	}
	return name
}

// candidateCredentialID 這次改密的秘密最終要落在哪一筆憑證上。
func candidateCredentialID(job rotationJob, tgt changeSecretTarget) uint {
	if job.sharedCredentialID != 0 {
		return job.sharedCredentialID
	}
	return tgt.credentialID
}

// candidateCredentialName 同上的名稱快照。
func candidateCredentialName(job rotationJob, tgt changeSecretTarget) string {
	if job.sharedCredentialID != 0 {
		return job.sharedCredentialName
	}
	return tgt.credentialName
}

// committedVersionID 提交完成後該掛載的就位版本（記錄的目標版本快照）。
//
// 專用憑證的新版本在提交那一刻才產生，故只能提交後回讀；整批同一組模式的版本
// 在批次開始時就建好，直接用它，讀不回來時不因此把一次成功的改密算成失敗。
func committedVersionID(db *gorm.DB, accountID, fallback uint) uint {
	var acc model.AssetAccount
	if err := db.Where("id = ?", accountID).First(&acc).Error; err == nil &&
		acc.EffectiveVersionID != nil {
		return *acc.EffectiveVersionID
	}
	return fallback
}
