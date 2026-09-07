package asset

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// 憑證取密的單一入口。
//
// # 為什麼只取掛載的就位版本
//
// 一筆憑證同時可能有三個版本指標：憑證的現行版本、輪替中的待生效版本，
// 以及每個掛載各自的就位版本。連線要用的是**這一台當下實際生效的那一版**，
// 也只有掛載列知道它是哪一版——共用憑證在輪替中途必然出現「甲台已就位新版、
// 乙台仍是舊版」的狀態，讀憑證的現行版本會讓其中一台拿到它機器上不存在的秘密。
//
// 就位版本為空時一律回 ErrAssetNoUsableAccount，**不退回現行版本**：那是猜測，
// 而猜錯的代價是一次失敗的登入嘗試。
//
// # 為什麼不自動試兩個版本
//
// 兩版輪流試等於每次連線最多產生兩次登入失敗，對有鎖定策略的目標系統就是
// 自帶的帳號鎖定器；對攻擊者則是一個「這個秘密對不對」的線上判別器（送一個
// 猜測值進來，看它是被第一版還是第二版接受）。一次連線只做一次登入嘗試。
//
// # 為什麼兩支方法各自解封、不抽共用函式
//
// 解封點清單守衛（internal/guards/moduleboundary/asset_credential_exit_guard_test.go）
// 以「哪個函式體內出現字面 keyvault.RefX 的 DecryptFor」認定出口。把解封收進
// 一個吃 ref 參數的共用函式，會讓兩個出口在守衛的掃描面上一起消失，
// 而清單看起來仍然完整——一份不完整的出口清單比沒有清單更危險。
// 這幾行重複是守衛的代價，刻意付。

// ResolvedCredential 一次取密的結果。明文欄位只在行程內存活，永不出站。
type ResolvedCredential struct {
	// AccountID 掛載列 id；ResolveVersion 取不到掛載，此欄為 0
	AccountID uint
	// CredentialID 憑證 id
	CredentialID uint
	// VersionID 實際解封的密文版本 id
	VersionID uint
	// Username 登入帳號名（取自憑證，憑證是帳號名的真相）
	Username string
	// SecretType 見 model.ChangeSecretType* 常數
	SecretType string

	Password   string
	PrivateKey string

	// PublicKey／PreviousPublicKey 公鑰非機密，供金鑰輪替比對與清理
	PublicKey         string
	PreviousPublicKey string
}

// CredentialResolver 憑證解析器。
//
// 不持有 *gorm.DB：連線路徑與改密路徑各自帶進自己的交易或連線，
// 由呼叫端決定讀取要不要與寫入同一交易。
type CredentialResolver struct {
	crypto crypto.ColumnCodec
}

// NewCredentialResolver 建立解析器。codec SHALL 與資產服務用同一個實例——
// 兩份 codec 會讓憑證在管理員沒察覺時走不同的加密路徑。
func NewCredentialResolver(codec crypto.ColumnCodec) *CredentialResolver {
	return &CredentialResolver{crypto: codec}
}

// ResolveForBinding 取某掛載當下用以連線的秘密。
//
// fail-close 與 GetWithCredentialsForAccount 同源（共用 resolveAssetAccount）：
// 帳號不存在、已軟刪、或屬於別的資產一律回 ErrAssetAccountNotFound，
// 絕不靜默退回預設帳號。掛載尚無就位版本回 ErrAssetNoUsableAccount。
func (r *CredentialResolver) ResolveForBinding(ctx context.Context, assetID, accountID uint) (*ResolvedCredential, error) {
	db := database.DB
	account, err := resolveAssetAccount(db, assetID, accountID)
	if err != nil {
		return nil, err
	}
	if account == nil {
		// 零掛載資產：連身分都沒有
		return nil, ErrAssetNoUsableAccount
	}
	if account.EffectiveVersionID == nil || *account.EffectiveVersionID == 0 {
		// 掛載在，但尚未取得任何密文。**不是**「猜一個版本來試」的理由。
		// 錯誤帶著掛載身分回去，讓呼叫端不必為了拿帳號名再查一次同一列
		return nil, &BindingWithoutSecretError{AccountID: account.ID, Username: account.Username}
	}
	version, err := loadCredentialVersion(db, account.CredentialID, *account.EffectiveVersionID)
	if err != nil {
		return nil, err
	}
	out := &ResolvedCredential{
		AccountID:         account.ID,
		CredentialID:      account.CredentialID,
		VersionID:         version.ID,
		Username:          account.Username,
		SecretType:        version.SecretType,
		PublicKey:         version.PublicKey,
		PreviousPublicKey: version.PreviousPublicKey,
	}
	// 憑證讀不到即 fail-close，**不沿用掛載列上的帳號名繼續**：憑證是軟刪的，
	// 讀不到的最常見成因就是它已被刪除，而「憑證已刪但這台仍連得上」正是刪除
	// 這個動作要消除的東西。吞掉這個錯等於讓軟刪對連線路徑失效
	cred, cerr := loadCredential(db, account.CredentialID)
	if cerr != nil {
		return nil, cerr
	}
	if cred.Username != "" {
		// 帳號名的真相在憑證；掛載列的同名欄位是過渡期的顯示副本
		out.Username = cred.Username
	}
	if version.PasswordEnc != "" {
		plain, derr := r.crypto.DecryptFor(ctx, keyvault.RefCredentialVersionPassword, version.PasswordEnc)
		if derr != nil {
			return nil, fmt.Errorf("解密密碼失敗: %w", derr)
		}
		out.Password = plain
	}
	if version.PrivateKeyEnc != "" {
		plain, derr := r.crypto.DecryptFor(ctx, keyvault.RefCredentialVersionPrivateKey, version.PrivateKeyEnc)
		if derr != nil {
			return nil, fmt.Errorf("解密私鑰失敗: %w", derr)
		}
		out.PrivateKey = plain
	}
	return out, nil
}

// ResolveVersion 以指定版本取密（輪替內部的驗證步驟用）。
//
// versionID 必須屬於 credentialID：跨憑證的版本識別一律回錯，不查不屬於自己的密文。
func (r *CredentialResolver) ResolveVersion(ctx context.Context, credentialID, versionID uint) (*ResolvedCredential, error) {
	db := database.DB
	if credentialID == 0 || versionID == 0 {
		return nil, ErrCredentialVersionNotFound
	}
	version, err := loadCredentialVersion(db, credentialID, versionID)
	if err != nil {
		return nil, err
	}
	out := &ResolvedCredential{
		CredentialID:      credentialID,
		VersionID:         version.ID,
		SecretType:        version.SecretType,
		PublicKey:         version.PublicKey,
		PreviousPublicKey: version.PreviousPublicKey,
	}
	// 同 ResolveForBinding：憑證讀不到即 fail-close，軟刪的憑證不得再供取密
	cred, cerr := loadCredential(db, credentialID)
	if cerr != nil {
		return nil, cerr
	}
	out.Username = cred.Username
	if version.PasswordEnc != "" {
		plain, derr := r.crypto.DecryptFor(ctx, keyvault.RefCredentialVersionPassword, version.PasswordEnc)
		if derr != nil {
			return nil, fmt.Errorf("解密密碼失敗: %w", derr)
		}
		out.Password = plain
	}
	if version.PrivateKeyEnc != "" {
		plain, derr := r.crypto.DecryptFor(ctx, keyvault.RefCredentialVersionPrivateKey, version.PrivateKeyEnc)
		if derr != nil {
			return nil, fmt.Errorf("解密私鑰失敗: %w", derr)
		}
		out.PrivateKey = plain
	}
	return out, nil
}

// BindingWithoutSecretError 掛載存在但尚無就位版本。
//
// **包著既有的 ErrAssetNoUsableAccount**（`errors.Is` 對全部既有呼叫端仍成立），
// 只多帶掛載身分：連線入口要回「有這個帳號、但沒有可用秘密」，
// 沒有這兩個欄位就得為了同一列再查一次資料庫。
type BindingWithoutSecretError struct {
	AccountID uint
	Username  string
}

func (e *BindingWithoutSecretError) Error() string { return ErrAssetNoUsableAccount.Error() }

func (e *BindingWithoutSecretError) Unwrap() error { return ErrAssetNoUsableAccount }

var (
	// ErrCredentialNotFound 憑證不存在（含掛載指向已刪憑證的殘態）
	ErrCredentialNotFound = errors.New("憑證不存在")
	// ErrCredentialVersionNotFound 密文版本不存在，或不屬於該憑證。
	// 兩者共用同一個哨兵：分流等於讓呼叫端據此列舉「哪些版本識別存在」
	ErrCredentialVersionNotFound = errors.New("憑證密文版本不存在或不屬於該憑證")
	// ErrAccountSharedCredentialSecret 單台入口對共用憑證寫入新密文
	// （RULE_ACCOUNT_SHARED_CREDENTIAL_SECRET）。理由見 appendDeclaredSecret 檔內說明
	ErrAccountSharedCredentialSecret = errors.New("此掛載使用共用憑證，新秘密須由憑證層整組寫入或先脫離共用")
)

// loadCredential 取憑證本體（不含密文，密文只在版本列上）。
func loadCredential(db *gorm.DB, credentialID uint) (*model.Credential, error) {
	if credentialID == 0 {
		return nil, ErrCredentialNotFound
	}
	var cred model.Credential
	if err := db.Where("id = ?", credentialID).First(&cred).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrCredentialNotFound
		}
		return nil, fmt.Errorf("查詢憑證失敗: %w", err)
	}
	return &cred, nil
}

// loadCredentialVersion 取密文版本，並以 credential_id 作為 WHERE 條件確認歸屬。
//
// 歸屬條件寫進查詢而不是查完再比：查完再比的寫法一旦漏掉那個 if，
// 就是一條「給我任意版本識別，我解給你看」的路徑。
func loadCredentialVersion(db *gorm.DB, credentialID, versionID uint) (*model.CredentialSecretVersion, error) {
	if credentialID == 0 || versionID == 0 {
		return nil, ErrCredentialVersionNotFound
	}
	var version model.CredentialSecretVersion
	err := db.Where("id = ? AND credential_id = ?", versionID, credentialID).First(&version).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrCredentialVersionNotFound
		}
		return nil, fmt.Errorf("查詢憑證密文版本失敗: %w", err)
	}
	return &version, nil
}

// accountSecretFlags 掛載列對外可揭露的投影：持有什麼、所引用的憑證是誰、
// 該台當下用的是哪一版。
//
// Shared 與 CredentialScope 取自憑證範圍（credentials.scope）而非掛載列上的任何
// 欄位——共用關係的真相在憑證本體，掛載列只是指向它的一條線。
//
// **本結構的欄位只給完整版投影（管理視圖）使用**：憑證識別、名稱、範圍與掛載數
// 合起來是一張「哪些主機共用同一組秘密」的地圖，精簡版投影一個都不回，
// 由 `SlimAssetAccountDTO` 的欄位集合把這件事釘死在型別上。
type accountSecretFlags struct {
	HasPassword   bool
	HasPrivateKey bool
	Shared        bool

	// CredentialID 該掛載引用的憑證識別；0＝資料狀態異常（掛載必有憑證）
	CredentialID uint
	// CredentialName 共用＝落庫名稱；專用＝「資產名 / 帳號名」計算值
	CredentialName string
	// CredentialScope 見 model.CredentialScope* 常數
	CredentialScope string
	// EffectiveVersionNo 該台當下用以連線的版本序號；0＝尚未取得任何密文
	EffectiveVersionNo int
	// BindingCount 該憑證的掛載數（專用恆為 1）
	BindingCount int
}

// bindingSecretFlags 取單一掛載的投影。
//
// **以 SQL 直接算布林、不把密文取進行程**：這裡要回答的只有「有沒有」，
// 把密文讀進記憶體只是為了判斷它非空，等於毫無必要地擴大明文以外的暴露面。
func bindingSecretFlags(db *gorm.DB, account *model.AssetAccount) (accountSecretFlags, error) {
	if account == nil {
		return accountSecretFlags{}, nil
	}
	byAccount, err := accountsSecretFlags(db, []model.AssetAccount{*account})
	if err != nil {
		return accountSecretFlags{}, err
	}
	return byAccount[account.ID], nil
}

// sharedCredentialFlags 批次判定一組憑證是否為共用範圍（鍵為憑證識別）。
//
// 含軟刪憑證：掛載可能指向一筆剛被刪除的憑證，此時仍要據實回答它是共用的。
func sharedCredentialFlags(db *gorm.DB, credentialIDs []uint) (map[uint]bool, error) {
	out := map[uint]bool{}
	ids := make([]uint, 0, len(credentialIDs))
	seen := map[uint]bool{}
	for _, id := range credentialIDs {
		if id != 0 && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return out, nil
	}
	type row struct {
		ID    uint
		Scope string
	}
	var rows []row
	if err := db.Unscoped().Model(&model.Credential{}).
		Select("id, scope").Where("id IN ?", ids).Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("查詢憑證範圍失敗: %w", err)
	}
	for _, r := range rows {
		out[r.ID] = r.Scope == model.CredentialScopeShared
	}
	return out, nil
}

// versionSecretFlags 批次取多個版本的持有布林（避免逐帳號查詢）。
func versionSecretFlags(db *gorm.DB, versionIDs []uint) (map[uint]accountSecretFlags, error) {
	out := map[uint]accountSecretFlags{}
	ids := make([]uint, 0, len(versionIDs))
	for _, id := range versionIDs {
		if id != 0 {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return out, nil
	}
	type flagRow struct {
		ID            uint
		HasPassword   bool
		HasPrivateKey bool
	}
	var rows []flagRow
	err := db.Model(&model.CredentialSecretVersion{}).
		Select("id, password_enc <> '' AS has_password, private_key_enc <> '' AS has_private_key").
		Where("id IN ?", ids).Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("查詢憑證持有狀態失敗: %w", err)
	}
	for _, r := range rows {
		out[r.ID] = accountSecretFlags{HasPassword: r.HasPassword, HasPrivateKey: r.HasPrivateKey}
	}
	return out, nil
}

// accountsSecretFlags 批次取一組掛載的持有布林與共用標示，鍵為掛載 id。
func accountsSecretFlags(db *gorm.DB, accounts []model.AssetAccount) (map[uint]accountSecretFlags, error) {
	versionIDs := make([]uint, 0, len(accounts))
	credentialIDs := make([]uint, 0, len(accounts))
	for i := range accounts {
		if v := accounts[i].EffectiveVersionID; v != nil {
			versionIDs = append(versionIDs, *v)
		}
		credentialIDs = append(credentialIDs, accounts[i].CredentialID)
	}
	byVersion, err := versionSecretFlags(db, versionIDs)
	if err != nil {
		return nil, err
	}
	sharedByCredential, err := sharedCredentialFlags(db, credentialIDs)
	if err != nil {
		return nil, err
	}
	// 憑證身分（識別、顯示名、就位版本序號）與快照面共用同一份投影：
	// 兩處各算一次的下場是「憑證庫上的名字」與「帳號列上的名字」在改名後不一致
	snapshots, err := accountsCredentialSnapshots(db, accounts)
	if err != nil {
		return nil, err
	}
	bindingCounts, err := credentialBindingCounts(db, credentialIDs)
	if err != nil {
		return nil, err
	}
	out := make(map[uint]accountSecretFlags, len(accounts))
	for i := range accounts {
		flags := accountSecretFlags{}
		if v := accounts[i].EffectiveVersionID; v != nil {
			flags = byVersion[*v]
		}
		credID := accounts[i].CredentialID
		flags.Shared = sharedByCredential[credID]
		flags.CredentialID = credID
		flags.CredentialScope = model.CredentialScopeDedicated
		if flags.Shared {
			flags.CredentialScope = model.CredentialScopeShared
		}
		snap := snapshots[accounts[i].ID]
		flags.CredentialName = snap.Name
		flags.EffectiveVersionNo = snap.EffectiveVersionNo
		flags.BindingCount = bindingCounts[credID]
		out[accounts[i].ID] = flags
	}
	return out, nil
}

// credentialBindingCounts 批次取一組憑證各自的掛載數（鍵為憑證識別）。
func credentialBindingCounts(db *gorm.DB, credentialIDs []uint) (map[uint]int, error) {
	out := map[uint]int{}
	ids := make([]uint, 0, len(credentialIDs))
	seen := map[uint]bool{}
	for _, id := range credentialIDs {
		if id != 0 && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return out, nil
	}
	type row struct {
		CredentialID uint
		N            int
	}
	var rows []row
	if err := db.Model(&model.AssetAccount{}).
		Select("credential_id, COUNT(*) AS n").
		Where("credential_id IN ?", ids).
		Group("credential_id").Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("查詢憑證掛載數失敗: %w", err)
	}
	for _, r := range rows {
		out[r.CredentialID] = r.N
	}
	return out, nil
}

// --- 寫入面（不解封，故不屬於出口清單的射程）---

// createDedicatedCredential 建立一筆專用憑證。
//
// 專用憑證的 Name 是 NULL 而非空字串——共用名稱的唯一索引是 partial unique，
// 專用以 NULL 表達「沒有名稱」才不會在任何情況下互撞。
func createDedicatedCredential(tx *gorm.DB, username, secretType, authMethod, protocolFamily string) (*model.Credential, error) {
	if authMethod == "" {
		authMethod = AuthMethodSQL
	}
	if secretType == "" {
		secretType = model.ChangeSecretTypePassword
	}
	if protocolFamily == "" {
		protocolFamily = model.ProtocolFamilySSH
	}
	cred := &model.Credential{
		Scope:          model.CredentialScopeDedicated,
		Username:       username,
		SecretType:     secretType,
		AuthMethod:     authMethod,
		ProtocolFamily: protocolFamily,
	}
	if err := tx.Create(cred).Error; err != nil {
		return nil, fmt.Errorf("建立專用憑證失敗: %w", err)
	}
	return cred, nil
}

// appendCredentialVersion 為憑證追加一筆密文版本。
//
// **只新增、不就地覆寫**：就位指標之所以能表達「這台用舊版、那台用新版」，
// 前提正是舊版列的密文原封不動；覆寫會讓尚未就位的主機失去可用的秘密。
//
// 版本序號在同一交易內以 MAX+1 取得；並行寫入由呼叫端的憑證列鎖序列化，
// 真的撞上時 (credential_id, version_no) 的唯一索引是最後一道網。
func appendCredentialVersion(tx *gorm.DB, credentialID uint, secretType, passwordEnc, privateKeyEnc, reason string) (*model.CredentialSecretVersion, error) {
	if credentialID == 0 {
		return nil, ErrCredentialNotFound
	}
	var maxNo int
	if err := tx.Model(&model.CredentialSecretVersion{}).
		Where("credential_id = ?", credentialID).
		Select("COALESCE(MAX(version_no), 0)").Scan(&maxNo).Error; err != nil {
		return nil, fmt.Errorf("查詢憑證版本序號失敗: %w", err)
	}
	version := &model.CredentialSecretVersion{
		CredentialID:  credentialID,
		VersionNo:     maxNo + 1,
		SecretType:    secretType,
		PasswordEnc:   passwordEnc,
		PrivateKeyEnc: privateKeyEnc,
		CreatedReason: reason,
	}
	if err := tx.Create(version).Error; err != nil {
		return nil, fmt.Errorf("建立憑證密文版本失敗: %w", err)
	}
	return version, nil
}

// setCredentialCurrentVersion 把憑證的現行版本指向某一版（操作者宣告的密文路徑）。
func setCredentialCurrentVersion(tx *gorm.DB, credentialID, versionID uint) error {
	if err := tx.Model(&model.Credential{}).Where("id = ?", credentialID).
		Update("current_version_id", versionID).Error; err != nil {
		return fmt.Errorf("更新憑證現行版本失敗: %w", err)
	}
	return nil
}

// lockCredentialRow 交易內取憑證列鎖。
//
// 鎖的是憑證而非掛載：同一筆共用憑證的多個掛載會被同一次輪替一起動到，
// 逐掛載上鎖擋不住「兩次輪替同時對同一組秘密動手」。
// sqlite 靠單寫者達成同等序列化，故僅 postgres 需顯式鎖。
func lockCredentialRow(tx *gorm.DB, credentialID uint) (*model.Credential, error) {
	if credentialID == 0 {
		return nil, ErrCredentialNotFound
	}
	if tx.Dialector != nil && tx.Dialector.Name() == "postgres" {
		var locked uint
		if err := tx.Raw("SELECT id FROM credentials WHERE id = ? AND deleted_at IS NULL FOR UPDATE", credentialID).
			Scan(&locked).Error; err != nil {
			return nil, fmt.Errorf("鎖定憑證失敗: %w", err)
		}
		if locked == 0 {
			return nil, ErrCredentialNotFound
		}
	}
	return loadCredential(tx, credentialID)
}

// lockCredentialRowsOrdered 一次取多筆憑證列鎖，**依憑證識別升冪**。
//
// 同時動兩筆憑證的路徑（改綁）若各按自己的順序取鎖，兩條方向相反的操作會各自
// 持有對方要的那一列。順序由識別決定即與呼叫端的語義無關，不會再有第二種次序。
// 回傳以憑證識別為鍵，呼叫端不必記得自己送進來的順序。
func lockCredentialRowsOrdered(tx *gorm.DB, credentialIDs ...uint) (map[uint]*model.Credential, error) {
	ordered := make([]uint, 0, len(credentialIDs))
	seen := make(map[uint]bool, len(credentialIDs))
	for _, id := range credentialIDs {
		if id == 0 || seen[id] {
			continue
		}
		seen[id] = true
		ordered = append(ordered, id)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })

	out := make(map[uint]*model.Credential, len(ordered))
	for _, id := range ordered {
		cred, err := lockCredentialRow(tx, id)
		if err != nil {
			return nil, err
		}
		out[id] = cred
	}
	return out, nil
}

// lockAssetsOfCredential 依資產識別升冪，取該憑證全部掛載所屬資產的列鎖。
//
// 於憑證列鎖**之前**呼叫：全域鎖次序是先資產、後憑證（見 credential_binding.go
// 檔頭）。此處讀掛載時尚未持憑證列鎖，讀到的集合可能少一筆——但會長出新掛載的
// 只有共用憑證，而需要本函式的路徑（專用憑證改名）在共用憑證上一律被拒，
// 故該集合只會縮不會長。
func lockAssetsOfCredential(tx *gorm.DB, credentialID uint) error {
	bindings, err := credentialBindingRows(tx, credentialID)
	if err != nil {
		return err
	}
	ids := make([]uint, 0, len(bindings))
	seen := make(map[uint]bool, len(bindings))
	for i := range bindings {
		if seen[bindings[i].AssetID] {
			continue
		}
		seen[bindings[i].AssetID] = true
		ids = append(ids, bindings[i].AssetID)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, assetID := range ids {
		if err := lockAssetForAccountMutation(tx, assetID); err != nil {
			return err
		}
	}
	return nil
}

// carryOverVersionCiphertext 把某一版尚未被本次更動的那一欄原樣帶出來。
//
// **密文原樣搬、不解密**：信封 AAD 綁 表|欄 而非列，來源與去向同為
// credential_secret_versions 的同一欄，跨列可解。本函式故不屬於解封出口的射程。
//
// 用途：系統路徑只改一種秘密時保住另一種（金鑰輪替不得順手清掉密碼備援，
// 只補登密碼同樣不得清掉私鑰）。
func carryOverVersionCiphertext(db *gorm.DB, credentialID, versionID uint,
	passwordEnc, privateKeyEnc string) (string, string, error) {

	if credentialID == 0 || versionID == 0 {
		return passwordEnc, privateKeyEnc, nil
	}
	prev, err := loadCredentialVersion(db, credentialID, versionID)
	if err != nil {
		if errors.Is(err, ErrCredentialVersionNotFound) {
			return passwordEnc, privateKeyEnc, nil
		}
		return "", "", err
	}
	if passwordEnc == "" {
		passwordEnc = prev.PasswordEnc
	}
	if privateKeyEnc == "" {
		privateKeyEnc = prev.PrivateKeyEnc
	}
	return passwordEnc, privateKeyEnc, nil
}

// bindingCiphertext 取某掛載就位版本的兩個密文欄（原樣，不解密）。
// 掛載尚無就位版本時回兩個空字串。
func bindingCiphertext(db *gorm.DB, account *model.AssetAccount) (string, string, error) {
	if account == nil || account.EffectiveVersionID == nil || *account.EffectiveVersionID == 0 {
		return "", "", nil
	}
	return carryOverVersionCiphertext(db, account.CredentialID, *account.EffectiveVersionID, "", "")
}

// bindNewDedicatedCredential 為一筆**尚未寫入**的掛載列配上新的專用憑證。
//
// 呼叫端負責建立掛載列本身；本函式只填 CredentialID 與 EffectiveVersionID。
// 兩者必須與掛載列同一交易寫入——建了掛載卻沒有憑證，該掛載就是一筆
// 連得上介面卻取不到秘密的死列。
//
// 密文非空時同交易建 v1 並把**憑證的現行版本與該掛載的就位版本**一併指向它：
// 這幾條路徑（新增資產直填、建號直填、舊表單透明轉寫）講的都是
// 「遠端現況就是這樣」，宣告的責任在操作者，故立即生效。這不等於宣稱該秘密在
// 遠端有效——是否有效由第一次連線或改密揭露，只是把「未經驗證」從「連不上」
// 降級為「連得上或連不上，兩者都看得見」。
func bindNewDedicatedCredential(tx *gorm.DB, account *model.AssetAccount, asset *model.Asset,
	authMethod, passwordEnc, privateKeyEnc, reason string) error {

	if account == nil {
		return fmt.Errorf("建立專用憑證失敗: 掛載列為空")
	}
	if authMethod == "" {
		authMethod = account.AuthMethod
	}
	secretType := credentialSecretTypeFor(passwordEnc != "", privateKeyEnc != "")
	cred, err := createDedicatedCredential(tx, account.Username, secretType,
		authMethod, model.ProtocolFamilyForAsset(asset))
	if err != nil {
		return err
	}
	account.CredentialID = cred.ID
	account.EffectiveVersionID = nil
	if passwordEnc == "" && privateKeyEnc == "" {
		// 三欄全空的掛載合法（靠 SSH agent 等免密路徑者仍需掛載承載帳號名），
		// 就位版本留空即「尚未取得任何密文」——取密路徑會據此大聲失敗
		return nil
	}
	version, err := appendCredentialVersion(tx, cred.ID, secretType, passwordEnc, privateKeyEnc, reason)
	if err != nil {
		return err
	}
	if err := setCredentialCurrentVersion(tx, cred.ID, version.ID); err != nil {
		return err
	}
	account.EffectiveVersionID = &version.ID
	return nil
}

// appendDeclaredSecret 操作者宣告的密文寫入面：為既有掛載所引用的憑證追加一版，
// 並把憑證的現行版本指向它。回傳新版本 id 供呼叫端在同一交易內寫入就位版本。
//
// 未被本次更動的那一欄自就位版本原樣帶過來（密文原樣搬、不解密）：
// 只改密碼不得順手清掉私鑰——那會讓原本兩種入口的帳號失去其中一種，
// 而使用者的操作裡沒有任何一步表達過這個意思。
//
// **受影響的全部掛載一併就位**：憑證掛在幾台上，操作者宣告的新密文就對那幾台
// 同時生效——他說的是「這組秘密現在長這樣」，那句話的射程是整組，不是他當時
// 點進去的那一台。只改一台會讓其餘各台停在舊版而畫面上看不出差別。
//
// **共用憑證一律拒絕**：本函式的兩個呼叫端都是單一資產的表單（帳號更新、資產更新
// 同步預設帳號），操作者在那個畫面上看得見的只有這一台。射程是整組的寫入若由
// 單台入口發動，其餘主機的登入身分會在操作者不知情的情況下一起改變，
// 而畫面上沒有任何一處說過那句話。出口是憑證層的整組寫入，或先讓這台脫離共用。
//
// 掛載沒有憑證識別時**大聲失敗**：存量轉換已保證該欄非空，此狀態只可能來自繞過
// 服務層的資料層寫入。就地補一筆憑證看似體貼，實際是讓一個不該存在的狀態靜默
// 延續，而它下一次出現時仍然沒有人知道它是怎麼來的。
//
// **改密進行中一律拒絕**，判定就放在這裡而不是各呼叫端：本函式是操作者宣告密文的
// 唯一寫入面，也是取憑證列鎖的地方，判定放在呼叫端就會多一份、而漏掉的那一份在
// 資料庫狀態上看不出來——它會在改密的目標集合底下換掉全部掛載的就位版本，
// 於是那一輪改密收斂到一個沒有人宣告過的秘密上。
func appendDeclaredSecret(tx *gorm.DB, account *model.AssetAccount, passwordEnc, privateKeyEnc string) (uint, error) {
	if account == nil {
		return 0, ErrAssetAccountNotFound
	}
	if account.CredentialID == 0 {
		return 0, ErrBindingWithoutCredential
	}

	cred, err := lockCredentialRow(tx, account.CredentialID)
	if err != nil {
		return 0, err
	}
	if cred.Scope == model.CredentialScopeShared {
		return 0, ErrAccountSharedCredentialSecret
	}
	if err := assertNoActiveRotation(cred); err != nil {
		return 0, err
	}
	if account.EffectiveVersionID != nil {
		passwordEnc, privateKeyEnc, err = carryOverVersionCiphertext(tx, cred.ID,
			*account.EffectiveVersionID, passwordEnc, privateKeyEnc)
		if err != nil {
			return 0, err
		}
	}
	secretType := credentialSecretTypeFor(passwordEnc != "", privateKeyEnc != "")
	version, err := appendCredentialVersion(tx, cred.ID, secretType,
		passwordEnc, privateKeyEnc, model.CredentialVersionReasonManual)
	if err != nil {
		return 0, err
	}
	if err := setCredentialCurrentVersion(tx, cred.ID, version.ID); err != nil {
		return 0, err
	}
	if cred.SecretType != secretType {
		if err := tx.Model(&model.Credential{}).Where("id = ?", cred.ID).
			Update("secret_type", secretType).Error; err != nil {
			return 0, fmt.Errorf("更新憑證秘密型別失敗: %w", err)
		}
	}
	if err := setAllBindingsEffectiveVersion(tx, cred.ID, version.ID); err != nil {
		return 0, err
	}
	account.EffectiveVersionID = &version.ID
	return version.ID, nil
}

// setAllBindingsEffectiveVersion 把某憑證全部掛載的就位版本一併指向同一版。
//
// 只用於**操作者宣告的密文**：那句宣告講的是「這組秘密現在長這樣」，射程是整組。
// 系統產生的密文走的是另一條路——遠端是否收下未知，只有該台驗證通過的那一筆
// 交易才改寫它自己的就位版本，故絕不可在此類路徑上呼叫本函式。
func setAllBindingsEffectiveVersion(tx *gorm.DB, credentialID, versionID uint) error {
	if credentialID == 0 || versionID == 0 {
		return ErrCredentialVersionNotFound
	}
	if err := tx.Model(&model.AssetAccount{}).
		Where("credential_id = ?", credentialID).
		Update("effective_version_id", versionID).Error; err != nil {
		return fmt.Errorf("更新掛載就位版本失敗: %w", err)
	}
	return nil
}

// credentialSecretTypeFor 由密文有無推導秘密型別（私鑰優先）。
func credentialSecretTypeFor(hasPassword, hasPrivateKey bool) string {
	if hasPrivateKey {
		return model.ChangeSecretTypeSSHKey
	}
	if hasPassword {
		return model.ChangeSecretTypePassword
	}
	return model.ChangeSecretTypePassword
}
