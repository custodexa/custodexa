package database

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// 存量搬移的**需要金鑰的那一半**：把搬進密文版本表的密文改綁到新的欄位身分，
// 再以解密後的明文判定既有隱性共用關係能否合併。
//
// # 為何是解封後佇列項而非 versioned migration
//
// 兩件事都需要 codec，而啟動段 1 沒有（ui 模式下 KEK 要等解封後的段 2）。
// 「需要 codec 的資料 migration 一律登記進解封後佇列」是既有的架構裁決
// （internal/modules/keyvault/post_unseal_migration.go 檔頭）。純結構與不需解密的
// 存量搬移留在段 1 的 versioned migration（migration_credential_library.go）。
//
// # 第一步：密文改綁欄位身分（不是可選的）
//
// 信封密文的 AAD 綁 **表|欄**。段 1 把帳號列的密文原樣搬進
// credential_secret_versions，那批值的 AAD 仍是帳號表的身分，**以新表的身分解不開**。
// 若不改綁，兩件事會壞：
//
//   - DEK 輪替與退役金鑰的引用掃描以登記清單的 表|欄 為身分逐欄解密重加密，
//     整批舊身分的值會逐筆失敗；
//   - 取密路徑得永遠記得「這一版是舊身分、那一版是新身分」，等於把一次性搬遷的
//     殘留永久留在讀取路徑上。
//
// 故本步以 keyvault 的跨表重加密入口逐筆改綁——那個入口存在的理由正是跨表搬遷。
//
// # 第二步：隱性共用關係的合併
//
// 判定「這些帳號是不是真的共用同一組秘密」只能比對**明文**：同一組明文的兩份信封
// 密文帶各自的隨機 nonce，密文層永遠不相等。一致者合併為一筆具名共用憑證，
// 不一致者各留專用並留下可查的待處理記錄。
//
// 判準有三面，任一面不一致即不合併（見 evaluateGroupForMerge）：明文、秘密的**有無**
// （「沒有秘密」與「秘密是空的」是兩件事，明文比對分不出來），以及合併後由共用憑證
// **單一持有**的四個屬性（帳號名、秘密型別、認證方式、協定族）。不比屬性等於靜默改寫
// 其餘成員的協定族——那正是掛載相容性的判準。
//
// # 冪等閘＝執行期 marker
//
// 不像欄位型轉換能以「欄位還在不在」判定終態——本轉換不刪任何欄，且不一致的群組
// 每次都會再度符合「未合併」的形狀，沒有 marker 就會每次啟動重覆標記與重覆寫審計。
// 故以 schema_migrations 的執行期 marker 記錄「已評估完畢」，並登記於
// runtimeMarkerVersions（漏登會讓每個跑過本轉換的安裝在下次啟動被 fail-close 擋住）。
//
// # 失敗即整批回滾，修正後可再執行一次
//
// 兩步全程包在單一交易內：任一筆解密失敗、金鑰不可用、或寫入失敗，即整段 rollback、
// **不寫 marker**，佇列記一筆失敗，下次啟動重試。**不得降級**為「解不開就全部各留專用」
// ——那會靜默丟掉全部共用關係，而管理者從畫面上看不出差別。
// 回滾後密文版本仍帶舊身分，取密路徑會大聲失敗；那是刻意的——一個解不開的秘密
// 必須被看見，不能靠讀取路徑的相容分支蓋過去。
//
// 失敗**不阻塞服務**（那也是刻意的），於是每次失敗嘗試另外留一筆審計列
// （recordConversionFailure）：只有啟動日誌時，等到有人去連線才暴露錯誤的那一刻，
// 已經沒有任何可查的紀錄說「開機時這件事失敗過、當時還有多少沒轉」。
// 該列**寫在交易之外**——寫在交易內會跟著回滾一起消失。
//
// # 待處理記錄的形態
//
// 不新增第五張表：不一致群組的每筆憑證在 note 前置固定機器碼標記
// `[MIGRATION_GROUP_MISMATCH:<群組值>]`（顯示在憑證詳情、可由 admin 自行清除；
// 憑證庫搜尋不比對備註，定位靠下述審計列），
// 同時每組寫一筆審計列（resource=credential、action=migration，details 列出受影響的
// 憑證與群組），審計列是不可竄改的永久證據面。

// CredentialSecretConversionMarkerVersion 憑證密文轉換的執行標記
// （寫入 schema_migrations 的 version）。
//
// 它**不是** migrations 清單裡的版本項（本轉換不是 versioned migration，而是
// 解封後佇列項），只是共用 schema_migrations 表做冪等標記；故必須登記於
// runtimeMarkerVersions，否則 RunMigrations 的 fail-close 會把它判成未知版本。
const CredentialSecretConversionMarkerVersion = "20260906_credential_secrets_converted"

// PostUnsealMigrationCredentialSecretConversion 內建佇列項名（組裝根登記用具名常數，
// 沿既有佇列項慣例——登記名不得走字面量字串）。
const PostUnsealMigrationCredentialSecretConversion = "credential_secret_conversion"

// sharedCredentialAutoNamePrefix 自動命名的前綴；序號依群組出現順序遞增，
// 產生後 admin 可自行改名。
const sharedCredentialAutoNamePrefix = "共用憑證 #"

// MigrationGroupMismatchPrefix 不一致群組的待處理標記前綴（機器碼，可搜尋）。
const MigrationGroupMismatchPrefix = "[MIGRATION_GROUP_MISMATCH:"

// RunCredentialSecretConversion 執行轉換（解封後佇列項的執行體）。
//
// codec 由佇列注入；為 nil 即金鑰不可用，一律回錯而非跳過——跳過等於把一批
// 解不開的密文留在庫裡，並靜默放棄全部共用關係。
func RunCredentialSecretConversion(db *gorm.DB, codec crypto.ColumnCodec) error {
	if db == nil {
		return fmt.Errorf("憑證密文轉換需要資料庫句柄")
	}
	done, err := migrationMarkerApplied(db, CredentialSecretConversionMarkerVersion)
	if err != nil {
		recordConversionFailure(db, conversionStageMarkerRead)
		return fmt.Errorf("讀取轉換執行標記失敗: %w", err)
	}
	if done {
		return nil // 已評估完畢，不再執行第二次
	}
	if codec == nil {
		recordConversionFailure(db, conversionStageCodec)
		return fmt.Errorf("憑證密文轉換需要可用的資料金鑰：金鑰未就緒時中止並回滾，" +
			"不得降級為「留著舊身分的密文、全部各建專用憑證」")
	}

	rebound, merged, mismatched := 0, 0, 0
	stage := conversionStageRebind
	err = db.Transaction(func(tx *gorm.DB) error {
		var err error
		if rebound, err = rebindMigratedVersionCiphertext(tx, codec); err != nil {
			return err
		}
		stage = conversionStageScan
		groups, err := credentialGroupsForMerge(tx)
		if err != nil {
			return err
		}
		for _, g := range groups {
			stage = conversionStageCompare
			verdict, err := evaluateGroupForMerge(codec, g)
			if err != nil {
				return err
			}
			if verdict.Merge {
				merged++
				stage = conversionStageMerge
				if err := mergeGroupIntoSharedCredential(tx, g, merged); err != nil {
					return err
				}
				continue
			}
			mismatched++
			stage = conversionStageMark
			if err := markGroupMismatch(tx, g, verdict); err != nil {
				return err
			}
		}
		stage = conversionStageMarker
		return tx.Create(&SchemaMigration{
			Version:   CredentialSecretConversionMarkerVersion,
			AppliedAt: time.Now(),
		}).Error
	})
	if err != nil {
		recordConversionFailure(db, stage)
		return err
	}
	log.Printf("[CredentialSecretConversion] 完成：改綁密文 %d 筆、合併共用 %d 組、標記待處理 %d 組",
		rebound, merged, mismatched)
	return nil
}

// rebindMigratedVersionCiphertext 把段 1 原樣搬入的密文改綁到密文版本表的欄位身分。
//
// 對象＝建立原因為「存量搬移」的版本列，那是唯一一批帶舊身分的值；此後由憑證路徑
// 寫入的版本一律已是新身分。回傳改綁的欄位值數。
func rebindMigratedVersionCiphertext(tx *gorm.DB, codec crypto.ColumnCodec) (int, error) {
	type versionRow struct {
		ID            uint
		PasswordEnc   string
		PrivateKeyEnc string
	}
	var rows []versionRow
	if err := tx.Raw(`SELECT id, COALESCE(password_enc, '') AS password_enc,
		COALESCE(private_key_enc, '') AS private_key_enc
		FROM credential_secret_versions WHERE created_reason = ? ORDER BY id`,
		model.CredentialVersionReasonMigration).Scan(&rows).Error; err != nil {
		return 0, fmt.Errorf("讀取待改綁的密文版本失敗: %w", err)
	}

	ctx := context.Background()
	rebound := 0
	for _, r := range rows {
		updates := map[string]interface{}{}
		if r.PasswordEnc != "" {
			out, err := keyvault.RecryptForNewRef(ctx, codec,
				keyvault.RefAccountPassword, keyvault.RefCredentialVersionPassword, r.PasswordEnc)
			if err != nil {
				return 0, fmt.Errorf("改綁密文版本 #%d 的密碼欄失敗（中止並回滾）: %w", r.ID, err)
			}
			updates["password_enc"] = out
		}
		if r.PrivateKeyEnc != "" {
			out, err := keyvault.RecryptForNewRef(ctx, codec,
				keyvault.RefAccountPrivateKey, keyvault.RefCredentialVersionPrivateKey, r.PrivateKeyEnc)
			if err != nil {
				return 0, fmt.Errorf("改綁密文版本 #%d 的私鑰欄失敗（中止並回滾）: %w", r.ID, err)
			}
			updates["private_key_enc"] = out
		}
		if len(updates) == 0 {
			continue
		}
		if err := tx.Model(&model.CredentialSecretVersion{}).Where("id = ?", r.ID).
			Updates(updates).Error; err != nil {
			return 0, fmt.Errorf("寫回改綁後的密文版本 #%d 失敗: %w", r.ID, err)
		}
		rebound += len(updates)
	}
	return rebound, nil
}

// credentialGroupMember 一個待評估群組的成員（掛載列、其專用憑證與該憑證的現行版本）。
type credentialGroupMember struct {
	AccountID    uint
	CredentialID uint
	AssetID      uint
	// 一致判準涵蓋的四個憑證屬性（見 mergeAttributesOf）
	Username       string
	SecretType     string
	AuthMethod     string
	ProtocolFamily string
	// VersionID 現行版本；0＝該憑證還沒有任何版本。
	// **與「版本存在但秘密欄是空的」是兩件事**，見 secretPresenceOf
	VersionID     uint
	PasswordEnc   string
	PrivateKeyEnc string
	Note          string
}

// mergeAttribute 一致判準涵蓋的一個憑證屬性（名稱是機器碼，會落進審計列）。
type mergeAttribute struct {
	Name  string
	Value string
}

// mergeAttributesOf 合併後由共用憑證**單一持有**的屬性。
//
// 這四項全部必須一致才准合併：合併只留第一位成員的值
//（mergeGroupIntoSharedCredential），任一項不同就代表其餘成員的屬性被靜默改寫。
// 協定族尤其致命——它是掛載時與資產協定比對相容性的判準，被改掉的那台此後
// 對不上任何憑證，而畫面上看不出發生過什麼。
func mergeAttributesOf(m credentialGroupMember) []mergeAttribute {
	return []mergeAttribute{
		{Name: "username", Value: m.Username},
		{Name: "secret_type", Value: m.SecretType},
		{Name: "auth_method", Value: m.AuthMethod},
		{Name: "protocol_family", Value: m.ProtocolFamily},
	}
}

// secretPresence 秘密的**有無**三元組：版本在不在、兩個秘密欄各自在不在。
//
// 「沒有秘密」與「秘密是空的」是兩件事：前者代表這筆憑證從來沒有過秘密，
// 後者代表有一版秘密而它的某一欄沒有內容。明文比對分不出這兩者
//（兩邊解出來都是空字串），故存在性另外比。
type secretPresence struct {
	Version    bool
	Password   bool
	PrivateKey bool
}

func secretPresenceOf(m credentialGroupMember) secretPresence {
	return secretPresence{
		Version:    m.VersionID != 0,
		Password:   m.PasswordEnc != "",
		PrivateKey: m.PrivateKeyEnc != "",
	}
}

// credentialGroup 一個待評估的隱性共用群組（成員兩個以上）。
type credentialGroup struct {
	Value   string
	Members []credentialGroupMember
}

// credentialGroupsForMerge 取出全部待評估群組，依群組首次出現的帳號 id 排序。
//
// 密文取自**憑證的現行版本**而非帳號列：前一步已把版本列改綁為新身分，
// 從版本列讀可以只用一組欄位身分，不必在同一支流程裡同時處理兩種 AAD。
//
// 只評估成員兩個以上者：單一成員的群組值不構成共用關係，維持專用即可，
// 既不合併也不標記待處理。軟刪的掛載列不算成員（墓碑列不參與任何連線或輪替）。
func credentialGroupsForMerge(tx *gorm.DB) ([]credentialGroup, error) {
	type row struct {
		AccountID       uint
		CredentialID    uint
		AssetID         uint
		Username        string
		SecretType      string
		AuthMethod      string
		ProtocolFamily  string
		VersionID       uint
		PasswordEnc     string
		PrivateKeyEnc   string
		CredentialGroup string
		Note            string
	}
	var rows []row
	if err := tx.Raw(`SELECT a.id AS account_id, a.credential_id, a.asset_id,
		c.username AS username,
		COALESCE(c.secret_type, '') AS secret_type,
		COALESCE(c.auth_method, '') AS auth_method,
		COALESCE(c.protocol_family, '') AS protocol_family,
		COALESCE(v.id, 0) AS version_id,
		COALESCE(v.password_enc, '') AS password_enc,
		COALESCE(v.private_key_enc, '') AS private_key_enc,
		COALESCE(a.credential_group, '') AS credential_group,
		COALESCE(c.note, '') AS note
		FROM asset_accounts a
		JOIN credentials c ON c.id = a.credential_id
		LEFT JOIN credential_secret_versions v ON v.id = c.current_version_id
		WHERE a.deleted_at IS NULL AND COALESCE(a.credential_group, '') <> ''
		ORDER BY a.id`).Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("讀取既有共用群組成員失敗: %w", err)
	}

	order := []string{}
	byValue := map[string][]credentialGroupMember{}
	for _, r := range rows {
		if _, seen := byValue[r.CredentialGroup]; !seen {
			order = append(order, r.CredentialGroup)
		}
		byValue[r.CredentialGroup] = append(byValue[r.CredentialGroup], credentialGroupMember{
			AccountID:      r.AccountID,
			CredentialID:   r.CredentialID,
			AssetID:        r.AssetID,
			Username:       r.Username,
			SecretType:     r.SecretType,
			AuthMethod:     r.AuthMethod,
			ProtocolFamily: r.ProtocolFamily,
			VersionID:      r.VersionID,
			PasswordEnc:    r.PasswordEnc,
			PrivateKeyEnc:  r.PrivateKeyEnc,
			Note:           r.Note,
		})
	}
	var out []credentialGroup
	for _, v := range order {
		if len(byValue[v]) < 2 {
			continue
		}
		out = append(out, credentialGroup{Value: v, Members: byValue[v]})
	}
	return out, nil
}

// 群組不一致的分類（審計列的 reason 值；機器碼，供事後查案分辨處置方式）。
const (
	// conversionReasonSecretsMismatch 秘密本身不同：明文不同，或秘密的有無不同。
	// 出路只有一條——由管理者判定哪一組秘密是對的
	conversionReasonSecretsMismatch = "group_secrets_mismatch"
	// conversionReasonMetadataMismatch 秘密相同但憑證屬性不同（見 mergeAttributesOf）。
	// 出路是先對齊屬性；秘密本身沒有衝突
	conversionReasonMetadataMismatch = "group_metadata_mismatch"
)

// groupMergeVerdict 一個群組的合併判定。
type groupMergeVerdict struct {
	// Merge 全體一致，可合併為一筆共用憑證
	Merge bool
	// Reason 不可合併的分類（見上方常數）；Merge 為真時為空
	Reason string
	// Fields 不一致的項目（機器碼，去重且保序）：屬性名，或秘密面的
	// secret_presence／secret_value。落進審計列，讓管理者知道要去對齊什麼
	Fields []string
}

// evaluateGroupForMerge 判定一個隱性群組能否合併為一筆共用憑證。
//
// 判準分兩面，**任一面不一致即不合併**：
//
//   - 秘密面：密碼與私鑰的明文（常數時間比較），以及秘密的**有無**
//     （secretPresence）。兩欄都要比，只比其一會把「密碼相同但金鑰不同」
//     誤判為同一組秘密；有無另外比，因為明文比對分不出「沒有秘密」與「秘密是空的」。
//   - 屬性面：mergeAttributesOf 的四項。合併後的共用憑證只留第一位成員的值，
//     不比就等於靜默改寫其餘成員的協定族、認證方式與秘密型別。
//
// 解密失敗一律回錯（整批回滾）：拿不到明文就無從判定，此時「各留專用」是猜的。
func evaluateGroupForMerge(codec crypto.ColumnCodec, g credentialGroup) (groupMergeVerdict, error) {
	ctx := context.Background()
	first := g.Members[0]
	firstPassword, err := decryptCredentialPassword(ctx, codec, first.PasswordEnc)
	if err != nil {
		return groupMergeVerdict{}, fmt.Errorf("解密帳號 #%d 的密碼以比對共用關係失敗: %w", first.AccountID, err)
	}
	firstKey, err := decryptCredentialPrivateKey(ctx, codec, first.PrivateKeyEnc)
	if err != nil {
		return groupMergeVerdict{}, fmt.Errorf("解密帳號 #%d 的私鑰以比對共用關係失敗: %w", first.AccountID, err)
	}
	firstAttrs := mergeAttributesOf(first)
	firstPresence := secretPresenceOf(first)

	secretsDiffer, metadataDiffer := false, false
	fields := []string{}
	addField := func(name string) {
		for _, existing := range fields {
			if existing == name {
				return
			}
		}
		fields = append(fields, name)
	}
	for _, m := range g.Members[1:] {
		password, err := decryptCredentialPassword(ctx, codec, m.PasswordEnc)
		if err != nil {
			return groupMergeVerdict{}, fmt.Errorf("解密帳號 #%d 的密碼以比對共用關係失敗: %w", m.AccountID, err)
		}
		key, err := decryptCredentialPrivateKey(ctx, codec, m.PrivateKeyEnc)
		if err != nil {
			return groupMergeVerdict{}, fmt.Errorf("解密帳號 #%d 的私鑰以比對共用關係失敗: %w", m.AccountID, err)
		}
		// 常數時間比較：逐筆全比完才回結論，不因先發現不同而提早離開迴圈
		sameSecret := subtle.ConstantTimeCompare([]byte(password), []byte(firstPassword)) == 1 &&
			subtle.ConstantTimeCompare([]byte(key), []byte(firstKey)) == 1
		if !sameSecret {
			secretsDiffer = true
			addField("secret_value")
		}
		if secretPresenceOf(m) != firstPresence {
			secretsDiffer = true
			addField("secret_presence")
		}
		for i, attr := range mergeAttributesOf(m) {
			if attr.Value != firstAttrs[i].Value {
				metadataDiffer = true
				addField(attr.Name)
			}
		}
	}
	if !secretsDiffer && !metadataDiffer {
		return groupMergeVerdict{Merge: true}, nil
	}
	// 秘密面優先：兩面都不一致時，秘密的衝突是先要被人判的那一件，
	// 屬性對齊了也不會讓它變成可合併
	reason := conversionReasonMetadataMismatch
	if secretsDiffer {
		reason = conversionReasonSecretsMismatch
	}
	return groupMergeVerdict{Reason: reason, Fields: fields}, nil
}

// decryptCredentialPassword／decryptCredentialPrivateKey 解封一個密文版本欄；
// 空值即空明文（沒有秘密可比）。
//
// **兩支分開寫、各自帶字面 ref**：解封出口守衛以 AST 判定 `DecryptFor` 的第二個
// 引數是不是資產類 CipherRef，把 ref 收成參數會讓這個解封點在掃描面上變成隱形人
// ——那正是該守衛存在的理由。兩支皆具名登記於 assetCredentialExits。
func decryptCredentialPassword(ctx context.Context, codec crypto.ColumnCodec, ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	return codec.DecryptFor(ctx, keyvault.RefCredentialVersionPassword, ciphertext)
}

func decryptCredentialPrivateKey(ctx context.Context, codec crypto.ColumnCodec, ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	return codec.DecryptFor(ctx, keyvault.RefCredentialVersionPrivateKey, ciphertext)
}

// mergeGroupIntoSharedCredential 把一致的群組合併為一筆具名共用憑證。
//
// 密文取第一個成員的版本列原樣搬（成員明文已證實一致，故取誰都相同；
// 該值在前一步已改綁為版本表身分，於是這次是**同表同欄的列間複製**，不需重加密，
// 也不需要在此持有明文）。全部成員的掛載改指新憑證與其 v1 版本，
// 成員原本的專用憑證與版本一併刪除，不留零掛載的孤兒。
func mergeGroupIntoSharedCredential(tx *gorm.DB, g credentialGroup, seq int) error {
	first := g.Members[0]
	var base model.Credential
	if err := tx.First(&base, first.CredentialID).Error; err != nil {
		return fmt.Errorf("讀取群組 %s 的來源憑證失敗: %w", g.Value, err)
	}
	name := fmt.Sprintf("%s%d", sharedCredentialAutoNamePrefix, seq)
	shared := model.Credential{
		Name:           &name,
		Scope:          model.CredentialScopeShared,
		Username:       base.Username,
		SecretType:     base.SecretType,
		AuthMethod:     base.AuthMethod,
		ProtocolFamily: base.ProtocolFamily,
	}
	if err := tx.Create(&shared).Error; err != nil {
		return fmt.Errorf("建立群組 %s 的共用憑證失敗: %w", g.Value, err)
	}

	var effective *uint
	if first.PasswordEnc != "" || first.PrivateKeyEnc != "" {
		version := model.CredentialSecretVersion{
			CredentialID:  shared.ID,
			VersionNo:     1,
			SecretType:    base.SecretType,
			PasswordEnc:   first.PasswordEnc,
			PrivateKeyEnc: first.PrivateKeyEnc,
			CreatedReason: model.CredentialVersionReasonMigration,
		}
		if err := tx.Create(&version).Error; err != nil {
			return fmt.Errorf("建立群組 %s 的密文版本失敗: %w", g.Value, err)
		}
		if err := tx.Model(&model.Credential{}).Where("id = ?", shared.ID).
			Update("current_version_id", version.ID).Error; err != nil {
			return fmt.Errorf("回填共用憑證 #%d 的現行版本失敗: %w", shared.ID, err)
		}
		effective = &version.ID
	}

	for _, m := range g.Members {
		if err := tx.Model(&model.AssetAccount{}).Where("id = ?", m.AccountID).
			Updates(map[string]interface{}{
				"credential_id":        shared.ID,
				"effective_version_id": effective,
			}).Error; err != nil {
			return fmt.Errorf("將帳號 #%d 改指共用憑證失敗: %w", m.AccountID, err)
		}
		if err := tx.Where("credential_id = ?", m.CredentialID).
			Delete(&model.CredentialSecretVersion{}).Error; err != nil {
			return fmt.Errorf("刪除帳號 #%d 的專用密文版本失敗: %w", m.AccountID, err)
		}
		if err := tx.Unscoped().Delete(&model.Credential{}, m.CredentialID).Error; err != nil {
			return fmt.Errorf("刪除帳號 #%d 的專用憑證失敗: %w", m.AccountID, err)
		}
	}
	return nil
}

// markGroupMismatch 標記不一致的群組：成員各留專用憑證，note 前置機器碼標記，
// 並寫一筆審計列作為永久證據。
//
// 標記本身冪等（已帶同一標記者不重覆前置）；全部成員都已標記過時不再寫第二筆審計列
// ——證據要留，但同一件事重覆留痕會讓事後查案分不出發生過幾次。
//
// 審計列帶 verdict 的分類與不一致項目：管理者看到標記之後的第一個問題是
// 「要去對齊什麼」，只寫「不一致」等於把整組秘密逐台重看一遍的工作留給他。
func markGroupMismatch(tx *gorm.DB, g credentialGroup, verdict groupMergeVerdict) error {
	marker := MigrationGroupMismatchPrefix + g.Value + "]"
	ids := make([]uint, 0, len(g.Members))
	newlyMarked := 0
	for _, m := range g.Members {
		ids = append(ids, m.CredentialID)
		if strings.HasPrefix(m.Note, marker) {
			continue
		}
		note := marker
		if m.Note != "" {
			note = marker + " " + m.Note
		}
		if err := tx.Model(&model.Credential{}).Where("id = ?", m.CredentialID).
			Update("note", note).Error; err != nil {
			return fmt.Errorf("標記憑證 #%d 的待處理狀態失敗: %w", m.CredentialID, err)
		}
		newlyMarked++
	}
	if newlyMarked == 0 {
		return nil
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	details, err := json.Marshal(map[string]interface{}{
		"reason":          verdict.Reason,
		"mismatch_fields": verdict.Fields,
		"group":           g.Value,
		"credential_ids":  ids,
		"member_count":    len(g.Members),
	})
	if err != nil {
		return fmt.Errorf("序列化群組 %s 的待處理記錄失敗: %w", g.Value, err)
	}
	entry := model.AuditLog{
		Action:   model.ActionMigration,
		Resource: model.ResourceCredential,
		Status:   model.StatusSuccess,
		UserID:   0,
		Username: "system",
		Details:  string(details),
	}
	if err := tx.Create(&entry).Error; err != nil {
		return fmt.Errorf("寫入群組 %s 的待處理審計失敗: %w", g.Value, err)
	}
	return nil
}

// 轉換失敗的階段（審計列的 stage 值）。
//
// **記階段而不記原始錯誤字串**：階段是本轉換自己定義的固定集合，事後可長期比對；
// 原始錯誤來自資料庫與 codec，內容不受本檔控制，落進不可竄改的證據面之前
// 無法保證它不帶入任何值。原始錯誤仍完整留在啟動日誌
//（RunPostUnsealMigrations 逐項印出），兩者配套使用。
const (
	conversionStageMarkerRead = "marker_read"
	conversionStageCodec      = "codec_unavailable"
	conversionStageRebind     = "rebind"
	conversionStageScan       = "scan_groups"
	conversionStageCompare    = "compare"
	conversionStageMerge      = "merge"
	conversionStageMark       = "mark_mismatch"
	conversionStageMarker     = "write_marker"
)

// conversionPending 尚未處理完的工作量（失敗留痕的規模欄）。
type conversionPending struct {
	// Versions 待改綁的密文版本列數
	Versions int64
	// Groups 待評估的隱性共用群組數
	Groups int64
}

// pendingConversionWorkload 量出「這次失敗留下多少沒做完的事」。
//
// 兩個數字都是失敗**當下**的實況（交易已回滾，庫回到轉換前的形狀），
// 它們回答的是管理者的第一個問題：這台機器現在有多少存量還沒轉。
func pendingConversionWorkload(db *gorm.DB) (conversionPending, error) {
	var out conversionPending
	if err := db.Raw(`SELECT count(*) FROM credential_secret_versions WHERE created_reason = ?`,
		model.CredentialVersionReasonMigration).Scan(&out.Versions).Error; err != nil {
		return out, err
	}
	if err := db.Raw(`SELECT count(*) FROM (
		SELECT credential_group FROM asset_accounts
		WHERE deleted_at IS NULL AND COALESCE(credential_group, '') <> ''
		GROUP BY credential_group HAVING count(*) >= 2) g`).Scan(&out.Groups).Error; err != nil {
		return out, err
	}
	return out, nil
}

// recordConversionFailure 為一次失敗的轉換嘗試留一筆持久痕跡。
//
// # 為何非留不可
//
// 佇列項失敗不阻塞服務（那是刻意的：一批解不開的秘密不該讓整台機器起不來），
// 於是服務照常起來、未改綁的存量憑證要等到有人去連線才暴露錯誤。只留啟動日誌時，
// 那個時候已經沒有任何可查的紀錄說「開機時這件事失敗過、當時還有多少沒轉」。
//
// # 為何寫在交易之外
//
// 失敗即整批回滾，寫在交易內的證據會跟著回滾一起消失——那正是這條路徑最需要
// 留痕的時刻。故以 db（非 tx）寫入，於交易返回錯誤之後。
//
// # 為何失敗了也不回錯
//
// 留痕本身失敗不得改變轉換的結局（呼叫端要收到的是原始錯誤，不是留痕的錯誤），
// 也不得阻塞啟動。此時降級為只有日誌。
func recordConversionFailure(db *gorm.DB, stage string) {
	payload := map[string]interface{}{
		"reason": "conversion_failed",
		"stage":  stage,
	}
	if pending, err := pendingConversionWorkload(db); err != nil {
		payload["counts_available"] = false
	} else {
		payload["pending_versions"] = pending.Versions
		payload["pending_groups"] = pending.Groups
	}
	details, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[CredentialSecretConversion] 失敗留痕序列化失敗（僅剩啟動日誌）: %v", err)
		return
	}
	entry := model.AuditLog{
		Action:   model.ActionMigration,
		Resource: model.ResourceCredential,
		Status:   model.StatusFailure,
		UserID:   0,
		Username: "system",
		Details:  string(details),
	}
	if err := db.Create(&entry).Error; err != nil {
		log.Printf("[CredentialSecretConversion] 失敗留痕寫入失敗（僅剩啟動日誌）: %v", err)
	}
}

// migrationMarkerApplied 判定某個版本標記是否已寫入 schema_migrations。
func migrationMarkerApplied(db *gorm.DB, version string) (bool, error) {
	var count int64
	if err := db.Model(&SchemaMigration{}).Where("version = ?", version).
		Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}
