package keyvault

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 委託拓撲的讀寫與逐欄驗證。
//
// **本檔零出向依賴**（除 model 與 gorm）：拓撲是「上鎖的資料金鑰送去哪裡解」的
// 事實源，其讀取發生在**已封存狀態**——段 2 的任何服務都尚未建構，此處不得
// 依賴它們。寫入端（API handler）另負責審計與告警，本層只保證原子性與驗證。
//
// **秘密不經本層**：AWS 存取金鑰、GCP 服務帳號金鑰檔、Vault 角色密鑰或權杖
// 一律不進本表、不進本層的任何參數。

// 服務商常數（值與 config 的 KEK_KMS_PROVIDER 一致）。
const (
	TopologyProviderAWS   = "aws"
	TopologyProviderGCP   = "gcp"
	TopologyProviderVault = "vault"
)

// ErrKEKTopologyNotConfigured 拓撲尚未設定（表內無列）。
//
// **不是錯誤狀態而是正常的初始狀態**：全新安裝在解封頁完成拓撲設定之前即為此，
// 委託部署於此時停在已封存等待人工設定。呼叫端 SHALL NOT 以此為由非零退出。
var ErrKEKTopologyNotConfigured = errors.New("委託拓撲尚未設定")

// ErrKEKTopologyNotEditable 該服務商沒有可編輯的拓撲欄位。
//
// GCP 即屬此類：其金鑰識別是完整 CryptoKey 資源名（含專案與位置），沿金鑰列的
// kek_id，本表不另存一份可與之分歧的副本；服務區域對 GCP 不生效。
var ErrKEKTopologyNotEditable = errors.New("該服務商沒有可編輯的拓撲欄位")

// KEKTopologyValidationError 逐欄驗證失敗。
//
// Fields 只列**欄位名**，不含值——錯誤訊息會進審計與 API 回應，而拓撲雖非秘密，
// 回顯企圖值的職責屬審計本文（經端點感知遮罩登記為可追蹤），不屬錯誤訊息。
type KEKTopologyValidationError struct {
	Fields []string
}

func (e *KEKTopologyValidationError) Error() string {
	return fmt.Sprintf("拓撲欄位不合格式或缺項：%s", strings.Join(e.Fields, "、"))
}

// KEKTopologyInput 一次拓撲更新的輸入（**按服務商的完整欄位集**）。
//
// 刻意不用指標欄位表達「這次不改這一欄」：部分更新會讓「位址已改、角色未改」
// 成為可達狀態，而半套目的地正是本表要防的那件事。呼叫端一律送整組。
type KEKTopologyInput struct {
	Provider       string
	Address        string
	TransitKeyName string
	RoleID         string
	Region         string
	UpdatedBy      string
}

// awsRegionPattern 服務區域的正規形式（如 ap-northeast-1、us-gov-east-1）。
var awsRegionPattern = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d$`)

// transitKeyPattern Vault Transit 具名金鑰的字元約束。
var transitKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// roleIDPattern AppRole 角色識別的字元約束（Vault 簽發的是 UUID 形態，
// 但不同版本與掛載點的格式不完全一致，故只約束字元集與長度）。
var roleIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// EditableTopologyFields 該服務商可經介面編輯的欄位（順序即呈現順序）。
//
// 單一事實源：API 的鍵集精確比對、前端的欄位渲染、驗證的必填判定共用此表。
func EditableTopologyFields(provider string) []string {
	switch provider {
	case TopologyProviderVault:
		return []string{"address", "transit_key_name", "role_id"}
	case TopologyProviderAWS:
		return []string{"region"}
	default:
		// GCP 與未知服務商皆無可編輯欄位。
		return nil
	}
}

// LoadKEKTopology 讀取拓撲（封存狀態下亦可讀：全部欄位明文）。
func LoadKEKTopology(db *gorm.DB) (*model.KEKTopology, error) {
	var row model.KEKTopology
	err := db.Where("singleton = ?", 1).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrKEKTopologyNotConfigured
	}
	if err != nil {
		return nil, fmt.Errorf("讀取委託拓撲失敗: %w", err)
	}
	return &row, nil
}

// ValidateKEKTopology 逐欄驗證。非法即整筆拒絕，呼叫端不得部分套用。
func ValidateKEKTopology(in KEKTopologyInput) error {
	var bad []string
	switch in.Provider {
	case TopologyProviderVault:
		if !isHTTPSURL(in.Address) {
			bad = append(bad, "address")
		}
		if !transitKeyPattern.MatchString(in.TransitKeyName) {
			bad = append(bad, "transit_key_name")
		}
		if !roleIDPattern.MatchString(in.RoleID) {
			bad = append(bad, "role_id")
		}
	case TopologyProviderAWS:
		if !awsRegionPattern.MatchString(in.Region) {
			bad = append(bad, "region")
		}
	case TopologyProviderGCP:
		return ErrKEKTopologyNotEditable
	default:
		return ErrKEKTopologyNotEditable
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return &KEKTopologyValidationError{Fields: bad}
	}
	return nil
}

// isHTTPSURL 位址須為 HTTPS。
//
// **不以警告後放行的方式接受明文傳輸**：這條連線上走的是解包後的資料金鑰材料，
// 明文傳輸等於把 DEK 交給任何在路徑上的人。
func isHTTPSURL(raw string) bool {
	if strings.TrimSpace(raw) != raw || raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return false
	}
	// 不接受帶使用者資訊、查詢字串或片段的位址：那些在保管處位址上沒有語義，
	// 出現即代表這不是一個位址而是被夾帶了別的東西。
	return u.User == nil && u.RawQuery == "" && u.Fragment == ""
}

// SaveKEKTopology 單筆原子更新（全有全無）。回傳更新前後的列供審計。
//
// before 於首次設定時為 nil。整個讀改寫落在單一交易內——並行的兩次更新若各自
// 讀出舊值再寫，後到者會以陳舊基準覆寫，而拓撲的每一次覆寫都是一次目的地變更。
func SaveKEKTopology(db *gorm.DB, in KEKTopologyInput) (before *model.KEKTopology, after *model.KEKTopology, err error) {
	if verr := ValidateKEKTopology(in); verr != nil {
		return nil, nil, verr
	}
	err = db.Transaction(func(tx *gorm.DB) error {
		before, after, err = SaveKEKTopologyTx(tx, in)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return before, after, nil
}

// SaveKEKTopologyTx 於**呼叫端已開啟的交易內**寫拓撲（讀改寫同 SaveKEKTopology）。
//
// **存在的唯一理由是全新安裝的原子性**：首批金鑰列與拓撲必須全有全無落庫。
// 分兩個交易寫會留下「拓撲已設定但無金鑰」——`initialization_required` 讀的是
// 金鑰表筆數，該殘留雖可重試，但它使「目的地已成立」這件事在沒有任何金鑰
// 送往該目的地時就先成真。反向（金鑰已落表而拓撲回滾）則讓下一次啟動拿不到
// 建構 provider 所需的位址。
//
// 呼叫端負責交易邊界與鎖；本函式不自行開交易。
func SaveKEKTopologyTx(tx *gorm.DB, in KEKTopologyInput) (before *model.KEKTopology, after *model.KEKTopology, err error) {
	if verr := ValidateKEKTopology(in); verr != nil {
		return nil, nil, verr
	}
	var row model.KEKTopology
	lookupErr := tx.Where("singleton = ?", 1).First(&row).Error
	switch {
	case lookupErr == nil:
		snapshot := row
		before = &snapshot
	case errors.Is(lookupErr, gorm.ErrRecordNotFound):
		row = model.KEKTopology{Singleton: 1}
	default:
		return nil, nil, fmt.Errorf("讀取委託拓撲失敗: %w", lookupErr)
	}
	row.Provider = in.Provider
	row.Address = in.Address
	row.TransitKeyName = in.TransitKeyName
	row.RoleID = in.RoleID
	row.Region = in.Region
	row.UpdatedBy = in.UpdatedBy
	row.UpdatedAt = time.Now()
	if err := tx.Save(&row).Error; err != nil {
		return nil, nil, fmt.Errorf("寫入委託拓撲失敗: %w", err)
	}
	saved := row
	after = &saved
	return before, after, nil
}

// TopologyDigest 拓撲快照摘要，供解封頁核對綁定。
//
// 解封頁在核對步驟取得本值，於送出憑證時帶回；不符即拒並要求重新核對——
// **舊核對結果不得授權送往新目的地**。以欄位串接後雜湊，不以 updated_at
// 為準（同一秒內的兩次改動在時戳上不可分）。
func TopologyDigest(row *model.KEKTopology, keyRef string) string {
	provider, address, transit, roleID, region := "", "", "", "", ""
	if row != nil {
		provider, address, transit, roleID, region = row.Provider, row.Address, row.TransitKeyName, row.RoleID, row.Region
	}
	return digestFields(provider, address, transit, roleID, region, keyRef)
}

// digestFields 以長度前綴串接後 SHA-256，避免欄位邊界歧義
//（`a|bc` 與 `ab|c` 在無長度前綴時雜湊到同一輸入）。
func digestFields(fields ...string) string {
	h := sha256.New()
	for _, f := range fields {
		fmt.Fprintf(h, "%d:", len(f))
		h.Write([]byte(f))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// CurrentKEKID 現行代表列共用的 KEK 引用（既有部署的**金鑰識別事實源**）。
//
// 解封頁顯示的金鑰識別、委託 provider 建構所用的金鑰識別一律取自此處，
// **拓撲表不另存一份**——兩份可分歧的識別會讓「核對目的地」失去意義：
// 顯示的是一把金鑰、實際解包用的是另一把。
//
// 空金鑰表回空字串（全新安裝的正常狀態，不是錯誤）。
//
// **多個相異引用並存時取最新的那一把**：那是換鑰精靈的中途狀態——重包會讓新舊
// 兩組現行列並存到切換完成為止，而此時本部署實際要用來解的是新的那一把
//（重啟後的建構同樣以新引用為準）。回錯而非取一個會讓解封頁在一次正常的換鑰
// 中途完全打不開，而那正是最需要它的時候。
//
// 「最新」以列的建立序判定（`created_at`，同時點再以 id 收斂），不以字典序——
// 字典序與「哪一把比較新」沒有任何關係。
func CurrentKEKID(db *gorm.DB) (string, error) {
	var rows []model.DataKey
	if err := db.Where("kek_retired_at IS NULL AND wrapped_key <> ''").
		Order("created_at DESC, id DESC").Limit(1).Find(&rows).Error; err != nil {
		return "", fmt.Errorf("讀取現行 KEK 引用失敗: %w", err)
	}
	if len(rows) == 0 {
		return "", nil
	}
	return rows[0].KEKID, nil
}
