package config

import (
	"crypto/subtle"
	"fmt"
	"os"
	"strings"

	"github.com/custodexa/backend/pkg/crypto"
)

// KEK 來源模式判定（kek-provider-modularization D2）。
//
// **本檔的全部 env 讀取一律走 LookupEnv 三值語義**（未設／設為空字串／設為
// 有效值互相區分），SHALL NOT 經任何預設值注入（D2.0）——config.getEnv 的
// 「空字串即視為未設並回落預設值」語義用於金鑰類鍵會造成兩個致命後果：
// (1) 委託／ui 模式下「本地鑰有值」恆為真而永遠不可啟動；
// (2) 公開已知的出廠預設材料被靜默注入為 KEK。
//
// **KEK 材料鍵是單一鍵 `ENCRYPTION_KEY`**（名稱與規格債清理）：原本另有一把
// 新鍵並以「新鍵未設時回落相容鍵」兩步解析，該雙鍵窗已整組移除（產品未發佈、
// 無存量站點，不需相容窗）。隨之消滅的還有原列 12「以空字串遮蔽仍非空的
// 相容鍵」——單鍵下不存在可被遮蔽的第二把鑰，該格恆不可達。
// **SHALL NOT 再引入第二把 KEK 材料鍵**（守衛見 kek_matrix_test.go 的
// TestKEKMaterialKeyIsSingleSourceOfTruth）。

// 金鑰類環境變數鍵名（單一事實源；env 漂移守衛掃這些字面）
const (
	EnvKeyKEKProvider   = "KEK_PROVIDER"
	EnvKeyEncryptionKey = "ENCRYPTION_KEY"

	EnvKeyKMSProvider = "KEK_KMS_PROVIDER"
	EnvKeyKMSKeyID    = "KEK_KMS_KEY_ID"
	EnvKeyKMSRegion   = "KEK_KMS_REGION"

	EnvKeyHSMModule     = "KEK_HSM_MODULE"
	EnvKeyHSMTokenLabel = "KEK_HSM_TOKEN_LABEL"
	EnvKeyHSMKeyLabel   = "KEK_HSM_KEY_LABEL"
	EnvKeyHSMPin        = "KEK_HSM_PIN"
	EnvKeyHSMPinFile    = "KEK_HSM_PIN_FILE"
)

// KEKGenerateCommandSpec 一條文件化的 KEK 材料生成指令與其產出形態。
type KEKGenerateCommandSpec struct {
	// Command 給 operator 直接貼進 shell 的指令
	Command string
	// Form 該指令產出的材料形態（crypto.KEKForm*）
	Form string
}

// KEKGenerateCommands 文件化的 KEK 材料生成指令集合（**單一事實源**）。
//
// 缺陷史（兩輪）：
//
//  1. 最初文件指示 `openssl rand -base64 24`，雖恰得 32 字元但 base64 字元集含
//     `+` `/`，理論 (62/64)^32 ≈ 36% 才通過驗證——照文件做有六成機率拒啟動，
//     且列 3b 的錯誤訊息重複同一條壞指令，操作者無自救線索。當時的處置是把指令
//     換成必然合格的 `tr` 管線。
//  2. 2026-08-16 全新安裝實測：operator 自行使用 `openssl rand -hex 32`
//     （一把**完全正確**的 32 位元組金鑰的 hex 編碼）而被拒。真因不在指令，
//     在於驗證器把「輸入編碼」與「金鑰長度」綁成同一條規則。處置是拆開兩者
//     （見 crypto.DecodeKEKMaterial），並把單一指令改為**涵蓋三種形態各一條**的集合
//     ——只給一條等於暗示只有一種寫法，而那正是使用者自行發明指令的動機。
//
// **每形態恰一條**：列三條的目的是讓「有三種寫法」透過範例被看見；
// 同一形態列兩條只是雜訊。**不列 Windows／PowerShell 版本**：本集合的每一條都由
// TestDocumentedKEKCommandsAlwaysValidate 於 Linux 測試容器內**實跑**驗證，
// 無法被實跑的指令列上去就是一條未經驗證的宣稱——那正是本次缺陷的成因。
// 沒有 shell 的情境由介面的「本地生成」按鈕承擔。
//
// 本集合同時被列 3b 錯誤訊息、`.env.example`（由 env 漂移守衛比對）、
// 介面的生成指令參考（由前端 fixture 守衛比對）與實跑守衛引用。
var KEKGenerateCommands = []KEKGenerateCommandSpec{
	{Command: "openssl rand -hex 32", Form: crypto.KEKFormHex},
	{Command: "openssl rand -base64 32", Form: crypto.KEKFormBase64},
	{Command: "LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32", Form: crypto.KEKFormRaw},
}

// KEKGenerateCommandLines 生成指令的純文字清單（供錯誤訊息與範本比對）。
func KEKGenerateCommandLines() []string {
	out := make([]string, 0, len(KEKGenerateCommands))
	for _, c := range KEKGenerateCommands {
		out = append(out, c.Command)
	}
	return out
}

// KEK 執行期模式白名單（大小寫敏感）
const (
	KEKModeEnv = "env"
	KEKModeUI  = "ui"
	KEKModeKMS = "kms"
	KEKModeHSM = "hsm"
)

// EnvLookup os.LookupEnv 的可注入形式（矩陣逐格測試不得污染行程 env）
type EnvLookup func(key string) (string, bool)

// OSEnvLookup 生產路徑的三值讀取器
func OSEnvLookup(key string) (string, bool) { return os.LookupEnv(key) }

// MapEnvLookup 由 map 構造的讀取器；**值為 nil 的鍵視為未設**
func MapEnvLookup(m map[string]string) EnvLookup {
	return func(key string) (string, bool) {
		v, ok := m[key]
		return v, ok
	}
}

// KEKDecision 組態段（DB-independent）判定結果。
// 判定於連 DB 之前完成，任一 fail-close 路徑不產生任何 DB 寫入（D2.3 第一段）。
type KEKDecision struct {
	// Mode 執行期模式（env／ui／kms／hsm）
	Mode string
	// MatrixRow 命中的判定矩陣列（決議依據；啟動 log 與 D10 稽核證據來源）
	MatrixRow string
	// Rationale 決議依據的人可讀說明（不含任何金鑰材料）
	Rationale string
	// Material 本地 KEK 材料（僅 env 模式非空）；**永不落日誌**
	Material string
	// MaterialSource 材料來源鍵名（單一鍵：ENCRYPTION_KEY）；無材料時為空
	MaterialSource string
	// KMS／HSM 組態（委託模式）
	KMS KMSSettings
	HSM HSMSettings
}

// KMSSettings 雲端金鑰服務委託組態
type KMSSettings struct {
	Provider string
	KeyID    string
	Region   string
}

// HSMSettings 硬體模組委託組態
type HSMSettings struct {
	Module     string
	TokenLabel string
	KeyLabel   string
	Pin        string
	PinFile    string
}

// lookupTrimmed 三值讀取＋trim；回 (原值, trim 後值, 是否已設)
func lookupTrimmed(lookup EnvLookup, key string) (raw, trimmed string, set bool) {
	raw, set = lookup(key)
	return raw, strings.TrimSpace(raw), set
}

// DecideKEK 判定 KEK 來源模式（D2.2 判定矩陣）。
//
// **legacy 解密鑰格已拆除**（release-transitional-cleanup D3）：
// `LEGACY_ENCRYPTION_KEY` 完全不被讀取（與 `AUDIT_INTEGRITY_KEY` 同處置），
// 原列 3b 的 legacy 長度驗證與列 6b 的 legacy 殘縫閘隨之消滅——該鍵已無解密
// 能力，為一把死值新增一格與「矩陣簡化」目標矛盾，且會迫使 config 繼續消費它。
// hsmBuild＝本執行檔是否含 pkcs11 能力（列 11）。
//
// 判定順序即矩陣的優先序；任一格皆 fail-close 且錯誤可辨識，SHALL NOT 猜測、
// SHALL NOT 回落預設。
func DecideKEK(lookup EnvLookup, hsmBuild bool) (*KEKDecision, error) {
	// --- 步 0：KEK_PROVIDER 值正規化（trim → 空即等同未設 → 大小寫敏感白名單）
	_, declared, providerSet := lookupTrimmed(lookup, EnvKeyKEKProvider)
	explicit := providerSet && declared != ""
	if explicit {
		switch declared {
		case KEKModeEnv, KEKModeUI, KEKModeKMS, KEKModeHSM:
		default:
			// 列 10：白名單外值（含大小寫不符，如 ENV）——不猜、不回落預設
			return nil, fmt.Errorf("[列 10] %s=%q 不在白名單（env／ui／kms／hsm，大小寫敏感）："+
				"拒絕啟動，不猜測亦不回落預設模式", EnvKeyKEKProvider, declared)
		}
	}

	// --- 步 1：材料鍵解析（單一鍵，無回落；名稱收斂後原兩步解析與遮蔽格消滅）
	encRaw, encTrim, encSet := lookupTrimmed(lookup, EnvKeyEncryptionKey)

	material, materialSource := "", ""
	if encSet {
		material, materialSource = encRaw, EnvKeyEncryptionKey
	}
	hasLocal := encTrim != "" // 出廠預設值仍算有值；全空白視為無值

	d := &KEKDecision{Material: material, MaterialSource: materialSource}

	// --- 步 2：依宣告模式查表
	if !explicit {
		if hasLocal {
			// 列 1：向後相容路徑（既有部署僅設 ENCRYPTION_KEY）。
			// **刻意不套材料格式驗證**——矩陣列 1 的「其他條件」欄為「—」，
			// 格式驗證僅適用於顯式宣告 env 的列 3／3b。此區分正是
			// 「既有部署升級後行為完全不變」這條硬驗收條件的落點。
			d.Mode, d.MatrixRow = KEKModeEnv, "1"
			d.Rationale = fmt.Sprintf("未宣告 %s，偵測到本地 KEK 材料（來源 %s）→ 向後相容之 env 模式；建議顯式宣告 %s=env",
				EnvKeyKEKProvider, materialSource, EnvKeyKEKProvider)
			return d, nil
		}
		// 列 2：留空不視為「想用 ui」（不隱式推斷）
		return nil, fmt.Errorf("[列 2] 未宣告 %s 且無本地 KEK 材料（%s 未設或為空）：拒絕啟動。"+
			"留空不會被推斷為介面填鑰模式——若確要不落地，請顯式設 %s=ui",
			EnvKeyKEKProvider, EnvKeyEncryptionKey, EnvKeyKEKProvider)
	}

	switch declared {
	case KEKModeEnv:
		if !hasLocal {
			// 列 4
			return nil, fmt.Errorf("[列 4] %s=env 但無本地 KEK 材料（%s 未設或為空）：拒絕啟動",
				EnvKeyKEKProvider, EnvKeyEncryptionKey)
		}
		if v := ValidateKEKMaterial(material); v != "" {
			// 列 3b：材料格式不合格（含全空白、出廠預設值）。
			// 錯誤訊息**逐條列出**可用的生成指令：缺陷史顯示「只給一條」會讓
			// operator 自行發明指令，而自行發明的那一條正是被拒的來源。
			return nil, fmt.Errorf("[列 3b] %s=env 的 KEK 材料不合格（來源 %s：%s）：拒絕啟動。"+
				"請以 CSPRNG 生成一把 32 位元組金鑰，下列任一皆可：%s",
				EnvKeyKEKProvider, materialSource, v,
				strings.Join(KEKGenerateCommandLines(), " ｜ "))
		}
		// 列 3
		d.Mode, d.MatrixRow = KEKModeEnv, "3"
		d.Rationale = fmt.Sprintf("顯式宣告 %s=env，材料來源 %s，格式驗證通過", EnvKeyKEKProvider, materialSource)
		return d, nil

	case KEKModeUI:
		if hasLocal {
			// 列 5：宣告不落地卻在 env 留鑰＝假 in-memory
			return nil, fmt.Errorf("[列 5] %s=ui 但本地 KEK 材料仍有值（來源 %s）：組態矛盾，拒絕啟動。"+
				"宣告材料不落地就不得在環境中留存材料", EnvKeyKEKProvider, materialSource)
		}
		// 列 6
		d.Mode, d.MatrixRow = KEKModeUI, "6"
		d.Rationale = fmt.Sprintf("顯式宣告 %s=ui，環境無本地 KEK 材料 → 啟動即封印", EnvKeyKEKProvider)
		return d, nil

	case KEKModeKMS, KEKModeHSM:
		if hasLocal {
			// 列 7：宣告委託卻留本地材料
			return nil, fmt.Errorf("[列 7] %s=%s 但本地 KEK 材料仍有值（來源 %s）：組態矛盾，拒絕啟動",
				EnvKeyKEKProvider, declared, materialSource)
		}
		// 列 8：逐鍵齊備檢查（含空字串／純空白），錯誤逐鍵列出缺少／衝突項
		if declared == KEKModeKMS {
			kms, missing := collectKMS(lookup)
			if len(missing) > 0 {
				return nil, fmt.Errorf("[列 8] %s=kms 的必要組態不齊：%s", EnvKeyKEKProvider, strings.Join(missing, "、"))
			}
			d.KMS = kms
		} else {
			// **列 11 先於列 8**（雙審 F4，與 design D2.2 表列序對齊）：
			// 執行檔不具 pkcs11 能力時，無論 HSM 組態齊不齊都不可能啟動——
			// 先回「請換 HSM 變體映像」比先回「組態不齊」更接近根因，
			// 免得操作者把組態補齊了才發現映像根本不對。兩者皆 fail-close，
			// 差別只在錯誤訊息的有用程度
			if !hsmBuild {
				return nil, fmt.Errorf("[列 11] %s=hsm 但本執行檔未含 HSM（pkcs11）能力：拒絕啟動。"+
					"請改用 HSM 變體映像（custodexa/backend:hsm）", EnvKeyKEKProvider)
			}
			hsm, problems := collectHSM(lookup)
			if len(problems) > 0 {
				return nil, fmt.Errorf("[列 8] %s=hsm 的必要組態不齊或衝突：%s", EnvKeyKEKProvider, strings.Join(problems, "、"))
			}
			d.HSM = hsm
		}
		// 列 9
		d.Mode, d.MatrixRow = declared, "9"
		d.Rationale = fmt.Sprintf("顯式宣告 %s=%s，委託組態齊備", EnvKeyKEKProvider, declared)
		return d, nil
	}

	// 不可達（步 0 已窮舉白名單）；保守 fail-close
	return nil, fmt.Errorf("[列 10] %s=%q 判定落空：拒絕啟動", EnvKeyKEKProvider, declared)
}

// collectKMS 逐鍵齊備檢查（trim 後非空才算有值）
func collectKMS(lookup EnvLookup) (KMSSettings, []string) {
	var missing []string
	get := func(key string) string {
		raw, trimmed, _ := lookupTrimmed(lookup, key)
		if trimmed == "" {
			missing = append(missing, fmt.Sprintf("缺 %s", key))
			return ""
		}
		return raw
	}
	s := KMSSettings{
		Provider: get(EnvKeyKMSProvider),
		KeyID:    get(EnvKeyKMSKeyID),
		Region:   get(EnvKeyKMSRegion),
	}
	return s, missing
}

// KMSSettingsFromEnv 讀取 KMS 組態但**不做齊備檢查**（缺項回空字串）。
//
// 用途只有一個：換鑰精靈的委託目標需要「本行程的 region／服務商」，而該情境下
// 本行程仍以 env／ui 模式運行——此時 DecideKEK 根本不會走列 8，KEKDecision.KMS
// 恆為零值。呼叫端 SHALL 自行判定缺項並回可辨識錯誤（見 buildDelegatedRewrapProvider）。
func KMSSettingsFromEnv(lookup EnvLookup) KMSSettings {
	get := func(key string) string {
		_, trimmed, _ := lookupTrimmed(lookup, key)
		return trimmed
	}
	return KMSSettings{
		Provider: get(EnvKeyKMSProvider),
		KeyID:    get(EnvKeyKMSKeyID),
		Region:   get(EnvKeyKMSRegion),
	}
}

// collectHSM 逐鍵齊備檢查；PIN 與 PIN_FILE **恰一有值**（皆無＝缺項、
// 皆有＝組態矛盾），不做隱式優先序猜測
func collectHSM(lookup EnvLookup) (HSMSettings, []string) {
	var problems []string
	get := func(key string) string {
		raw, trimmed, _ := lookupTrimmed(lookup, key)
		if trimmed == "" {
			problems = append(problems, fmt.Sprintf("缺 %s", key))
			return ""
		}
		return raw
	}
	s := HSMSettings{
		Module:     get(EnvKeyHSMModule),
		TokenLabel: get(EnvKeyHSMTokenLabel),
		KeyLabel:   get(EnvKeyHSMKeyLabel),
	}
	pinRaw, pinTrim, _ := lookupTrimmed(lookup, EnvKeyHSMPin)
	fileRaw, fileTrim, _ := lookupTrimmed(lookup, EnvKeyHSMPinFile)
	switch {
	case pinTrim == "" && fileTrim == "":
		problems = append(problems, fmt.Sprintf("缺 %s 或 %s（須恰一有值）", EnvKeyHSMPin, EnvKeyHSMPinFile))
	case pinTrim != "" && fileTrim != "":
		problems = append(problems, fmt.Sprintf("%s 與 %s 同時有值（須恰一，不做隱式優先序）", EnvKeyHSMPin, EnvKeyHSMPinFile))
	default:
		s.Pin, s.PinFile = pinRaw, fileRaw
	}
	return s, problems
}

// kekReasonFactoryDefault 出廠預設值的違規原因（單一事實源）。
const kekReasonFactoryDefault = "仍為出廠預設值（PCI 2.2.2）"

// ValidateKEKMaterial 本地 KEK 材料的伺服端格式驗證（D2.1 列 3b／D8）：
// 輸入編碼可解為 32 位元組、原字元形態的字元集、非出廠預設值。回空字串＝合格。
func ValidateKEKMaterial(material string) string {
	if v := crypto.ValidateKEKMaterialFormat(material); v != "" {
		return v
	}
	key, _, reason := crypto.DecodeKEKMaterial(material)
	if reason != "" {
		return reason
	}
	defer zeroKey(key)
	return validateDecodedKEK(key)
}

// DecodeKEKMaterialKey 解碼材料並套用出廠預設值閘，**不套字元集政策**。
//
// 供兩個「刻意不套格式政策」的入口使用：未宣告 KEK_PROVIDER 的相容路徑（列 1）
// 與金鑰表非空的一般解封。它們的既有語義是「任意 32 位元組皆可」，本函式只是
// 把可接受的**寫法**從一種擴充為三種，SHALL NOT 順手加上新的政策。
//
// 回傳的 key 長度恆為 crypto.KEKMaterialLength，其所有權移交呼叫端（用畢須歸零）。
func DecodeKEKMaterialKey(material string) ([]byte, string) {
	return DecodeKEKMaterialKeyBytes([]byte(material))
}

// DecodeKEKMaterialKeyBytes 同 DecodeKEKMaterialKey，但收 []byte。
// 解封路徑走這一支，避免為了呼叫 string 版而多出一份不可覆寫的明文副本。
func DecodeKEKMaterialKeyBytes(material []byte) ([]byte, string) {
	key, _, reason := crypto.DecodeKEKMaterialBytes(material)
	if reason != "" {
		return nil, reason
	}
	return key, ""
}

// ValidateKEKKey 對**已解碼金鑰**的重驗：長度與非出廠預設值。
//
// 用於重包目標的 sink 端不變式重驗。**刻意不含字元集檢查**——字元集是輸入編碼的
// 性質，解碼之後該資訊已不存在，在 sink 端假裝還驗得到它是不誠實的
// （原註解「重驗同一個驗證器」已隨本函式一併更正）。
func ValidateKEKKey(key []byte) string {
	if len(key) != crypto.KEKMaterialLength {
		return "金鑰長度不符（須恰 32 bytes）"
	}
	return validateDecodedKEK(key)
}

// validateDecodedKEK 出廠預設值閘。
//
// **比對解碼後的金鑰位元組而非輸入字串**：否則 `hex(預設值)` 與 `base64(預設值)`
// 都能繞過這道閘，而它是 PCI 2.2.2 的紅線。定時比較——預設值是公開值、時間差無
// 資訊量，但一致性成本為零，且避免這段被複製到真的需要定時比較的地方。
func validateDecodedKEK(key []byte) string {
	def, _, reason := crypto.DecodeKEKMaterial(DefaultEncryptionKey)
	if reason != "" {
		// 出廠預設值必然可解碼（它是 32 個字元）；解不開代表常數被改壞，
		// 此時 fail-close 比放行安全
		return kekReasonFactoryDefault
	}
	defer zeroKey(def)
	if subtle.ConstantTimeCompare(key, def) == 1 {
		return kekReasonFactoryDefault
	}
	return ""
}

// IsDefaultEncryptionKeyMaterial 判定一段材料是否為出廠預設 KEK（任一編碼寫法）。
// 供 release 模式的預設密鑰閘使用（DefaultSecretViolations）。
func IsDefaultEncryptionKeyMaterial(material string) bool {
	key, _, reason := crypto.DecodeKEKMaterial(material)
	if reason != "" {
		// 解不開的材料本來就不會成為 KEK，另有其他閘擋下；此處只回答「是不是預設值」
		return false
	}
	defer zeroKey(key)
	return validateDecodedKEK(key) != ""
}

func zeroKey(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// UsesLocalMaterial 本模式是否於本行程持有本地 KEK 材料
func (d *KEKDecision) UsesLocalMaterial() bool { return d.Mode == KEKModeEnv }

// LogLine 啟動時輸出的單行決議 log（D2.3／D10 稽核證據來源）。
// **不含任何金鑰材料**——僅列模式、矩陣列、材料來源鍵名與決議依據。
func (d *KEKDecision) LogLine() string {
	return fmt.Sprintf("[KEK] provider=%s matrix_row=%s material_source=%s rationale=%s",
		d.Mode, d.MatrixRow, orNone(d.MaterialSource), d.Rationale)
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
