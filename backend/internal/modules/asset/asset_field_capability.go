package asset

import (
	"context"
	"errors"
	"sort"
	"strings"
)

// 資產寫入的欄位級能力。
//
// 帳號與憑證秘密的寫入、掛載既有憑證，需要資產寫入能力之外的另一項能力。路由登錄項宣告各欄位
// 所需的權限點（authz 模組持有宣告與判定），本模組不依賴 authz：呼叫端（HTTP 層）把「主體是否持有
// 某欄位的額外能力」綁成一個判定函式放進 context，服務在載入目標之後、任何寫入之前，
// 以「實際會變更」為準判定，缺任一能力整筆拒絕。
//
// 缺判定一律拒絕（fail-closed）：context 內沒有判定函式、也沒有系統呼叫者標記時，凡涉及受限欄位
// 的寫入都回 ErrFieldCapabilityDenied，新入口漏綁判定不會靜默繞過。沒有操作者主體的內部作業
// （系統路徑、匯入引擎、單元測試）必須以 WithSystemCaller 明確標記；該標記只能由組裝根或
// 內部服務在服務端設定，不得由請求內容帶入（靜態守衛測試限制呼叫位置）。

// ErrFieldCapabilityDenied 請求變更了主體缺少額外能力的欄位。回應形狀沿既有的權限不足，不帶權限名。
var ErrFieldCapabilityDenied = errors.New("缺少變更此欄位所需的能力")

// FieldCapGrant 欄位能力的判定結果：未通過、經該欄宣告的權限點通過、經該欄宣告的相容並列能力通過。
type FieldCapGrant int

const (
	// FieldCapDenied 主體缺該欄所需的能力（未宣告的欄位亦同）。
	FieldCapDenied FieldCapGrant = iota
	// FieldCapViaPerm 經該欄宣告的權限點（憑證語義能力）通過：服務層另以目標判定該語義能力。
	FieldCapViaPerm
	// FieldCapViaCompat 經該欄宣告的相容並列能力通過（只在全域持有時生效）：不另做語義目標判定。
	FieldCapViaCompat
)

// FieldCapabilityCheck 回傳主體對該請求欄位的判定結果；未宣告的欄位必須回 FieldCapDenied。
type FieldCapabilityCheck func(field string) FieldCapGrant

type fieldCapabilityKey struct{}

// WithFieldCapability 把判定函式綁進 context。
func WithFieldCapability(ctx context.Context, check FieldCapabilityCheck) context.Context {
	return context.WithValue(ctx, fieldCapabilityKey{}, check)
}

type systemCallerKey struct{}

// WithSystemCaller 標記 ctx 為服務端內部呼叫（無操作者主體的系統作業），略過欄位級能力判定。
// 僅限組裝根與內部服務使用，HTTP 處理層不得呼叫；呼叫位置由靜態守衛測試鎖定。
func WithSystemCaller(ctx context.Context) context.Context {
	return context.WithValue(ctx, systemCallerKey{}, true)
}

func isSystemCaller(ctx context.Context) bool {
	v, _ := ctx.Value(systemCallerKey{}).(bool)
	return v
}

func fieldCapabilityFrom(ctx context.Context) FieldCapabilityCheck {
	check, _ := ctx.Value(fieldCapabilityKey{}).(FieldCapabilityCheck)
	return check
}

// FieldCapabilityKey 回傳該請求欄位所需額外能力的權限點鍵；未宣告的欄位回空字串。
// 只用來在拒絕時帶出依據，不參與判定。
type FieldCapabilityKey func(field string) string

type fieldCapabilityKeyKey struct{}

// WithFieldCapabilityKey 把「欄位→權限點鍵」查詢綁進 context（與 WithFieldCapability 同一呼叫端綁定）。
func WithFieldCapabilityKey(ctx context.Context, key FieldCapabilityKey) context.Context {
	return context.WithValue(ctx, fieldCapabilityKeyKey{}, key)
}

// fieldCapabilityKeyOf 取欄位的權限點鍵；未綁查詢回空字串（拒絕依據由 HTTP 層退回路由要求）。
func fieldCapabilityKeyOf(ctx context.Context, field string) string {
	key, _ := ctx.Value(fieldCapabilityKeyKey{}).(FieldCapabilityKey)
	if key == nil {
		return ""
	}
	return key(field)
}

// FieldCapClass 請求欄位在欄位級能力上的歸類。
type FieldCapClass string

const (
	// FieldCapNone 不需要額外能力（只需路由本身的資產寫入能力）。
	FieldCapNone FieldCapClass = "none"
	// FieldCapCredential 帳號／憑證秘密寫入，或掛載既有憑證：以憑證管理能力承擔。
	FieldCapCredential FieldCapClass = "credential"
	// FieldCapCredentialBind 掛載既有共用憑證：以掛載能力承擔（範圍由逐列或交易內的掛載來源判定收斂）。
	FieldCapCredentialBind FieldCapClass = "credential_bind"
	// FieldCapAccessPolicy 存取政策覆寫欄位：以存取政策權限點承擔（路由登錄宣告 access_policy 欄位條件）。
	FieldCapAccessPolicy FieldCapClass = "access_policy"
)

// UpdateRequestFieldCaps 更新請求每個 JSON 欄位的歸類；測試以反射比對請求結構，零落差。
var UpdateRequestFieldCaps = map[string]FieldCapClass{
	"name": FieldCapNone, "protocol": FieldCapNone, "host": FieldCapNone, "port": FieldCapNone,
	"username": FieldCapCredential, "password": FieldCapCredential, "private_key": FieldCapCredential,
	"description": FieldCapNone, "tags": FieldCapNone, "active": FieldCapNone, "node_ids": FieldCapNone,
	"access_policy": FieldCapAccessPolicy,
	"rdp_security":  FieldCapNone, "rdp_verify_cert": FieldCapNone,
	"db_name": FieldCapNone, "db_tls_mode": FieldCapNone, "db_ca_cert": FieldCapNone, "allowed_databases": FieldCapNone,
	"k8s_namespace": FieldCapNone, "k8s_pod": FieldCapNone, "k8s_container": FieldCapNone,
	"k8s_ca_cert": FieldCapNone, "k8s_insecure_skip_tls": FieldCapNone,
	"sftp_enabled": FieldCapNone, "sftp_port": FieldCapNone,
	"sftp_username": FieldCapCredential, "sftp_password": FieldCapCredential,
	"rotation_channel": FieldCapNone, "winrm_scheme": FieldCapNone, "winrm_port": FieldCapNone,
	"winrm_tls_mode": FieldCapNone, "winrm_ca_cert": FieldCapNone, "rotation_ssh_port": FieldCapNone,
}

// CreateRequestFieldCaps 建立請求每個 JSON 欄位的歸類。
var CreateRequestFieldCaps = map[string]FieldCapClass{
	"name": FieldCapNone, "protocol": FieldCapNone, "host": FieldCapNone, "port": FieldCapNone,
	"username": FieldCapCredential, "password": FieldCapCredential, "private_key": FieldCapCredential,
	"description": FieldCapNone, "tags": FieldCapNone, "node_ids": FieldCapNone,
	"access_policy": FieldCapAccessPolicy,
	"rdp_security":  FieldCapNone, "rdp_verify_cert": FieldCapNone,
	"db_name": FieldCapNone, "db_tls_mode": FieldCapNone, "db_ca_cert": FieldCapNone, "allowed_databases": FieldCapNone,
	"k8s_namespace": FieldCapNone, "k8s_pod": FieldCapNone, "k8s_container": FieldCapNone,
	"k8s_ca_cert": FieldCapNone, "k8s_insecure_skip_tls": FieldCapNone,
	"sftp_enabled": FieldCapNone, "sftp_port": FieldCapNone,
	"sftp_username": FieldCapCredential, "sftp_password": FieldCapCredential,
	"rotation_channel": FieldCapNone, "winrm_scheme": FieldCapNone, "winrm_port": FieldCapNone,
	"winrm_tls_mode": FieldCapNone, "winrm_ca_cert": FieldCapNone, "rotation_ssh_port": FieldCapNone,
	"credential_id": FieldCapCredentialBind, "credential": FieldCapCredential,
	"copy_from_account_id": FieldCapNone, // 已退場參數：帶值即被拒絕，不會寫入任何東西
}

// ImportRowFieldCaps 匯入列每個 JSON 欄位的歸類；只有掛載既有憑證（掛載能力）與存取政策需要額外能力。
var ImportRowFieldCaps = map[string]FieldCapClass{
	"line": FieldCapNone, "name": FieldCapNone, "protocol": FieldCapNone, "host": FieldCapNone, "port": FieldCapNone,
	"credential_id": FieldCapCredentialBind, "tags": FieldCapNone, "node_ids": FieldCapNone, "node_paths": FieldCapNone,
	"description": FieldCapNone, "access_policy": FieldCapAccessPolicy, "db_name": FieldCapNone,
	"k8s_namespace": FieldCapNone, "rdp_security": FieldCapNone, "db_tls_mode": FieldCapNone,
}

// CredentialFieldNames 歸類為憑證能力的欄位名（排序穩定供登錄項與測試對照）。
func CredentialFieldNames(classes map[string]FieldCapClass) []string {
	var out []string
	for f, c := range classes {
		if c == FieldCapCredential {
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}

// CredentialBindFieldNames 歸類為掛載能力的欄位名（排序穩定供登錄項與測試對照）。
func CredentialBindFieldNames(classes map[string]FieldCapClass) []string {
	var out []string
	for f, c := range classes {
		if c == FieldCapCredentialBind {
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}

// semanticFields 經欄位權限點（未經相容並列能力）通過的欄位；呼叫端只對其中本次需要的欄位
// 另做語義目標判定，其餘欄位（掛載、存取政策等）維持各自原有的判定。
type semanticFields map[string]bool

// any 集合是否含任一指定欄位。
func (s semanticFields) any(fields ...string) bool {
	for _, f := range fields {
		if s[f] {
			return true
		}
	}
	return false
}

// requireFieldCapabilities 逐欄判定；任一欄缺能力即拒絕。通過時回傳經權限點通過的欄位
// （經相容能力通過者不在其內）；系統呼叫者與無受限欄位時回空集合。
func requireFieldCapabilities(ctx context.Context, fields []string) (semanticFields, error) {
	if len(fields) == 0 {
		return nil, nil
	}
	check := fieldCapabilityFrom(ctx)
	if check == nil {
		if isSystemCaller(ctx) {
			return nil, nil
		}
		// 未綁判定函式：沒有可指認的欄位能力，依據由 HTTP 層退回路由要求
		return nil, capabilityDenied(ErrFieldCapabilityDenied)
	}
	var semantic semanticFields
	for _, f := range fields {
		switch check(f) {
		case FieldCapViaCompat:
		case FieldCapViaPerm:
			if semantic == nil {
				semantic = semanticFields{}
			}
			semantic[f] = true
		default:
			return nil, capabilityDenied(ErrFieldCapabilityDenied, fieldCapabilityKeyOf(ctx, f))
		}
	}
	return semantic, nil
}

// createNamedViaSemantic 建立資產時經建立憑證能力通過的帳號與秘密欄位：帳號名稱、登入秘密、
// 內嵌憑證與 SFTP 側車。掛載既有憑證與存取政策另有各自的能力，不觸發建立憑證的目標判定。
func createNamedViaSemantic(s semanticFields) bool {
	return s.any("username", "password", "private_key", "credential", "sftp_username", "sftp_password")
}

// updateRestrictedFields 更新請求中「實際會變更」且需要額外能力的欄位。
// username、sftp_username 以現值比對（同值不算變更）；秘密欄位以非空判定（空字串＝沿用既有，不更新）。
func updateRestrictedFields(currentUsername, currentSftpUsername string, req *UpdateAssetRequest) []string {
	var out []string
	if req.Username != nil && *req.Username != currentUsername {
		out = append(out, "username")
	}
	if req.hasAccessPolicyKey() {
		// 本文出現此鍵即算（含清除用的空字串與 null），不論值是否相同
		out = append(out, "access_policy")
	}
	if req.Password != nil && *req.Password != "" {
		out = append(out, "password")
	}
	if req.PrivateKey != nil && *req.PrivateKey != "" {
		out = append(out, "private_key")
	}
	if req.SftpUsername != nil && *req.SftpUsername != currentSftpUsername {
		out = append(out, "sftp_username")
	}
	if req.SftpPassword != nil && *req.SftpPassword != "" {
		out = append(out, "sftp_password")
	}
	return out
}

// createRestrictedFields 建立請求中需要額外能力的欄位（非空／非零才算）。
func createRestrictedFields(req *CreateAssetRequest) []string {
	var out []string
	if req.Username != "" {
		out = append(out, "username")
	}
	if req.Password != "" {
		out = append(out, "password")
	}
	if req.PrivateKey != "" {
		out = append(out, "private_key")
	}
	if req.SftpUsername != "" {
		out = append(out, "sftp_username")
	}
	if req.SftpPassword != "" {
		out = append(out, "sftp_password")
	}
	if req.AccessPolicy != "" {
		out = append(out, "access_policy")
	}
	if req.Credential != nil {
		out = append(out, "credential")
	}
	if req.CredentialID != 0 {
		out = append(out, "credential_id")
	}
	return out
}

// createDeclaresSecret 建立請求是否內嵌登入秘密（頂層簡寫或 credential 物件的密碼／私鑰）。
// 建立時的內嵌秘密是新建一份專用憑證，需 credential:create（與憑證庫直接建立同一能力）。
func createDeclaresSecret(req *CreateAssetRequest) bool {
	if req.Password != "" || req.PrivateKey != "" {
		return true
	}
	return req.Credential != nil && (req.Credential.Password != "" || req.Credential.PrivateKey != "")
}

// importCredentialIDs 匯入批次所指的既有憑證（去重）：任一列掛既有憑證即需掛載能力。
func importCredentialIDs(rows []ImportRow) []uint {
	var ids []uint
	for _, r := range rows {
		// 非正值不指向任何憑證，由逐列驗證回報為列錯誤
		if r.CredentialID != nil && *r.CredentialID > 0 {
			ids = append(ids, uint(*r.CredentialID))
		}
	}
	return nonZeroIDs(ids...)
}

// importRestrictedFields 匯入批次中需要額外能力的欄位：任一列帶非零 credential_id，或任一列 access_policy 非空。
func importRestrictedFields(rows []ImportRow) []string {
	var out []string
	for _, r := range rows {
		if r.CredentialID != nil && *r.CredentialID != 0 {
			out = append(out, "credential_id")
			break
		}
	}
	for _, r := range rows {
		// CSV 無法區分未填與空字串，空白一律視為未設定
		if strings.TrimSpace(r.AccessPolicy) != "" {
			out = append(out, "access_policy")
			break
		}
	}
	return out
}
