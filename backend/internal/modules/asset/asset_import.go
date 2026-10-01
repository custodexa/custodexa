package asset

// 資產批次新增（線上多筆＋CSV 匯入）的列模型與逐列驗證。
//
// 兩種入口共用同一套規則：CSV 由 ParseImportCSV 轉成列，線上填寫直接送列 JSON，
// 之後都走 validateImportBatch——預檢與寫入呼叫的是同一個函式，寫入端只多了
// 「交易內以鎖住的當下狀態重驗」這一步（見 asset_import_commit.go）。
//
// 每列的業務規則最後一律交給單筆建立的 prepareCreate 再走一次：匯入不另立一套
// 寬鬆或嚴格的建立規則，列驗證只是把錯誤「逐欄、不短路」地先收齊。

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
)

const (
	// ImportMaxRows 單次匯入的資料列上限（不含表頭與空列）
	ImportMaxRows = 500
	// ImportMaxBytes 單次請求本文上限（CSV 原文或 JSON）
	ImportMaxBytes = 1 << 20

	// ImportSourceCSV／ImportSourceForm 列的來源入口（稽核標記與列號語義）
	ImportSourceCSV  = "csv"
	ImportSourceForm = "form"
)

// 欄名：CSV 表頭與列錯誤的 field 共用同一組機器名
const (
	importFieldName         = "name"
	importFieldProtocol     = "protocol"
	importFieldHost         = "host"
	importFieldPort         = "port"
	importFieldCredentialID = "credential_id"
	importFieldTags         = "tags"
	importFieldNodes        = "nodes"
	importFieldDescription  = "description"
	importFieldAccessPolicy = "access_policy"
	importFieldDBName       = "db_name"
	importFieldK8sNamespace = "k8s_namespace"
	importFieldRDPSecurity  = "rdp_security"
	importFieldDBTLSMode    = "db_tls_mode"
)

// 欄位長度上限：與 model.Asset 的欄寬一致
const (
	importMaxNameRunes         = 100
	importMaxHostRunes         = 255
	importMaxDescriptionRunes  = 500
	importMaxDBNameRunes       = 128
	importMaxK8sNamespaceRunes = 63
)

// importDefaultPorts 協定預設埠（埠留空時採用）。值與前端 utils/protocol.js 的
// 預設埠同一組，兩邊各一份，由測試釘齊
var importDefaultPorts = map[model.ProtocolType]int{
	model.ProtocolSSH:      22,
	model.ProtocolRDP:      3389,
	model.ProtocolVNC:      5900,
	model.ProtocolMySQL:    3306,
	model.ProtocolPostgres: 5432,
	model.ProtocolRedis:    6379,
	model.ProtocolMSSQL:    1433,
	model.ProtocolK8s:      6443,
}

// importSecretFieldNames 秘密或帳號名欄位：CSV 表頭或 JSON 列帶這些欄即整批拒收。
// 帳號名一律來自所指定的共用憑證，匯入不承接任何登入秘密
var importSecretFieldNames = map[string]bool{
	"password":    true,
	"private_key": true,
	"passphrase":  true,
	"secret":      true,
	"token":       true,
	"username":    true,
	"credential":  true,
}

// IsImportSecretField 欄名（已正規化為小寫）是否為秘密或帳號名欄。名稱帶秘密片段的欄
// （db_password、api_token 之類）同樣視為秘密欄
func IsImportSecretField(name string) bool {
	if importSecretFieldNames[name] {
		return true
	}
	for _, m := range []string{"password", "passwd", "private_key", "privatekey", "passphrase", "secret", "token"} {
		if strings.Contains(name, m) {
			return true
		}
	}
	return false
}

// ImportRow 一列資產（兩種入口共用的 JSON 形狀）。未知欄位一律拒收
type ImportRow struct {
	// Line CSV 來源的檔案列號；線上填寫為 null（以陣列序顯示）
	Line *int `json:"line"`

	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	// Port null＝協定預設埠
	Port *int `json:"port"`
	// CredentialID 共用憑證編號；null＝待配憑證。以有號整數承接，使 0 與負數
	// 能以列錯誤回報而不是整份解碼失敗
	CredentialID *int64 `json:"credential_id"`
	Tags         string `json:"tags"`
	NodeIDs      []uint `json:"node_ids"`
	// NodePaths 以全路徑指定節點（CSV 來源）。帶此欄時路徑為準：預檢解析成節點，
	// 寫入時於交易內重算每個節點的當下全路徑比對，預檢後節點被改名或搬移即本次匯入回 409
	NodePaths    []string `json:"node_paths,omitempty"`
	Description  string   `json:"description"`
	AccessPolicy string   `json:"access_policy"`
	DBName       string   `json:"db_name"`
	K8sNamespace string   `json:"k8s_namespace"`
	RDPSecurity  string   `json:"rdp_security"`
	DBTLSMode    string   `json:"db_tls_mode"`
}

// ImportRequest 預檢與寫入端點的 JSON 本文
type ImportRequest struct {
	Source string      `json:"source"`
	Rows   []ImportRow `json:"rows"`
}

// ImportBatch 一批待驗證的列（JSON 直送或 CSV 解析而來）
type ImportBatch struct {
	Source string
	Rows   []ImportRow
	// raw／parseErrs 只由 CSV 解析產生：無法轉型的格原文與其錯誤，與 Rows 同索引
	raw       []map[string]string
	parseErrs [][]ImportFieldError
}

// ImportFieldError 一列中一個欄位的錯誤
type ImportFieldError struct {
	Field  string           `json:"field"`
	Code   apierror.ErrCode `json:"code"`
	Params map[string]any   `json:"params"`
}

// ImportCredentialRef 所指共用憑證的回顯（只對具資產建立權限者）
type ImportCredentialRef struct {
	ID       uint   `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
}

// ImportResolved 系統將如何解讀這一列（寫入前讓使用者看見）
type ImportResolved struct {
	PortDefaulted bool                 `json:"port_defaulted"`
	Credential    *ImportCredentialRef `json:"credential,omitempty"`
	NodePaths     []string             `json:"node_paths"`
	// Tags 實際會落庫的寫法（含全庫與同批歸一）
	Tags string `json:"tags"`
}

// ImportRowReport 一列的檢查結果
type ImportRowReport struct {
	Index    int                `json:"index"`
	Line     *int               `json:"line"`
	Values   ImportRow          `json:"values"`
	Raw      map[string]string  `json:"raw,omitempty"`
	Resolved ImportResolved     `json:"resolved"`
	Errors   []ImportFieldError `json:"errors"`
}

// ImportSummary 整批摘要
type ImportSummary struct {
	Total             int `json:"total"`
	Valid             int `json:"valid"`
	Invalid           int `json:"invalid"`
	CredentialPending int `json:"credential_pending"`
}

// ImportPreview 預檢回應
type ImportPreview struct {
	OK      bool              `json:"ok"`
	Summary ImportSummary     `json:"summary"`
	Rows    []ImportRowReport `json:"rows"`
}

// ImportResult 寫入成功回應
type ImportResult struct {
	Created           int    `json:"created"`
	CredentialPending int    `json:"credential_pending"`
	AssetIDs          []uint `json:"asset_ids"`
}

// ImportFileError 檔案層錯誤：整份拒收，不做逐列驗證
type ImportFileError struct {
	Code   apierror.ErrCode
	Params map[string]any
	Meta   map[string]any
}

func (e *ImportFileError) Error() string { return "asset import rejected: " + string(e.Code) }

// ImportRowsInvalidError 交易外驗證有列錯誤：未開交易、未寫任何資料
type ImportRowsInvalidError struct{ Preview *ImportPreview }

func (e *ImportRowsInvalidError) Error() string { return "asset import has invalid rows" }

// ImportStateChangedError 交易內重驗失敗：整筆回滾，Rows 標出出事的列與原因
type ImportStateChangedError struct{ Rows []ImportRowReport }

func (e *ImportStateChangedError) Error() string { return "asset import state changed; rolled back" }

func fieldErr(field string, code apierror.ErrCode) ImportFieldError {
	return ImportFieldError{Field: field, Code: code, Params: map[string]any{}}
}

func fieldErrP(field string, code apierror.ErrCode, params map[string]any) ImportFieldError {
	return ImportFieldError{Field: field, Code: code, Params: params}
}

// DecodeImportJSON 解析 JSON 本文。未知欄位整批拒收：秘密或帳號名欄回
// SECRET_FIELD（指出欄名、不回顯值），其餘格式問題回 BAD_REQUEST_FORMAT
func DecodeImportJSON(data []byte) (*ImportBatch, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var req ImportRequest
	if err := dec.Decode(&req); err != nil {
		if name, ok := unknownJSONField(err); ok && IsImportSecretField(strings.ToLower(name)) {
			return nil, &ImportFileError{Code: apierror.CodeAssetImportSecretField,
				Params: map[string]any{"column": name}}
		}
		return nil, &ImportFileError{Code: apierror.CodeBadRequestFormat}
	}
	if dec.More() {
		return nil, &ImportFileError{Code: apierror.CodeBadRequestFormat}
	}
	switch req.Source {
	case ImportSourceCSV, ImportSourceForm:
	case "":
		req.Source = ImportSourceForm
	default:
		return nil, &ImportFileError{Code: apierror.CodeBadRequestFormat}
	}
	return &ImportBatch{Source: req.Source, Rows: req.Rows}, nil
}

// unknownJSONField 自 encoding/json 的未知欄位錯誤取欄名（錯誤字串只含欄名、不含值）
func unknownJSONField(err error) (string, bool) {
	const prefix = `json: unknown field "`
	msg := err.Error()
	if !strings.HasPrefix(msg, prefix) {
		return "", false
	}
	return strings.TrimSuffix(strings.TrimPrefix(msg, prefix), `"`), true
}

// checkBatchSize 列數的檔案層檢查（兩種入口共用）
func checkBatchSize(batch *ImportBatch) error {
	if batch == nil || len(batch.Rows) == 0 {
		return &ImportFileError{Code: apierror.CodeAssetImportEmpty}
	}
	if len(batch.Rows) > ImportMaxRows {
		return &ImportFileError{Code: apierror.CodeAssetImportTooManyRows,
			Params: map[string]any{"max": ImportMaxRows}}
	}
	return nil
}

// PreviewImport 唯讀預檢：逐列完整驗證並回報，不寫任何資料
func (s *AssetService) PreviewImport(ctx context.Context, batch *ImportBatch) (*ImportPreview, error) {
	if err := checkBatchSize(batch); err != nil {
		return nil, err
	}
	preview, _, err := s.validateImportBatch(ctx, batch, 0, "")
	return preview, err
}
