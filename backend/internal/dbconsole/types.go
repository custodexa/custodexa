package dbconsole

import "context"

// Protocol 本套件支援的方言。與資產協議值同字面，但**刻意是本套件自己的型別**：
// 呼叫端一定要顯式轉換，才不會有人把 redis 之類的協議直接遞進來
type Protocol string

const (
	ProtocolMySQL    Protocol = "mysql"
	ProtocolPostgres Protocol = "postgres"
	ProtocolMSSQL    Protocol = "mssql"
)

// Supported 是否為本套件支援的方言（協議閘的唯一判定點）
func (p Protocol) Supported() bool {
	return p == ProtocolMySQL || p == ProtocolPostgres || p == ProtocolMSSQL
}

// Config 建立目標連線所需的一切。
//
// **`Password` 是 `[]byte` 而不是 `string`**：Go 的字串不可變且無法就地清零，
// 一份密碼字串會在 GC 決定回收之前一直躺在堆上，而我方的紀律是 dial 完成即清零。
// 呼叫端傳入後**所有權移交本套件**：`Open` 返回時（成功或失敗）本切片已被覆寫為零。
type Config struct {
	Protocol Protocol
	Host     string
	Port     int
	Username string
	Password []byte
	// Database 起始資料庫。空＝各方言的預設語義
	// （MySQL 未選庫、PostgreSQL 以帳號名為庫名、MSSQL 登入預設庫）
	Database string
	// TLSMode 五檔：''（沿 driver 預設）／disable／require／verify-ca／verify-full
	TLSMode string
	// CACert 自訂 CA（PEM）。空＝驗系統根憑證。
	// **走記憶體 CertPool，不落任何暫存檔**——落檔就要負責刪檔，
	// 而刪檔失敗的路徑是行程崩潰時，那時沒有人在清
	CACert string
}

// TLS 五檔的字面值（與資產欄位 `db_tls_mode` 同一組值）
const (
	TLSModeDefault    = ""
	TLSModeDisable    = "disable"
	TLSModeRequire    = "require"
	TLSModeVerifyCA   = "verify-ca"
	TLSModeVerifyFull = "verify-full"
)

// DatabaseInfo 目錄列出的一個資料庫。
//
// Connectable 是**預檢不是保證**：它答的是「目錄說這個庫上線且此帳號有連線權」，
// 真的連下去仍可能因主機端規則、連線數上限、剛剛才離線而失敗。
// MySQL 恆為 true——`SHOW DATABASES` 本身已依權限過濾，沒有第二層資訊
type DatabaseInfo struct {
	Name        string `json:"name"`
	Connectable bool   `json:"connectable"`
}

// TableInfo 當前庫內的一張表或檢視
type TableInfo struct {
	Schema string `json:"schema"`
	Name   string `json:"name"`
	// Kind ∈ {table, view}
	Kind string `json:"kind"`
}

// ColumnInfo 一個欄位的目錄資訊（樹用；與結果集的 ColumnMeta 是不同的東西）
type ColumnInfo struct {
	Name     string `json:"name"`
	TypeName string `json:"type_name"`
	Nullable bool   `json:"nullable"`
}

// ColumnMeta 結果集的欄位中繼資料。
//
// TypeName 是 driver 回報的型別名**原文**（`DECIMAL(18,4)`／`int8`／`datetime2`）；
// Kind 是給畫面對齊與 CSV 轉義用的粗分類。兩者都給，是因為原文對懂目標端的人
// 才有意義，而畫面需要一個有限的值域才能做對齊
type ColumnMeta struct {
	Name     string `json:"name"`
	TypeName string `json:"type_name"`
	Kind     Kind   `json:"kind"`
}

// Kind 欄位的粗分類
type Kind string

const (
	KindText     Kind = "text"
	KindInteger  Kind = "integer"
	KindDecimal  Kind = "decimal"
	KindFloat    Kind = "float"
	KindBool     Kind = "bool"
	KindDateTime Kind = "datetime"
	KindBinary   Kind = "binary"
	KindJSON     Kind = "json"
	KindOther    Kind = "other"
)

// ResultSet 一個結果集。
//
// **Rows 的元素是 `*string`**：所有值一律以文字傳輸，`nil` 代表 SQL NULL。
// 不用 JSON number 的理由是 2^53 以上的整數與 decimal 的尾數會在瀏覽器端
// 悄悄失真——對金額與識別碼，那是靜默的資料錯誤而不是顯示問題。
type ResultSet struct {
	SetIndex  int          `json:"set_index"`
	Columns   []ColumnMeta `json:"columns"`
	Rows      [][]*string  `json:"rows"`
	RowCount  int          `json:"row_count"`
	Truncated bool         `json:"truncated"`
}

// ExecOutcome 一個執行單位的結果事實。
//
// 本結構是呼叫端寫審計列與回應訊息的唯一來源：狀態與原因碼已在此分類完成，
// 呼叫端不再自行判讀 driver 錯誤——判讀散在兩處就會漂移。
type ExecOutcome struct {
	// Status 八值狀態之一（值與 model.ResultStatus* 同字面，
	// 但本套件不 import model：那會讓方言層依賴資料庫層）
	Status string
	// Reason 原因碼（可空）
	Reason string
	// Sets 已讀到的結果集（partial 時是錯誤發生前已完成的部分）
	Sets []ResultSet
	// RowsAffected 目標端回報的影響列數合計
	RowsAffected int64
	// Truncated 任一上限達標
	Truncated bool
	// DBError 目標端錯誤（僅已建連線上的 SQL 層錯誤帶 Message）
	DBError *DBError
	// CancelConfirmed 取消或逾時時，目標端是否確認了取消
	CancelConfirmed bool
	// ConnectionLost 本單位結束時目標連線已經不能再用。
	//
	// **與 Reason 分開帶**：原因碼的值域要先講取消與逾時（那是使用者問的問題），
	// 於是「連線死了」這個事實在 cancel_unconfirmed 與 timeout_unconfirmed 兩個碼上
	// 被蓋掉。呼叫端據此判斷會話能不能繼續——只看原因碼的話，它得等下一個單位
	// 撞上死連線才知道，而那一個單位根本沒送到目標端就先留下一列紀錄
	ConnectionLost bool
	// TxState 本單位執行後的交易態（取自同一次探詢，零額外往返）。
	// 它是**脈絡不是結果**：稽核據此判讀「這筆 ok 落在未提交的交易內」
	TxState string
}

// 八值狀態（與 model.SessionCommand 的 ResultStatus* 逐字對應）。
//
// **本套件不 import internal/model**：方言層依賴資料庫層會讓「換一個持久化形態」
// 變成要動 driver 適配器。兩份常數的一致性由呼叫端的對照測試承擔
const (
	StatusOK            = "ok"
	StatusError         = "error"
	StatusPartial       = "partial"
	StatusCancelled     = "cancelled"
	StatusTimeout       = "timeout"
	StatusEffectUnknown = "effect_unknown"
)

// 原因碼（同上，與 model.Reason* 逐字對應）
const (
	ReasonErrorAfterResults  = "error_after_results"
	ReasonCancelConfirmed    = "cancel_confirmed"
	ReasonCancelUnconfirmed  = "cancel_unconfirmed"
	ReasonTimeoutConfirmed   = "timeout_confirmed"
	ReasonTimeoutUnconfirmed = "timeout_unconfirmed"
	ReasonConnectionLost     = "connection_lost"
	ReasonBatchStopped       = "batch_stopped"
	ReasonCellTruncated      = "cell_truncated"
)

// DBError 目標端回報的錯誤。
//
// Code 是 SQLSTATE／MySQL errno／MSSQL number 的字串形態；Message 是原文，
// **只在「已建連線上、使用者自己語句的 SQL 層錯誤」時才填**——
// 連線與拓撲層的錯誤字串常含主機、埠、憑證主體與主機端規則，那些不是使用者的
// 產品內容而是我們的拓撲
type DBError struct {
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

// TxState 交易態（與 model.TxState* 逐字對應）
const (
	TxStateNone    = "none"
	TxStateActive  = "active"
	TxStateFailed  = "failed"
	TxStateUnknown = "unknown"
)

// State 逐單位探詢到的連線脈絡（當前庫＋交易態）。
// 兩者取自同一次往返——分兩次問會拿到兩個時點的答案
type State struct {
	Database string
	TxState  string
}

// Dialect 一個主控台會話持有的目標連線適配器。
//
// 由 Open 建構（Open 是本介面的建構半邊，寫成套件函式是因為它要依方言分派）。
// 所有方法**非並行安全**，只有 Cancel 例外——它本來就必須在 Exec 進行中被呼叫。
type Dialect interface {
	// ListDatabases 列出目錄可見的資料庫（含可連線旗標）
	ListDatabases(ctx context.Context) ([]DatabaseInfo, error)
	// ListTables 列出當前庫的表與檢視。schema 為空＝列全部 schema
	ListTables(ctx context.Context, schema string) ([]TableInfo, error)
	// ListColumns 列出當前庫某張表的欄位
	ListColumns(ctx context.Context, schema, table string) ([]ColumnInfo, error)
	// Switch 切換當前資料庫。
	// **name 必須是目錄剛回傳的名稱**——實作只做識別字引用，不做跳脫解析
	Switch(ctx context.Context, name string) error
	// Exec 送出一個執行單位並讀回結果。回傳的 outcome 已完成狀態分類；
	// 第二個回傳值只在「連本地都沒送出去」時非 nil
	Exec(ctx context.Context, sql string) (*ExecOutcome, error)
	// Cancel 取消進行中的執行單位，回傳目標端**是否確認**了取消。
	// 沒有進行中的單位時回 ErrNoStatementInFlight
	Cancel(ctx context.Context) (confirmed bool, err error)
	// ProbeState 探詢當前庫與交易態（一次往返）。
	// 失敗不代表連線壞了——交易態在 MySQL 上本來就取不到，該方言恆回 unknown
	ProbeState(ctx context.Context) (State, error)
	// CurrentDatabase 我方記錄的當前庫（不往返；供 Switch 後的即時回報）
	CurrentDatabase() string
	// Close 關閉目標連線
	Close() error
}

// BudgetedDialect 支援「一次送出的多個單位共用位元組額度」的方言。
//
// 以可選介面而非併進 Dialect：只有會把送出切成多個單位的方言需要它
// （目前是 MSSQL 的 GO 批次），而讓每個方言都實作一個自己用不到的方法，
// 只會多出一份沒有人會讀的轉發程式碼。呼叫端型別斷言取用，取不到就走 Exec
type BudgetedDialect interface {
	Dialect
	ExecWithin(ctx context.Context, sql string, s *Submission) (*ExecOutcome, error)
}
