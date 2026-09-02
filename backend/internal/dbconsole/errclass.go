package dbconsole

import (
	"context"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"

	mssql "github.com/microsoft/go-mssqldb"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
)

// 錯誤分類：決定哪些錯誤把目標端原文回給使用者、哪些只回一支機器碼。
//
// # 原則
//
// **連線階段永不回原文**。連線與拓撲層的錯誤字串常夾帶主機、埠、憑證主體、
// 主機端連線規則——那些是我們的拓撲，不是使用者的產品內容，回出去等於替探測者
// 省掉一輪掃描。
//
// **只有「已建連線上、使用者自己語句的 SQL 層錯誤」回原文**。那是他自己寫的
// SQL 撞到的錯，命令列路徑本來就原樣顯示；藏起來只會讓人改用命令列。
//
// **切庫的回應永遠只帶碼不帶訊息**。切庫在 PostgreSQL 上是重新連線，在
// MySQL／MSSQL 上是一句系統自發的控制語句——兩者都不是使用者寫的語句，
// 而 PG 那一側的錯誤屬連線階段。分兩種待遇會讓同一個動作在不同方言上洩漏不同的東西。

// ErrorClass 連線階段錯誤的類別（只進審計與日誌，不出到使用者）
type ErrorClass string

const (
	// ClassAuth 認證失敗
	ClassAuth ErrorClass = "auth"
	// ClassTLS TLS 交握或憑證驗證失敗
	ClassTLS ErrorClass = "tls"
	// ClassNetwork 撥號逾時、被拒、重置、EOF
	ClassNetwork ErrorClass = "network"
	// ClassTopology 目標庫不存在、離線、連線數上限——目標端在，但這個庫此刻進不去
	ClassTopology ErrorClass = "topology"
	// ClassUnknown 以上皆非。**不併入其他類**：把未知歸進 network 會讓
	// 「我們沒看懂」與「我們判定是網路」在審計上不可分辨
	ClassUnknown ErrorClass = "unknown"
)

// 各方言的認證錯誤碼。
//
// 值取自各家的官方錯誤碼表，逐碼列出而非以字串比對訊息——
// 訊息文字會隨版本與語系變動，錯誤碼不會。
var (
	// PostgreSQL：28000 invalid_authorization_specification、28P01 invalid_password
	pgAuthStates = map[string]bool{"28000": true, "28P01": true}
	// PostgreSQL：3D000 資料庫不存在、57P03 尚未接受連線、53300 連線數上限
	pgTopologyStates = map[string]bool{"3D000": true, "57P03": true, "53300": true}

	// MySQL：1045 Access denied
	mysqlAuthErrs = map[uint16]bool{1045: true}
	// MySQL：1049 Unknown database、1040 Too many connections
	mysqlTopologyErrs = map[uint16]bool{1049: true, 1040: true}

	// MSSQL：18456 Login failed
	mssqlAuthNumbers = map[int32]bool{18456: true}
	// MSSQL：4060 無法開啟資料庫、40613 資料庫目前無法使用
	mssqlTopologyNumbers = map[int32]bool{4060: true, 40613: true}
)

// ClassifyConnect 連線階段錯誤的分類（純函式）。
//
// 順序是判定的一部分：認證與拓撲要在網路之前判，因為 driver 常把它們包在
// 一個同時滿足「是 net.Error」的錯誤裡。
func ClassifyConnect(p Protocol, err error) ErrorClass {
	if err == nil {
		return ClassUnknown
	}
	if code, ok := dbErrorCode(p, err); ok {
		switch p {
		case ProtocolPostgres:
			if pgAuthStates[code] {
				return ClassAuth
			}
			if pgTopologyStates[code] {
				return ClassTopology
			}
		case ProtocolMySQL:
			if n, convErr := strconv.ParseUint(code, 10, 16); convErr == nil {
				if mysqlAuthErrs[uint16(n)] {
					return ClassAuth
				}
				if mysqlTopologyErrs[uint16(n)] {
					return ClassTopology
				}
			}
		case ProtocolMSSQL:
			if n, convErr := strconv.ParseInt(code, 10, 32); convErr == nil {
				if mssqlAuthNumbers[int32(n)] {
					return ClassAuth
				}
				if mssqlTopologyNumbers[int32(n)] {
					return ClassTopology
				}
			}
		}
		// 有錯誤碼但不在三張表內：目標端答了話，故不是網路問題。
		// 歸 unknown 而非 topology——我們沒有依據說這個庫進不去
		return ClassUnknown
	}
	if isTLSError(err) {
		return ClassTLS
	}
	if isNetworkError(err) {
		return ClassNetwork
	}
	return ClassUnknown
}

// IsConnectionLost 錯誤是否為「連線在送出後斷掉」。
//
// 這個判定決定一個執行單位記成 error 還是 effect_unknown，
// 差別是稽核員讀到的是「沒生效」還是「不知道有沒有生效」——後者不能讀成前者。
func IsConnectionLost(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, driver.ErrBadConn) || errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	// database/sql 對一條已經死掉的連線回這支哨兵，而不是 driver 的原始錯誤。
	// 少了它，取消或逾時打死連線之後的每一個單位都會被歸成 error
	//（＝「這句沒生效」，一句我們沒有依據說的話），而 database/sql 的內部字串
	// 也會被當成目標端的錯誤原文送到使用者面前
	if errors.Is(err, sql.ErrConnDone) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	// pgconn 在連線斷掉時包成 SafeToRetry；mysql driver 回 ErrInvalidConn。
	// **mysql 的取消即斷線**正是走這條路
	if errors.Is(err, mysqldriver.ErrInvalidConn) {
		return true
	}
	var pgErr *pgconn.ConnectError
	return errors.As(err, &pgErr)
}

// IsCancelConfirmed 目標端是否**確認**了取消。
//
// 「確認」的定義是目標端回了一個明確表示「這個語句被取消了」的錯誤：
// PostgreSQL 的 57014 query_canceled、MSSQL 的取消回應。MySQL 沒有這個回應——
// 它的取消實作是關閉連線，故該方言的取消一律未獲確認。
//
// **這不是保守派的悲觀假設，是事實描述**：連線關了之後，語句在目標端是跑完了
// 還是被中斷了，我們沒有任何管道知道。
func IsCancelConfirmed(p Protocol, err error) bool {
	if err == nil {
		return false
	}
	switch p {
	case ProtocolPostgres:
		code, ok := dbErrorCode(p, err)
		return ok && code == "57014"
	case ProtocolMSSQL:
		// go-mssqldb 在 Attention 封包被目標端確認後回一個帶
		// "canceled"／"cancelled" 語義的錯誤，且**連線保留**——
		// 連線還活著本身就是「目標端處理完這次取消」的證據
		var mssqlErr mssql.Error
		if errors.As(err, &mssqlErr) {
			return false
		}
		return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
			strings.Contains(strings.ToLower(err.Error()), "cancel")
	case ProtocolMySQL:
		return false
	}
	return false
}

// dbErrorCode 自 driver 錯誤取出目標端的錯誤碼（SQLSTATE／errno／number）。
// 第二個回傳值為假代表這不是一個 SQL 層錯誤——那多半是網路或 TLS。
func dbErrorCode(p Protocol, err error) (string, bool) {
	switch p {
	case ProtocolPostgres:
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			return pgErr.Code, true
		}
	case ProtocolMySQL:
		var myErr *mysqldriver.MySQLError
		if errors.As(err, &myErr) {
			return strconv.FormatUint(uint64(myErr.Number), 10), true
		}
	case ProtocolMSSQL:
		var msErr mssql.Error
		if errors.As(err, &msErr) {
			return strconv.FormatInt(int64(msErr.Number), 10), true
		}
	}
	return "", false
}

// DBErrorOf 產出回給使用者的錯誤物件。
//
// withMessage 由呼叫端依「這是不是使用者自己語句的 SQL 層錯誤」決定——
// 判斷點刻意留在呼叫端而不在此處：本函式看不到這個錯誤是哪個階段產生的，
// 而在看不到脈絡的地方猜測，猜錯的方向是洩漏。
func DBErrorOf(p Protocol, err error, withMessage bool) *DBError {
	code, ok := dbErrorCode(p, err)
	if !ok {
		return nil
	}
	out := &DBError{Code: code}
	if withMessage {
		out.Message = sqlErrorMessage(p, err)
	}
	return out
}

// sqlErrorMessage 取目標端的錯誤訊息原文（不含我方包裝的前綴）。
func sqlErrorMessage(p Protocol, err error) string {
	switch p {
	case ProtocolPostgres:
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			return pgErr.Message
		}
	case ProtocolMySQL:
		var myErr *mysqldriver.MySQLError
		if errors.As(err, &myErr) {
			return myErr.Message
		}
	case ProtocolMSSQL:
		var msErr mssql.Error
		if errors.As(err, &msErr) {
			return msErr.Message
		}
	}
	return err.Error()
}

func isTLSError(err error) bool {
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var invalidErr x509.CertificateInvalidError
	if errors.As(err, &unknownAuthority) || errors.As(err, &hostnameErr) || errors.As(err, &invalidErr) {
		return true
	}
	// `crypto/tls` 的交握錯誤沒有共同的具名型別，只能看訊息。
	// **這個 fallback 只影響審計上的分類粒度**：判錯的後果是某筆連線失敗被記成
	// unknown 而非 tls，對外回應完全相同（連線階段一律泛化）
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "tls") || strings.Contains(msg, "x509") ||
		strings.Contains(msg, "certificate")
}

func isNetworkError(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var opErr *net.OpError
	return errors.As(err, &opErr)
}
