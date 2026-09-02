package dbconsole

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
	mssql "github.com/microsoft/go-mssqldb"

	"github.com/jackc/pgx/v5/pgconn"
)

// 連線階段錯誤的分類，逐方言逐碼。
//
// 分類只進審計與日誌——對外一律泛化，故分錯**不會被使用者看到**。
// 那正是它需要表驅動測試的理由：沒有任何症狀會提醒有人把 28P01 從認證挪到了拓撲，
// 而事後查「這批連線失敗是密碼錯還是庫不存在」時，審計上的分類是唯一的依據。

func TestClassifyConnect(t *testing.T) {
	cases := []struct {
		name  string
		proto Protocol
		err   error
		want  ErrorClass
	}{
		// ── PostgreSQL ──
		{"pg 28000 認證", ProtocolPostgres, &pgconn.PgError{Code: "28000"}, ClassAuth},
		{"pg 28P01 密碼錯", ProtocolPostgres, &pgconn.PgError{Code: "28P01"}, ClassAuth},
		{"pg 3D000 庫不存在", ProtocolPostgres, &pgconn.PgError{Code: "3D000"}, ClassTopology},
		{"pg 57P03 尚未接受連線", ProtocolPostgres, &pgconn.PgError{Code: "57P03"}, ClassTopology},
		{"pg 53300 連線數上限", ProtocolPostgres, &pgconn.PgError{Code: "53300"}, ClassTopology},
		{"pg 其他 SQL 錯誤不歸網路", ProtocolPostgres, &pgconn.PgError{Code: "42601"}, ClassUnknown},

		// ── MySQL ──
		{"mysql 1045 認證", ProtocolMySQL, &mysqldriver.MySQLError{Number: 1045}, ClassAuth},
		{"mysql 1049 庫不存在", ProtocolMySQL, &mysqldriver.MySQLError{Number: 1049}, ClassTopology},
		{"mysql 1040 連線數上限", ProtocolMySQL, &mysqldriver.MySQLError{Number: 1040}, ClassTopology},
		{"mysql 其他錯誤碼", ProtocolMySQL, &mysqldriver.MySQLError{Number: 1064}, ClassUnknown},

		// ── MSSQL ──
		{"mssql 18456 登入失敗", ProtocolMSSQL, mssql.Error{Number: 18456}, ClassAuth},
		{"mssql 4060 無法開啟資料庫", ProtocolMSSQL, mssql.Error{Number: 4060}, ClassTopology},
		{"mssql 40613 資料庫無法使用", ProtocolMSSQL, mssql.Error{Number: 40613}, ClassTopology},
		{"mssql 其他錯誤碼", ProtocolMSSQL, mssql.Error{Number: 208}, ClassUnknown},

		// ── 與方言無關的階段錯誤 ──
		{"憑證簽發者不明", ProtocolPostgres, x509.UnknownAuthorityError{}, ClassTLS},
		{"憑證主機名不符", ProtocolMySQL, x509.HostnameError{Host: "db"}, ClassTLS},
		{"撥號逾時", ProtocolMySQL, &net.OpError{Op: "dial", Err: errTimeout{}}, ClassNetwork},
		{"連線被拒", ProtocolMSSQL, &net.OpError{Op: "dial", Err: errors.New("connection refused")}, ClassNetwork},
		{"EOF", ProtocolPostgres, io.EOF, ClassNetwork},
		{"context 逾時", ProtocolPostgres, context.DeadlineExceeded, ClassNetwork},
		{"完全不認得", ProtocolPostgres, errors.New("something else entirely"), ClassUnknown},
		{"nil", ProtocolPostgres, nil, ClassUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyConnect(tc.proto, tc.err); got != tc.want {
				t.Errorf("分類 = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestIsConnectionLost 連線斷掉的判定決定一個單位記成 error 還是 effect_unknown。
func TestIsConnectionLost(t *testing.T) {
	lost := []struct {
		name string
		err  error
	}{
		{"EOF", io.EOF},
		{"未預期的 EOF", io.ErrUnexpectedEOF},
		{"連線已關閉", net.ErrClosed},
		{"網路作業錯誤", &net.OpError{Op: "read", Err: errors.New("reset")}},
		{"mysql 取消即斷線", mysqldriver.ErrInvalidConn},
		{"pgconn 連線錯誤", &pgconn.ConnectError{}},
	}
	for _, tc := range lost {
		t.Run(tc.name, func(t *testing.T) {
			if !IsConnectionLost(tc.err) {
				t.Errorf("%v 應判為連線中斷——判錯的方向是把「不知道有沒有生效」記成「沒生效」", tc.err)
			}
		})
	}

	notLost := []struct {
		name string
		err  error
	}{
		{"nil", nil},
		{"SQL 語法錯誤", &mysqldriver.MySQLError{Number: 1064}},
		{"pg SQL 錯誤", &pgconn.PgError{Code: "42601"}},
	}
	for _, tc := range notLost {
		t.Run(tc.name, func(t *testing.T) {
			if IsConnectionLost(tc.err) {
				t.Errorf("%v 不該判為連線中斷——那會把一個明確的語法錯誤記成結果未知", tc.err)
			}
		})
	}
}

// TestIsCancelConfirmed 目標端是否確認取消，逐方言。
//
// MySQL 恆為未確認**不是保守假設而是事實描述**：它的取消實作是關閉連線，
// 連線關了之後語句在目標端跑完了還是被中斷了，我們沒有任何管道知道。
func TestIsCancelConfirmed(t *testing.T) {
	cases := []struct {
		name  string
		proto Protocol
		err   error
		want  bool
	}{
		{"pg 57014 已取消", ProtocolPostgres, &pgconn.PgError{Code: "57014"}, true},
		{"pg 其他錯誤", ProtocolPostgres, &pgconn.PgError{Code: "42601"}, false},
		{"pg 非 SQL 錯誤", ProtocolPostgres, io.EOF, false},
		{"mysql 取消一律未確認", ProtocolMySQL, mysqldriver.ErrInvalidConn, false},
		{"mysql 即使 ctx 取消也未確認", ProtocolMySQL, context.Canceled, false},
		{"mssql ctx 取消", ProtocolMSSQL, context.Canceled, true},
		{"mssql 逾時", ProtocolMSSQL, context.DeadlineExceeded, true},
		{"mssql SQL 錯誤不是取消確認", ProtocolMSSQL, mssql.Error{Number: 208}, false},
		{"nil", ProtocolPostgres, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsCancelConfirmed(tc.proto, tc.err); got != tc.want {
				t.Errorf("確認 = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestDBErrorOfHidesMessageWhenAsked 訊息只在被要求時才帶。
//
// 連線與拓撲層的錯誤字串常夾帶主機、埠、憑證主體與主機端規則，
// 回出去等於替探測者省掉一輪掃描。
func TestDBErrorOfHidesMessageWhenAsked(t *testing.T) {
	err := &pgconn.PgError{Code: "3D000", Message: `database "secret_db" does not exist on host db-primary-01`}

	withMsg := DBErrorOf(ProtocolPostgres, err, true)
	if withMsg == nil || withMsg.Code != "3D000" || withMsg.Message == "" {
		t.Fatalf("帶訊息時 = %+v", withMsg)
	}

	noMsg := DBErrorOf(ProtocolPostgres, err, false)
	if noMsg == nil || noMsg.Code != "3D000" {
		t.Fatalf("不帶訊息時 = %+v", noMsg)
	}
	if noMsg.Message != "" {
		t.Errorf("不帶訊息時仍帶了原文：%q", noMsg.Message)
	}

	// 非 SQL 層錯誤沒有目標端錯誤碼可回
	if got := DBErrorOf(ProtocolPostgres, io.EOF, true); got != nil {
		t.Errorf("非 SQL 層錯誤應無目標端錯誤物件，實得 %+v", got)
	}
}

type errTimeout struct{}

func (errTimeout) Error() string   { return "i/o timeout" }
func (errTimeout) Timeout() bool   { return true }
func (errTimeout) Temporary() bool { return true }
