package dbrotate

import (
	"database/sql"
	"strconv"
	"strings"

	"github.com/custodexa/backend/internal/dbconsole"
	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/model"
)

// 探測語句：版本與連上的身分一次問完（MySQL 另問 sql_mode 與用戶端字元集，決定字面值跳脫）。
const (
	probeMySQL    = "SELECT VERSION(), CURRENT_USER(), @@SESSION.sql_mode, @@SESSION.character_set_client"
	probePostgres = "SELECT current_setting('server_version_num'), session_user"
	probeMSSQL    = "SELECT CAST(SERVERPROPERTY('ProductMajorVersion') AS nvarchar(16)), ORIGINAL_LOGIN()"

	// mssqlAlterTemplate 伺服器端組句：登入名取 ORIGINAL_LOGIN()，密碼走 RPC 參數，
	// 以 REPLACE 跳脫單引號後交 sp_executesql。不用 QUOTENAME 包密碼：輸入超過 128
	// 字元時它回 NULL，整句變 NULL 後什麼都不執行卻沒有錯誤。
	mssqlAlterTemplate = "DECLARE @s nvarchar(max) = N'ALTER LOGIN ' + QUOTENAME(ORIGINAL_LOGIN()) + " +
		"N' WITH PASSWORD = N''' + REPLACE(@p_new, N'''', N'''''') + " +
		"N''' OLD_PASSWORD = N''' + REPLACE(@p_old, N'''', N'''''') + N''''; EXEC sp_executesql @s;"
)

// mysqlCharsetSafe 字面值跳脫可靠的用戶端字元集。gbk、big5、sjis 這類多位元組字元集的
// 尾位元組可能是 0x5c，反斜線跳脫會失效。
func mysqlCharsetSafe(charset string) bool {
	switch charset {
	case "utf8mb4", "utf8mb3", "utf8", "latin1", "ascii":
		return true
	default:
		return false
	}
}

// probeQuery 方言的探測語句。
func probeQuery(p dbconsole.Protocol) string {
	switch p {
	case dbconsole.ProtocolMySQL:
		return probeMySQL
	case dbconsole.ProtocolMSSQL:
		return probeMSSQL
	default:
		return probePostgres
	}
}

// probeResult 探測結果。
type probeResult struct {
	// sqlMode MySQL 的 session sql_mode（決定反斜線是否為跳脫字元）
	sqlMode string
}

// checkProbe 版本門檻、字元集與身分釘選。回空字串＝通過，否則回原因碼。
func checkProbe(p dbconsole.Protocol, username string, row []string) (probeResult, string) {
	var out probeResult
	switch p {
	case dbconsole.ProtocolMySQL:
		if len(row) != 4 {
			return out, model.ChangeSecretReasonRemoteRejected
		}
		if !mysqlVersionSupported(row[0]) {
			return out, model.ChangeSecretReasonTargetVersionUnsupported
		}
		if !mysqlCharsetSafe(strings.ToLower(strings.TrimSpace(row[3]))) {
			return out, model.ChangeSecretReasonRemoteRejected
		}
		// CURRENT_USER() 是權限實際套用的帳號（user@host），取使用者部分：擋代理帳號
		// （以 X 登入、權限是 Y）改到別人的密碼
		at := strings.LastIndex(row[1], "@")
		if at < 0 || row[1][:at] != username {
			return out, model.ChangeSecretReasonRemoteRejected
		}
		out.sqlMode = row[2]
	case dbconsole.ProtocolPostgres:
		if len(row) != 2 {
			return out, model.ChangeSecretReasonRemoteRejected
		}
		n, err := strconv.Atoi(strings.TrimSpace(row[0]))
		if err != nil || n < 100000 {
			return out, model.ChangeSecretReasonTargetVersionUnsupported
		}
		// 用 session_user 而非 current_user：角色層的 SET role 預設值可讓登入後的
		// current_user 變成別的角色
		if row[1] != username {
			return out, model.ChangeSecretReasonRemoteRejected
		}
	case dbconsole.ProtocolMSSQL:
		if len(row) != 2 {
			return out, model.ChangeSecretReasonRemoteRejected
		}
		// 預設定序不分大小寫
		if !strings.EqualFold(row[1], username) {
			return out, model.ChangeSecretReasonRemoteRejected
		}
	default:
		return out, model.ChangeSecretReasonRemoteRejected
	}
	return out, ""
}

// mysqlVersionSupported 8.0.13 起（ALTER USER 的 REPLACE 子句），且不是 MariaDB。
func mysqlVersionSupported(v string) bool {
	if strings.Contains(strings.ToLower(v), "mariadb") {
		return false
	}
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 3 {
		return false
	}
	nums := make([]int, 3)
	for i, s := range parts {
		end := 0
		for end < len(s) && s[end] >= '0' && s[end] <= '9' {
			end++
		}
		n, err := strconv.Atoi(s[:end])
		if err != nil {
			return false
		}
		nums[i] = n
	}
	switch {
	case nums[0] != 8:
		return nums[0] > 8
	case nums[1] != 0:
		return nums[1] > 0
	default:
		return nums[2] >= 13
	}
}

// statement 一句待送的改密語句與參數。
type statement struct {
	query string
	args  []any
}

// buildAlter 組出「自 from 換成 to」的改密語句。改密與回滾共用（回滾即新舊互換）。
// PostgreSQL 的 toVerifier 為 to 的 SCRAM verifier，語句只含它。
// 不改動 from、to。
func buildAlter(p dbconsole.Protocol, probe probeResult, from, to []byte, toVerifier string) statement {
	switch p {
	case dbconsole.ProtocolMySQL:
		noBackslash := strings.Contains(strings.ToUpper(probe.sqlMode), "NO_BACKSLASH_ESCAPES")
		buf := make([]byte, 0, 64+2*(len(from)+len(to)))
		buf = append(buf, "ALTER USER USER() IDENTIFIED BY '"...)
		buf = appendMySQLLiteral(buf, to, noBackslash)
		buf = append(buf, "' REPLACE '"...)
		buf = appendMySQLLiteral(buf, from, noBackslash)
		buf = append(buf, '\'')
		q := string(buf)
		material.Wipe(buf)
		return statement{query: q}
	case dbconsole.ProtocolMSSQL:
		return statement{query: mssqlAlterTemplate, args: []any{
			sql.Named("p_new", string(to)), sql.Named("p_old", string(from)),
		}}
	default:
		return statement{query: "ALTER ROLE SESSION_USER PASSWORD '" + toVerifier + "'"}
	}
}

// appendMySQLLiteral 依 sql_mode 跳脫字面值：單引號一律重複成兩個；反斜線是跳脫字元時再重複反斜線。
func appendMySQLLiteral(buf, s []byte, noBackslash bool) []byte {
	for _, b := range s {
		switch {
		case b == '\'':
			buf = append(buf, '\'', '\'')
		case b == '\\' && !noBackslash:
			buf = append(buf, '\\', '\\')
		default:
			buf = append(buf, b)
		}
	}
	return buf
}
