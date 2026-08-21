// Package dbproxy 資料庫資產的 CLI 代理（database-protocol）：
// 以本地 CLI 子程序連線目標資料庫，憑證後端組裝、零出端；
// 文字流走 sshproxy bridge 的 TerminalConn 介面，審計鏈全沿用。
package dbproxy

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/custodexa/backend/internal/localpty"
)

// Target 連線目標（憑證由後端記憶體組裝，不出端）
type Target struct {
	Protocol string // mysql / postgres / redis / mssql
	Host     string
	Port     int
	Username string
	Password string
	DBName   string
	// TLSMode DB 連線 TLS 模式（per-asset 可選）：
	//   ""(預設，沿用 client 預設，不破壞既有資產) / disable(停用) /
	//   require(加密不驗憑證) / verify-ca(加密並驗證伺服器憑證) /
	//   verify-full(加密、驗證憑證並核對主機名——M6；Redis 無獨立檔位等同 verify-ca)
	TLSMode string
	CACert  string // verify-ca/verify-full 用的自訂 CA（PEM，選填；空＝驗系統根憑證）
}

// BuildCommand 依協議組裝 CLI 程式與參數（database-protocol 階段 1）：
// 回傳 (程式, 參數, 環境)。**密碼既不進 argv 也不進環境**——CLI 子程序在其生命期內
// 完全不持有真憑證，密碼改由 PTY 提示注入（見 PasswordPrompt 與 localpty.PasswordAuth）。
// caFile 為 verify-ca 模式下已寫好的 CA 暫存檔路徑（由 Start 準備，無則為空）。
func BuildCommand(t Target, caFile string) (string, []string, []string, error) {
	// 進入 argv 的欄位防 flag 注入（host/username/dbname 以 - 開頭會被 CLI 當旗標）
	for field, val := range map[string]string{
		"主機": t.Host, "使用者名稱": t.Username, "資料庫名稱": t.DBName,
	} {
		if err := localpty.SafeArg(field, val); err != nil {
			return "", nil, nil, err
		}
	}

	switch t.Protocol {
	case "postgres":
		port := t.Port
		if port == 0 {
			port = 5432
		}
		args := []string{
			// -X 不讀 ~/.psqlrc：後端容器 HOME 為全體會話共用，會話行為不該
			// 受共享檔案左右。-P pager=off 關掉 pager——它經 popen 進 shell
			// （正式版已無 shell，開著會讓大結果集輸出直接壞掉）
			"-X",
			"-P", "pager=off",
			"-h", t.Host,
			"-p", strconv.Itoa(port),
			"-U", t.Username,
		}
		if t.DBName != "" {
			args = append(args, t.DBName)
		}
		// 環境不含 PGPASSWORD：psql 會在需要時輸出 "Password for user <name>: "
		// 並停下等輸入，由 PTY 層注入（PasswordPrompt）。TLS 以 PGSSLMODE/PGSSLROOTCERT 控制。
		// PSQL_HISTORY 導向 /dev/null：CLI 子程序的執行身分為全體 DB 會話共用，
		// 落檔的歷史會讓 SQL 文字跨會話、跨使用者殘留（本會話內的上下鍵歷史
		// 由 readline 的記憶體緩衝提供，不受影響）
		env := []string{"PSQL_HISTORY=/dev/null"}
		switch t.TLSMode {
		case "disable":
			env = append(env, "PGSSLMODE=disable")
		case "require":
			env = append(env, "PGSSLMODE=require")
		case "verify-ca", "verify-full":
			// verify-full 額外核對憑證 CN/SAN 與連線主機名（M6，PGSSLMODE 原生支援）
			env = append(env, "PGSSLMODE="+t.TLSMode)
			if caFile != "" {
				env = append(env, "PGSSLROOTCERT="+caFile)
			}
		}
		return "psql", args, env, nil

	case "mysql":
		port := t.Port
		if port == 0 {
			port = 3306
		}
		args := []string{
			// --sandbox 為 client 原生的檔案存取拒絕（實測擋 system／\!／source／tee）。
			// 視為加值層而非唯一控制——實測它仍放行 `pager <程式>` 與 `edit`；
			// 真正的保證來自子程序的執行環境（非 root、無可讀憑證、無可寫路徑）
			"--sandbox",
			// LOAD DATA LOCAL INFILE 是與 psql \lo_import 等價的本機讀檔原語，
			// 且不在 --sandbox 的守備範圍內（不可假設 client 原生限制會擋）
			"--local-infile=0",
			"-h", t.Host,
			"-P", strconv.Itoa(port),
			"-u", t.Username,
		}
		if t.Password != "" {
			// -p 不帶值＝提示密碼（帶值會落 argv）。實測後接的位置參數不會被
			// 當成密碼吃掉：`-u root -p testdb` 仍以 testdb 為資料庫
			args = append(args, "-p")
		}
		if t.DBName != "" {
			args = append(args, t.DBName)
		}
		// MariaDB client TLS 旗標（mariadb 為 mysql 的非 deprecated 別名，flag 相容）。
		// --ssl-verify-server-cert 即含主機名核對：verify-ca 與 verify-full 同映射
		//（spec 檔位映射——MySQL client 無「只驗 CA 不核對主機名」的獨立旗標）
		switch t.TLSMode {
		case "disable":
			args = append(args, "--skip-ssl")
		case "require":
			// 明確關掉憑證核對：MariaDB client 11.4 起，「有提供密碼」會自動把
			// --ssl-verify-server-cert 打開（無密碼時反而自動關閉並印警告）。
			// 密碼改走 -p 提示注入後這個啟發式會被觸發，若不明示就等於把
			// require（加密不驗憑證）偷偷升級成 verify-full，既有資產全數連不上
			args = append(args, "--ssl", "--ssl-verify-server-cert=0")
		case "verify-ca", "verify-full":
			args = append(args, "--ssl", "--ssl-verify-server-cert")
			if caFile != "" {
				args = append(args, "--ssl-ca="+caFile)
			}
		default:
			// 未設定 TLS 檔位（既有資產的預設）：維持「不核對伺服器憑證」的既有
			// 行為。理由同 require——改用 -p 之後 client 會自動開啟核對，等於讓
			// 每個沒設 TLS 的資產在升級當下突然要求可信憑證鏈。要提高保證應
			// 明示改 per-asset 的 TLS 檔位，而不是由一個憑證面修正順手改掉
			args = append(args, "--ssl-verify-server-cert=0")
		}
		// 環境不含 MYSQL_PWD：改由 PTY 注入回答 "Enter password: "。
		// 呼叫 mariadb（非 deprecated 別名 mysql）：避免連線時印出
		// 「Deprecated program name」警告雜訊；同一執行檔，flag/env 完全相容。
		// MYSQL_HISTFILE 導向 /dev/null：理由同 psql
		return "mariadb", args, []string{"MYSQL_HISTFILE=/dev/null"}, nil

	case "redis":
		port := t.Port
		if port == 0 {
			port = 6379
		}
		args := []string{"-h", t.Host, "-p", strconv.Itoa(port)}
		if t.DBName != "" {
			args = append(args, "-n", t.DBName)
		}
		// redis-cli TLS：require=加密不驗(--insecure)、verify-ca=加密並驗 CA；
		// verify-full 無獨立檔位等同 verify-ca（spec 檔位映射）
		switch t.TLSMode {
		case "require":
			args = append(args, "--tls", "--insecure")
		case "verify-ca", "verify-full":
			args = append(args, "--tls")
			if caFile != "" {
				args = append(args, "--cacert", caFile)
			}
		}
		// 環境不含 REDISCLI_AUTH：--askpass 讓 redis-cli 輸出
		// "Please input password: " 並停下等輸入，由 PTY 層注入。
		// 歷史檔導向 /dev/null（理由同 psql）
		if t.Password != "" {
			args = append(args, "--askpass")
		}
		return "redis-cli", args, []string{"REDISCLI_HISTFILE=/dev/null"}, nil

	case "mssql":
		port := t.Port
		if port == 0 {
			port = 1433
		}
		// -S <host>,<port> 的逗號是 sqlcmd 的埠分隔語義：host 欄位本身若含逗號會被
		// 解讀成埠。SafeArg 只擋 - 開頭與控制字元（逗號在其他協議合法），故此處
		// 另外擋，不動 SafeArg 的通用語義（mssql-web-cli D8）
		if strings.Contains(t.Host, ",") {
			return "", nil, nil, fmt.Errorf("mssql 主機不得含逗號（-S host,port 的埠分隔語義）")
		}
		args := []string{
			"-S", t.Host + "," + strconv.Itoa(port),
			"-U", t.Username,
			// -X 0＝disable-cmd-and-warn：關閉 :!!（執行本機程式）與 :ED（開編輯器），
			// 這兩者是 sqlcmd 僅有的本機執行原語。取 0（警告）而非 1（遇到即結束程序）：
			// 一個誤打的 :!! 不該讓整條會話與未存的查詢一起消失（D5）。
			// **-X 與 0 必須是兩個獨立 argv 元素**——它是 cobra 的 Int 旗標且無
			// NoOptDefVal（上游 cobra issue 866），裸 -X 會被拒。
			"-X", "0",
		}
		if t.DBName != "" {
			args = append(args, "-d", t.DBName)
		}
		// TLS（D7）：-N 加密檔位、-C 信任伺服器憑證（不驗）、-J 指定伺服器憑證。
		// **-J 的語義是憑證「釘選」而非 CA 信任錨**，與其他三協議的 db_ca_cert
		// （CA bundle）不同；UI 說明文字另以 mssqlCaCertHint 標示。
		switch t.TLSMode {
		case "disable":
			args = append(args, "-N", "false")
		case "require":
			args = append(args, "-N", "true", "-C")
		case "verify-ca", "verify-full":
			// go-mssqldb 驗證憑證時本就核對主機名，兩檔位無獨立差異
			args = append(args, "-N", "true")
			if caFile != "" {
				args = append(args, "-J", caFile)
			}
		}
		// 環境不含 SQLCMDPASSWORD：sqlcmd 在有 -U 而無 -P／SQLCMDPASSWORD 時輸出
		// "Password:" 並以 raw 模式從 stdin 讀，由 PTY 層注入（PasswordPrompt）。
		// 環境亦**不得**含 SQLCMD_LANG：提示字串經 localizer 在地化，該變數一進來
		// 提示就不再是 "Password:"，matcher 必定失準（守衛測試釘住）。
		// sqlcmd 無歷史檔機制，故無需 HISTFILE 類的導向。
		return "sqlcmd", args, nil, nil

	default:
		return "", nil, nil, fmt.Errorf("不支援的資料庫協議: %s", t.Protocol)
	}
}

// PasswordPrompt 依協議回傳該 client 索取密碼時的提示注入設定（無密碼時回 nil）。
// 提示字串為 dev compose 內對 psql 16.14／mariadb client 15.2／redis-cli 8.4.2 的實測值。
//
// psql 的提示帶使用者名稱，且**刻意**以本會話帳號的名稱做完整比對：
// `\c db otheruser` 會提示別的使用者名稱，那把密碼送出去只會是洩漏。
// 至於同名但換 host 的 `\c db user otherhost`，由 promptAuth 的一次性注入擋下
// （實測同 user/host/port 的 `\connect` 會重用快取密碼、根本不再提示，
// 故第一次注入之後的同名提示必然是換了目標）。
func PasswordPrompt(t Target) *localpty.PasswordAuth {
	if t.Password == "" {
		return nil
	}
	switch t.Protocol {
	case "postgres":
		return &localpty.PasswordAuth{
			Password: t.Password,
			Prompt:   "Password for user " + t.Username + ": ",
			// psql 讀密碼時 ICANON=true／ECHO=false，互動 readline 則 ICANON=false
			RequireCanonical: true,
		}
	case "mysql":
		return &localpty.PasswordAuth{
			Password:         t.Password,
			Prompt:           "Enter password: ",
			RequireCanonical: true,
		}
	case "redis":
		return &localpty.PasswordAuth{
			Password: t.Password,
			Prompt:   "Please input password: ",
			// redis-cli --askpass 走遮罩式 raw 讀取（實測 ICANON=false／ECHO=false），
			// 與其互動模式同態，無 termios 判準可用
			RequireCanonical: false,
		}
	case "mssql":
		return &localpty.PasswordAuth{
			Password: t.Password,
			// **無尾隨空白**：上游為 localizer.Sprintf("Password:")
			//（pkg/sqlcmd/sqlcmd.go:350），與 psql 的 "Password for user X: " 不同型，
			// 套錯 matcher 必定不命中
			Prompt: "Password:",
			// sqlcmd 經 peterh/liner 讀密碼，liner 自行下 raw mode（ICANON 關、
			// ECHO 關），與其互動 readline 同態——與 redis-cli --askpass 完全同型，
			// 無 termios 判準可用
			RequireCanonical: false,
		}
	default:
		return nil
	}
}
