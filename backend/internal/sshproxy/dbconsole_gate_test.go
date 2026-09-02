package sshproxy

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/dbconsole"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/proxy"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 主控台兌換點的閘序與 admission。
//
// 兌換入口自此有三條（`/connect`、`/ssh`、`/db-console`），三者共用同一張閘序表
// 與同一個拒絕留痕寫入點。本檔守的是「多出來的那兩道閘」與「拒絕仍然留痕」。

// TestConsoleTicketDenialsAreIndistinguishable 缺票與不成立的票各自留痕，
// 且**同一個分支的兩種原因（偽造／過期）對外逐字相同**。
//
// 分得出來的一方必須是稽核，不是攻擊者——回應若分化，票證的存在性就成了
// 可探測的資訊。偽造與過期在 handler 走同一個分支、原因字串原樣轉交審計，
// 故本檔以偽票驗那條路徑，過期格由 `internal/proxy` 的兌換單元測試釘住
// （`connectTokenTTL` 是套件私有常數，不為測試在生產型別上開提前過期的入口）
func TestConsoleTicketDenialsAreIndistinguishable(t *testing.T) {
	env := setupConsoleEnv(t, "mysql")

	missing := env.redeem("")
	if missing.code != http.StatusUnauthorized {
		t.Fatalf("缺票狀態碼 = %d, want 401", missing.code)
	}
	missingRows := env.auditRows(t)
	if len(missingRows) != 1 {
		t.Fatalf("缺票留痕 = %d 列, want 1", len(missingRows))
	}

	env.db.Exec("DELETE FROM audit_logs")
	forged := env.redeem("?connect_token=" + strings.Repeat("a", 43))
	forgedRows := env.auditRows(t)
	if len(forgedRows) != 1 {
		t.Fatalf("偽票留痕 = %d 列, want 1", len(forgedRows))
	}

	// 已兌換過的票（一次性，兌換即焚）：走與偽票同一個分支
	env.db.Exec("DELETE FROM audit_logs")
	tok := env.issueTicket(t)
	_ = env.redeem("?connect_token=" + tok)
	env.db.Exec("DELETE FROM audit_logs")
	spent := env.redeem("?connect_token=" + tok)

	if forged.code != spent.code || forged.body != spent.body {
		t.Fatalf("偽票與已焚票對外可區分：%d/%q vs %d/%q",
			forged.code, forged.body, spent.code, spent.body)
	}
	spentRows := env.auditRows(t)
	if len(spentRows) != 1 {
		t.Fatalf("已焚票留痕 = %d 列, want 1", len(spentRows))
	}
	if missingRows[0].ErrorMsg != string(proxy.RedeemDenyMissing) {
		t.Errorf("缺票的審計原因 = %q, want %q", missingRows[0].ErrorMsg, proxy.RedeemDenyMissing)
	}
	if forgedRows[0].ErrorMsg != string(proxy.RedeemDenyInvalid) {
		t.Errorf("偽票的審計原因 = %q, want %q", forgedRows[0].ErrorMsg, proxy.RedeemDenyInvalid)
	}
	if missingRows[0].ErrorMsg == forgedRows[0].ErrorMsg {
		t.Errorf("缺票與偽票在審計上不可區分——探測訊號與「忘了帶票」是兩回事")
	}
	if !strings.Contains(spentRows[0].Details, `"via":"`+proxy.ViaDBConsole+`"`) {
		t.Errorf("主控台入口的拒絕列未標記為主控台（稽核以 via 分流時會被算進別條入口）：%q",
			spentRows[0].Details)
	}
	if strings.Contains(spentRows[0].Details, `"via":"`+proxy.ViaSSH+`"`) {
		t.Errorf("主控台入口的拒絕列沿用了終端入口的標記：%q", spentRows[0].Details)
	}
}

// TestConsoleProtocolGateRejectsNonSQL G-C1：非三方言的資產走不了這個入口
func TestConsoleProtocolGateRejectsNonSQL(t *testing.T) {
	env := setupConsoleEnv(t, "redis")
	env.seedAccount(t)
	tok := env.issueTicket(t)

	resp := env.redeem("?connect_token=" + tok)

	if resp.code != http.StatusBadRequest {
		t.Fatalf("狀態碼 = %d, want 400（body=%s）", resp.code, resp.body)
	}
	if !strings.Contains(resp.body, string(apierror.CodeDBConsoleUnsupportedProtocol)) {
		t.Fatalf("回應碼不符：%s", resp.body)
	}
	rows := env.auditRows(t)
	if len(rows) != 1 {
		t.Fatalf("閘序拒絕留痕 = %d 列, want 1", len(rows))
	}
	if !strings.Contains(rows[0].Details,
		string(apierror.CodeDBConsoleUnsupportedProtocol)) {
		t.Errorf("拒絕列未記下被哪一道閘擋：%q", rows[0].Details)
	}
}

// TestConsoleAdmissionGateRejectsAtLimit G-C2：達上限即拒，
// 且拒絕列帶 scope／current／limit
func TestConsoleAdmissionGateRejectsAtLimit(t *testing.T) {
	env := setupConsoleEnv(t, "mysql")
	env.seedAccount(t)
	for i := 0; i < dbconsole.MaxConcurrentSessionsPerUser; i++ {
		rel, denial := env.h.consoleAdmission().acquire(1)
		if denial != nil || rel == nil {
			t.Fatalf("第 %d 個名額佔用失敗: %+v", i+1, denial)
		}
	}
	tok := env.issueTicket(t)

	resp := env.redeem("?connect_token=" + tok)

	if resp.code != http.StatusTooManyRequests {
		t.Fatalf("狀態碼 = %d, want 429（body=%s）", resp.code, resp.body)
	}
	if !strings.Contains(resp.body, string(apierror.CodeDBConsoleLimitReached)) {
		t.Fatalf("回應碼不符：%s", resp.body)
	}
	var found string
	for _, r := range env.auditRows(t) {
		if strings.Contains(r.RequestBody, consoleKindAdmission) {
			found = r.RequestBody
		}
	}
	if found == "" {
		t.Fatalf("admission 拒絕未留痕")
	}
	for _, key := range []string{`"scope":"user"`, `"current":4`, `"limit":4`} {
		if !strings.Contains(found, key) {
			t.Errorf("拒絕列缺 %s：%s", key, found)
		}
	}
}

// TestConsoleAdmissionCountsRuntimeNotOrphanRows 計數口徑是運行時註冊表，
// 不是會話表的 active 列。
//
// 崩潰後殘留的孤兒列會留到收斂寬限期結束；拿它們計數，使用者會被自己的
// 殘留會話擋在門外，而他沒有任何辦法自救
func TestConsoleAdmissionCountsRuntimeNotOrphanRows(t *testing.T) {
	env := setupConsoleEnv(t, "mysql")
	aid := uint(1)
	for i := 0; i < dbconsole.MaxConcurrentSessionsPerUser+2; i++ {
		orphan := &model.Session{UserID: 1, AssetID: &aid, Protocol: model.ProtocolMySQL,
			SessionID: fmt.Sprintf("orphan-%d", i),
			Status:    model.SessionStatusActive, DBConsole: true, StartTime: time.Now()}
		if err := env.db.Create(orphan).Error; err != nil {
			t.Fatalf("seed orphan: %v", err)
		}
	}

	rel, denial := env.h.consoleAdmission().acquire(1)
	if denial != nil {
		t.Fatalf("殘留的 active 列佔了名額：%+v（口徑必須是運行時註冊表）", denial)
	}
	rel()
	if u, total := env.h.consoleAdmission().counts(1); u != 0 || total != 0 {
		t.Errorf("釋放後計數 = %d/%d, want 0/0", u, total)
	}
}

// TestConsoleAdmissionReleasedOnLaterGateDenial 名額佔用之後才被拒的兌換
// 必須把名額還回去——否則一次被拒會永久吃掉一個名額
func TestConsoleAdmissionReleasedOnLaterGateDenial(t *testing.T) {
	env := setupConsoleEnv(t, "mysql")
	// 不 seed 帳號：G-S11（零帳號 fail-close）在 G-C2 之後擋下
	tok := env.issueTicket(t)

	resp := env.redeem("?connect_token=" + tok)

	if resp.code == http.StatusOK {
		t.Fatalf("零帳號資產竟然放行：%s", resp.body)
	}
	if u, total := env.h.consoleAdmission().counts(1); u != 0 || total != 0 {
		t.Fatalf("被拒後名額未釋放：%d/%d", u, total)
	}
}

// TestConsoleDialFailureLeavesNoSession 起始連線失敗不建會話列，
// 但留一筆帶分類的審計——那是該次嘗試的唯一痕跡
func TestConsoleDialFailureLeavesNoSession(t *testing.T) {
	env := setupConsoleEnv(t, "mysql")
	env.seedAccount(t)
	// 指向一個確定不會有人在聽的埠
	if err := env.db.Model(&model.Asset{}).Where("id = ?", 1).
		Updates(map[string]any{"host": "127.0.0.1", "port": 1}).Error; err != nil {
		t.Fatalf("set host: %v", err)
	}
	tok := env.issueTicket(t)

	resp := env.redeem("?connect_token=" + tok)

	if resp.code != http.StatusBadGateway {
		t.Fatalf("狀態碼 = %d, want 502（body=%s）", resp.code, resp.body)
	}
	if !strings.Contains(resp.body, string(apierror.CodeDBConsoleConnectFailed)) &&
		!strings.Contains(resp.body, string(apierror.CodeDBConsoleDatabaseUnavailable)) {
		t.Fatalf("回應碼不符：%s", resp.body)
	}
	if strings.Contains(resp.body, "127.0.0.1") || strings.Contains(resp.body, "connection refused") {
		t.Errorf("連線階段的回應洩漏了拓撲：%s", resp.body)
	}
	var sessions int64
	env.db.Model(&model.Session{}).Count(&sessions)
	if sessions != 0 {
		t.Errorf("起始連線失敗卻建了 %d 筆會話列", sessions)
	}
	var connectRow string
	for _, r := range env.auditRows(t) {
		if strings.Contains(r.RequestBody, consoleKindConnect) {
			connectRow = r.RequestBody
		}
	}
	if connectRow == "" {
		t.Fatalf("起始連線失敗未留痕")
	}
	if !strings.Contains(connectRow, `"class":"`) {
		t.Errorf("連線失敗列未帶分類：%s", connectRow)
	}
	if u, total := env.h.consoleAdmission().counts(1); u != 0 || total != 0 {
		t.Errorf("連線失敗後名額未釋放：%d/%d", u, total)
	}
}

// TestConsoleGateSequenceIncludesConsoleGates 兩道主控台專屬閘插在 G-S8 之後、
// G-S9 之前，且協議閘在 admission 之前。
//
// 順序是實質：協議閘判的是「這個資產根本不該走這個入口」，那個判定不必先過
// 授權；admission 佔名額，佔在授權之前會讓一次注定被拒的兌換也吃掉名額
func TestConsoleGateSequenceIncludesConsoleGates(t *testing.T) {
	env := setupConsoleEnv(t, "mysql")
	var release func()
	gates := env.h.consoleResolvedAccountGates(nil,
		gatewayapi.ConnectSubject{UserID: 1},
		gatewayapi.ResolvedConnectObject{
			ConnectObjectRef: gatewayapi.ConnectObjectRef{AssetID: 1}},
		&redeemState{}, &consoleAuditContext{}, &release)

	names := make([]string, 0, len(gates))
	for _, g := range gates {
		names = append(names, g.Name)
	}
	i8 := indexOfExact(names, "G-S8")
	ic1 := indexOfExact(names, "G-C1")
	ic2 := indexOfExact(names, "G-C2")
	i9 := indexOfExact(names, "G-S9")
	if i8 < 0 || ic1 < 0 || ic2 < 0 || i9 < 0 {
		t.Fatalf("閘序缺項：%v", names)
	}
	if !(i8 < ic1 && ic1 < ic2 && ic2 < i9) {
		t.Fatalf("閘序 = %v，want G-S8 → G-C1 → G-C2 → G-S9", names)
	}
}

func indexOfExact(names []string, want string) int {
	for i, n := range names {
		if n == want {
			return i
		}
	}
	return -1
}
