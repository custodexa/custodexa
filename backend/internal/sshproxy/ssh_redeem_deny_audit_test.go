package sshproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/proxy"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// `GET /api/v1/ssh` 的連線票證兌換遭拒必須留痕（connection-gating spec）。
//
// # 缺陷
//
// `connection-gating` 的「兌換拒絕留痕」**沒有端點限定**，但當初只補了 `/connect`。
// 文字側的 `/api/v1/ssh` 缺票／無效票各回 401 即返，且用不帶原因的
// `RedeemConnectToken`；閘序拒絕走 `writeOutcome` 亦純 HTTP。該路由在
// `cmd/server/audit_rejection_coverage_guard_test.go` 中列為 `exemptHandlerSelfAuth`
// （不掛 AuthMiddleware，票證於 handler 內自解析），故**沒有任何守衛看得見**——
// 修法前 `audit_logs` 對這條路徑的拒絕為零列（實測 2026-08-14）。
//
// 這是零憑證即可觸發的路徑：任何人都能對它反覆打偽造票證，而稽核上與「沒有人試過」
// 在資料上無從分辨。
//
// # 本檔守的五件事
//
//  1. 票證不成立（缺／偽造／過期）三種拒絕**各自**留痕，原因在審計上**可區分**。
//  2. 閘序拒絕留痕，原因與票證類可區分，且 `asset_id` 填實
//     （「有人試圖連這台機器但被擋下」必須出現在資產樞紐上）。
//  3. `status` 依下列規則分流：401＝憑證不成立→`failure`；其餘→`denied`。
//  4. `details.via` 為 `ssh`——兩條兌換入口的拒絕列同表，沒有這個欄位就分不出
//     被探測的是哪一個入口。
//  5. **對外回應不因留痕而分化**：偽造票與過期票的狀態碼與 body 逐字元相同。
//     審計分得出來、攻擊者分不出來，是本 change 的既有裁決。
//
// # 突變自檢
//
// 拿掉 `HandleSSH` 內票證分支的 `h.auditRedeemDenied(...)` ⇒ 票證三格轉紅；
// 拿掉 `writeRedeemOutcome` 內的呼叫 ⇒ 閘序格轉紅。兩者互不掩蓋。

type sshDenyEnv struct {
	h  *Handler
	db *gorm.DB
}

// setupSSHDenyEnv 與生產同構的最小鏈路：真 handler ＋ 真 audit service ＋ 真 sqlite
// ＋ 真 AuditLogMiddleware（掛法同 `cmd/server/main.go` 的全域鏈），斷言 `audit_logs`
// 實列。
//
// 審計服務刻意 `AsyncAuditEnabled: false`：非同步下「等不到」與「根本沒寫」在失敗
// 訊息上無從分辨。
//
// protocol 決定閘序在哪一道擋下：`ssh` 為可建線協議（本檔不走到建線），
// `rdp` 會在 G-S8（非文字終端）被擋，即本檔的「閘序拒絕」格。
func setupSSHDenyEnv(t *testing.T, protocol string) *sshDenyEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	// 單連線：ff51836 的「單獨跑綠、整包跑紅」防護
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserGroup{}, &model.Asset{},
		&model.AssetAccount{}, &model.AssetGroup{}, &model.AssetNode{}, &model.AssetAuthorization{},
		&model.AccessRequest{}, &model.SecurityPolicy{}, &model.AuditLog{}, &model.Session{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	roles := []model.Role{{Name: model.RoleUser}, {Name: model.RoleAdmin}}
	for i := range roles {
		if err := db.Create(&roles[i]).Error; err != nil {
			t.Fatalf("seed role: %v", err)
		}
	}
	users := []model.User{
		{Username: "u1", Email: emailPtr("u1@x"), Active: true, Roles: []model.Role{roles[0]}},
		{Username: "u2", Email: emailPtr("u2@x"), Active: true, Roles: []model.Role{roles[1]}},
	}
	for i := range users {
		if err := db.Create(&users[i]).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
	}
	if err := db.Create(&model.Asset{
		Name: "target", Protocol: model.ProtocolType(protocol), Host: "h", Port: 22, CreatedBy: 2,
	}).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	if err := db.Model(&model.Asset{}).Where("id = ?", 1).
		Update("access_policy", model.AccessPolicyOpen).Error; err != nil {
		t.Fatalf("set policy: %v", err)
	}
	uid, aid := uint(1), uint(1)
	if err := db.Create(&model.AssetAuthorization{
		UserID: &uid, AssetID: &aid, Permission: model.PermissionConnect, GrantedBy: 2,
	}).Error; err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	// 資產建立經 GORM hook 落一筆自己的審計列（AP-23）：清空後起算，
	// 使「恰好一列」指的是**兌換拒絕**的列數
	if err := db.Exec("DELETE FROM audit_logs").Error; err != nil {
		t.Fatalf("清空 seed 期審計列: %v", err)
	}

	assetSvc, err := asset.NewAssetService(aesColumnCodec(t, make([]byte, 32)), "localhost", 4822, audit.NewTxSink())
	if err != nil {
		t.Fatalf("asset service: %v", err)
	}
	authzSvc := authz.NewAssetAuthorizationService(db)
	auditService := audit.NewAuditLogService(&config.FeatureFlags{
		AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false,
	})
	h := NewHandler(assetSvc, identity.NewAuthService("ssh-deny-secret", time.Hour),
		authzSvc, nil, nil, t.TempDir(), auditService)
	policies := policy.NewSecurityPolicyService(db)
	h.AccessPolicy = policy.NewAccessPolicyService(db, policies, authzSvc)
	return &sshDenyEnv{h: h, db: db}
}

// sshDenyResponse 一次兌換嘗試的**完整對外面**：狀態碼、body 原文與標頭。
// 三者一併留存，才能斷言「偽票與過期票對外不可區分」——只比狀態碼會漏掉 body 分化。
type sshDenyResponse struct {
	code   int
	body   string
	header http.Header
}

// redeem 走與生產同構的路由（含全域真審計中介層，位置同 cmd/server/main.go）
func (e *sshDenyEnv) redeem(query string) sshDenyResponse {
	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(e.h.AuditService))
	r.GET("/api/v1/ssh", e.h.HandleSSH)
	req := httptest.NewRequest("GET", "/api/v1/ssh"+query, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return sshDenyResponse{code: w.Code, body: w.Body.String(), header: w.Header().Clone()}
}

// onlyRow 取唯一一列審計；不是恰好一列即失敗
// （0＝拒絕零留痕，>1＝中介層與 handler 重複記錄）
func (e *sshDenyEnv) onlyRow(t *testing.T, why string) model.AuditLog {
	t.Helper()
	var rows []model.AuditLog
	if err := e.db.Order("id asc").Find(&rows).Error; err != nil {
		t.Fatalf("查 audit_logs: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("%s：審計列 = %d 列, want 1（0＝拒絕零留痕，>1＝重複記錄）", why, len(rows))
	}
	return rows[0]
}

// issueLiveTicket 簽一張有效票（指向 seed 的 asset 1）
func (e *sshDenyEnv) issueLiveTicket(t *testing.T) string {
	t.Helper()
	tok, err := e.h.ConnectTokens.IssueConnectToken(context.Background(),
		proxy.ConnectGrant{UserID: 1, AssetID: 1, AccountID: 0})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return tok
}

// assertSSHDenyRow 逐欄檢查一列 `/ssh` 兌換拒絕留痕
func assertSSHDenyRow(t *testing.T, row model.AuditLog, why, wantReason string,
	wantStatus model.AuditStatus, wantHTTP int, wantAsset *uint) {
	t.Helper()
	if row.Action != model.ActionCreate || row.Resource != model.ResourceSession {
		t.Errorf("%s：action/resource = %q/%q, want %q/%q",
			why, row.Action, row.Resource, model.ActionCreate, model.ResourceSession)
	}
	if row.Status != wantStatus {
		t.Errorf("%s：status = %q, want %q（認證失敗與授權拒絕不得混為一談）",
			why, row.Status, wantStatus)
	}
	if row.StatusCode != wantHTTP {
		t.Errorf("%s：status_code = %d, want %d", why, row.StatusCode, wantHTTP)
	}
	if row.ErrorMsg != wantReason {
		t.Errorf("%s：error_msg = %q, want %q（拒絕原因不可區分即無從辨識探測行為）",
			why, row.ErrorMsg, wantReason)
	}
	if !strings.Contains(row.Details, `"reason":"`+wantReason+`"`) {
		t.Errorf("%s：details = %q 未帶 reason", why, row.Details)
	}
	if !strings.Contains(row.Details, `"via":"`+proxy.ViaSSH+`"`) {
		t.Errorf("%s：details = %q 未標記入口為 %q（兩條兌換入口的拒絕列同表，"+
			"缺這個欄位就分不出被探測的是哪一個）", why, row.Details, proxy.ViaSSH)
	}
	if row.ClientIP == "" {
		t.Errorf("%s：client_ip 為空（來源位址是這類事件的主要證據）", why)
	}
	if row.Method != http.MethodGet {
		t.Errorf("%s：method = %q, want GET", why, row.Method)
	}
	if row.Path != "/api/v1/ssh" {
		t.Errorf("%s：path = %q, want /api/v1/ssh", why, row.Path)
	}
	switch {
	case wantAsset == nil && row.AssetID != nil:
		t.Errorf("%s：asset_id = %d, want nil（票證不成立時目標未知，0 會被讀成編號 0 的資產）",
			why, *row.AssetID)
	case wantAsset != nil && (row.AssetID == nil || *row.AssetID != *wantAsset):
		t.Errorf("%s：asset_id = %v, want %d（資產樞紐上看不到被擋下的連線企圖）",
			why, row.AssetID, *wantAsset)
	}
	if row.CreatedAt.IsZero() {
		t.Errorf("%s：created_at 為零值（嘗試時間答不出來）", why)
	}
}

// --- 格 1-3：票證類拒絕，三種原因各自留痕且可區分 ---

// TestSSHTicketDenialsAreAudited 缺票／偽票／過期票三者在審計上必須分得出來
// ——那正是「有人在探測」與「使用者慢了一步」的差別。
func TestSSHTicketDenialsAreAudited(t *testing.T) {
	t.Run("缺票證", func(t *testing.T) {
		e := setupSSHDenyEnv(t, "ssh")
		if r := e.redeem(""); r.code != http.StatusUnauthorized {
			t.Fatalf("缺票證狀態碼 = %d, want 401", r.code)
		}
		assertSSHDenyRow(t, e.onlyRow(t, "缺票證"), "缺票證", string(proxy.RedeemDenyMissing),
			model.StatusFailure, http.StatusUnauthorized, nil)
	})

	t.Run("偽造票證", func(t *testing.T) {
		e := setupSSHDenyEnv(t, "ssh")
		if r := e.redeem("?connect_token=deadbeefdeadbeefdeadbeefdeadbeef"); r.code != http.StatusUnauthorized {
			t.Fatalf("偽造票證狀態碼 = %d, want 401", r.code)
		}
		assertSSHDenyRow(t, e.onlyRow(t, "偽造票證"), "偽造票證", string(proxy.RedeemDenyInvalid),
			model.StatusFailure, http.StatusUnauthorized, nil)
	})

	t.Run("已兌換過的票證", func(t *testing.T) {
		e := setupSSHDenyEnv(t, "ssh")
		tok := e.issueLiveTicket(t)
		// 一次性：第一發用掉它（會走到閘序，本格不關心結果），第二發即「票不存在」
		e.redeem("?connect_token=" + tok)
		if err := e.db.Exec("DELETE FROM audit_logs").Error; err != nil {
			t.Fatalf("清空第一發的列: %v", err)
		}
		if r := e.redeem("?connect_token=" + tok); r.code != http.StatusUnauthorized {
			t.Fatalf("重放票證狀態碼 = %d, want 401", r.code)
		}
		assertSSHDenyRow(t, e.onlyRow(t, "重放票證"), "重放票證", string(proxy.RedeemDenyInvalid),
			model.StatusFailure, http.StatusUnauthorized, nil)
	})

	// 「過期票證」格**不在本檔**：`connectTokenTTL` 是 60 秒的套件私有常數，
	// 跨包的測試既撥不動時鐘、也碰不到未匯出的 grant 表，唯一走法是真的等 65 秒
	// ——那筆帳掛在實走驗證（tasks 10-A.5），不掛進單元套件。
	//
	// **不為了測試在生產型別上開一個「讓票提前過期」的匯出方法**：那是為驗證而
	// 增設的可竄改面，而本 change 的威脅模型邊界明載不為此類情境加碼。
	//
	// 覆蓋上並無缺口：handler 對「無效」與「過期」走**同一個分支**
	//（`denyReason != RedeemDenyNone`），原因字串原樣轉交審計；「過期與偽造不得
	// 收斂為同一字串」的判定本體在 `RedeemConnectTokenWithReason`，由
	// `internal/proxy/connect_token_test.go` 與 `/connect` 側 `connect_deny_audit_test.go`
	// 的過期格釘住。
}

// --- 格 4：閘序拒絕（兩階段各一發）---

// TestSSHGateDenialIsAudited 閘序的**兩個出口**各自留痕。
//
// `HandleSSH` 有兩處 `writeRedeemOutcome`：`AuthorizePreResolve`（憑證解封前）與
// `AuthorizeResolvedAccount`（解封後）。只測其一的話，另一處被改回 `writeOutcome`
// 不會有任何東西轉紅——而那正是這類缺口最可能復發的形態。
//
// 這組同時證明：閘序出口有留痕、拒絕原因與票證類可區分、授權拒絕記 `denied`
// 而非 `failure`、`asset_id` 由 grant 填實（「有人試圖連這台機器但被擋下」
// 必須出現在資產樞紐上）。
func TestSSHGateDenialIsAudited(t *testing.T) {
	wantAsset := uint(1)

	t.Run("解封前的閘（G-S5 終端尺寸）", func(t *testing.T) {
		e := setupSSHDenyEnv(t, "ssh")
		tok := e.issueLiveTicket(t)
		// 不帶 cols／rows：閘序在 AuthorizePreResolve 階段即拒
		if r := e.redeem("?connect_token=" + tok); r.code != http.StatusBadRequest {
			t.Fatalf("終端尺寸缺漏狀態碼 = %d, want 400", r.code)
		}
		row := e.onlyRow(t, "解封前閘序拒絕")
		assertSSHDenyRow(t, row, "解封前閘序拒絕", string(apierror.CodeTerminalColsInvalid),
			model.StatusDenied, http.StatusBadRequest, &wantAsset)
		if row.UserID != 1 {
			t.Errorf("解封前閘序拒絕：user_id = %d, want 1（票證帶得出主體時不得留空）", row.UserID)
		}
	})

	t.Run("解封後的閘（G-S8 非文字終端）", func(t *testing.T) {
		e := setupSSHDenyEnv(t, "rdp")
		tok := e.issueLiveTicket(t)
		// 帶合法尺寸讓 G-S5 通過，RDP 資產在解封後的 G-S8 被擋
		if r := e.redeem("?connect_token=" + tok + "&cols=80&rows=24"); r.code != http.StatusBadRequest {
			t.Fatalf("非文字終端狀態碼 = %d, want 400", r.code)
		}
		row := e.onlyRow(t, "解封後閘序拒絕")
		assertSSHDenyRow(t, row, "解封後閘序拒絕", string(apierror.CodeAssetNotTextTerminal),
			model.StatusDenied, http.StatusBadRequest, &wantAsset)
		// 與票證類拒絕的原因不同義：稽核據此分得出「票不成立」與「票成立但不准」
		if row.ErrorMsg == string(proxy.RedeemDenyInvalid) ||
			row.ErrorMsg == string(proxy.RedeemDenyExpired) {
			t.Fatalf("閘序拒絕被記成票證類原因（%q）", row.ErrorMsg)
		}
	})
}

// --- 格 5：對外回應不因留痕而分化 ---

// TestSSHTicketDenialResponsesAreIndistinguishable 票證類拒絕的對外回應必須
// **逐字元相同**，且不得洩漏內部拒絕原因。
//
// 這是本 change 的既有裁決（`/connect` 同此）：原因分流只存在於審計。
// 若對外分得出來，攻擊者拿一張猜來的票就能問出「這張票存不存在」——那就是票證
// 存在性探測面。狀態碼、body、`Content-Type` 三者一併比對：只比狀態碼會漏掉
// body 分化。
//
// 本檔在單元層走得到的兩種原因是「票不存在」與「已兌換過」（皆 `ticket_invalid`），
// 故第二段補一條更強的斷言：**回應本文不得出現任何一個內部原因字串**。日後若有人
// 把 `denyReason` 順手塞進回應（那是最容易發生的分化形態），這條當場轉紅，
// 不必等到有人想起要比對兩種原因的 body。「過期票 vs 偽造票」的逐字元比對由實走
// 驗證承擔（見上方註解）。
func TestSSHTicketDenialResponsesAreIndistinguishable(t *testing.T) {
	forged := setupSSHDenyEnv(t, "ssh").redeem("?connect_token=deadbeefdeadbeefdeadbeefdeadbeef")

	e := setupSSHDenyEnv(t, "ssh")
	tok := e.issueLiveTicket(t)
	e.redeem("?connect_token=" + tok) // 用掉它
	replayed := e.redeem("?connect_token=" + tok)

	if forged.code != replayed.code {
		t.Errorf("偽造票 %d 與重放票 %d 的狀態碼不同：票證存在性可經狀態碼探測",
			forged.code, replayed.code)
	}
	if forged.body != replayed.body {
		t.Errorf("偽造票與重放票的 body 不同：\n偽造=%s\n重放=%s\n"+
			"原因分流只准存在於審計，對外回應必須逐字元相同", forged.body, replayed.body)
	}
	if got, want := replayed.header.Get("Content-Type"), forged.header.Get("Content-Type"); got != want {
		t.Errorf("偽造票與重放票的 Content-Type 不同（%q vs %q）", want, got)
	}
	// 下界：body 不得是空字串——兩邊都空也會「相同」，那是假綠
	if strings.TrimSpace(forged.body) == "" {
		t.Fatalf("拒絕回應 body 為空：兩邊皆空的「相同」不構成不可區分的證據")
	}
	for _, leak := range []string{
		string(proxy.RedeemDenyMissing), string(proxy.RedeemDenyInvalid),
		string(proxy.RedeemDenyExpired),
	} {
		for _, r := range []struct {
			name string
			resp sshDenyResponse
		}{{"偽造票", forged}, {"重放票", replayed}} {
			if strings.Contains(r.resp.body, leak) {
				t.Errorf("%s 的回應 body 帶出內部拒絕原因 %q：%s\n"+
					"原因一旦外洩，攻擊者即可用它區分票證狀態", r.name, leak, r.resp.body)
			}
		}
	}
}
