package sshproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/proxy"
)

// 唯讀觀看的兩條 WebSocket 一律以一次性觀看票認證。本檔守的是**拒絕面**：
//
//  1. 缺票、偽票、過期票、重放票、用途錯置、客體錯置一律 401，且對外是同一則
//     「token 無效」——分流即票證存在性與用途的探測面。
//  2. 審計分得出成因（`ticket_missing`／`ticket_invalid`／`ticket_expired`／
//     `ticket_purpose_mismatch`）：反覆拿不存在的票試是探測訊號，過期多半只是
//     慢了一步，用途錯置則是越權嘗試。三者寫成同一個字串等於把探測藏進噪音裡。
//  3. 終端連線票**不能**開監看或分享觀看（型別分立，兌換表根本不同）。
//  4. 監看的角色限制在簽發端現查，且拒發時不產生票。
//
// 突變自檢：把 `redeemObserverTicket` 的用途比對拿掉 ⇒ 用途錯置格轉紅；
// 把客體比對拿掉 ⇒ 客體錯置格轉紅；把兌換改成不刪除（非一次性）⇒ 重放格轉紅。

// setObserverTicketsForTest 以指定的登記表取代 handler 的觀看票表
// （必須在任何簽發之前呼叫：惰性建立只跑一次）
func setObserverTicketsForTest(h *Handler, m *proxy.ObserverTicketManager) {
	h.observerTicketsOnce.Do(func() { h.observerTicketsReg = m })
}

// getWS 對 WS 路徑發一般 GET（升級前即被拒的路徑，收得到 HTTP 狀態碼）
func getWS(t *testing.T, e *observerAuditEnv, path string) *http.Response {
	t.Helper()
	srv := httptest.NewServer(e.router())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + path) //nolint:gosec // 測試伺服器位址
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// assertRedeemDenied 斷言：401、且審計恰一列帶指定的入口與成因
func assertRedeemDenied(t *testing.T, e *observerAuditEnv, resp *http.Response,
	via, reason, why string) {
	t.Helper()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("%s：狀態碼 = %d, want %d", why, resp.StatusCode, http.StatusUnauthorized)
	}
	rows := e.waitAuditRows(t, 1, why)
	row := rows[len(rows)-1]
	if row.Status != model.StatusFailure {
		t.Errorf("%s：status = %q, want %q（憑證不成立歸 failure）", why, row.Status, model.StatusFailure)
	}
	if !strings.Contains(row.Details, `"via":"`+via+`"`) {
		t.Errorf("%s：details = %q 未標記入口 %s", why, row.Details, via)
	}
	if !strings.Contains(row.Details, `"reason":"`+reason+`"`) {
		t.Errorf("%s：details = %q 未記成因 %s（成因合併即無從分辨探測與慢一步）",
			why, row.Details, reason)
	}
	if row.ClientIP == "" {
		t.Errorf("%s：來源位址留白，探測來自哪裡答不出來", why)
	}
}

// --- 缺票 ---

func TestObserverWSWithoutTicketIsRejected(t *testing.T) {
	t.Run("monitor", func(t *testing.T) {
		e := setupObserverAuditEnv(t)
		resp := getWS(t, e, "/api/v1/sessions/1/monitor")
		assertRedeemDenied(t, e, resp, observerViaMonitor,
			string(proxy.RedeemDenyMissing), "監看缺票")
	})
	t.Run("share", func(t *testing.T) {
		e := setupObserverAuditEnv(t)
		code, _, err := e.h.Shares.Create(observerAuditSession, observerAuditOwner, time.Minute)
		if err != nil {
			t.Fatalf("建立分享碼: %v", err)
		}
		resp := getWS(t, e, "/api/v1/sessions/share/"+code+"/ws")
		assertRedeemDenied(t, e, resp, observerViaShare,
			string(proxy.RedeemDenyMissing), "分享加入缺票")
	})
}

// --- 偽票 ---

func TestObserverWSWithForgedTicketIsRejected(t *testing.T) {
	const forged = "deadbeefdeadbeefdeadbeefdeadbeef"
	t.Run("monitor", func(t *testing.T) {
		e := setupObserverAuditEnv(t)
		resp := getWS(t, e, monitorWSPath(observerAuditSession, forged))
		assertRedeemDenied(t, e, resp, observerViaMonitor,
			string(proxy.RedeemDenyInvalid), "監看偽票")
	})
	t.Run("share", func(t *testing.T) {
		e := setupObserverAuditEnv(t)
		code, _, err := e.h.Shares.Create(observerAuditSession, observerAuditOwner, time.Minute)
		if err != nil {
			t.Fatalf("建立分享碼: %v", err)
		}
		resp := getWS(t, e, shareWSPath(code, forged))
		assertRedeemDenied(t, e, resp, observerViaShare,
			string(proxy.RedeemDenyInvalid), "分享加入偽票")
	})
}

// --- 過期票 ---

// TestObserverWSWithExpiredTicketIsRejected 過期與偽票的對外回應相同、審計成因不同
func TestObserverWSWithExpiredTicketIsRejected(t *testing.T) {
	t.Run("monitor", func(t *testing.T) {
		e := setupObserverAuditEnv(t)
		// 負 TTL：簽出來的票立即逾時，不需等待
		setObserverTicketsForTest(e.h, proxy.NewObserverTicketManagerWithTTL(-time.Second))
		obs := e.seedObserver(t, "expired-monitor")
		ticket := e.monitorTicket(t, obs, model.RoleAdmin)

		resp := getWS(t, e, monitorWSPath(observerAuditSession, ticket))
		assertRedeemDenied(t, e, resp, observerViaMonitor,
			string(proxy.RedeemDenyExpired), "監看過期票")
	})
	t.Run("share", func(t *testing.T) {
		e := setupObserverAuditEnv(t)
		setObserverTicketsForTest(e.h, proxy.NewObserverTicketManagerWithTTL(-time.Second))
		obs := e.seedObserver(t, "expired-share")
		code, _, err := e.h.Shares.Create(observerAuditSession, observerAuditOwner, time.Minute)
		if err != nil {
			t.Fatalf("建立分享碼: %v", err)
		}
		ticket := e.shareTicket(t, obs, code)

		resp := getWS(t, e, shareWSPath(code, ticket))
		assertRedeemDenied(t, e, resp, observerViaShare,
			string(proxy.RedeemDenyExpired), "分享加入過期票")
	})
}

// --- 重放 ---

// TestObserverTicketIsSingleUse 票兌換即焚：同一張票第二次使用必須被拒。
// 第一次成功建線的斷言不可省——少了它，「第二次被拒」也可能只是因為第一次也被拒
func TestObserverTicketIsSingleUse(t *testing.T) {
	t.Run("monitor", func(t *testing.T) {
		e := setupObserverAuditEnv(t)
		obs := e.seedObserver(t, "replay-monitor")
		ticket := e.monitorTicket(t, obs, model.RoleAdmin)

		ws := dialWS(t, e.router(), monitorWSPath(observerAuditSession, ticket))
		waitRegistered(t, e.tap, ws, "監看訂閱（第一次使用）")

		resp := getWS(t, e, monitorWSPath(observerAuditSession, ticket))
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("監看重放票狀態碼 = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
		}
	})
	t.Run("share", func(t *testing.T) {
		e := setupObserverAuditEnv(t)
		obs := e.seedObserver(t, "replay-share")
		code, _, err := e.h.Shares.Create(observerAuditSession, observerAuditOwner, time.Minute)
		if err != nil {
			t.Fatalf("建立分享碼: %v", err)
		}
		ticket := e.shareTicket(t, obs, code)

		ws := dialWS(t, e.router(), shareWSPath(code, ticket))
		waitRegistered(t, e.tap, ws, "分享訂閱（第一次使用）")

		resp := getWS(t, e, shareWSPath(code, ticket))
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("分享重放票狀態碼 = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
		}
	})
}

// --- 用途錯置 ---

// TestObserverTicketPurposeIsEnforced 分享票不得開監看、監看票不得加入分享。
// 兩種用途的准入條件不同（監看限 admin／auditor），不比對即等於讓任何登入者
// 拿分享票看遍進行中的連線
func TestObserverTicketPurposeIsEnforced(t *testing.T) {
	e := setupObserverAuditEnv(t)
	obs := e.seedObserver(t, "purpose-mixer")
	code, _, err := e.h.Shares.Create(observerAuditSession, observerAuditOwner, time.Minute)
	if err != nil {
		t.Fatalf("建立分享碼: %v", err)
	}

	shareTicket := e.shareTicket(t, obs, code)
	resp := getWS(t, e, monitorWSPath(observerAuditSession, shareTicket))
	assertRedeemDenied(t, e, resp, observerViaMonitor,
		string(proxy.RedeemDenyPurpose), "以分享票開監看")

	monitorTicket := e.monitorTicket(t, obs, model.RoleAdmin)
	resp2 := getWS(t, e, shareWSPath(code, monitorTicket))
	assertRedeemDenied(t, e, resp2, observerViaShare,
		string(proxy.RedeemDenyPurpose), "以監看票加入分享")
}

// TestTerminalConnectTokenCannotOpenObserverWS 終端連線票與觀看票是兩張不同的表：
// 拿 `/ssh` 用的票開監看或分享觀看，兌換不到任何東西
func TestTerminalConnectTokenCannotOpenObserverWS(t *testing.T) {
	e := setupObserverAuditEnv(t)
	obs := e.seedObserver(t, "terminal-ticket-holder")
	terminal, err := e.h.ConnectTokens.IssueConnectToken(t.Context(), proxy.ConnectGrant{
		UserID: obs.ID, AssetID: observerAuditAsset,
	})
	if err != nil {
		t.Fatalf("簽發終端連線票: %v", err)
	}

	resp := getWS(t, e, monitorWSPath(observerAuditSession, terminal))
	assertRedeemDenied(t, e, resp, observerViaMonitor,
		string(proxy.RedeemDenyInvalid), "以終端連線票開監看")
}

// --- 客體錯置 ---

// TestObserverTicketObjectIsEnforced 票只能開它被簽出來要開的那一個客體
func TestObserverTicketObjectIsEnforced(t *testing.T) {
	t.Run("monitor 換別的會話", func(t *testing.T) {
		e := setupObserverAuditEnv(t)
		obs := e.seedObserver(t, "object-monitor")
		ticket := e.monitorTicket(t, obs, model.RoleAdmin)

		resp := getWS(t, e, monitorWSPath(observerAuditSession+1, ticket))
		assertRedeemDenied(t, e, resp, observerViaMonitor,
			string(proxy.RedeemDenyPurpose), "監看票換別的會話")
	})
	t.Run("share 換別的分享碼", func(t *testing.T) {
		e := setupObserverAuditEnv(t)
		obs := e.seedObserver(t, "object-share")
		codeA, _, err := e.h.Shares.Create(observerAuditSession, observerAuditOwner, time.Minute)
		if err != nil {
			t.Fatalf("建立分享碼 A: %v", err)
		}
		ticket := e.shareTicket(t, obs, codeA)

		resp := getWS(t, e, shareWSPath("another-code", ticket))
		assertRedeemDenied(t, e, resp, observerViaShare,
			string(proxy.RedeemDenyPurpose), "分享票換別的碼")
	})
}

// --- 簽發端的角色限制 ---

// TestMonitorTicketRequiresAuditRole 監看是稽核職能：非 admin／auditor 不得取票，
// 且拒發時不產生任何票（否則角色閘只是延後到兌換）。
//
// **角色以 DB 現查**：JWT 帶 admin 快照但 DB 已降權者一樣拿不到票
func TestMonitorTicketRequiresAuditRole(t *testing.T) {
	e := setupObserverAuditEnv(t)
	r := e.ticketRouter()

	plain := e.seedObserver(t, "plain-user")
	clearUserRoles(t, e.db, plain.ID)
	// JWT 仍帶 admin 快照——現查為準時它不算數
	code, body := postObserverTicket(r, monitorTicketPath(observerAuditSession),
		e.token(t, plain, model.RoleAdmin))
	if code != http.StatusForbidden {
		t.Fatalf("降權者取監看票應 403，實得 %d（body=%v）", code, body)
	}
	if body["connect_token"] != nil {
		t.Fatalf("拒發仍產出票證：%v", body)
	}

	auditor := e.seedObserver(t, "auditor-user")
	clearUserRoles(t, e.db, auditor.ID)
	grantDBRole(t, e.db, auditor.ID, model.RoleAuditor)
	if tok := mustObserverTicket(t, r, monitorTicketPath(observerAuditSession),
		e.token(t, auditor, model.RoleAuditor)); tok == "" {
		t.Fatal("auditor 應取得監看票")
	}
}

// TestMonitorTicketRequiresLiveSession 監看票只對進行中的文字終端會話簽發：
// 目標不存在回 404、已結束回 400，兩者都不產票
func TestMonitorTicketRequiresLiveSession(t *testing.T) {
	e := setupObserverAuditEnv(t)
	r := e.ticketRouter()
	obs := e.seedObserver(t, "live-session-checker")

	code, body := postObserverTicket(r, monitorTicketPath(observerAuditSession+42),
		e.token(t, obs, model.RoleAdmin))
	if code != http.StatusNotFound || body["connect_token"] != nil {
		t.Fatalf("不存在的會話應 404 且不產票：code=%d body=%v", code, body)
	}

	if err := e.db.Model(&model.Session{}).Where("id = ?", observerAuditSession).
		Update("status", model.SessionStatusClosed).Error; err != nil {
		t.Fatalf("結束會話: %v", err)
	}
	code, body = postObserverTicket(r, monitorTicketPath(observerAuditSession),
		e.token(t, obs, model.RoleAdmin))
	if code != http.StatusBadRequest || body["connect_token"] != nil {
		t.Fatalf("已結束的會話應 400 且不產票：code=%d body=%v", code, body)
	}
}

// TestObserverTicketRequiresAuthenticatedIssuer 簽發端點掛認證中介層：
// 無憑證取票即 401，而 WS 端沒有任何不經票的入口
func TestObserverTicketRequiresAuthenticatedIssuer(t *testing.T) {
	e := setupObserverAuditEnv(t)
	r := e.ticketRouter()
	for _, path := range []string{
		monitorTicketPath(observerAuditSession),
		shareTicketPath,
	} {
		if code, body := postObserverTicket(r, path, ""); code != http.StatusUnauthorized {
			t.Fatalf("%s 無憑證取票應 401，實得 %d（body=%v）", path, code, body)
		}
	}
}

// TestShareTicketIssueDoesNotRecordShareCode 分享碼是短期憑證，SHALL NOT 落進長期
// 保存的審計表。
//
// **這條路徑上的風險與加入端不同**：加入端由 handler 自寫、路徑取路由樣板，碼本來
// 就進不去；簽發端掛審計中介層，而中介層以**原始路徑**留痕——碼若在路徑上就會逐字
// 入庫，且審計表受檢查點鏈保護，寫進去刪不掉。故碼走請求本體（非白名單欄，
// 中介層一律遮蔽）。
//
// 突變自檢：把簽發路由改回 `/sessions/share/:code/token` 並自 `c.Param` 取碼，本格轉紅。
func TestShareTicketIssueDoesNotRecordShareCode(t *testing.T) {
	e := setupObserverAuditEnv(t)
	obs := e.seedObserver(t, "share-code-privacy")
	code, _, err := e.h.Shares.Create(observerAuditSession, observerAuditOwner, time.Minute)
	if err != nil {
		t.Fatalf("建立分享碼: %v", err)
	}

	// 與生產同形：簽發端點掛認證＋審計兩個中介層
	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(e.h.AuditService))
	r.POST(shareTicketPath, middleware.AuthMiddleware(e.h.AuthService), e.h.HandleCreateShareTicket)
	if status, body := postObserverTicket(r, shareTicketPath,
		e.token(t, obs, model.RoleUser), shareTicketBody(code)); status != http.StatusOK {
		t.Fatalf("簽發分享票應 200，實得 %d（body=%v）", status, body)
	}

	rows := e.waitAuditRows(t, 1, "分享票簽發")
	for _, row := range rows {
		if strings.Contains(row.Path, code) || strings.Contains(row.Details, code) ||
			strings.Contains(row.RequestBody, code) {
			t.Fatalf("分享碼落入審計列（path=%q details=%q body=%q）",
				row.Path, row.Details, row.RequestBody)
		}
	}
}
