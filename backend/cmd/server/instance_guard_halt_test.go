package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	pgdriver "gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/observability"
	"github.com/custodexa/backend/internal/testgate"
	"github.com/custodexa/backend/pkg/crypto"
)

// 守衛攔下模式的組裝根測試。
//
//   - TestInstanceGuardHaltedMode（pg-gated）：A 持鎖、B 停在攔下模式，
//     B 啟動前後資料表數、索引數與 `schema_migrations` 列數完全相同，
//     行程仍存活（守衛物件仍在、watchdog 仍重取），攔下端點可達。
//   - 確認送出的憑證閘：帳密錯即拒絕且不觸及守衛狀態；使用者表讀不到即
//     回 users_unavailable（指向環境變數路徑），**不以憑證錯誤頂替未知狀態**。

const haltAdminPassword = "halt-admin-pw-2026"

// installHaltAdminDB 建一個只有 users／roles 的 sqlite 庫，內含一個具 admin 角色的本地帳號。
func installHaltAdminDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("開 sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserRole{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	hashed, err := crypto.DefaultPasswordHasher().Hash([]byte(haltAdminPassword))
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	email := "halt-admin@example.invalid"
	u := model.User{Username: "halt-admin", Email: &email, Password: hashed, Active: true,
		Roles: []model.Role{{Name: model.RoleAdmin}}}
	if err := db.Create(&u).Error; err != nil {
		t.Fatalf("建管理員: %v", err)
	}
	return db
}

// installHaltGuard 讓包級單例停在攔下模式，回傳當下持鎖者的確認碼。
func installHaltGuard(t *testing.T) string {
	t.Helper()
	lockDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("開鎖用 sqlite: %v", err)
	}
	holder := database.NewInstanceGuard(lockDB, database.InstanceGuardOptions{
		RetryInterval: time.Millisecond, RetryAttempts: 2})
	if err := holder.Acquire(context.Background()); err != nil {
		t.Fatalf("持鎖者取鎖失敗: %v", err)
	}
	t.Cleanup(holder.Stop)

	halted, _ := database.AcquireInstanceLockOrHalt(context.Background(), lockDB,
		database.InstanceGuardOptions{RetryInterval: time.Millisecond, RetryAttempts: 2})
	if !halted {
		t.Fatal("前置條件不成立：第二實例未進入攔下模式")
	}
	snap := database.InstanceGuardSnapshot()
	if snap.State != database.GuardStateHalted || snap.Holder == nil {
		t.Fatalf("包級單例未停在攔下模式：%+v", snap)
	}
	return snap.Holder.Code
}

// TestInstanceGuardHaltConfirmRejectsBadCredential 帳密錯即拒絕，且不觸及守衛狀態。
//
// **憑證閘先於確認碼比對**：故此格即使帶著正確的碼也必須被拒，
// 且守衛仍停在攔下模式（沒有任何 overridden 發生）。
func TestInstanceGuardHaltConfirmRejectsBadCredential(t *testing.T) {
	db := installHaltAdminDB(t)
	code := installHaltGuard(t)

	res := instanceGuardHaltConfirm(db, api.InstanceGuardAckRequest{
		ConfirmedPrimaryDown: true, Code: code, Username: "halt-admin", Password: "wrong"})
	if res.Outcome != api.AckOutcomeInvalidCredential {
		t.Fatalf("帳密錯 MUST 拒絕，實得 %s", res.Outcome)
	}
	if st := database.InstanceGuardSnapshot().State; st != database.GuardStateHalted {
		t.Fatalf("被拒的確認不得改變守衛狀態，實得 %s", st)
	}

	// 非 admin／不存在的帳號同樣被拒（不區分成因是刻意的：未認證端點不得成為帳號列舉機）
	res = instanceGuardHaltConfirm(db, api.InstanceGuardAckRequest{
		ConfirmedPrimaryDown: true, Code: code, Username: "nobody", Password: haltAdminPassword})
	if res.Outcome != api.AckOutcomeInvalidCredential {
		t.Fatalf("不存在的帳號 MUST 拒絕，實得 %s", res.Outcome)
	}
}

// TestInstanceGuardHaltConfirmAcceptsAdminAndMatchingCode 帳密對且碼與當下持鎖者相符：接受並記真實帳號。
func TestInstanceGuardHaltConfirmAcceptsAdminAndMatchingCode(t *testing.T) {
	db := installHaltAdminDB(t)
	code := installHaltGuard(t)

	res := instanceGuardHaltConfirm(db, api.InstanceGuardAckRequest{
		ConfirmedPrimaryDown: true, Code: code, Username: "halt-admin", Password: haltAdminPassword})
	if res.Outcome != api.AckOutcomeAccepted {
		t.Fatalf("三要件相符 MUST 接受，實得 %s", res.Outcome)
	}
	snap := database.InstanceGuardSnapshot()
	if snap.State != database.GuardStateOverridden {
		t.Fatalf("接受後應轉 overridden，實得 %s", snap.State)
	}
	if snap.Actor != "halt-admin" || snap.ActorSource != database.GuardActorSourcePage {
		t.Fatalf("確認者應為通過驗證的管理員帳號、來源 page：%+v", snap)
	}
}

// TestInstanceGuardHaltConfirmRejectsStaleCode 帳密對但碼不符：回持鎖者已變更並附新指紋。
func TestInstanceGuardHaltConfirmRejectsStaleCode(t *testing.T) {
	db := installHaltAdminDB(t)
	code := installHaltGuard(t)

	res := instanceGuardHaltConfirm(db, api.InstanceGuardAckRequest{
		ConfirmedPrimaryDown: true, Code: "000000000000", Username: "halt-admin", Password: haltAdminPassword})
	if res.Outcome != api.AckOutcomeHolderChanged {
		t.Fatalf("碼不符 MUST 回 holder_changed，實得 %s", res.Outcome)
	}
	if res.Holder == nil || res.Holder.Code != code {
		t.Fatalf("MUST 回當下持鎖者的新確認碼，實得 %+v", res.Holder)
	}
	if st := database.InstanceGuardSnapshot().State; st != database.GuardStateHalted {
		t.Fatalf("被拒的確認不得改變守衛狀態，實得 %s", st)
	}
}

// TestInstanceGuardHaltConfirmUsersTableUnavailable 讀不到使用者表時不猜：
// 回 users_unavailable（頁面據此指向環境變數路徑），而不是「憑證錯誤」。
func TestInstanceGuardHaltConfirmUsersTableUnavailable(t *testing.T) {
	// 刻意不 AutoMigrate：schema 與本版本不相容的等價情境
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("開 sqlite: %v", err)
	}
	code := installHaltGuard(t)

	res := instanceGuardHaltConfirm(db, api.InstanceGuardAckRequest{
		ConfirmedPrimaryDown: true, Code: code, Username: "halt-admin", Password: haltAdminPassword})
	if res.Outcome != api.AckOutcomeUsersUnavailable {
		t.Fatalf("使用者表讀取失敗 MUST 回 users_unavailable（不得以憑證錯誤頂替未知狀態），實得 %s", res.Outcome)
	}
	if st := database.InstanceGuardSnapshot().State; st != database.GuardStateHalted {
		t.Fatalf("讀取失敗不得改變守衛狀態，實得 %s", st)
	}
}

// TestInstanceGuardHaltProbeExposesHolderOnlyWhileHalted 攔下探針只在攔下期揭露持鎖者。
func TestInstanceGuardHaltProbeExposesHolderOnlyWhileHalted(t *testing.T) {
	code := installHaltGuard(t)
	v := instanceGuardHaltProbe()
	if v.State != api.InstanceGuardHaltStateHalted || v.Holder == nil || v.Holder.Code != code {
		t.Fatalf("攔下期探針應帶持鎖者指紋：%+v", v)
	}
	if v.RetryIntervalSeconds <= 0 {
		t.Fatalf("探針應帶重取週期（頁面要說明多久自動接手），實得 %d", v.RetryIntervalSeconds)
	}
}

// ── pg-gated：攔下模式的零寫入與可達性 ─────────────────────────────────────

// TestInstanceGuardHaltedMode 真 postgres 上的攔下模式。
//
// A 以釘選連線持有 advisory lock，B 對同一個 database 啟動守衛：
// B MUST 進入攔下模式（不退出、保留連線、每週期重取），且 B 進入前後
// **資料表數、索引數與 `schema_migrations` 列數完全相同**——攔下模式的核心承諾
// 就是「本實例未動過這個資料庫」。最小 router 於此同時驗可達性：
// 攔下端點回 200＋持鎖者指紋，白名單外一律 503。
//
// DSN SHALL 指向 postgres 維護庫，理由同 instance_guard_pg_test.go 的檔頭。
func TestInstanceGuardHaltedMode(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	open := func() *gorm.DB {
		db, err := gorm.Open(pgdriver.Open(dsn), &gorm.Config{Logger: logger.Discard})
		if err != nil {
			t.Fatalf("postgres 連線失敗（TEST_PG_DSN 是否正確？）: %v", err)
		}
		t.Cleanup(func() {
			if sqlDB, err := db.DB(); err == nil {
				_ = sqlDB.Close()
			}
		})
		return db
	}
	dbA, dbB := open(), open()

	// schema_migrations 不存在於維護庫時以 -1 表示「不存在」——
	// 前後都必須是同一個值，「表被建出來」與「列數改變」都會轉紅。
	schemaSnapshot := func(db *gorm.DB) [3]int64 {
		var tables, indexes, rows int64
		if err := db.Raw(`SELECT count(*) FROM information_schema.tables WHERE table_schema='public'`).Scan(&tables).Error; err != nil {
			t.Fatalf("查表數失敗: %v", err)
		}
		if err := db.Raw(`SELECT count(*) FROM pg_indexes WHERE schemaname='public'`).Scan(&indexes).Error; err != nil {
			t.Fatalf("查索引數失敗: %v", err)
		}
		rows = -1
		var exists bool
		if err := db.Raw(`SELECT to_regclass('public.schema_migrations') IS NOT NULL`).Scan(&exists).Error; err != nil {
			t.Fatalf("查 schema_migrations 是否存在失敗: %v", err)
		}
		if exists {
			if err := db.Raw(`SELECT count(*) FROM public.schema_migrations`).Scan(&rows).Error; err != nil {
				t.Fatalf("查 schema_migrations 列數失敗: %v", err)
			}
		}
		return [3]int64{tables, indexes, rows}
	}

	before := schemaSnapshot(dbA)

	guardA := database.NewInstanceGuard(dbA, database.InstanceGuardOptions{
		WatchPeriod: time.Hour, RetryInterval: 50 * time.Millisecond, RetryAttempts: 2})
	if err := guardA.Acquire(context.Background()); err != nil {
		t.Fatalf("A 取鎖失敗: %v", err)
	}
	t.Cleanup(guardA.Stop)
	if guardA.State() != database.GuardStateHeld {
		t.Fatalf("前置條件不成立：A 的狀態 = %s", guardA.State())
	}

	guardB := database.NewInstanceGuard(dbB, database.InstanceGuardOptions{
		WatchPeriod: time.Hour, RetryInterval: 50 * time.Millisecond, RetryAttempts: 2})
	halted, blockErr := guardB.AcquireOrHalt(context.Background())
	if !halted {
		t.Fatalf("B MUST 進入攔下模式，實得 halted=%v err=%v", halted, blockErr)
	}
	t.Cleanup(guardB.Stop)

	if after := schemaSnapshot(dbA); after != before {
		t.Fatalf("攔下模式 MUST NOT 產生任何 schema 變更：前 %v 後 %v（表數／索引數／schema_migrations 列數）",
			before, after)
	}

	// 行程仍存活的可觀察代理：守衛物件仍在攔下態、釘選連線仍在（快照帶得出持鎖者），
	// 且再跑一輪 watchdog 仍是 halted（鎖仍被 A 持有）。
	snap := guardB.Snapshot()
	if snap.State != database.GuardStateHalted {
		t.Fatalf("B 應停在 halted，實得 %s", snap.State)
	}
	if snap.Holder == nil || snap.Holder.Code == "" || snap.Holder.Source != database.FingerprintSourcePGStatActivity {
		t.Fatalf("攔下狀態應帶自 pg_stat_activity 取得的持鎖者指紋：%+v", snap.Holder)
	}
	if st := guardB.CheckNow(context.Background()); st != database.GuardStateHalted {
		t.Fatalf("鎖仍被持有時 B 應維持 halted（不退出、下一週期再試），實得 %s", st)
	}

	// 攔下頁的最小面：兩條端點可達，白名單外一律 503。
	r := newHaltTestRouter(func() api.InstanceGuardHaltView {
		return api.InstanceGuardHaltView{
			State: api.InstanceGuardHaltStateHalted,
			Holder: &api.InstanceGuardHolder{
				Code: snap.Holder.Code, ApplicationName: snap.Holder.ApplicationName,
				PID: snap.Holder.PID, BackendStart: snap.Holder.BackendStart,
				FingerprintSource: snap.Holder.Source},
			RetryIntervalSeconds: 15,
		}
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/instance-guard/halt", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("攔下端點應可達，實得 %d", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("回應非 JSON: %s", w.Body.String())
	}
	holder, ok := body["holder"].(map[string]any)
	if body["state"] != "halted" || !ok || holder["code"] != snap.Holder.Code {
		t.Fatalf("攔下端點應回持鎖者指紋與確認碼：%v", body)
	}
	for _, path := range []string{"/api/v1/assets", "/api/v1/auth/login", "/api/v1/seal/unseal", "/api/v1/nope"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("攔下白名單外的 %s 應回 503，實得 %d", path, w.Code)
		}
	}

	// A 釋放 → B 於一輪內取得鎖並放行啟動，且不寫 overridden。
	guardA.Stop()
	if st := guardB.CheckNow(context.Background()); st != database.GuardStateHeld {
		t.Fatalf("A 釋放後 B 應自動取得鎖（不需重啟），實得 %s", st)
	}
	select {
	case <-guardB.Resume():
	case <-time.After(2 * time.Second):
		t.Fatal("取得鎖後 MUST 放行啟動（resume 訊號未送達）")
	}
	if after := schemaSnapshot(dbA); after != before {
		t.Fatalf("整段攔下期 MUST NOT 產生任何 schema 變更：前 %v 後 %v", before, after)
	}
}

// newHaltTestRouter 以攔下模式的閘與最小路由面建 router（不需 config）。
func newHaltTestRouter(probe api.InstanceGuardHaltProbe) *gin.Engine {
	h := api.NewInstanceGuardHaltHandler(probe, func(api.InstanceGuardAckRequest) api.InstanceGuardAckResult {
		return api.InstanceGuardAckResult{Outcome: api.AckOutcomeNotHalted}
	})
	r := gin.New()
	r.RedirectTrailingSlash = false
	r.RedirectFixedPath = false
	registerRoutes(r, routeDeps{
		haltOnly:          true,
		sealGate:          haltGateMiddleware(),
		corsMiddleware:    cors.New(buildCORSConfig(nil, false)),
		metrics:           observability.New(),
		seal:              &api.SealHandler{},
		instanceGuardHalt: h,
	})
	return r
}

// TestHaltOnlyRoutesAreStrictSubset 攔下模式的路由面是完整路由表的真子集。
//
// 這是 `haltOnly` 得以豁免旗標矩陣的機器前提（api_index_parser_test.go 的
// `subtractive`）：攔下 router 若引入一條完整路由表沒有的端點，那條端點
// 不會進入 API 索引，也不會進入路由 golden 與審計分類——三道守衛同時瞎掉。
func TestHaltOnlyRoutesAreStrictSubset(t *testing.T) {
	full, _ := buildRouter(t, gin.TestMode, true)

	haltOnly := map[[2]string]bool{}
	for _, rt := range newHaltTestRouter(func() api.InstanceGuardHaltView {
		return api.InstanceGuardHaltView{State: api.InstanceGuardHaltStateHalted}
	}).Routes() {
		haltOnly[[2]string{rt.Method, rt.Path}] = true
	}
	if len(haltOnly) == 0 {
		t.Fatal("攔下 router 沒有任何路由——本測試的前提不成立")
	}
	if len(haltOnly) >= len(full) {
		t.Fatalf("攔下 router 有 %d 條路由、完整路由表有 %d 條——已不是真子集，旗標矩陣的豁免前提消失",
			len(haltOnly), len(full))
	}
	for k := range haltOnly {
		if _, ok := full[k]; !ok {
			t.Errorf("攔下 router 引入了完整路由表沒有的 %s %s——該端點不會進入索引", k[0], k[1])
		}
	}
}

// TestHaltOnlyBusinessRoutesReturn503 攔下期業務路由一律 503（**不需 postgres**）。
//
// 同一條斷言原本只寫在 pg-gated 的 TestInstanceGuardHaltedMode 裡，無 DSN 時整支被
// SKIP——而它是本模式最有價值的一條安全斷言（攔下期業務面不可達），卻也是最容易
// 靜默失效的一條（gated 測試的 skip 不算驗過，見 docs/dev/testing.md §5 第 13 條）。
// 這裡只用 httptest ＋ newHaltTestRouter，故整包 `go test ./cmd/server` 必定跑到。
func TestHaltOnlyBusinessRoutesReturn503(t *testing.T) {
	r := newHaltTestRouter(func() api.InstanceGuardHaltView {
		return api.InstanceGuardHaltView{
			State:                api.InstanceGuardHaltStateHalted,
			Holder:               &api.InstanceGuardHolder{Code: "abc123abc123"},
			RetryIntervalSeconds: 15,
		}
	})

	// 正向對照：白名單內的攔下端點可達。缺了它，「router 根本沒建起來」
	// 也會讓下面全部 503 的斷言成立。
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/instance-guard/halt", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("前提不成立：攔下端點應可達，實得 %d", w.Code)
	}

	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/auth/login"},
		{http.MethodGet, "/api/v1/auth/login"},
		{http.MethodGet, "/api/v1/assets"},
		{http.MethodPost, "/api/v1/assets"},
		{http.MethodGet, "/api/v1/users"},
		{http.MethodPost, "/api/v1/users"},
		{http.MethodPost, "/api/v1/seal/unseal"},
		{http.MethodGet, "/api/v1/nope"},
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("攔下期 %s %s 應回 503，實得 %d（body=%s）",
				tc.method, tc.path, w.Code, w.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s %s 的回應非 JSON: %s", tc.method, tc.path, w.Body.String())
		}
		if body["code"] != "SEAL_SERVICE_SEALED" {
			t.Fatalf("%s %s 的機器碼 = %v，want SEAL_SERVICE_SEALED", tc.method, tc.path, body["code"])
		}
	}
}
