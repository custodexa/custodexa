package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/observability"
	"github.com/custodexa/backend/internal/seal"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// 守衛攔下模式的組裝根 adapter 與最小監聽。
//
// 攔下模式的形態刻意比照封印模式（sealgate.go）：DB 已連、服務未起、只開最小面，
// 其餘一律 503＋機器碼。差別只有三處：
//
//   - 面更小（四條：/health、/healthz、/api/v1/seal/status、兩條 instance-guard）；
//   - 不開 /metrics——封印期開它是為了讓「封印中」與「當機」在監控上可分辨，
//     而攔下期的可分辨性已由 /health 與 seal/status 的 instance_guard.state=halted 承擔，
//     且此時段 2 的指標註冊尚未發生，曝光面沒有對應的收益；
//   - 監聽於解除攔下後**關閉**，由 main 的正常流程重新開放同一個埠。
//
// 攔下期間 SHALL NOT 執行 migration、SHALL NOT 產生任何資料庫寫入：本檔的三個
// 資料庫接觸點（持鎖者指紋、advisory lock 重取、管理員憑證讀取）全部是唯讀。

// instanceGuardHaltProbe 攔下狀態的現讀來源（包級單例快照）。
func instanceGuardHaltProbe() api.InstanceGuardHaltView {
	snap := database.InstanceGuardSnapshot()
	v := api.InstanceGuardHaltView{
		State:                api.InstanceGuardHaltStateRunning,
		RetryIntervalSeconds: int(database.InstanceGuardRetryInterval() / time.Second),
	}
	if snap.State != database.GuardStateHalted {
		return v
	}
	v.State = api.InstanceGuardHaltStateHalted
	v.Since = rfc3339OrEmpty(snap.Since)
	if snap.Holder != nil {
		v.Holder = &api.InstanceGuardHolder{
			ApplicationName:   snap.Holder.ApplicationName,
			PID:               snap.Holder.PID,
			BackendStart:      snap.Holder.BackendStart,
			Code:              snap.Holder.Code,
			FingerprintSource: snap.Holder.Source,
		}
	}
	return v
}

// instanceGuardHaltConfirm 攔下頁確認送出的處理：憑證驗證 → 碼與當下持鎖者重比。
//
// **順序是憑證先於確認碼**：兩者皆為必要條件、失敗結果對呼叫者可分辨（處置不同），
// 但先驗憑證使未經授權的呼叫者拿不到「這個碼對不對」這個訊號——攔下端點未認證，
// 碼先驗等於對外提供一台確認碼的線上校驗機。
//
// **憑證驗證沿用初始化解封的同一個驗證器**：唯讀、只依賴 users 的既有欄位
// （username／password／active／is_ldap 等），不觸碰任何受 KEK 保護的欄位，
// 也不寫回任何欄位。讀取失敗（schema 不相容或連線問題）與「憑證不符」嚴格區分：
// 前者回 users_unavailable 指向環境變數路徑，**不以憑證錯誤頂替未知狀態**。
func instanceGuardHaltConfirm(db *gorm.DB, req api.InstanceGuardAckRequest) api.InstanceGuardAckResult {
	if err := identity.VerifyInitialAdminCredential(db, req.Username, []byte(req.Password)); err != nil {
		if errors.Is(err, identity.ErrSealInitialAdminInvalid) {
			database.NoteInstanceGuardHaltCredentialFailure()
			return api.InstanceGuardAckResult{Outcome: api.AckOutcomeInvalidCredential}
		}
		log.Printf("[InstanceGuard] 攔下頁確認：讀取使用者表失敗，無法在此驗證管理員憑證（請改用環境變數路徑）: %v", err)
		return api.InstanceGuardAckResult{Outcome: api.AckOutcomeUsersUnavailable}
	}

	res := database.ConfirmInstanceGuardHalt(context.Background(), req.Code, req.Username)
	out := api.InstanceGuardAckResult{}
	if res.Holder != nil {
		out.Holder = &api.InstanceGuardHolder{
			ApplicationName:   res.Holder.ApplicationName,
			PID:               res.Holder.PID,
			BackendStart:      res.Holder.BackendStart,
			Code:              res.Holder.Code,
			FingerprintSource: res.Holder.Source,
		}
	}
	switch res.Outcome {
	case database.HaltConfirmAccepted:
		out.Outcome = api.AckOutcomeAccepted
	case database.HaltConfirmHolderChanged:
		out.Outcome = api.AckOutcomeHolderChanged
	case database.HaltConfirmUnavailable:
		// 釘選連線建不起來：這一刻判定不了，不是「已經不必確認了」。
		// 沿用既有的 INSTANCE_GUARD_ACK_UNAVAILABLE（503）——機器碼集合不變，
		// 且它的語義本來就是「此路徑暫時判定不了，可改用環境變數路徑」。
		log.Println("[InstanceGuard] 攔下頁確認：守衛的釘選連線暫時不可用，本次無法判定（503；重建仍在每週期重試）")
		out.Outcome = api.AckOutcomeUsersUnavailable
	default:
		out.Outcome = api.AckOutcomeNotHalted
	}
	return out
}

// haltNoopJournal 是攔下模式下 seal.Machine 的 journal 占位。
//
// **它永遠不會被寫入**：攔下模式的 router 只註冊 /seal/status，不註冊
// /seal/unseal，故狀態機的解封路徑（唯一的 journal 寫入者）不可達。
// 建一台真的狀態機而不是另寫一份狀態回應，是為了讓攔下期的 /seal/status
// 與封印期回同一個形狀——兩份形狀分開漂移，前端就得寫兩套判斷。
type haltNoopJournal struct{}

func (haltNoopJournal) WriteReceived(context.Context, uint64, string) (uint64, error) {
	return 0, errors.New("攔下模式不受理解封")
}
func (haltNoopJournal) WriteOutcome(context.Context, uint64, uint64, string) error {
	return errors.New("攔下模式不受理解封")
}
func (haltNoopJournal) WritePublished(context.Context, uint64, uint64) error {
	return errors.New("攔下模式不受理解封")
}
func (haltNoopJournal) RecordRejected(string) {}
func (haltNoopJournal) Close() error          { return nil }

// newHaltedSealHandler 建攔下模式的 /seal/status 來源：狀態恆 sealed
// （服務未起、任何業務路由皆不可達），instance_guard 欄回 halted。
func newHaltedSealHandler(cfg *config.Config) (*api.SealHandler, error) {
	m, err := seal.New(seal.Config{
		Journal: haltNoopJournal{},
		Verify: func(context.Context, []byte) (seal.VerifiedMaterial, error) {
			var zero seal.VerifiedMaterial
			return zero, errors.New("攔下模式不受理解封")
		},
		Stage2: func(context.Context, seal.VerifiedMaterial) (seal.ServiceGraph, error) {
			return nil, errors.New("攔下模式不受理解封")
		},
	})
	if err != nil {
		return nil, err
	}
	h := api.NewSealHandler(m, nil)
	allowed, err := cfg.Seal.ParseAllowedCIDRs()
	if err != nil {
		return nil, err
	}
	h.SetSourceControls(cfg.Seal.TrustedProxyConfigured(), allowed, "")
	h.SetInstanceGuardProbe(instanceGuardStatusProbe)
	return h, nil
}

// serveHaltedUntilResumed 開放攔下頁所需的最小監聽，直到攔下解除才返回。
//
// 兩條解除路徑（watchdog 取得鎖、攔下頁確認相符）共用 database 的 resume 訊號。
// 返回前 Shutdown 本監聽並等待進行中的請求收尾——確認送出的那一個回應必須
// 送得出去，否則操作者只會看到連線中斷，不知道自己成功了沒有。
//
// 建不出 router 或繫結不了埠時 fail-close：攔下模式的價值全在那個頁面，
// 開不出來就退回既有行為（印攔下訊息後結束行程，由 supervisor 重啟）。
func serveHaltedUntilResumed(cfg *config.Config) {
	r, err := buildHaltedEngine(cfg)
	if err != nil {
		log.Fatalf("建立守衛攔下模式 router 失敗（無法提供攔下頁）: %v", err)
	}
	srv := &http.Server{Addr: ":" + cfg.Server.Port, Handler: r}
	listeners, err := openListeners(srv)
	if err != nil {
		log.Fatalf("守衛攔下模式開放監聽失敗: %v", err)
	}
	serveAll(listeners)
	log.Printf("[InstanceGuard] 攔下模式：守衛攔下頁已於 :%s 開放（只有健康檢查、封印狀態與攔下確認；"+
		"未執行 migration、未產生任何資料庫寫入）。鎖被釋放時本實例會自動接手，無需重啟。",
		cfg.Server.Port)

	<-database.InstanceGuardResume()

	ctx, cancel := context.WithTimeout(context.Background(), listenerShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("[InstanceGuard] 攔下模式監聽收束未於預算內完成（繼續啟動）: %v", err)
	}
	log.Println("[InstanceGuard] 攔下已解除：繼續執行段 1 其餘步驟與段 2（同一行程，不需重啟）")
}

// buildHaltedEngine 組出攔下模式的最小 router。
//
// 指標實例是本模式專屬的一份、且 /metrics 未註冊：攔下期不曝光指標
// （見本檔開頭），故此實例的計數無採集者，不存在「換 router 使 counter 歸零」
// 被讀成行程重啟的問題——那條顧慮的前提是同一份計數被同一個採集端讀過兩次。
func buildHaltedEngine(cfg *config.Config) (*gin.Engine, error) {
	r := middleware.NewEngineWithAccessLog()
	// 與封印期同一理由：尾斜線／路徑修正的自動 redirect 發生在中間件鏈之前，
	// 會成為一個路由存在性 oracle，把閘刻意抹平的區別重新洩漏出來。
	r.RedirectTrailingSlash = false
	r.RedirectFixedPath = false
	if proxies := cfg.Seal.TrustedProxies; len(proxies) > 0 {
		if err := r.SetTrustedProxies(proxies); err != nil {
			return nil, err
		}
	}
	sealHandler, err := newHaltedSealHandler(cfg)
	if err != nil {
		return nil, err
	}
	allowed, err := cfg.Seal.ParseAllowedCIDRs()
	if err != nil {
		return nil, err
	}
	haltHandler := api.NewInstanceGuardHaltHandler(instanceGuardHaltProbe, func(req api.InstanceGuardAckRequest) api.InstanceGuardAckResult {
		return instanceGuardHaltConfirm(database.DB, req)
	})
	haltHandler.SetSourceControls(cfg.Seal.TrustedProxyConfigured(), allowed)

	registerRoutes(r, routeDeps{
		haltOnly: true,
		// 閘：攔下白名單以外一律 503＋機器碼（含未匹配任何路由者），
		// 與封印期同一語義——不對外透露路由是否存在。
		sealGate:          haltGateMiddleware(),
		corsMiddleware:    cors.New(buildCORSConfig(cfg.Server.CORSAllowedOrigins, cfg.IsReleaseMode())),
		metrics:           observability.New(),
		seal:              sealHandler,
		instanceGuardHalt: haltHandler,
	})
	return r, nil
}
