package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/modules/session"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 資料傳輸閘的角色×動作×政策矩陣（data-transfer-control tasks 4.5）。
//
// 三條不變式由本檔釘死：
//  1. **admin 不豁免**——全域禁止下 admin 與一般 user 同樣被 403 擋。
//     `requireTransferAllowed` 與 `EffectiveTransfer` 內都不得出現 role 分支。
//  2. **list 恆通**——列目錄不是資料傳輸，兩種政策值下都不進傳輸閘
//     （列目錄與 stat 不搬運內容，不屬資料傳輸動作）。
//  3. **授權不足 ≠ 傳輸被拒**——未授權者（此處為 auditor，CheckPermission 對
//     connect 不為其短路）得到 404／`NOTFOUND_ASSET`（不洩漏資產存在性），
//     傳輸閘拒絕得到 403／`RULE_TRANSFER_DENIED`。兩者是不同狀態不同碼，
//     測試**不得**寫成「非 200 即算擋住」——那會讓「閘失效但授權剛好擋住」
//     的回歸偽裝成通過。
//
// 「通過閘」如何斷言：本包不建真 SSH／SFTP 靶機，資產帳號亦無憑證，故通過閘後
// 必然落在資料面的 `connect` 失敗上，回 502＋**該動作專屬**的錯誤碼
// （`INTERNAL_SFTP_{LIST,DOWNLOAD,UPLOAD,MKDIR,DELETE}_FAILED`，由
// `TestSFTPHandlersUseDistinctActionCodes` 保證兩兩相異）。
// 收到動作專屬的 502 即證明「閘已放行且確實是該 handler 在跑」——
// 這比斷言 200 更能分辨是哪一格通過。真 200（實際傳完檔）需要活的 SSH 靶機，
// 屬 e2e_smoke 的守備範圍，見檔尾 note。

// transferMatrixRole 矩陣的角色維度。
// role 欄是**寫進 gin context 的 JWT 快照**；實際判定以 DB 現查角色為準
// （`CurrentConnectRole`），此處兩者刻意一致，以免與角色重判測試混淆語義。
type transferMatrixRole struct {
	name           string
	userID         uint
	jwtRole        string
	wantDenyBySeat bool // true＝連線授權不足，永遠停在 404，走不到傳輸閘
}

// transferMatrixAction 矩陣的動作維度。五個端點的請求形態各異
// （query／multipart／JSON），故各自帶請求建構器。
type transferMatrixAction struct {
	name string
	// gated 是否受傳輸閘判定。list=false（不變式 2）
	gated bool
	// gateAction 被拒時 envelope 回報的傳輸 action（mkdir 刻意判 file_upload）
	gateAction string
	// method/route gin 路由掛法
	method string
	route  string
	// newRequest 每次呼叫都要建新的（multipart body 只能讀一次）
	newRequest func() *http.Request
	// handle 對應的 handler 方法
	handle func(h *SFTPHandler, c *gin.Context)
	// dataPlaneCode 通過閘後落在資料面失敗時的動作專屬碼
	dataPlaneCode apierror.ErrCode
}

func transferMatrixActions() []transferMatrixAction {
	return []transferMatrixAction{
		{
			name: "upload", gated: true, gateAction: policy.TransferActionFileUpload,
			method: "POST", route: "/assets/:id/files/upload",
			newRequest:    newUploadRequest,
			handle:        func(h *SFTPHandler, c *gin.Context) { h.Upload(c) },
			dataPlaneCode: apierror.CodeInternalSFTPUploadFailed,
		},
		{
			name: "download", gated: true, gateAction: policy.TransferActionFileDownload,
			method: "GET", route: "/assets/:id/files/download",
			newRequest: func() *http.Request {
				return httptest.NewRequest("GET", "/assets/1/files/download?path=/tmp/payload.txt", nil)
			},
			handle:        func(h *SFTPHandler, c *gin.Context) { h.Download(c) },
			dataPlaneCode: apierror.CodeInternalSFTPDownloadFailed,
		},
		{
			name: "delete", gated: true, gateAction: policy.TransferActionFileDelete,
			method: "DELETE", route: "/assets/:id/files",
			newRequest: func() *http.Request {
				return httptest.NewRequest("DELETE", "/assets/1/files?path=/tmp/payload.txt", nil)
			},
			handle:        func(h *SFTPHandler, c *gin.Context) { h.Delete(c) },
			dataPlaneCode: apierror.CodeInternalSFTPDeleteFailed,
		},
		{
			// mkdir 判 file_upload 鍵（D3 註 2：對遠端檔案系統的寫入），
			// 但審計仍記 file_mkdir——判定粒度與留痕粒度刻意分離。
			// 本矩陣只驗 HTTP 狀態＋錯誤碼，**分離本身由
			// TestDeniedMkdirAuditsAsMkdir 釘住**（該不變式先前只存在於註解）
			name: "mkdir", gated: true, gateAction: policy.TransferActionFileUpload,
			method: "POST", route: "/assets/:id/files/mkdir",
			newRequest: func() *http.Request {
				req := httptest.NewRequest("POST", "/assets/1/files/mkdir",
					bytes.NewBufferString(`{"path":"/tmp/newdir"}`))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
			handle:        func(h *SFTPHandler, c *gin.Context) { h.Mkdir(c) },
			dataPlaneCode: apierror.CodeInternalSFTPMkdirFailed,
		},
		{
			name: "list", gated: false, method: "GET", route: "/assets/:id/files",
			newRequest: func() *http.Request {
				return httptest.NewRequest("GET", "/assets/1/files?path=/tmp", nil)
			},
			handle:        func(h *SFTPHandler, c *gin.Context) { h.List(c) },
			dataPlaneCode: apierror.CodeInternalSFTPListFailed,
		},
	}
}

// newUploadRequest 建 multipart 上傳請求（path + file）。
// 注意 Upload handler 先解 multipart 再過傳輸閘，故被拒的格子同樣要送合法的 body，
// 否則會停在 400 而根本測不到閘
func newUploadRequest() *http.Request {
	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	if err := mw.WriteField("path", "/tmp"); err != nil {
		panic(err)
	}
	fw, err := mw.CreateFormFile("file", "payload.txt")
	if err != nil {
		panic(err)
	}
	if _, err := fw.Write([]byte("matrix-payload")); err != nil {
		panic(err)
	}
	if err := mw.Close(); err != nil {
		panic(err)
	}
	req := httptest.NewRequest("POST", "/assets/1/files/upload", body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

// setupTransferMatrixEnv 建矩陣環境。globalAllow 決定三支檔案政策鍵的全域值。
//
// 三個使用者：1=admin（掛 admin 角色）、2=user（無角色→折疊為 user，持 @ALL
// connect 授權）、3=auditor（掛 auditor 角色，**不給任何授權**）。
// auditor 之所以停在 404 而非 403，是因為 CheckPermission 對 connect 不為
// auditor 短路（CPG-002 職責分離），落正常授權查詢後查無授權
func setupTransferMatrixEnv(t *testing.T, globalAllow bool) (*SFTPHandler, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql db: %v", err)
	}
	sqlDB.SetMaxOpenConns(1) // :memory: 多連線＝多個獨立空庫（ff51836 教訓）
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserGroup{}, &model.Asset{},
		&model.AssetGroup{}, &model.AssetNode{}, &model.AssetAccount{}, &model.AssetAuthorization{},
		&model.ApproverScope{}, &model.Session{}, &model.AuditLog{}, &model.SecurityPolicy{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	adminRole := model.Role{Name: model.RoleAdmin}
	auditorRole := model.Role{Name: model.RoleAuditor}
	if err := db.Create(&adminRole).Error; err != nil {
		t.Fatalf("seed admin role: %v", err)
	}
	if err := db.Create(&auditorRole).Error; err != nil {
		t.Fatalf("seed auditor role: %v", err)
	}
	if err := db.Create(&model.User{Username: "admin1", Email: emailPtr("admin@x"), Active: true,
		Roles: []model.Role{adminRole}}).Error; err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	if err := db.Create(&model.User{Username: "user1", Email: emailPtr("user@x"), Active: true}).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := db.Create(&model.User{Username: "auditor1", Email: emailPtr("auditor@x"), Active: true,
		Roles: []model.Role{auditorRole}}).Error; err != nil {
		t.Fatalf("seed auditor: %v", err)
	}

	if err := db.Create(&model.Asset{Name: "a1", Protocol: model.ProtocolSSH, Host: "h", Port: 22,
		CreatedBy: 1, Active: true}).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	if err := db.Create(&model.AssetAccount{AssetID: 1, Username: "root", IsDefault: true}).Error; err != nil {
		t.Fatalf("seed account: %v", err)
	}
	uid, aid := uint(2), uint(1)
	if err := db.Create(&model.AssetAuthorization{
		UserID: &uid, AssetID: &aid, Permission: model.PermissionConnect, GrantedBy: 1,
		Accounts: model.AccountScope{model.AccountScopeAll},
	}).Error; err != nil {
		t.Fatalf("seed grant: %v", err)
	}

	policies := policy.NewSecurityPolicyService(db)
	if !globalAllow {
		if _, err := policies.UpdateBatch(map[string]string{
			policy.PolicyFileUploadEnabled:   "false",
			policy.PolicyFileDownloadEnabled: "false",
			policy.PolicyFileDeleteEnabled:   "false",
		}, "matrix-test"); err != nil {
			t.Fatalf("關閉檔案政策鍵失敗: %v", err)
		}
	}
	// 前置自檢：政策層真的處於預期狀態才有資格談閘的行為。
	// 少了這段，出廠預設哪天翻面就會讓「全域允許」那一半靜默變成測禁止
	for _, key := range []string{policy.PolicyFileUploadEnabled,
		policy.PolicyFileDownloadEnabled, policy.PolicyFileDeleteEnabled} {
		if got := policies.GetBool(key); got != globalAllow {
			t.Fatalf("政策前置條件不符: %s=%v，預期 %v", key, got, globalAllow)
		}
	}

	// 同步審計（AsyncAuditEnabled=false）：拒絕留痕須在請求返回時已落庫，
	// 否則斷言會與 worker 競態
	auditSvc := audit.NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true})

	assetSvc, err := asset.NewAssetService(aesColumnCodec(t, make([]byte, 32)), "localhost", 4822, audit.NewTxSink())
	if err != nil {
		t.Fatalf("asset service: %v", err)
	}
	handler := NewSFTPHandler(
		session.NewSFTPService(assetSvc, asset.NewHostKeyService(db)),
		authz.NewAssetAuthorizationService(db), auditSvc, newSFTPTestAuthService(t, db))
	handler.SetDataTransfer(policy.NewDataTransferService(policies))
	return handler, db
}

// callTransferEndpoint 以指定身分打某個檔案端點
func callTransferEndpoint(h *SFTPHandler, act transferMatrixAction, userID uint, jwtRole string) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Handle(act.method, act.route, func(c *gin.Context) {
		c.Set("userID", userID)
		c.Set("role", jwtRole)
		act.handle(h, c)
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, act.newRequest())
	return w
}

// transferCell 一格的實測結果
type transferCell struct {
	status int
	code   string
	// params 統一錯誤 envelope 的 `params` 欄（CodeTransferDenied 以此帶
	// action／reason 兩個機器欄）
	params map[string]any
}

// readTransferCell 解析回應為 (狀態碼, 機器碼, params)。五個動作在本測試中一律
// 走錯誤路徑，回應必為 JSON envelope
func readTransferCell(t *testing.T, w *httptest.ResponseRecorder) transferCell {
	t.Helper()
	var resp struct {
		Code   string         `json:"code"`
		Params map[string]any `json:"params"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("回應非 JSON envelope（status=%d body=%q）: %v", w.Code, w.Body.String(), err)
	}
	return transferCell{status: w.Code, code: resp.Code, params: resp.Params}
}

// TestTransferGateMatrix {admin,user,auditor} × {upload,download,delete,mkdir,list}
// × {全域允許, 全域禁止} 共 30 格。每格斷言精確到「HTTP 狀態碼＋錯誤碼」。
func TestTransferGateMatrix(t *testing.T) {
	roles := []transferMatrixRole{
		{name: "admin", userID: 1, jwtRole: model.RoleAdmin},
		{name: "user", userID: 2, jwtRole: model.RoleUser},
		// auditor 無 connect 授權＝授權不足，永遠停在 404，走不到傳輸閘
		{name: "auditor", userID: 3, jwtRole: model.RoleAuditor, wantDenyBySeat: true},
	}
	actions := transferMatrixActions()

	// 全部 30 格的實測結果，供其後的不變式子測試交叉檢查
	results := map[string]transferCell{}
	key := func(role, action, pol string) string { return role + "/" + action + "/" + pol }

	for _, globalAllow := range []bool{true, false} {
		policyName := "policy_deny"
		if globalAllow {
			policyName = "policy_allow"
		}
		handler, db := setupTransferMatrixEnv(t, globalAllow)

		for _, role := range roles {
			for _, act := range actions {
				name := fmt.Sprintf("%s/%s/%s", role.name, act.name, policyName)
				t.Run(name, func(t *testing.T) {
					before := countDeniedAudits(t, db)
					got := readTransferCell(t, callTransferEndpoint(handler, act, role.userID, role.jwtRole))
					results[key(role.name, act.name, policyName)] = got

					wantStatus, wantCode := expectedTransferCell(role, act, globalAllow)
					if got.status != wantStatus || got.code != string(wantCode) {
						t.Fatalf("狀態/碼 = %d/%s，預期 %d/%s", got.status, got.code, wantStatus, wantCode)
					}

					gateDenied := wantStatus == http.StatusForbidden && wantCode == apierror.CodeTransferDenied
					if gateDenied {
						// params 是前端查譯與稽核的機器欄，不得退化為空
						if got.params["reason"] != "global_policy" {
							t.Fatalf("拒絕來源 params.reason = %v，預期 global_policy", got.params["reason"])
						}
						// mkdir 判 file_upload 是刻意的（D3 註 2）：此處把它釘住，
						// 否則哪天有人「順手」給 mkdir 開一支自己的鍵，upload 全禁
						// 就會留下一個能寫遠端檔案系統的洞
						if got.params["action"] != act.gateAction {
							t.Fatalf("params.action = %v，預期 %s", got.params["action"], act.gateAction)
						}
						// 拒絕必須留痕（D6）：不留痕就答不出「有沒有人試著把資料帶出去」
						if after := countDeniedAudits(t, db); after != before+1 {
							t.Fatalf("被拒的傳輸未寫入 denied 審計: before=%d after=%d", before, after)
						}
					}
				})
			}
		}
	}

	// ---- 不變式 1：admin 不豁免 ----
	t.Run("invariant/admin_has_no_exemption", func(t *testing.T) {
		for _, act := range actions {
			if !act.gated {
				continue
			}
			admin := results[key("admin", act.name, "policy_deny")]
			user := results[key("user", act.name, "policy_deny")]
			if admin.status != http.StatusForbidden || admin.code != string(apierror.CodeTransferDenied) {
				t.Fatalf("全域禁止下 admin 的 %s 未被擋: %d/%s", act.name, admin.status, admin.code)
			}
			if admin.status != user.status || admin.code != user.code {
				t.Fatalf("%s 的 admin 與 user 結果不一致（出現角色分支）: admin=%d/%s user=%d/%s",
					act.name, admin.status, admin.code, user.status, user.code)
			}
		}
	})

	// ---- 不變式 2：list 恆通（兩種政策值都不進傳輸閘）----
	t.Run("invariant/list_always_passes_gate", func(t *testing.T) {
		for _, roleName := range []string{"admin", "user"} {
			for _, pol := range []string{"policy_allow", "policy_deny"} {
				got := results[key(roleName, "list", pol)]
				if got.code == string(apierror.CodeTransferDenied) {
					t.Fatalf("%s 的 list 在 %s 被傳輸閘擋下（list 不是資料傳輸）: %+v", roleName, pol, got)
				}
				if got.status != http.StatusBadGateway || got.code != string(apierror.CodeInternalSFTPListFailed) {
					t.Fatalf("%s/list/%s 應通過閘進入資料面: %d/%s", roleName, pol, got.status, got.code)
				}
			}
		}
	})

	// ---- 不變式 3：授權不足是 404，不是 403 ----
	t.Run("invariant/unauthorized_is_404_not_403", func(t *testing.T) {
		for _, act := range actions {
			for _, pol := range []string{"policy_allow", "policy_deny"} {
				got := results[key("auditor", act.name, pol)]
				if got.status != http.StatusNotFound || got.code != string(apierror.CodeAssetNotFound) {
					t.Fatalf("auditor/%s/%s 應為授權不足的 404/NOTFOUND_ASSET: %d/%s",
						act.name, pol, got.status, got.code)
				}
				if got.code == string(apierror.CodeTransferDenied) || got.status == http.StatusForbidden {
					t.Fatalf("授權不足被誤報為傳輸被拒: auditor/%s/%s = %d/%s",
						act.name, pol, got.status, got.code)
				}
			}
		}
	})

	if len(results) != 30 {
		t.Fatalf("矩陣格數 = %d，預期 30（角色 3 × 動作 5 × 政策 2）", len(results))
	}
}

// expectedTransferCell 一格的預期結果。三條分支即三條不變式的正面表述
func expectedTransferCell(role transferMatrixRole, act transferMatrixAction, globalAllow bool) (int, apierror.ErrCode) {
	// 授權不足：停在 requireConnectPermission，與傳輸閘無關（不變式 3）
	if role.wantDenyBySeat {
		return http.StatusNotFound, apierror.CodeAssetNotFound
	}
	// 傳輸閘拒絕：admin 同樣適用（不變式 1）；list 不受此判（不變式 2）
	if act.gated && !globalAllow {
		return http.StatusForbidden, apierror.CodeTransferDenied
	}
	// 通過閘：落在資料面的動作專屬失敗碼（本包無真 SSH 靶機）
	return http.StatusBadGateway, act.dataPlaneCode
}

// countDeniedAudits 目前的 denied 檔案審計筆數
func countDeniedAudits(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	if err := db.Model(&model.AuditLog{}).
		Where("status = ? AND resource = ?", model.StatusDenied, model.ResourceFile).
		Count(&n).Error; err != nil {
		t.Fatalf("count denied audits: %v", err)
	}
	return n
}

// note（tasks 4.5 交付說明）：本矩陣沒有 200 格。
// 五個端點的成功路徑都要求對遠端 SSH 資產真的建線，本包不建靶機、資產帳號亦無憑證，
// 故「通過閘」一律以動作專屬的 502 表達。真 200 的端到端覆蓋在 `scripts/e2e_smoke.sh`。
// 若日後有人想把這裡改成 200，請在本包內起一支真的 SFTP 測試伺服器
// （形態可參考 `internal/modules/asset/change_secret_testserver_test.go`），
// **不要**把斷言放寬成「非 403 即算通過」——那會讓閘的失效無法被本測試發現。

// callTransferCapabilities 以指定身分打能力查詢端點
func callTransferCapabilities(h *SFTPHandler, userID uint, jwtRole string) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/assets/:id/transfer-capabilities", func(c *gin.Context) {
		c.Set("userID", userID)
		c.Set("role", jwtRole)
		h.TransferCapabilities(c)
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/assets/1/transfer-capabilities", nil))
	return w
}

// TestTransferCapabilitiesRequiresConnectAuthorization 能力端點的**授權前置**回歸守衛
// （data-transfer-control 6.2；驗收缺口第三項）。
//
// **為什麼單獨一支**：`auth_context_touchpoints_guard_test.go` 對本 handler 只斷言
// `AuthMiddleware` 掛載數＝2，那擋的是「未認證即可打」；**它不驗 connect 授權**。
// 驗收實證：把 `TransferCapabilities` 內的 `h.requireConnectAsset(c)` 整段拆掉，
// `./internal/api` 與 `./cmd/server` 仍全綠。
//
// 拆掉的後果是「授權關係的匿名探測器」復辟——本端點回答的是「這個人對這台機器
// 能不能傳檔」，任何已登入者都能對任意 asset id 逐一查詢，既洩漏資產存在性，
// 也洩漏他人的授權關係（自動化安全審查在該突變當下即報 HIGH IDOR）。
//
// 斷言採「兩側都要對」：未授權者 404／`NOTFOUND_ASSET`（與檔案端點同一把尺，
// 不洩漏存在性），已授權者 200 且能力欄位確實回傳。**只驗未授權那半是不夠的**
// ——把 handler 改成一律 404 也會通過，而那等於整個端點失能。
func TestTransferCapabilitiesRequiresConnectAuthorization(t *testing.T) {
	h, _ := setupTransferMatrixEnv(t, true)

	// auditor（userID=3）無任何 connect 授權：CheckPermission 對 connect 不為
	// auditor 短路（CPG-002 職責分離），故落正常授權查詢後查無授權
	w := callTransferCapabilities(h, 3, model.RoleAuditor)
	if w.Code != http.StatusNotFound {
		t.Errorf("未授權者 status = %d, want 404——授權前置若被拆除，"+
			"本端點即成為授權關係與資產存在性的探測器（body=%s）", w.Code, w.Body.String())
	}
	cell := readTransferCell(t, w)
	if cell.code != string(apierror.CodeAssetNotFound) {
		t.Errorf("未授權者 code = %q, want %q（與檔案端點同語義，不洩漏存在性）",
			cell.code, apierror.CodeAssetNotFound)
	}

	// 對照組：已授權者（userID=2 持 @ALL connect 授權）必須拿得到 200＋能力
	// ——缺這半，「一律 404」的失能實作同樣會通過
	okResp := callTransferCapabilities(h, 2, model.RoleUser)
	if okResp.Code != http.StatusOK {
		t.Fatalf("已授權者 status = %d, want 200（body=%s）", okResp.Code, okResp.Body.String())
	}
	var body struct {
		Capabilities policy.TransferCapabilities `json:"capabilities"`
	}
	if err := json.Unmarshal(okResp.Body.Bytes(), &body); err != nil {
		t.Fatalf("回應非 JSON: %v", err)
	}
	if !body.Capabilities.FileUpload || !body.Capabilities.FileDownload {
		t.Errorf("全域允許下能力 = %+v, want 上傳／下載皆為 true", body.Capabilities)
	}
}

// TestDeniedMkdirAuditsAsMkdir 判定粒度與留痕粒度分離的回歸守衛（驗收缺口第四項）。
//
// **這條不變式先前只存在於註解**：`sftp_handler.go` 與本檔第 106 行都寫著
// 「mkdir 判 file_upload 鍵，但審計仍記 file_mkdir」，而 `transferAuditAction`
// 的 default 分支把 mkdir 一併映到 `model.ActionFileUpload`（live 佐證：
// audit_logs id=22142 的 `action=file_upload`）。宣稱的不變式從未被實作，
// 也從未被任何測試檢查。
//
// **為什麼選「讓實碼符合註解」而非訂正註解**：成功路徑的 mkdir 記
// `model.ActionFileMkdir`（`sftp_handler.go` 的 `h.audit(...)`）。若被擋的 mkdir
// 記 file_upload，同一個操作就會因成功／被擋而落在**兩個不同的 action 值**——
// 稽核者以 `action=file_mkdir` 篩選時只看得到成功的那些，被擋的那些藏在
// file_upload 桶裡與真正的傳檔混同。而「有沒有人試著繞過政策建目錄」正是
// 拒絕留痕（D6）要回答的問題。
//
// 三條斷言：mkdir 被擋記 `file_mkdir`；upload 被擋記 `file_upload`（兩者不得
// 同形，否則分離失去意義）；403 envelope 的 `action` 仍為判定鍵 `file_upload`
// （那回答「哪條政策擋的」，是機器可讀的政策鍵，刻意與留痕不同源）。
func TestDeniedMkdirAuditsAsMkdir(t *testing.T) {
	h, db := setupTransferMatrixEnv(t, false) // 全域禁止：三個檔案政策鍵皆 false

	var mkdirAct, uploadAct transferMatrixAction
	for _, act := range transferMatrixActions() {
		switch act.name {
		case "mkdir":
			mkdirAct = act
		case "upload":
			uploadAct = act
		}
	}

	// user（userID=2，持 @ALL connect 授權）走得到傳輸閘
	w := callTransferEndpoint(h, mkdirAct, 2, model.RoleUser)
	if w.Code != http.StatusForbidden {
		t.Fatalf("mkdir status = %d, want 403（全域禁止）body=%s", w.Code, w.Body.String())
	}
	cell := readTransferCell(t, w)
	if got := cell.params["action"]; got != policy.TransferActionFileUpload {
		t.Errorf("403 envelope action = %v, want %q——envelope 帶的是**判定鍵**，"+
			"改成 file_mkdir 會讓前端分不出是哪條政策擋的",
			got, policy.TransferActionFileUpload)
	}

	if w := callTransferEndpoint(h, uploadAct, 2, model.RoleUser); w.Code != http.StatusForbidden {
		t.Fatalf("upload status = %d, want 403", w.Code)
	}

	var rows []model.AuditLog
	if err := db.Model(&model.AuditLog{}).
		Where("status = ? AND resource = ?", model.StatusDenied, model.ResourceFile).
		Order("id ASC").Find(&rows).Error; err != nil {
		t.Fatalf("查 denied 留痕: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("denied 留痕 = %d 筆, want 2（mkdir 與 upload 各一）", len(rows))
	}
	if rows[0].Action != model.ActionFileMkdir {
		t.Errorf("被擋的 mkdir 留痕 action = %q, want %q——與成功路徑的 file_mkdir 不一致時，"+
			"稽核者以 action 篩選會看不到被擋的建目錄嘗試",
			rows[0].Action, model.ActionFileMkdir)
	}
	if rows[1].Action != model.ActionFileUpload {
		t.Errorf("被擋的 upload 留痕 action = %q, want %q", rows[1].Action, model.ActionFileUpload)
	}
	if rows[0].Action == rows[1].Action {
		t.Errorf("mkdir 與 upload 的拒絕留痕同形（%q）：判定粒度與留痕粒度並未分離",
			rows[0].Action)
	}
}
