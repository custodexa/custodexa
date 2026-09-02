package sshproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/dbconsole"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/proxy"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// 連線閘序 characterization matrix
//
// **這份測試的職責不是「找缺陷」，是「證明閘序收斂前後等價」**：維度＝
// `Stage × 各閘通過/失敗 × 帳號解析成敗`，每一格斷言三件事——
// (Allowed, 拒絕碼, 副作用)。收斂前先跑一次把現況固定下來，收斂後必須逐格相同。
//
// 格名以閘編號（G-I*／G-S*／G-C*）標註。**編號的定義在 `internal/sshproxy/connect_gates.go`**
// ——每個 `{Name: "G-…"}` 之後緊接該閘的實作與理由；本檔的 `TestMatrixCoverageIsDeclared`
// 則是編號的完整登記表（含刻意不涵蓋者與其逐條理由）。
//
// **副作用的統一斷言**：任何被閘擋下的請求 SHALL NOT 留下 session 列
//（全部閘都排在 createSession 之前——這是「拒絕時機」的機器證據，
// 只驗碼不驗副作用會漏掉「先建 session 再拒」這種同碼不同義的退化）。
//
// **雙碼不對稱**：同一語義失敗（帳號不在授權範圍）在簽發側是 404
// RULE_ASSET_ACCOUNT_NOT_FOUND、兌換側是 403 AUTH_ASSET_CONNECT_DENIED，
// 兩格都在本矩陣內逐格釘住。看到不一致 SHALL NOT 逕行「修掉」。

// gateFixture 三處入口共用的基準夾具：user1（一般，持 asset1 常設 connect）、
// user2（admin）、user3（auditor）；asset1＝ssh／active／open 段位；尚未建帳號
func gateFixture(t *testing.T) (*Handler, *gorm.DB) {
	t.Helper()
	h, db, _ := setupPolicyGateTest(t)
	seedGateFixture(t, db)
	setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
	return h, db
}

// gateSeedAccount 建帳號並回傳 ID
func gateSeedAccount(t *testing.T, db *gorm.DB, assetID uint, username string, isDefault bool) uint {
	t.Helper()
	acct := model.AssetAccount{AssetID: assetID, Username: username, IsDefault: isDefault}
	if err := db.Create(&acct).Error; err != nil {
		t.Fatalf("seed account: %v", err)
	}
	return acct.ID
}

// gateIssueRequest 以指定身分／帳號呼叫簽發端點；rawBody 非空時直送原始位元組
// （供「請求體綁定失敗」格使用）
func gateIssueRequest(h *Handler, userID uint, role string, assetID, accountID uint, rawBody string) (int, map[string]any, map[string]any) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	var keys map[string]any
	r.POST("/connect-tokens", func(c *gin.Context) {
		c.Set("userID", userID)
		c.Set("role", role)
		h.HandleCreateConnectToken(c)
		keys = c.Keys
	})
	var body []byte
	if rawBody != "" {
		body = []byte(rawBody)
	} else {
		payload := map[string]any{"asset_id": assetID}
		if accountID != 0 {
			payload["account_id"] = accountID
		}
		body, _ = json.Marshal(payload)
	}
	req := httptest.NewRequest("POST", "/connect-tokens", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp, keys
}

// gateUnwritableRecordingPath 造一條必然探測失敗的錄影路徑：指向一個**普通檔案**
// 而非目錄，使 ProbeWritable 的 MkdirAll 失敗。
// 不用 chmod——容器內測試以 root 執行，權限位對 root 無效（會造成假綠）
func gateUnwritableRecordingPath(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed unwritable path: %v", err)
	}
	return p
}

// gateRedeemSSH 兌換終端連線；cols／rows 可覆寫（供尺寸解析格使用）
func gateRedeemSSH(h *Handler, token, cols, rows string) (int, map[string]any) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/ssh", h.HandleSSH)
	req := httptest.NewRequest("GET",
		"/ssh?connect_token="+token+"&cols="+cols+"&rows="+rows, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp
}

// gateSetAllowedCIDRs 直寫使用者的允許來源網段儲存字串。
//
// **繞過 service 層的驗證是刻意的**：本檔要造的其中一格正是「儲存字串損壞」，
// 而那個狀態按定義走不到 service 的驗證路徑（唯一寫入路徑是驗證後寫入，
// 損壞只可能來自 DB 直寫或程式缺陷）。經 service 就造不出這一格。
func gateSetAllowedCIDRs(t *testing.T, db *gorm.DB, userID uint, raw string) {
	t.Helper()
	if err := db.Model(&model.User{}).Where("id = ?", userID).
		Update("allowed_cidrs", raw).Error; err != nil {
		t.Fatalf("set allowed_cidrs: %v", err)
	}
}

// gateAssertNoSession 副作用斷言：被閘擋下者不得留下 session 列
func gateAssertNoSession(t *testing.T, db *gorm.DB, cell string) {
	t.Helper()
	var n int64
	if err := db.Model(&model.Session{}).Count(&n).Error; err != nil {
		t.Fatalf("[%s] count sessions: %v", cell, err)
	}
	if n != 0 {
		t.Fatalf("[%s] 閘拒絕後不得留下 session 列，實得 %d 列", cell, n)
	}
}

// gateAssertMeta 機器欄逐項比對（JSON 反序列化後數值為 float64，故以字面比對）
func gateAssertMeta(t *testing.T, cell string, resp map[string]any, want map[string]any) {
	t.Helper()
	for k, v := range want {
		got, ok := resp[k]
		if !ok {
			t.Fatalf("[%s] 回應缺機器欄 %q: resp=%v", cell, k, resp)
		}
		if fmt.Sprint(got) != fmt.Sprint(v) {
			t.Fatalf("[%s] 機器欄 %q 不符: got=%v want=%v", cell, k, got, v)
		}
	}
}

type gateIssueCell struct {
	name       string
	gate       string
	setup      func(t *testing.T, h *Handler, db *gorm.DB)
	userID     uint
	role       string
	assetID    uint
	accountID  uint
	rawBody    string
	wantStatus int
	wantCode   apierror.ErrCode // 空＝期待放行
	wantMeta   map[string]any
	wantAbsent []string          // 期待「不存在」的機器欄（釘住兩側 meta 形狀差異）
	wantAudit  map[string]string // audit_details 副作用
}

// gateIssueCells StageIssue 矩陣的全部格。
//
// **獨立於測試函式存在，是為了讓涵蓋面自證能真正耦合**：`TestMatrixCoverageIsDeclared`
// 直接從本函式擷取 `gate` 欄，故「登記表說涵蓋了哪些閘」與「矩陣實際跑了哪些閘」
// 不可能分家（原版的 covered 由硬編碼閘表扣掉 uncovered 推導，恆真）。
func gateIssueCells() []gateIssueCell {
	return []gateIssueCell{
		{
			name: "全閘通過（零帳號資產，帳號解析 Found=false）", gate: "—",
			userID: 1, role: model.RoleUser, assetID: 1,
			wantStatus: http.StatusOK,
		},
		{
			name: "全閘通過（帳號解析成功＋範圍內）", gate: "—",
			setup: func(t *testing.T, h *Handler, db *gorm.DB) {
				gateSeedAccount(t, db, 1, "root", true)
			},
			userID: 1, role: model.RoleUser, assetID: 1,
			wantStatus: http.StatusOK,
		},
		{
			name: "G-I2 使用者已停用", gate: "G-I2",
			setup: func(t *testing.T, h *Handler, db *gorm.DB) {
				if err := db.Model(&model.User{}).Where("id = ?", 1).Update("active", false).Error; err != nil {
					t.Fatalf("deactivate: %v", err)
				}
			},
			userID: 1, role: model.RoleUser, assetID: 1,
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeUserInactive,
		},
		{
			name: "G-I2 帳號鎖定中", gate: "G-I2",
			setup: func(t *testing.T, h *Handler, db *gorm.DB) {
				until := time.Now().Add(time.Hour)
				if err := db.Model(&model.User{}).Where("id = ?", 1).Update("locked_until", until).Error; err != nil {
					t.Fatalf("lock: %v", err)
				}
			},
			userID: 1, role: model.RoleUser, assetID: 1,
			wantStatus: http.StatusLocked, wantCode: apierror.CodeAccountLocked,
		},
		{
			// 來源限定：清單非空且請求來源（httptest 的 192.0.2.1）不在內。
			// **assetID 指向不存在的資產**：本閘若被排到資產解析之後，
			// 回應會變成 404 資產不存在——那正是「來源不對的人不該知道」的事
			name: "G-I15 來源不在允許網段（先於資產存在性）", gate: "G-I15",
			setup: func(t *testing.T, h *Handler, db *gorm.DB) {
				gateSetAllowedCIDRs(t, db, 1, "10.0.0.0/8")
			},
			userID: 1, role: model.RoleUser, assetID: 4242,
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeAuthSourceNotAllowed,
			wantMeta: map[string]any{"reason": "source_not_allowed"},
		},
		{
			// 政策損壞（DB 直寫或程式缺陷）：**不得視為空清單放行**。
			// 對外與上一格逐字相同——成因只進審計
			name: "G-I15 清單字串損壞（不得當成不限）", gate: "G-I15",
			setup: func(t *testing.T, h *Handler, db *gorm.DB) {
				gateSetAllowedCIDRs(t, db, 1, "not-a-cidr")
			},
			userID: 1, role: model.RoleUser, assetID: 1,
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeAuthSourceNotAllowed,
			wantMeta: map[string]any{"reason": "source_not_allowed"},
		},
		{
			name: "G-I3 請求體綁定失敗", gate: "G-I3",
			userID: 1, role: model.RoleUser, assetID: 1, rawBody: `{"asset_id":`,
			wantStatus: http.StatusBadRequest, wantCode: apierror.CodeBadParams,
		},
		{
			name: "G-I4 資產不存在", gate: "G-I4",
			userID: 1, role: model.RoleUser, assetID: 4242,
			wantStatus: http.StatusNotFound, wantCode: apierror.CodeAssetNotFound,
		},
		{
			name: "G-I5 無連線授權（auditor 不自動放行）", gate: "G-I5",
			userID: 3, role: model.RoleAuditor, assetID: 1,
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeAssetConnectDenied,
		},
		{
			name: "G-I6 資產停用（admin 亦不豁免）", gate: "G-I6",
			setup: func(t *testing.T, h *Handler, db *gorm.DB) {
				if err := db.Model(&model.Asset{}).Where("id = ?", 1).Update("active", false).Error; err != nil {
					t.Fatalf("disable asset: %v", err)
				}
			},
			userID: 2, role: model.RoleAdmin, assetID: 1,
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeAssetDisabled,
			wantMeta: map[string]any{"reason": "asset_disabled"},
		},
		{
			name: "G-I7 K8s 資產帶 account_id", gate: "G-I7",
			setup: func(t *testing.T, h *Handler, db *gorm.DB) {
				if err := db.Model(&model.Asset{}).Where("id = ?", 1).
					Update("protocol", model.ProtocolK8s).Error; err != nil {
					t.Fatalf("set k8s: %v", err)
				}
			},
			userID: 1, role: model.RoleUser, assetID: 1, accountID: 4242,
			wantStatus: http.StatusBadRequest, wantCode: apierror.CodeAccountK8sDefaultOnly,
		},
		{
			name: "G-I8 帳號屬於別的資產（簽發側 404）", gate: "G-I8",
			setup: func(t *testing.T, h *Handler, db *gorm.DB) {
				if err := db.Create(&model.Asset{Name: "a2", Protocol: "ssh", Host: "h2", Port: 22, CreatedBy: 2}).Error; err != nil {
					t.Fatalf("seed asset2: %v", err)
				}
				gateSeedAccount(t, db, 2, "other", true)
			},
			userID: 1, role: model.RoleUser, assetID: 1, accountID: 1,
			wantStatus: http.StatusNotFound, wantCode: apierror.CodeAssetAccountNotFound,
		},
		{
			name: "G-I10 帳號不在授權範圍（簽發側 404，與不存在共用碼）", gate: "G-I10",
			setup: func(t *testing.T, h *Handler, db *gorm.DB) {
				gateSeedAccount(t, db, 1, "root", true)
				if err := db.Model(&model.AssetAuthorization{}).Where("user_id = ?", 1).
					Update("accounts", model.AccountScope{"app"}).Error; err != nil {
					t.Fatalf("narrow scope: %v", err)
				}
			},
			userID: 1, role: model.RoleUser, assetID: 1,
			wantStatus: http.StatusNotFound, wantCode: apierror.CodeAssetAccountNotFound,
		},
		{
			name: "G-I11 錄影 probe 失敗＋fail-close（非 admin）", gate: "G-I11",
			setup: func(t *testing.T, h *Handler, db *gorm.DB) {
				h.RecordingPath = gateUnwritableRecordingPath(t)
				h.RecordingFailClose = func() bool { return true }
			},
			userID: 1, role: model.RoleUser, assetID: 1,
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeRecordingUnavailable,
			wantMeta: map[string]any{"reason": "recording_unavailable"},
		},
		{
			name: "G-I11 錄影 fail-close 的 admin 豁免（放行＋審計標記）", gate: "G-I11",
			setup: func(t *testing.T, h *Handler, db *gorm.DB) {
				h.RecordingPath = gateUnwritableRecordingPath(t)
				h.RecordingFailClose = func() bool { return true }
			},
			userID: 2, role: model.RoleAdmin, assetID: 1,
			wantStatus: http.StatusOK,
			wantAudit:  map[string]string{"recording_exemption": "admin"},
		},
		{
			name: "G-I12 存取政策 approval 攔截", gate: "G-I12",
			setup: func(t *testing.T, h *Handler, db *gorm.DB) {
				setGroupPolicy(t, db, 1, model.AccessPolicyApproval)
			},
			userID: 1, role: model.RoleUser, assetID: 1,
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeAccessApprovalRequired,
			wantMeta: map[string]any{"reason": "approval_required"},
		},
		{
			name: "G-I12 存取政策 reason 攔截（碼隨 reason 分流）", gate: "G-I12",
			setup: func(t *testing.T, h *Handler, db *gorm.DB) {
				setGroupPolicy(t, db, 1, model.AccessPolicyReason)
			},
			userID: 1, role: model.RoleUser, assetID: 1,
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeAccessReasonRequired,
			wantMeta: map[string]any{"reason": "reason_required"},
		},
		{
			name: "G-I12 admin 豁免（放行＋審計標記）", gate: "G-I12",
			setup: func(t *testing.T, h *Handler, db *gorm.DB) {
				setGroupPolicy(t, db, 1, model.AccessPolicyApproval)
			},
			userID: 2, role: model.RoleAdmin, assetID: 1,
			wantStatus: http.StatusOK,
			wantAudit:  map[string]string{"policy_exemption": "admin"},
		},
		{
			name: "G-I13 傳輸安全閘 warn 無同意", gate: "G-I13",
			setup: func(t *testing.T, h *Handler, db *gorm.DB) {
				policies := policy.NewSecurityPolicyService(db)
				if err := db.Create(&model.Asset{Name: "rdp1", Protocol: "rdp", Host: "h", Port: 3389, CreatedBy: 2}).Error; err != nil {
					t.Fatalf("seed rdp: %v", err)
				}
				if err := db.Model(&model.Asset{}).Where("id = ?", 2).
					Update("access_policy", model.AccessPolicyOpen).Error; err != nil {
					t.Fatalf("set policy: %v", err)
				}
				uid, aid := uint(1), uint(2)
				if err := db.Create(&model.AssetAuthorization{
					UserID: &uid, AssetID: &aid, Permission: model.PermissionConnect, GrantedBy: 2,
				}).Error; err != nil {
					t.Fatalf("seed grant: %v", err)
				}
				if _, err := policies.Update(policy.PolicyTransportRDPLevel, policy.TransportLevelWarn, "admin"); err != nil {
					t.Fatalf("set transport warn: %v", err)
				}
				h.TransmissionConsent = policy.NewTransmissionConsentService(db,
					policy.NewTransmissionPolicyService(policies, nil))
			},
			userID: 1, role: model.RoleUser, assetID: 2,
			wantStatus: http.StatusPreconditionRequired, wantCode: apierror.CodeTransmissionConsentRequired,
			wantMeta: map[string]any{"level": policy.TransportLevelWarn},
		},
	}
}

// TestCharacterizationMatrixIssue StageIssue 逐格特徵化
func TestCharacterizationMatrixIssue(t *testing.T) {
	for _, cell := range gateIssueCells() {
		t.Run(cell.name, func(t *testing.T) {
			h, db := gateFixture(t)
			if cell.setup != nil {
				cell.setup(t, h, db)
			}
			status, resp, keys := gateIssueRequest(h, cell.userID, cell.role, cell.assetID, cell.accountID, cell.rawBody)

			if status != cell.wantStatus {
				t.Fatalf("[%s] HTTP 狀態不符: got=%d want=%d resp=%v", cell.name, status, cell.wantStatus, resp)
			}
			if cell.wantCode == "" {
				if resp["connect_token"] == nil {
					t.Fatalf("[%s] 期待放行並簽發 token: resp=%v", cell.name, resp)
				}
			} else {
				if got, _ := resp["code"].(string); got != string(cell.wantCode) {
					t.Fatalf("[%s] 拒絕碼不符: got=%q want=%q resp=%v", cell.name, got, cell.wantCode, resp)
				}
				if resp["connect_token"] != nil {
					t.Fatalf("[%s] 被拒者不得同時簽出 token: resp=%v", cell.name, resp)
				}
			}
			gateAssertMeta(t, cell.name, resp, cell.wantMeta)
			for _, k := range cell.wantAbsent {
				if _, ok := resp[k]; ok {
					t.Fatalf("[%s] 機器欄 %q 不應存在: resp=%v", cell.name, k, resp)
				}
			}
			if len(cell.wantAudit) > 0 {
				details, _ := keys["audit_details"].(map[string]string)
				for k, v := range cell.wantAudit {
					if details[k] != v {
						t.Fatalf("[%s] 審計副作用 %q 不符: got=%q want=%q keys=%v", cell.name, k, details[k], v, keys)
					}
				}
			}
			gateAssertNoSession(t, db, cell.name)
		})
	}
}

type gateRedeemCell struct {
	name       string
	gate       string
	setup      func(t *testing.T, h *Handler, db *gorm.DB) // 於發 token 之前
	mutate     func(t *testing.T, h *Handler, db *gorm.DB) // 發 token 之後、兌換之前
	grant      proxy.ConnectGrant
	rawToken   string // 非空時不發 token，直接以此字串兌換
	noToken    bool   // true 時 connect_token 參數留空
	cols, rows string
	wantStatus int
	wantCode   apierror.ErrCode
	wantMeta   map[string]any
	wantAbsent []string
	wantBurned bool // 兌換後原 token 應已被消費（一次性即焚）
}

// gateRedeemCells StageRedeemTerminal 矩陣的全部格（涵蓋面自證的資料來源，同 gateIssueCells）
func gateRedeemCells() []gateRedeemCell {
	seedRoot := func(t *testing.T, h *Handler, db *gorm.DB) { gateSeedAccount(t, db, 1, "root", true) }

	return []gateRedeemCell{
		{
			name: "全閘通過（帳號解析＝預設帳號）抵達撥號", gate: "—",
			setup: seedRoot,
			grant: proxy.ConnectGrant{UserID: 1, AssetID: 1},
			// 撥號目標 host="h" 不可解析 ⇒ 502＋撥號碼＝所有閘皆已通過的機器證據
			wantStatus: http.StatusBadGateway, wantCode: apierror.CodeSSHUnreachable,
			wantBurned: true,
		},
		{
			name: "全閘通過（帳號解析＝指定帳號）抵達撥號", gate: "—",
			setup:      seedRoot,
			grant:      proxy.ConnectGrant{UserID: 1, AssetID: 1, AccountID: 1},
			wantStatus: http.StatusBadGateway, wantCode: apierror.CodeSSHUnreachable,
			wantBurned: true,
		},
		{
			name: "G-S1 connect_token 缺失", gate: "G-S1",
			noToken:    true,
			wantStatus: http.StatusUnauthorized, wantCode: apierror.CodeConnectTokenMissing,
		},
		{
			name: "G-S2 connect_token 無效", gate: "G-S2",
			rawToken:   "not-a-real-token",
			wantStatus: http.StatusUnauthorized, wantCode: apierror.CodeConnectTokenInvalid,
		},
		{
			// 兌換側現讀：票證在允許位址簽出也擋不住——本閘不信簽發時的判定
			name: "G-S14 兌換當下來源不在允許網段", gate: "G-S14",
			setup: seedRoot,
			mutate: func(t *testing.T, h *Handler, db *gorm.DB) {
				gateSetAllowedCIDRs(t, db, 1, "10.0.0.0/8")
			},
			grant:      proxy.ConnectGrant{UserID: 1, AssetID: 1},
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeAuthSourceNotAllowed,
			wantMeta:   map[string]any{"reason": "source_not_allowed"},
			wantBurned: true,
		},
		{
			name: "G-S3 使用者已停用", gate: "G-S3",
			setup: seedRoot,
			mutate: func(t *testing.T, h *Handler, db *gorm.DB) {
				if err := db.Model(&model.User{}).Where("id = ?", 1).Update("active", false).Error; err != nil {
					t.Fatalf("deactivate: %v", err)
				}
			},
			grant:      proxy.ConnectGrant{UserID: 1, AssetID: 1},
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeUserInactive,
			wantBurned: true,
		},
		{
			name: "G-S3 帳號鎖定中", gate: "G-S3",
			setup: seedRoot,
			mutate: func(t *testing.T, h *Handler, db *gorm.DB) {
				until := time.Now().Add(time.Hour)
				if err := db.Model(&model.User{}).Where("id = ?", 1).Update("locked_until", until).Error; err != nil {
					t.Fatalf("lock: %v", err)
				}
			},
			grant:      proxy.ConnectGrant{UserID: 1, AssetID: 1},
			wantStatus: http.StatusLocked, wantCode: apierror.CodeAccountLocked,
			wantBurned: true,
		},
		{
			name: "G-S4 憑證世代被推進（一律收斂為 token 無效）", gate: "G-S4",
			setup: seedRoot,
			mutate: func(t *testing.T, h *Handler, db *gorm.DB) {
				if err := db.Model(&model.User{}).Where("id = ?", 1).
					Update("credential_epoch", 7).Error; err != nil {
					t.Fatalf("bump epoch: %v", err)
				}
			},
			grant:      proxy.ConnectGrant{UserID: 1, AssetID: 1},
			wantStatus: http.StatusUnauthorized, wantCode: apierror.CodeConnectTokenInvalid,
			wantBurned: true,
		},
		{
			name: "G-S5 視窗尺寸解析失敗", gate: "G-S5",
			setup: seedRoot,
			grant: proxy.ConnectGrant{UserID: 1, AssetID: 1},
			cols:  "abc", rows: "24",
			wantStatus: http.StatusBadRequest, wantCode: apierror.CodeTerminalColsInvalid,
			wantBurned: true,
		},
		{
			name: "G-S6 帳號於簽發後被刪（絕不退回預設帳號）", gate: "G-S6",
			setup: func(t *testing.T, h *Handler, db *gorm.DB) {
				gateSeedAccount(t, db, 1, "root", true)
				gateSeedAccount(t, db, 1, "app", false)
			},
			mutate: func(t *testing.T, h *Handler, db *gorm.DB) {
				if err := db.Delete(&model.AssetAccount{}, 2).Error; err != nil {
					t.Fatalf("delete account: %v", err)
				}
			},
			grant:      proxy.ConnectGrant{UserID: 1, AssetID: 1, AccountID: 2},
			wantStatus: http.StatusNotFound, wantCode: apierror.CodeAssetAccountNotFound,
			wantBurned: true,
		},
		{
			name: "G-S7 資產於簽發後被停用", gate: "G-S7",
			setup: seedRoot,
			mutate: func(t *testing.T, h *Handler, db *gorm.DB) {
				if err := db.Model(&model.Asset{}).Where("id = ?", 1).Update("active", false).Error; err != nil {
					t.Fatalf("disable: %v", err)
				}
			},
			grant:      proxy.ConnectGrant{UserID: 1, AssetID: 1},
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeAssetDisabled,
			wantMeta:   map[string]any{"reason": "asset_disabled"},
			wantBurned: true,
		},
		{
			name: "G-S8 協議非文字終端", gate: "G-S8",
			setup: seedRoot,
			mutate: func(t *testing.T, h *Handler, db *gorm.DB) {
				if err := db.Model(&model.Asset{}).Where("id = ?", 1).
					Update("protocol", model.ProtocolRDP).Error; err != nil {
					t.Fatalf("set rdp: %v", err)
				}
			},
			grant:      proxy.ConnectGrant{UserID: 1, AssetID: 1},
			wantStatus: http.StatusBadRequest, wantCode: apierror.CodeAssetNotTextTerminal,
			wantBurned: true,
		},
		{
			name: "G-S9 連線授權於簽發後被撤銷", gate: "G-S9",
			setup: seedRoot,
			mutate: func(t *testing.T, h *Handler, db *gorm.DB) {
				if err := db.Where("user_id = ?", 1).Delete(&model.AssetAuthorization{}).Error; err != nil {
					t.Fatalf("revoke: %v", err)
				}
			},
			grant:      proxy.ConnectGrant{UserID: 1, AssetID: 1},
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeAssetConnectDenied,
			wantBurned: true,
		},
		{
			name: "G-S10 存取政策於簽發後收緊（兌換側 meta 不帶時長／在途單）", gate: "G-S10",
			setup: seedRoot,
			mutate: func(t *testing.T, h *Handler, db *gorm.DB) {
				setGroupPolicy(t, db, 1, model.AccessPolicyApproval)
			},
			grant:      proxy.ConnectGrant{UserID: 1, AssetID: 1},
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeAccessApprovalRequired,
			wantMeta:   map[string]any{"reason": "approval_required"},
			wantAbsent: []string{"max_duration_minutes", "pending_request_id"},
			wantBurned: true,
		},
		{
			name: "G-S11 零帳號資產 fail-close", gate: "G-S11",
			grant:      proxy.ConnectGrant{UserID: 1, AssetID: 1},
			wantStatus: http.StatusNotFound, wantCode: apierror.CodeAccountNoneUsable,
			wantBurned: true,
		},
		{
			name: "G-S12 K8s 資產帶指定帳號", gate: "G-S12",
			setup: func(t *testing.T, h *Handler, db *gorm.DB) {
				gateSeedAccount(t, db, 1, "root", true)
				if err := db.Model(&model.Asset{}).Where("id = ?", 1).
					Update("protocol", model.ProtocolK8s).Error; err != nil {
					t.Fatalf("set k8s: %v", err)
				}
			},
			grant:      proxy.ConnectGrant{UserID: 1, AssetID: 1, AccountID: 1},
			wantStatus: http.StatusBadRequest, wantCode: apierror.CodeAccountK8sDefaultOnly,
			wantBurned: true,
		},
		{
			name: "G-S13 帳號於簽發後移出授權範圍（兌換側 403）", gate: "G-S13",
			setup: seedRoot,
			mutate: func(t *testing.T, h *Handler, db *gorm.DB) {
				if err := db.Model(&model.AssetAuthorization{}).Where("user_id = ?", 1).
					Update("accounts", model.AccountScope{"app"}).Error; err != nil {
					t.Fatalf("narrow scope: %v", err)
				}
			},
			grant:      proxy.ConnectGrant{UserID: 1, AssetID: 1},
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeAssetConnectDenied,
			wantBurned: true,
		},
	}
}

// TestCharacterizationMatrixRedeemTerminal StageRedeemTerminal 逐格特徵化
func TestCharacterizationMatrixRedeemTerminal(t *testing.T) {
	for _, cell := range gateRedeemCells() {
		t.Run(cell.name, func(t *testing.T) {
			h, db := gateFixture(t)
			if cell.setup != nil {
				cell.setup(t, h, db)
			}
			token := cell.rawToken
			if token == "" && !cell.noToken {
				var err error
				token, err = h.ConnectTokens.IssueConnectToken(context.Background(), cell.grant)
				if err != nil {
					t.Fatalf("[%s] issue: %v", cell.name, err)
				}
			}
			if cell.mutate != nil {
				cell.mutate(t, h, db)
			}
			cols, rows := cell.cols, cell.rows
			if cols == "" {
				cols, rows = "80", "24"
			}
			status, resp := gateRedeemSSH(h, token, cols, rows)

			if status != cell.wantStatus {
				t.Fatalf("[%s] HTTP 狀態不符: got=%d want=%d resp=%v", cell.name, status, cell.wantStatus, resp)
			}
			if got, _ := resp["code"].(string); got != string(cell.wantCode) {
				t.Fatalf("[%s] 拒絕碼不符: got=%q want=%q resp=%v", cell.name, got, cell.wantCode, resp)
			}
			gateAssertMeta(t, cell.name, resp, cell.wantMeta)
			for _, k := range cell.wantAbsent {
				if _, ok := resp[k]; ok {
					t.Fatalf("[%s] 機器欄 %q 不應存在: resp=%v", cell.name, k, resp)
				}
			}
			// 副作用一：任何閘拒絕都不得留下 session 列
			gateAssertNoSession(t, db, cell.name)
			// 副作用二：一次性即焚——token 於 Resolve 當下即被消費，
			// 之後任何一道閘拒絕都不會把它還回去（重放必然 401 invalid）
			if cell.wantBurned {
				replayStatus, replayResp := gateRedeemSSH(h, token, "80", "24")
				if replayStatus != http.StatusUnauthorized ||
					replayResp["code"] != string(apierror.CodeConnectTokenInvalid) {
					t.Fatalf("[%s] token 於兌換後必須已焚: status=%d resp=%v", cell.name, replayStatus, replayResp)
				}
			}
		})
	}
}

// TestMatrixCoverageIsDeclared 涵蓋面自證：**涵蓋集合從實際矩陣格機器擷取**
// （`gateIssueCells()`／`gateRedeemCells()` 的 gate 欄），與基準表閘號、刻意不涵蓋登記表
// 三方比對，任一方向不一致即紅。
//
// **修法背景**：原版的 `covered` 由硬編碼閘表扣掉 `uncovered` 推導，
// 與矩陣實際有幾格毫無耦合——刪光所有格子它照樣綠，`len(covered)>=24` 恆真。
// 現版反過來：先擷取實跑格宣稱的閘號，再要求它與「基準表 − 不涵蓋」逐一相等。
// 少一道閘（格被刪／閘號改錯）與多一道閘（新增格卻沒更新登記表、或某閘被移出不涵蓋
// 卻沒補理由）**兩個方向都紅**。
func TestMatrixCoverageIsDeclared(t *testing.T) {
	// 基準表 §1.1／§1.2 的全部閘編號，加上主控台入口的兩道專屬閘
	// G-I15／G-S14＝來源限定閘（G1）。編號接在末尾而位置在閘序前段是本套編號的
	// 既有慣例：編號是穩定識別碼，不是序號（見 internal/connectgate 檔頭）
	issueGates := []string{"G-I1", "G-I2", "G-I3", "G-I4", "G-I5", "G-I6", "G-I7",
		"G-I8", "G-I9", "G-I10", "G-I11", "G-I12", "G-I13", "G-I14", "G-I15"}
	redeemGates := []string{"G-S1", "G-S2", "G-S3", "G-S4", "G-S5", "G-S6", "G-S7",
		"G-S8", "G-S9", "G-S10", "G-S11", "G-S12", "G-S13", "G-S14"}
	// 查詢主控台兌換入口的兩道專屬閘（插在 G-S8 之後、G-S9 之前）
	consoleGates := []string{"G-C1", "G-C2"}
	baseline := map[string]bool{}
	for _, g := range append(append(append([]string{}, issueGates...), redeemGates...), consoleGates...) {
		baseline[g] = true
	}

	// 刻意不涵蓋（逐條附理由）
	uncovered := map[string]string{
		"G-I1":  "authenticate：本矩陣一律經 middleware 分支（c.Set(\"userID\")）進入；?token= 分支是另一套認證面，由 ws_query_token_context_test.go 覆蓋",
		"G-I9":  "ResolveAccountIdentity 的失敗態在 G-I8 通過後不可達（同一解析條件、同一 sentinel），構造不出獨立格",
		"G-I14": "簽發容量拒絕需灌滿 token 池，已由 proxy/connect_token_capacity_test.go 專測覆蓋",
	}

	total := len(issueGates) + len(redeemGates) + len(consoleGates)
	if total != 31 {
		t.Fatalf("基準表閘數與矩陣宣稱不符: got=%d want=31（改動基準表時必須同步本測試）", total)
	}

	// 從實際矩陣格擷取涵蓋的閘號；gate=="—" 者是全閘通過格，不宣稱涵蓋任何單一閘。
	// 同時釘住「子測試名前綴＝gate 欄」——兩條機器擷取路徑（子測試名／資料欄）必須一致
	covered := map[string]bool{}
	cellCount := 0
	collect := func(kind, name, gate string) {
		cellCount++
		if gate == "—" {
			return
		}
		if gate == "" {
			t.Errorf("%s 格 %q 未標註 gate 欄（涵蓋面無從擷取；全閘通過格請標 \"—\"）", kind, name)
			return
		}
		if !strings.HasPrefix(name, gate+" ") {
			t.Errorf("%s 格名與 gate 欄不一致: name=%q gate=%q（格名須以閘號開頭，"+
				"否則從子測試名擷取涵蓋面會與資料欄分家）", kind, name, gate)
		}
		if !baseline[gate] {
			t.Errorf("%s 格 %q 宣稱涵蓋 %s，但該閘不在基準表內", kind, name, gate)
			return
		}
		covered[gate] = true
	}
	for _, c := range gateIssueCells() {
		collect("簽發", c.name, c.gate)
	}
	for _, c := range gateRedeemCells() {
		collect("SSH 兌換", c.name, c.gate)
	}
	for _, c := range gateConsoleCells() {
		collect("主控台兌換", c.name, c.gate)
	}
	if cellCount < 30 {
		t.Fatalf("矩陣格數 %d 低於下限 30：抽取器或矩陣疑似被削", cellCount)
	}

	// 三方比對：covered ∪ uncovered == baseline，且 covered ∩ uncovered == ∅
	for g := range uncovered {
		if !baseline[g] {
			t.Errorf("不涵蓋登記表列了不在基準表內的閘 %s", g)
		}
		if covered[g] {
			t.Errorf("閘 %s 同時被列為涵蓋與不涵蓋：矩陣已補上實跑格時應從 uncovered 移除", g)
		}
		if strings.TrimSpace(uncovered[g]) == "" {
			t.Errorf("不涵蓋的閘 %s 缺理由（缺理由即紅）", g)
		}
	}
	for g := range baseline {
		if covered[g] {
			continue
		}
		if _, declared := uncovered[g]; !declared {
			t.Errorf("閘 %s 既無實跑格、也未登記為刻意不涵蓋：涵蓋面宣稱大於證據"+
				"（要嘛補格，要嘛在 uncovered 登記理由）", g)
		}
	}
	if want := total - len(uncovered); len(covered) != want {
		t.Fatalf("實跑涵蓋閘數與登記表不符: covered=%d want=%d（基準表 %d − 不涵蓋 %d）",
			len(covered), want, total, len(uncovered))
	}
}

// ---------------------------------------------------------------------------
// StageRedeemConsole：查詢主控台兌換入口的矩陣格
//
// 第三條兌換入口共用同一張閘序表，另插兩道專屬閘（協議 G-C1、名額 G-C2）。
// 本段只釘「多出來的那兩道閘」與「全閘通過」——共用閘的逐格特徵化已在
// StageRedeemTerminal 完成，同表同碼，不重複跑一次
// ---------------------------------------------------------------------------

type gateConsoleCell struct {
	name       string
	gate       string
	protocol   string                              // 資產協議（決定 G-C1 的判定）
	setup      func(t *testing.T, env *consoleEnv) // 發票之前
	wantStatus int
	wantCode   apierror.ErrCode
}

// gateConsoleCells StageRedeemConsole 矩陣的全部格（涵蓋面自證的資料來源，同前兩段）
func gateConsoleCells() []gateConsoleCell {
	return []gateConsoleCell{
		{
			// 撥號目標埠 1 無人在聽 ⇒ 502＋連線階段泛化碼＝所有閘皆已通過的機器證據。
			// 對外碼不帶目標端訊息：連線階段的錯誤字串含主機、埠與憑證主體
			name: "全閘通過（帳號解析＝預設帳號）抵達撥號", gate: "—",
			protocol: "mysql",
			setup: func(t *testing.T, env *consoleEnv) {
				env.seedAccount(t)
				if err := env.db.Model(&model.Asset{}).Where("id = ?", 1).
					Updates(map[string]any{"host": "127.0.0.1", "port": 1}).Error; err != nil {
					t.Fatalf("set dial target: %v", err)
				}
			},
			wantStatus: http.StatusBadGateway, wantCode: apierror.CodeDBConsoleConnectFailed,
		},
		{
			// 非三方言的資產走不了這個入口；正確指引是改用命令列入口，故與
			// 「資產非文字終端」分碼
			name: "G-C1 資產協議非 SQL 方言", gate: "G-C1",
			protocol:   "redis",
			setup:      func(t *testing.T, env *consoleEnv) { env.seedAccount(t) },
			wantStatus: http.StatusBadRequest,
			wantCode:   apierror.CodeDBConsoleUnsupportedProtocol,
		},
		{
			// 名額佔滿後的兌換：計數口徑是運行時註冊表，不是會話表的 active 列
			name: "G-C2 同時進行的主控台會話達上限", gate: "G-C2",
			protocol: "mysql",
			setup: func(t *testing.T, env *consoleEnv) {
				env.seedAccount(t)
				for i := 0; i < dbconsole.MaxConcurrentSessionsPerUser; i++ {
					rel, denial := env.h.consoleAdmission().acquire(1)
					if denial != nil || rel == nil {
						t.Fatalf("第 %d 個名額佔用失敗: %+v", i+1, denial)
					}
				}
			},
			wantStatus: http.StatusTooManyRequests,
			wantCode:   apierror.CodeDBConsoleLimitReached,
		},
	}
}

// TestCharacterizationMatrixRedeemConsole StageRedeemConsole 逐格特徵化。
//
// 三項斷言與前兩段同構：狀態碼、拒絕碼、副作用（無 session 列、票已焚）。
// 「全閘通過」格的副作用同樣是零 session 列——起始連線失敗不建列，
// 該次嘗試的唯一痕跡在審計
func TestCharacterizationMatrixRedeemConsole(t *testing.T) {
	for _, cell := range gateConsoleCells() {
		t.Run(cell.name, func(t *testing.T) {
			env := setupConsoleEnv(t, cell.protocol)
			if cell.setup != nil {
				cell.setup(t, env)
			}
			tok := env.issueTicket(t)

			resp := env.redeem("?connect_token=" + tok)

			if resp.code != cell.wantStatus {
				t.Fatalf("[%s] HTTP 狀態不符: got=%d want=%d body=%s",
					cell.name, resp.code, cell.wantStatus, resp.body)
			}
			if !strings.Contains(resp.body, string(cell.wantCode)) {
				t.Fatalf("[%s] 拒絕碼不符: want=%q body=%s", cell.name, cell.wantCode, resp.body)
			}
			gateAssertNoSession(t, env.db, cell.name)

			replay := env.redeem("?connect_token=" + tok)
			if replay.code != http.StatusUnauthorized ||
				!strings.Contains(replay.body, string(apierror.CodeConnectTokenInvalid)) {
				t.Fatalf("[%s] token 於兌換後必須已焚: status=%d body=%s",
					cell.name, replay.code, replay.body)
			}
		})
	}
}
