package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 連線閘序 characterization matrix — StageRedeemGraphical
//
// 與 `internal/sshproxy/characterization_matrix_test.go` 同一份職責，格名以閘編號
// （G-G*）標註。**編號的定義在 `internal/proxy/connect_gates.go`**——每個 `{Name: "G-…"}`
// 之後緊接該閘的實作與理由；本檔的 `TestGuacMatrixCoverageIsDeclared` 則是編號的
// 完整登記表（含刻意不涵蓋者與其逐條理由）。
// 圖形側單獨成檔的理由：兩個入口分屬不同 package，共用夾具會逼出跨包測試接縫。
//
// 副作用斷言同文字側：閘拒絕 SHALL NOT 留下 session 列，且 token 一經 Resolve 即焚。

// gateRedeemGuac 兌換圖形連線；extra 為附加 query（供連線收口防呆格使用）
func gateRedeemGuac(h *ConnectionHandler, token, extra string) (int, map[string]any) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/connect", h.HandleConnect)
	url := "/connect?connect_token=" + token
	if extra != "" {
		url += "&" + extra
	}
	req := httptest.NewRequest("GET", url, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp
}

func gateSeedGuacAccount(t *testing.T, db *gorm.DB, username string, isDefault bool) uint {
	t.Helper()
	acct := model.AssetAccount{AssetID: 1, Username: username, IsDefault: isDefault}
	if err := db.Create(&acct).Error; err != nil {
		t.Fatalf("seed account: %v", err)
	}
	return acct.ID
}

func gateGuacAssertNoSession(t *testing.T, db *gorm.DB, cell string) {
	t.Helper()
	var n int64
	if err := db.Model(&model.Session{}).Count(&n).Error; err != nil {
		t.Fatalf("[%s] count sessions: %v", cell, err)
	}
	if n != 0 {
		t.Fatalf("[%s] 閘拒絕後不得留下 session 列，實得 %d 列", cell, n)
	}
}

type gateGuacCell struct {
	name       string
	gate       string
	setup      func(t *testing.T, h *ConnectionHandler, db *gorm.DB)
	mutate     func(t *testing.T, h *ConnectionHandler, db *gorm.DB)
	grant      ConnectGrant
	rawToken   string
	noToken    bool
	extraQuery string
	wantStatus int
	wantCode   apierror.ErrCode
	wantMeta   map[string]any
	wantAbsent []string
	wantBurned bool
}

// gateGuacCells StageRedeemGraphical 矩陣的全部格。
//
// **獨立於測試函式存在，是為了讓涵蓋面自證能真正耦合**：`TestGuacMatrixCoverageIsDeclared`
// 直接從本函式擷取 `gate` 欄（原版只比對兩個硬編碼常數，恆真）。
func gateGuacCells() []gateGuacCell {
	seedDefault := func(t *testing.T, h *ConnectionHandler, db *gorm.DB) {
		gateSeedGuacAccount(t, db, "administrator", true)
	}

	return []gateGuacCell{
		{
			name: "全閘通過（帳號解析＝預設帳號）抵達 guacd 握手", gate: "—",
			setup: seedDefault,
			grant: ConnectGrant{UserID: 1, AssetID: 1},
			// 測試環境 localhost:4822 無 guacd ⇒ 握手失敗＝所有閘皆已通過的機器證據
			wantStatus: http.StatusInternalServerError, wantCode: apierror.CodeGuacdHandshake,
			wantBurned: true,
		},
		{
			name: "G-G1 URL 帶目標／憑證參數（連線收口防呆）", gate: "G-G1",
			setup:      seedDefault,
			grant:      ConnectGrant{UserID: 1, AssetID: 1},
			extraQuery: "hostname=evil.example",
			wantStatus: http.StatusBadRequest, wantCode: apierror.CodeConnectTargetParamsRejected,
			// 本閘在 Resolve 之前 ⇒ token 未被消費（拒絕時機的機器證據）
			wantBurned: false,
		},
		{
			name: "G-G2 connect_token 缺失", gate: "G-G2",
			noToken:    true,
			wantStatus: http.StatusUnauthorized, wantCode: apierror.CodeConnectTokenMissing,
		},
		{
			name: "G-G3 connect_token 無效", gate: "G-G3",
			rawToken:   "not-a-real-token",
			wantStatus: http.StatusUnauthorized, wantCode: apierror.CodeConnectTokenInvalid,
		},
		{
			name: "G-G4 使用者已停用", gate: "G-G4",
			setup: seedDefault,
			mutate: func(t *testing.T, h *ConnectionHandler, db *gorm.DB) {
				if err := db.Model(&model.User{}).Where("id = ?", 1).Update("active", false).Error; err != nil {
					t.Fatalf("deactivate: %v", err)
				}
			},
			grant:      ConnectGrant{UserID: 1, AssetID: 1},
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeUserInactive,
			wantBurned: true,
		},
		{
			name: "G-G4 帳號鎖定中", gate: "G-G4",
			setup: seedDefault,
			mutate: func(t *testing.T, h *ConnectionHandler, db *gorm.DB) {
				until := time.Now().Add(time.Hour)
				if err := db.Model(&model.User{}).Where("id = ?", 1).Update("locked_until", until).Error; err != nil {
					t.Fatalf("lock: %v", err)
				}
			},
			grant:      ConnectGrant{UserID: 1, AssetID: 1},
			wantStatus: http.StatusLocked, wantCode: apierror.CodeAccountLocked,
			wantBurned: true,
		},
		{
			// 兌換側現讀、不信簽發：票證在允許位址簽出，換個位址兌換照樣擋
			name: "G-G13 兌換當下來源不在允許網段", gate: "G-G13",
			setup: seedDefault,
			mutate: func(t *testing.T, h *ConnectionHandler, db *gorm.DB) {
				gateGuacSetAllowedCIDRs(t, db, 1, "10.0.0.0/8")
			},
			grant:      ConnectGrant{UserID: 1, AssetID: 1},
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeAuthSourceNotAllowed,
			wantMeta:   map[string]any{"reason": "source_not_allowed"},
			wantBurned: true,
		},
		{
			// 政策損壞不得視為空清單放行；對外形狀與上一格逐字相同
			name: "G-G13 清單字串損壞（不得當成不限）", gate: "G-G13",
			setup: seedDefault,
			mutate: func(t *testing.T, h *ConnectionHandler, db *gorm.DB) {
				gateGuacSetAllowedCIDRs(t, db, 1, "10.0.0.0/8,garbage")
			},
			grant:      ConnectGrant{UserID: 1, AssetID: 1},
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeAuthSourceNotAllowed,
			wantMeta:   map[string]any{"reason": "source_not_allowed"},
			wantBurned: true,
		},
		{
			name: "G-G5 憑證世代被推進", gate: "G-G5",
			setup: seedDefault,
			mutate: func(t *testing.T, h *ConnectionHandler, db *gorm.DB) {
				if err := db.Model(&model.User{}).Where("id = ?", 1).
					Update("credential_epoch", 7).Error; err != nil {
					t.Fatalf("bump epoch: %v", err)
				}
			},
			grant:      ConnectGrant{UserID: 1, AssetID: 1},
			wantStatus: http.StatusUnauthorized, wantCode: apierror.CodeConnectTokenInvalid,
			wantBurned: true,
		},
		{
			name: "G-G6 帳號於簽發後被刪", gate: "G-G6",
			setup: func(t *testing.T, h *ConnectionHandler, db *gorm.DB) {
				gateSeedGuacAccount(t, db, "administrator", true)
				gateSeedGuacAccount(t, db, "operator", false)
			},
			mutate: func(t *testing.T, h *ConnectionHandler, db *gorm.DB) {
				if err := db.Delete(&model.AssetAccount{}, 2).Error; err != nil {
					t.Fatalf("delete account: %v", err)
				}
			},
			grant:      ConnectGrant{UserID: 1, AssetID: 1, AccountID: 2},
			wantStatus: http.StatusNotFound, wantCode: apierror.CodeAssetAccountNotFound,
			wantBurned: true,
		},
		{
			name: "G-G7 資產於簽發後被停用", gate: "G-G7",
			setup: seedDefault,
			mutate: func(t *testing.T, h *ConnectionHandler, db *gorm.DB) {
				if err := db.Model(&model.Asset{}).Where("id = ?", 1).Update("active", false).Error; err != nil {
					t.Fatalf("disable: %v", err)
				}
			},
			grant:      ConnectGrant{UserID: 1, AssetID: 1},
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeAssetDisabled,
			wantMeta:   map[string]any{"reason": "asset_disabled"},
			wantBurned: true,
		},
		{
			name: "G-G8 連線授權於簽發後被撤銷", gate: "G-G8",
			setup: seedDefault,
			mutate: func(t *testing.T, h *ConnectionHandler, db *gorm.DB) {
				if err := db.Where("user_id = ?", 1).Delete(&model.AssetAuthorization{}).Error; err != nil {
					t.Fatalf("revoke: %v", err)
				}
			},
			grant:      ConnectGrant{UserID: 1, AssetID: 1},
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeAssetConnectDenied,
			wantBurned: true,
		},
		{
			name: "G-G9 存取政策收緊為 approval", gate: "G-G9",
			setup: seedDefault,
			mutate: func(t *testing.T, h *ConnectionHandler, db *gorm.DB) {
				if err := db.Model(&model.Asset{}).Where("id = ?", 1).
					Update("access_policy", model.AccessPolicyApproval).Error; err != nil {
					t.Fatalf("set policy: %v", err)
				}
			},
			grant:      ConnectGrant{UserID: 1, AssetID: 1},
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeAccessApprovalRequired,
			wantMeta:   map[string]any{"reason": "approval_required"},
			wantAbsent: []string{"max_duration_minutes", "pending_request_id"},
			wantBurned: true,
		},
		{
			name: "G-G9 存取政策收緊為 reason（碼隨 reason 分流）", gate: "G-G9",
			setup: seedDefault,
			mutate: func(t *testing.T, h *ConnectionHandler, db *gorm.DB) {
				if err := db.Model(&model.Asset{}).Where("id = ?", 1).
					Update("access_policy", model.AccessPolicyReason).Error; err != nil {
					t.Fatalf("set policy: %v", err)
				}
			},
			grant:      ConnectGrant{UserID: 1, AssetID: 1},
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeAccessReasonRequired,
			wantMeta:   map[string]any{"reason": "reason_required"},
			wantBurned: true,
		},
		{
			name: "G-G10 SSH 協議已退出 guacd 路徑", gate: "G-G10",
			setup: func(t *testing.T, h *ConnectionHandler, db *gorm.DB) {
				gateSeedGuacAccount(t, db, "root", true)
				if err := db.Model(&model.Asset{}).Where("id = ?", 1).
					Update("protocol", model.ProtocolSSH).Error; err != nil {
					t.Fatalf("set ssh: %v", err)
				}
			},
			grant:      ConnectGrant{UserID: 1, AssetID: 1},
			wantStatus: http.StatusBadRequest, wantCode: apierror.CodeSSHEndpointMoved,
			wantBurned: true,
		},
		{
			name: "G-G11 零帳號資產 fail-close", gate: "G-G11",
			grant:      ConnectGrant{UserID: 1, AssetID: 1},
			wantStatus: http.StatusNotFound, wantCode: apierror.CodeAccountNoneUsable,
			wantBurned: true,
		},
		{
			name: "G-G12 帳號於簽發後移出授權範圍（兌換側 403）", gate: "G-G12",
			setup: seedDefault,
			mutate: func(t *testing.T, h *ConnectionHandler, db *gorm.DB) {
				if err := db.Model(&model.AssetAuthorization{}).Where("user_id = ?", 1).
					Update("accounts", model.AccountScope{"operator"}).Error; err != nil {
					t.Fatalf("narrow scope: %v", err)
				}
			},
			grant:      ConnectGrant{UserID: 1, AssetID: 1},
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeAssetConnectDenied,
			wantBurned: true,
		},
	}
}

// gateGuacSetAllowedCIDRs 直寫使用者的允許來源網段（理由同文字側的同名輔助：
// 「儲存字串損壞」那一格按定義造不出於 service 層）
func gateGuacSetAllowedCIDRs(t *testing.T, db *gorm.DB, userID uint, raw string) {
	t.Helper()
	if err := db.Model(&model.User{}).Where("id = ?", userID).
		Update("allowed_cidrs", raw).Error; err != nil {
		t.Fatalf("set allowed_cidrs: %v", err)
	}
}

// TestCharacterizationMatrixRedeemGraphical StageRedeemGraphical 逐格特徵化
func TestCharacterizationMatrixRedeemGraphical(t *testing.T) {
	for _, cell := range gateGuacCells() {
		t.Run(cell.name, func(t *testing.T) {
			h, db := setupGraphicsRedeemTest(t)
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
			status, resp := gateRedeemGuac(h, token, cell.extraQuery)

			if status != cell.wantStatus {
				t.Fatalf("[%s] HTTP 狀態不符: got=%d want=%d resp=%v", cell.name, status, cell.wantStatus, resp)
			}
			if got, _ := resp["code"].(string); got != string(cell.wantCode) {
				t.Fatalf("[%s] 拒絕碼不符: got=%q want=%q resp=%v", cell.name, got, cell.wantCode, resp)
			}
			for k, v := range cell.wantMeta {
				got, ok := resp[k]
				if !ok {
					t.Fatalf("[%s] 回應缺機器欄 %q: resp=%v", cell.name, k, resp)
				}
				if fmt.Sprint(got) != fmt.Sprint(v) {
					t.Fatalf("[%s] 機器欄 %q 不符: got=%v want=%v", cell.name, k, got, v)
				}
			}
			for _, k := range cell.wantAbsent {
				if _, ok := resp[k]; ok {
					t.Fatalf("[%s] 機器欄 %q 不應存在: resp=%v", cell.name, k, resp)
				}
			}
			gateGuacAssertNoSession(t, db, cell.name)
			if cell.rawToken == "" && !cell.noToken {
				replayStatus, replayResp := gateRedeemGuac(h, token, "")
				burned := replayStatus == http.StatusUnauthorized &&
					replayResp["code"] == string(apierror.CodeConnectTokenInvalid)
				if burned != cell.wantBurned {
					t.Fatalf("[%s] token 消費狀態不符（拒絕時機證據）: burned=%v want=%v status=%d resp=%v",
						cell.name, burned, cell.wantBurned, replayStatus, replayResp)
				}
			}
		})
	}
}

// TestGuacMatrixCoverageIsDeclared 涵蓋面自證：**涵蓋集合從實際矩陣格機器擷取**
//
// 圖形側宣稱「12／12 全涵蓋」，本測試即該宣稱的機器證據：每一道基準表 §1.3 的閘
// 都必須有至少一格實跑格宣稱涵蓋它，缺一即紅；格宣稱了基準表外的閘也紅。
// 原版只比對兩個硬編碼常數（`len(gates)!=12`、`len(uncovered)!=0`），與矩陣零耦合。
func TestGuacMatrixCoverageIsDeclared(t *testing.T) {
	// G-G13＝來源限定閘（G1）。編號接在末尾而位置在 G-G4 之後是既有慣例：
	// 編號是穩定識別碼，不是序號（見 internal/connectgate 檔頭）
	gates := []string{"G-G1", "G-G2", "G-G3", "G-G4", "G-G5", "G-G6",
		"G-G7", "G-G8", "G-G9", "G-G10", "G-G11", "G-G12", "G-G13"}
	baseline := map[string]bool{}
	for _, g := range gates {
		baseline[g] = true
	}
	// 刻意不涵蓋：圖形側為空集合。非空時每條須附理由（與文字側同一紀律）
	uncovered := map[string]string{}
	if len(gates) != 13 {
		t.Fatalf("基準表 §1.3 閘數與矩陣宣稱不符: got=%d want=13", len(gates))
	}

	covered := map[string]bool{}
	cellCount := 0
	for _, c := range gateGuacCells() {
		cellCount++
		if c.gate == "—" {
			continue
		}
		if c.gate == "" {
			t.Errorf("格 %q 未標註 gate 欄（涵蓋面無從擷取；全閘通過格請標 \"—\"）", c.name)
			continue
		}
		if !strings.HasPrefix(c.name, c.gate+" ") {
			t.Errorf("格名與 gate 欄不一致: name=%q gate=%q（格名須以閘號開頭）", c.name, c.gate)
		}
		if !baseline[c.gate] {
			t.Errorf("格 %q 宣稱涵蓋 %s，但該閘不在基準表 §1.3 內", c.name, c.gate)
			continue
		}
		covered[c.gate] = true
	}
	if cellCount < 14 {
		t.Fatalf("矩陣格數 %d 低於下限 12：抽取器或矩陣疑似被削", cellCount)
	}
	for g := range baseline {
		if covered[g] {
			continue
		}
		if reason, declared := uncovered[g]; !declared {
			t.Errorf("閘 %s 既無實跑格、也未登記為刻意不涵蓋：圖形側「12／12 全涵蓋」的宣稱大於證據", g)
		} else if strings.TrimSpace(reason) == "" {
			t.Errorf("不涵蓋的閘 %s 缺理由（缺理由即紅）", g)
		}
	}
	if want := len(gates) - len(uncovered); len(covered) != want {
		t.Fatalf("實跑涵蓋閘數與登記表不符: covered=%d want=%d", len(covered), want)
	}
}
