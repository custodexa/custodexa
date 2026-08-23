package sshproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/connectgate"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/proxy"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
)

// 逐閘 failure-injection ＋閘序等價（機器化的部分）
//
// **只驗拒絕碼不夠**：兩道不同的閘可能回同一個碼（G-S9 與 G-S13 同回
// AUTH_ASSET_CONNECT_DENIED），而「先寫審計再拒」與「先拒再寫審計」的碼也相同。
// 故每格斷言三件事：
//
//   - **拒絕碼**：與收斂前的行為基準逐字相同（現行權威＝connect_gates.go 各閘宣告的
//     拒絕碼）；
//   - **拒絕時機**：拒的是**哪一道閘**（以閘序表的位置判定，非以碼反推）；
//   - **副作用順序**：被拒之前**恰好**執行了哪些閘——短路語義是契約的一部分，
//     多執行一道就是多一次 DB 讀／多一筆審計，少執行一道就是漏了一道防線。

// gateWrap 以觀測包裝閘序，記錄實際執行到的閘名序列
func gateWrap(gates []connectgate.Gate, executed *[]string) []connectgate.Gate {
	wrapped := make([]connectgate.Gate, len(gates))
	for i := range gates {
		name := gates[i].Name
		orig := gates[i].Eval
		wrapped[i] = connectgate.Gate{Name: name, Eval: func() *connectgate.Outcome {
			*executed = append(*executed, name)
			return orig()
		}}
	}
	return wrapped
}

// gateObservePre／gateObservePost 驅動閘序並回傳（執行序列, 判定結果）。
//
// **只經 `gatewayapi.PolicyGate` 介面驅動**：本組守衛因此同時是
// 政策閘的消費側測試——閘序骨架若不能以契約的形狀被消費，這裡會編譯不過。
func gateObservePre(stage gatewayapi.Stage, sub gatewayapi.ConnectSubject,
	gates []connectgate.Gate) ([]string, *connectgate.Outcome) {
	executed := []string{}
	var gate gatewayapi.PolicyGate = connectgate.NewSequence(
		func(gatewayapi.ConnectSubject) []connectgate.Gate { return gateWrap(gates, &executed) }, nil)
	return executed, gate.AuthorizePreResolve(context.Background(), sub, stage)
}

func gateObservePost(stage gatewayapi.Stage, sub gatewayapi.ConnectSubject,
	obj gatewayapi.ResolvedConnectObject, gates []connectgate.Gate) ([]string, *connectgate.Outcome) {
	executed := []string{}
	var gate gatewayapi.PolicyGate = connectgate.NewSequence(nil,
		func(gatewayapi.ConnectSubject, gatewayapi.ResolvedConnectObject) []connectgate.Gate {
			return gateWrap(gates, &executed)
		})
	return executed, gate.AuthorizeResolvedAccount(context.Background(), sub, obj, stage)
}

// gateIssueSubject 簽發側主體：ClaimedRole 留空——本組驗的是閘序，
// 而閘序用的角色一律是 G-I2 現查後寫入 st.role 的那一份
func gateIssueSubject(userID uint) gatewayapi.ConnectSubject {
	return gatewayapi.ConnectSubject{UserID: userID}
}

// gateTestContext 造一個帶請求的 gin context（閘會用到 c.Request.Context()／ShouldBindJSON）
func gateTestContext(method, target string, body any) *gin.Context {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	var req *http.Request
	if body != nil {
		raw, _ := json.Marshal(body)
		req = httptest.NewRequest(method, target, bytes.NewBuffer(raw))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	c.Request = req
	return c
}

// ---------------------------------------------------------------------------
// 閘序等價（11.5 機器化）：宣告的閘序必須與基準表逐位相同
// ---------------------------------------------------------------------------

// gateBaselineIssuePre／Post 等價表 §1.1 的閘序（認證面 G-I1 與簽發動作 G-I14 不在骨架內）
var (
	gateBaselineIssuePre  = []string{"G-I2", "G-I3", "G-I4", "G-I5", "G-I6", "G-I7", "G-I8"}
	gateBaselineIssuePost = []string{"G-I10", "G-I11", "G-I12", "G-I13"}
	// 等價表 §1.2（G-S1／G-S2 為認證面，G-S6 為解封點本身的 fail-close）
	gateBaselineRedeemPre  = []string{"G-S3", "G-S4", "G-S5"}
	gateBaselineRedeemPost = []string{"G-S7", "G-S8", "G-S9", "G-S10", "G-S11", "G-S12", "G-S13"}
)

// TestGateSequenceMatchesBaseline 閘序＝資料，與等價表逐位比對。
// **這是「閘序未變」的機器證據**：任何插入、刪除、對調都會在此轉紅
func TestGateSequenceMatchesBaseline(t *testing.T) {
	h, _ := gateFixture(t)
	c := gateTestContext("POST", "/connect-tokens", map[string]any{"asset_id": 1})

	if got := connectgate.Names(h.issuePreResolveGates(c, gateIssueSubject(1), &issueState{})); !reflect.DeepEqual(got, gateBaselineIssuePre) {
		t.Fatalf("簽發側解封前閘序與基準表不符:\n got=%v\nwant=%v", got, gateBaselineIssuePre)
	}
	if got := connectgate.Names(h.issueResolvedAccountGates(c, gateIssueSubject(1),
		(&issueState{}).contractObject(), &issueState{})); !reflect.DeepEqual(got, gateBaselineIssuePost) {
		t.Fatalf("簽發側解封後閘序與基準表不符:\n got=%v\nwant=%v", got, gateBaselineIssuePost)
	}
	if got := connectgate.Names(h.redeemPreResolveGates(c, gatewayapi.ConnectSubject{},
		&redeemState{})); !reflect.DeepEqual(got, gateBaselineRedeemPre) {
		t.Fatalf("SSH 兌換側解封前閘序與基準表不符:\n got=%v\nwant=%v", got, gateBaselineRedeemPre)
	}
	if got := connectgate.Names(h.redeemResolvedAccountGates(c, gatewayapi.ConnectSubject{},
		gatewayapi.ResolvedConnectObject{}, &redeemState{})); !reflect.DeepEqual(got, gateBaselineRedeemPost) {
		t.Fatalf("SSH 兌換側解封後閘序與基準表不符:\n got=%v\nwant=%v", got, gateBaselineRedeemPost)
	}
}

// ---------------------------------------------------------------------------
// 逐閘 failure-injection
// ---------------------------------------------------------------------------

type gateInjectCell struct {
	name      string
	inject    func(t *testing.T, h *Handler, db *gorm.DB)
	accountID uint
	userID    uint
	// wantGate 期待拒絕的閘；wantExecuted 期待「恰好執行過」的閘序（含拒絕者本身）
	wantGate     string
	wantExecuted []string
	wantStatus   int
	wantCode     apierror.ErrCode
}

// TestIssueFailureInjectionPerGate 簽發側逐閘注入
func TestIssueFailureInjectionPerGate(t *testing.T) {
	cells := []gateInjectCell{
		{
			name: "G-I2 使用者停用",
			inject: func(t *testing.T, h *Handler, db *gorm.DB) {
				db.Model(&model.User{}).Where("id = ?", 1).Update("active", false)
			},
			wantGate: "G-I2", wantExecuted: []string{"G-I2"},
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeUserInactive,
		},
		{
			name: "G-I4 資產不存在",
			inject: func(t *testing.T, h *Handler, db *gorm.DB) {
				db.Where("id = ?", 1).Delete(&model.Asset{})
			},
			wantGate: "G-I4", wantExecuted: []string{"G-I2", "G-I3", "G-I4"},
			wantStatus: http.StatusNotFound, wantCode: apierror.CodeAssetNotFound,
		},
		{
			name: "G-I5 授權撤銷",
			inject: func(t *testing.T, h *Handler, db *gorm.DB) {
				db.Where("user_id = ?", 1).Delete(&model.AssetAuthorization{})
			},
			wantGate: "G-I5", wantExecuted: []string{"G-I2", "G-I3", "G-I4", "G-I5"},
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeAssetConnectDenied,
		},
		{
			name: "G-I6 資產停用",
			inject: func(t *testing.T, h *Handler, db *gorm.DB) {
				db.Model(&model.Asset{}).Where("id = ?", 1).Update("active", false)
			},
			wantGate: "G-I6", wantExecuted: []string{"G-I2", "G-I3", "G-I4", "G-I5", "G-I6"},
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeAssetDisabled,
		},
		{
			name: "G-I7 K8s 帶指定帳號",
			inject: func(t *testing.T, h *Handler, db *gorm.DB) {
				db.Model(&model.Asset{}).Where("id = ?", 1).Update("protocol", model.ProtocolK8s)
			},
			accountID: 4242,
			wantGate:  "G-I7", wantExecuted: []string{"G-I2", "G-I3", "G-I4", "G-I5", "G-I6", "G-I7"},
			wantStatus: http.StatusBadRequest, wantCode: apierror.CodeAccountK8sDefaultOnly,
		},
		{
			name:      "G-I8 帳號不存在",
			accountID: 4242,
			wantGate:  "G-I8", wantExecuted: []string{"G-I2", "G-I3", "G-I4", "G-I5", "G-I6", "G-I7", "G-I8"},
			wantStatus: http.StatusNotFound, wantCode: apierror.CodeAssetAccountNotFound,
		},
	}

	for _, cell := range cells {
		t.Run(cell.name, func(t *testing.T) {
			h, db := gateFixture(t)
			if cell.inject != nil {
				cell.inject(t, h, db)
			}
			body := map[string]any{"asset_id": 1}
			if cell.accountID != 0 {
				body["account_id"] = cell.accountID
			}
			c := gateTestContext("POST", "/connect-tokens", body)
			st := &issueState{}
			sub := gateIssueSubject(1)
			executed, out := gateObservePre(gatewayapi.StageIssue, sub,
				h.issuePreResolveGates(c, sub, st))
			gateAssertInjection(t, cell, executed, out)
		})
	}
}

// TestIssuePostResolveFailureInjection 簽發側解封後閘序逐閘注入
func TestIssuePostResolveFailureInjection(t *testing.T) {
	cells := []gateInjectCell{
		{
			name: "G-I10 帳號移出授權範圍",
			inject: func(t *testing.T, h *Handler, db *gorm.DB) {
				gateSeedAccount(t, db, 1, "root", true)
				db.Model(&model.AssetAuthorization{}).Where("user_id = ?", 1).
					Update("accounts", model.AccountScope{"app"})
			},
			wantGate: "G-I10", wantExecuted: []string{"G-I10"},
			wantStatus: http.StatusNotFound, wantCode: apierror.CodeAssetAccountNotFound,
		},
		{
			name: "G-I11 錄影 probe 失敗＋fail-close",
			inject: func(t *testing.T, h *Handler, db *gorm.DB) {
				h.RecordingPath = gateUnwritableRecordingPath(t)
				h.RecordingFailClose = func() bool { return true }
			},
			wantGate: "G-I11", wantExecuted: []string{"G-I10", "G-I11"},
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeRecordingUnavailable,
		},
		{
			name: "G-I12 存取政策收緊",
			inject: func(t *testing.T, h *Handler, db *gorm.DB) {
				setGroupPolicy(t, db, 1, model.AccessPolicyApproval)
			},
			wantGate: "G-I12", wantExecuted: []string{"G-I10", "G-I11", "G-I12"},
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeAccessApprovalRequired,
		},
	}

	for _, cell := range cells {
		t.Run(cell.name, func(t *testing.T) {
			h, db := gateFixture(t)
			if cell.inject != nil {
				cell.inject(t, h, db)
			}
			c := gateTestContext("POST", "/connect-tokens", map[string]any{"asset_id": 1})
			assetRow, err := h.AssetService.GetByID(1)
			if err != nil {
				t.Fatalf("fixture 資產取用失敗: %v", err)
			}
			identity, err := h.AssetService.ResolveAccountIdentity(1, 0)
			if err != nil {
				t.Fatalf("fixture 帳號解析失敗: %v", err)
			}
			st := &issueState{
				role:     model.RoleUser,
				req:      connectTokenRequest{AssetID: 1},
				assetRow: assetRow,
				identity: identity,
			}
			sub, obj := gateIssueSubject(1), st.contractObject()
			executed, out := gateObservePost(gatewayapi.StageIssue, sub, obj,
				h.issueResolvedAccountGates(c, sub, obj, st))
			gateAssertInjection(t, cell, executed, out)
		})
	}
}

// TestRedeemFailureInjectionPerGate SSH 兌換側解封後閘序逐閘注入
// （解封前三道由 characterization matrix 的 G-S3／G-S4／G-S5 格涵蓋）
func TestRedeemFailureInjectionPerGate(t *testing.T) {
	full := []string{"G-S7", "G-S8", "G-S9", "G-S10", "G-S11", "G-S12", "G-S13"}
	prefix := func(n int) []string { return full[:n] }

	cells := []gateInjectCell{
		{
			name: "G-S7 資產停用",
			inject: func(t *testing.T, h *Handler, db *gorm.DB) {
				db.Model(&model.Asset{}).Where("id = ?", 1).Update("active", false)
			},
			wantGate: "G-S7", wantExecuted: prefix(1),
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeAssetDisabled,
		},
		{
			name: "G-S8 協議非文字終端",
			inject: func(t *testing.T, h *Handler, db *gorm.DB) {
				db.Model(&model.Asset{}).Where("id = ?", 1).Update("protocol", model.ProtocolRDP)
			},
			wantGate: "G-S8", wantExecuted: prefix(2),
			wantStatus: http.StatusBadRequest, wantCode: apierror.CodeAssetNotTextTerminal,
		},
		{
			name: "G-S9 授權撤銷",
			inject: func(t *testing.T, h *Handler, db *gorm.DB) {
				db.Where("user_id = ?", 1).Delete(&model.AssetAuthorization{})
			},
			wantGate: "G-S9", wantExecuted: prefix(3),
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeAssetConnectDenied,
		},
		{
			name: "G-S10 存取政策收緊",
			inject: func(t *testing.T, h *Handler, db *gorm.DB) {
				setGroupPolicy(t, db, 1, model.AccessPolicyApproval)
			},
			wantGate: "G-S10", wantExecuted: prefix(4),
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeAccessApprovalRequired,
		},
		{
			name: "G-S11 零帳號資產",
			inject: func(t *testing.T, h *Handler, db *gorm.DB) {
				db.Where("asset_id = ?", 1).Delete(&model.AssetAccount{})
			},
			wantGate: "G-S11", wantExecuted: prefix(5),
			wantStatus: http.StatusNotFound, wantCode: apierror.CodeAccountNoneUsable,
		},
		{
			name: "G-S12 K8s 帶指定帳號",
			inject: func(t *testing.T, h *Handler, db *gorm.DB) {
				db.Model(&model.Asset{}).Where("id = ?", 1).Update("protocol", model.ProtocolK8s)
			},
			accountID: 1,
			wantGate:  "G-S12", wantExecuted: prefix(6),
			wantStatus: http.StatusBadRequest, wantCode: apierror.CodeAccountK8sDefaultOnly,
		},
		{
			name: "G-S13 帳號移出授權範圍",
			inject: func(t *testing.T, h *Handler, db *gorm.DB) {
				db.Model(&model.AssetAuthorization{}).Where("user_id = ?", 1).
					Update("accounts", model.AccountScope{"app"})
			},
			wantGate: "G-S13", wantExecuted: prefix(7),
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeAssetConnectDenied,
		},
	}

	for _, cell := range cells {
		t.Run(cell.name, func(t *testing.T) {
			h, db := gateFixture(t)
			gateSeedAccount(t, db, 1, "root", true)
			if cell.inject != nil {
				cell.inject(t, h, db)
			}
			// **無故障成功對照**：注入之前先確認同一夾具能一路走到底
			c := gateTestContext("GET", "/ssh?cols=80&rows=24", nil)
			creds, err := h.AssetService.GetWithCredentialsForAccount(1, cell.accountID)
			if err != nil {
				t.Fatalf("解封點取憑證失敗（本組注入不應影響解封點）: %v", err)
			}
			st := &redeemState{
				grant:       proxy.ConnectGrant{UserID: 1, AssetID: 1, AccountID: cell.accountID},
				currentRole: model.RoleUser,
				creds:       creds,
			}
			sub, obj := st.contractSubject(""), st.contractObject()
			executed, out := gateObservePost(gatewayapi.StageRedeemTerminal, sub, obj,
				h.redeemResolvedAccountGates(c, sub, obj, st))
			gateAssertInjection(t, cell, executed, out)
		})
	}
}

// TestRedeemNoFaultControl 無故障成功對照（fail-close 三件套的第一件）：
// 同一夾具在不注入任何故障時，七道解封後閘**全部執行且全部通過**。
// 沒有這一格，上面每一格的「紅」都可能來自別的前置條件而非注入本身
func TestRedeemNoFaultControl(t *testing.T) {
	h, db := gateFixture(t)
	gateSeedAccount(t, db, 1, "root", true)
	c := gateTestContext("GET", "/ssh?cols=80&rows=24", nil)
	creds, err := h.AssetService.GetWithCredentialsForAccount(1, 0)
	if err != nil {
		t.Fatalf("取憑證失敗: %v", err)
	}
	st := &redeemState{
		grant:       proxy.ConnectGrant{UserID: 1, AssetID: 1},
		currentRole: model.RoleUser,
		creds:       creds,
	}
	sub, obj := st.contractSubject(""), st.contractObject()
	executed, out := gateObservePost(gatewayapi.StageRedeemTerminal, sub, obj,
		h.redeemResolvedAccountGates(c, sub, obj, st))
	if out != nil {
		t.Fatalf("無故障對照不得被任何閘擋下: gate=%s code=%s", out.Gate, out.Decision.Code)
	}
	if !reflect.DeepEqual(executed, gateBaselineRedeemPost) {
		t.Fatalf("無故障時應逐道執行完整閘序:\n got=%v\nwant=%v", executed, gateBaselineRedeemPost)
	}
	// 解封確實產出了憑證與帳號身分（否則上面的「通過」可能是空跑）
	if creds.AccountID == 0 || creds.Username == "" {
		t.Fatalf("解封未產出帳號身分，對照組不成立: %+v", asset.AccountIdentity{
			AccountID: creds.AccountID, Username: creds.Username,
		})
	}
}

func gateAssertInjection(t *testing.T, cell gateInjectCell, executed []string, out *connectgate.Outcome) {
	t.Helper()
	if out == nil {
		t.Fatalf("[%s] 注入故障後閘序未拒絕（executed=%v）", cell.name, executed)
	}
	if out.Gate != cell.wantGate {
		t.Fatalf("[%s] 拒絕的閘不符（拒絕時機）: got=%s want=%s", cell.name, out.Gate, cell.wantGate)
	}
	if out.Decision.Code != string(cell.wantCode) {
		t.Fatalf("[%s] 拒絕碼不符: got=%s want=%s", cell.name, out.Decision.Code, cell.wantCode)
	}
	if out.Status != cell.wantStatus {
		t.Fatalf("[%s] HTTP 狀態不符: got=%d want=%d", cell.name, out.Status, cell.wantStatus)
	}
	if out.Decision.Allowed {
		t.Fatalf("[%s] 拒絕結果的 Decision.Allowed 必須為 false", cell.name)
	}
	if !reflect.DeepEqual(executed, cell.wantExecuted) {
		t.Fatalf("[%s] 副作用順序不符（短路語義）:\n got=%v\nwant=%v", cell.name, executed, cell.wantExecuted)
	}
}
