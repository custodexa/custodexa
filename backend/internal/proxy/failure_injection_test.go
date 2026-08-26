package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/connectgate"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
)

// 逐閘 failure-injection（圖形側）＋閘序等價（機器化）
//
// 職責與斷言口徑與文字側逐字相同：拒絕碼／拒絕時機（哪一道閘）／副作用順序
//（短路前恰好執行過哪些閘）。

var (
	// 等價表 §1.3（G-G1…G-G3 為連線收口防呆與認證面，G-G6 為解封點本身的 fail-close）
	gateBaselineGuacPre  = []string{"G-G4", "G-G13", "G-G5"}
	gateBaselineGuacPost = []string{"G-G7", "G-G8", "G-G9", "G-G10", "G-G11", "G-G12"}
)

// gateGuacObservePost 驅動解封後閘序並回傳（執行序列, 判定結果）。
//
// **只經 `gatewayapi.PolicyGate` 介面驅動**：本組守衛因此同時是
// 政策閘的消費側測試——閘序骨架若不能以契約的形狀被消費，這裡會編譯不過。
func gateGuacObservePost(stage gatewayapi.Stage, sub gatewayapi.ConnectSubject,
	obj gatewayapi.ResolvedConnectObject, gates []connectgate.Gate) ([]string, *connectgate.Outcome) {
	executed := []string{}
	wrapped := make([]connectgate.Gate, len(gates))
	for i := range gates {
		name := gates[i].Name
		orig := gates[i].Eval
		wrapped[i] = connectgate.Gate{Name: name, Eval: func() *connectgate.Outcome {
			executed = append(executed, name)
			return orig()
		}}
	}
	var gate gatewayapi.PolicyGate = connectgate.NewSequence(nil,
		func(gatewayapi.ConnectSubject, gatewayapi.ResolvedConnectObject) []connectgate.Gate {
			return wrapped
		})
	return executed, gate.AuthorizeResolvedAccount(context.Background(), sub, obj, stage)
}

func gateGuacContext() *gin.Context {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/connect", nil)
	return c
}

// TestGuacGateSequenceMatchesBaseline 圖形側閘序與等價表逐位比對
func TestGuacGateSequenceMatchesBaseline(t *testing.T) {
	h, _ := setupGraphicsRedeemTest(t)
	st := &graphicsRedeemState{}
	if got := connectgate.Names(h.redeemPreResolveGates(gatewayapi.ConnectSubject{}, st)); !reflect.DeepEqual(got, gateBaselineGuacPre) {
		t.Fatalf("圖形側解封前閘序與基準表不符:\n got=%v\nwant=%v", got, gateBaselineGuacPre)
	}
	if got := connectgate.Names(h.redeemResolvedAccountGates(gatewayapi.ConnectSubject{},
		gatewayapi.ResolvedConnectObject{}, st)); !reflect.DeepEqual(got, gateBaselineGuacPost) {
		t.Fatalf("圖形側解封後閘序與基準表不符:\n got=%v\nwant=%v", got, gateBaselineGuacPost)
	}
}

type gateGuacInjectCell struct {
	name         string
	inject       func(t *testing.T, h *ConnectionHandler, db *gorm.DB)
	accountID    uint
	wantGate     string
	wantExecuted []string
	wantStatus   int
	wantCode     apierror.ErrCode
}

// TestGuacFailureInjectionPerGate 圖形側解封後閘序逐閘注入
func TestGuacFailureInjectionPerGate(t *testing.T) {
	full := gateBaselineGuacPost
	prefix := func(n int) []string { return full[:n] }

	cells := []gateGuacInjectCell{
		{
			name: "G-G7 資產停用",
			inject: func(t *testing.T, h *ConnectionHandler, db *gorm.DB) {
				db.Model(&model.Asset{}).Where("id = ?", 1).Update("active", false)
			},
			wantGate: "G-G7", wantExecuted: prefix(1),
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeAssetDisabled,
		},
		{
			name: "G-G8 授權撤銷",
			inject: func(t *testing.T, h *ConnectionHandler, db *gorm.DB) {
				db.Where("user_id = ?", 1).Delete(&model.AssetAuthorization{})
			},
			wantGate: "G-G8", wantExecuted: prefix(2),
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeAssetConnectDenied,
		},
		{
			name: "G-G9 存取政策收緊",
			inject: func(t *testing.T, h *ConnectionHandler, db *gorm.DB) {
				db.Model(&model.Asset{}).Where("id = ?", 1).
					Update("access_policy", model.AccessPolicyApproval)
			},
			wantGate: "G-G9", wantExecuted: prefix(3),
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeAccessApprovalRequired,
		},
		{
			name: "G-G10 協議改為 SSH",
			inject: func(t *testing.T, h *ConnectionHandler, db *gorm.DB) {
				db.Model(&model.Asset{}).Where("id = ?", 1).Update("protocol", model.ProtocolSSH)
			},
			wantGate: "G-G10", wantExecuted: prefix(4),
			wantStatus: http.StatusBadRequest, wantCode: apierror.CodeSSHEndpointMoved,
		},
		{
			name: "G-G11 零帳號資產",
			inject: func(t *testing.T, h *ConnectionHandler, db *gorm.DB) {
				db.Where("asset_id = ?", 1).Delete(&model.AssetAccount{})
			},
			wantGate: "G-G11", wantExecuted: prefix(5),
			wantStatus: http.StatusNotFound, wantCode: apierror.CodeAccountNoneUsable,
		},
		{
			name: "G-G12 帳號移出授權範圍",
			inject: func(t *testing.T, h *ConnectionHandler, db *gorm.DB) {
				db.Model(&model.AssetAuthorization{}).Where("user_id = ?", 1).
					Update("accounts", model.AccountScope{"operator"})
			},
			wantGate: "G-G12", wantExecuted: prefix(6),
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeAssetConnectDenied,
		},
	}

	for _, cell := range cells {
		t.Run(cell.name, func(t *testing.T) {
			h, db := setupGraphicsRedeemTest(t)
			gateSeedGuacAccount(t, db, "administrator", true)
			if cell.inject != nil {
				cell.inject(t, h, db)
			}
			creds, err := h.AssetService.GetWithCredentialsForAccount(1, cell.accountID)
			if err != nil {
				t.Fatalf("解封點取憑證失敗（本組注入不應影響解封點）: %v", err)
			}
			c := gateGuacContext()
			st := &graphicsRedeemState{
				grant:       ConnectGrant{UserID: 1, AssetID: 1, AccountID: cell.accountID},
				currentRole: model.RoleUser,
				authzCtx:    c.Request.Context(),
				creds:       creds,
			}
			sub, obj := st.contractSubject(""), st.contractObject()
			executed, out := gateGuacObservePost(gatewayapi.StageRedeemGraphical, sub, obj,
				h.redeemResolvedAccountGates(sub, obj, st))
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
			if !reflect.DeepEqual(executed, cell.wantExecuted) {
				t.Fatalf("[%s] 副作用順序不符（短路語義）:\n got=%v\nwant=%v", cell.name, executed, cell.wantExecuted)
			}
		})
	}
}

// TestGuacNoFaultControl 無故障成功對照：六道解封後閘全部執行且全部通過
func TestGuacNoFaultControl(t *testing.T) {
	h, db := setupGraphicsRedeemTest(t)
	gateSeedGuacAccount(t, db, "administrator", true)
	creds, err := h.AssetService.GetWithCredentialsForAccount(1, 0)
	if err != nil {
		t.Fatalf("取憑證失敗: %v", err)
	}
	c := gateGuacContext()
	st := &graphicsRedeemState{
		grant:       ConnectGrant{UserID: 1, AssetID: 1},
		currentRole: model.RoleUser,
		authzCtx:    c.Request.Context(),
		creds:       creds,
	}
	sub, obj := st.contractSubject(""), st.contractObject()
	executed, out := gateGuacObservePost(gatewayapi.StageRedeemGraphical, sub, obj,
		h.redeemResolvedAccountGates(sub, obj, st))
	if out != nil {
		t.Fatalf("無故障對照不得被任何閘擋下: gate=%s code=%s", out.Gate, out.Decision.Code)
	}
	if !reflect.DeepEqual(executed, gateBaselineGuacPost) {
		t.Fatalf("無故障時應逐道執行完整閘序:\n got=%v\nwant=%v", executed, gateBaselineGuacPost)
	}
	if creds.AccountID == 0 || creds.Username == "" {
		t.Fatalf("解封未產出帳號身分，對照組不成立: accountID=%d username=%q", creds.AccountID, creds.Username)
	}
}
