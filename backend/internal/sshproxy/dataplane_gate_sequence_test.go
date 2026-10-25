package sshproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/connectgate"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// TestDataPlaneGateSequence 鎖定資料面裁決實際組出的閘清單與順序。
//
// 資料面以閘名從簽發側閘序挑閘：簽發側若把某道閘改名，名單挑不到它，裁決會靜默
// 少一道閘，而多數行為測試不會察覺。本測試取的是 AuthorizeDataPlane 使用的同一組
// 組裝函式（dataPlanePreResolveGates／dataPlaneResolvedAccountGates），少一道、
// 多一道或順序變動都轉紅。另兩格直接評估挑出的來源閘與傳輸閘，確認名稱底下確實是
// 簽發側那道判定，且觸發條件成立時會拒絕。
//
// 突變自檢：自 dataPlanePreGateNames 刪去 "G-I15"、或自 dataPlanePostGateNames
// 刪去 "G-I13"，第一格轉紅。
func TestDataPlaneGateSequence(t *testing.T) {
	newCtx := func() *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/assets/1/k8s/upload", nil)
		return c
	}
	compose := func(h *Handler, s gatewayapi.ConnectSubject, st *issueState) []connectgate.Gate {
		c := newCtx()
		gates := h.dataPlanePreResolveGates(c, s, st)
		return append(gates, h.dataPlaneResolvedAccountGates(c, s, st.contractObject(), st)...)
	}
	find := func(t *testing.T, gates []connectgate.Gate, name string) connectgate.Gate {
		t.Helper()
		for _, g := range gates {
			if g.Name == name {
				return g
			}
		}
		t.Fatalf("資料面閘序缺 %s", name)
		return connectgate.Gate{}
	}

	t.Run("實際組出的閘清單與順序固定", func(t *testing.T) {
		h, _, _ := setupPolicyGateTest(t)
		input := &ConnectTokenRequest{AssetID: 1}
		st := &issueState{input: input, req: *input}
		var got []string
		for _, g := range compose(h, gatewayapi.ConnectSubject{UserID: 1}, st) {
			got = append(got, g.Name)
		}
		want := []string{"G-I2", "G-I15", "G-I4", "G-I5", "G-I6", "G-D1", "G-I7", "G-I10", "G-I12", "G-I13"}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("資料面閘序不符：\n got  %v\n want %v", got, want)
		}
	})

	t.Run("挑出的來源閘即簽發側來源限定：清單外來源被拒", func(t *testing.T) {
		h, _, _ := setupPolicyGateTest(t)
		input := &ConnectTokenRequest{AssetID: 1}
		st := &issueState{input: input, req: *input, allowedCIDRs: "10.0.0.0/8"}
		s := gatewayapi.ConnectSubject{UserID: 1, ClientIP: "192.0.2.10"}
		out := find(t, compose(h, s, st), "G-I15").Eval()
		if out == nil || out.Status != http.StatusForbidden || out.Decision.Code != string(apierror.CodeAuthSourceNotAllowed) {
			t.Fatalf("清單外來源應以來源限定碼拒絕，得 %+v", out)
		}
		st.allowedCIDRs = "192.0.2.0/24"
		if out := find(t, compose(h, s, st), "G-I15").Eval(); out != nil {
			t.Fatalf("清單內來源應通過，得 %+v", out)
		}
	})

	t.Run("挑出的傳輸閘即簽發側傳輸安全：嚴格政策下有風險的資產被拒", func(t *testing.T) {
		// 正式路徑上 K8s 不在傳輸安全通道內，此閘恆通過（協定閘在它之前擋下其他協定）；
		// 此格以有風險的資產列直接評估挑出的閘，證明名稱底下是那道判定、條件成立會拒絕
		h, db, policies := setupPolicyGateTest(t)
		if _, err := policies.Update(policy.PolicyTransportVNCLevel, policy.TransportLevelStrict, "admin"); err != nil {
			t.Fatalf("set transport strict: %v", err)
		}
		h.TransmissionConsent = policy.NewTransmissionConsentService(db, policy.NewTransmissionPolicyService(policies, nil))
		input := &ConnectTokenRequest{AssetID: 9}
		st := &issueState{input: input, req: *input,
			assetRow: &model.Asset{ID: 9, Name: "vnc-risky", Protocol: model.ProtocolVNC, Active: true}}
		out := find(t, compose(h, gatewayapi.ConnectSubject{UserID: 1, ClientIP: "192.0.2.10"}, st), "G-I13").Eval()
		if out == nil || out.Status != http.StatusBadRequest || out.Decision.Code != string(apierror.CodeTransmissionStrictReject) {
			t.Fatalf("嚴格政策下有風險的資產應以傳輸安全碼拒絕，得 %+v", out)
		}
		st.assetRow = &model.Asset{ID: 1, Name: "cluster", Protocol: model.ProtocolK8s, Active: true}
		if out := find(t, compose(h, gatewayapi.ConnectSubject{UserID: 1, ClientIP: "192.0.2.10"}, st), "G-I13").Eval(); out != nil {
			t.Fatalf("K8s 資產不在傳輸安全通道內，應通過，得 %+v", out)
		}
	})
}
