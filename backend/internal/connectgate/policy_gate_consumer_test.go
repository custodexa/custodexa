package connectgate_test

// PolicyGate 的**消費側**測試（modular-architecture W10.2，DoD-2）
//
// 「消費側」＝以 `gatewayapi.PolicyGate` 這個**介面型別**為依賴的測試，不是測某個實作。
// 本檔的 `runConnectGates` 只認得介面，對 `connectgate` 的存在一無所知——它與兩個
// 被驗對象（手寫替身、真實 `connectgate.Sequence`）跑同一組斷言，證明
// 「只經介面就能完成兩階段連線判定這件職責」。
//
// 替身這一半刻意不碰 connectgate：若哪天介面被改成非實作了 connectgate 內部結構
// 就無法滿足的形狀，替身這半會先編譯不過。

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"

	"github.com/custodexa/backend/internal/connectgate"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// runConnectGates 兩階段骨架的**純介面消費端**：
// AuthorizePreResolve → 解封（unseal）→ AuthorizeResolvedAccount。
//
// 三處生產入口跑的正是這個形狀。unseal 只在兩階段之間被呼叫，且前階段被拒時
// **不得**被呼叫——「解封位置」是本 change 唯一被機器強制的不變式。
func runConnectGates(
	ctx context.Context,
	gate gatewayapi.PolicyGate,
	sub gatewayapi.ConnectSubject,
	stage gatewayapi.Stage,
	unseal func() (gatewayapi.ResolvedConnectObject, error),
) (*gatewayapi.Denial, error) {
	if d := gate.AuthorizePreResolve(ctx, sub, stage); d != nil {
		return d, nil
	}
	obj, err := unseal()
	if err != nil {
		return nil, err
	}
	return gate.AuthorizeResolvedAccount(ctx, sub, obj, stage), nil
}

// ── 手寫替身：只依介面契約而生，完全不使用 connectgate ──────────────────

type stubGate struct {
	preDenial  *gatewayapi.Denial
	postDenial *gatewayapi.Denial
	sawSubject gatewayapi.ConnectSubject
	sawObject  gatewayapi.ResolvedConnectObject
	calls      []string
}

var _ gatewayapi.PolicyGate = (*stubGate)(nil)

func (s *stubGate) AuthorizePreResolve(_ context.Context,
	sub gatewayapi.ConnectSubject, _ gatewayapi.Stage) *gatewayapi.Denial {
	s.calls = append(s.calls, "pre")
	s.sawSubject = sub
	return s.preDenial
}

func (s *stubGate) AuthorizeResolvedAccount(_ context.Context,
	sub gatewayapi.ConnectSubject, o gatewayapi.ResolvedConnectObject,
	_ gatewayapi.Stage) *gatewayapi.Denial {
	s.calls = append(s.calls, "post")
	s.sawSubject = sub
	s.sawObject = o
	return s.postDenial
}

// ── 共用斷言：兩個實作跑同一組 ────────────────────────────────────────

func TestPolicyGateConsumerStopsAtPreResolveDenial(t *testing.T) {
	deny := &gatewayapi.Denial{Decision: gatewayapi.Decision{Code: "PRE_DENIED"}, Status: http.StatusForbidden}
	sub := gatewayapi.ConnectSubject{UserID: 7}

	cases := map[string]gatewayapi.PolicyGate{
		"手寫替身": &stubGate{preDenial: deny},
		"connectgate.Sequence": connectgate.NewSequence(
			func(gatewayapi.ConnectSubject) []connectgate.Gate {
				return []connectgate.Gate{{Name: "G-X", Eval: func() *connectgate.Outcome {
					return connectgate.Deny(http.StatusForbidden, "PRE_DENIED", nil)
				}}}
			},
			func(gatewayapi.ConnectSubject, gatewayapi.ResolvedConnectObject) []connectgate.Gate {
				t.Fatal("前階段被拒後，後階段閘序不得被建構")
				return nil
			}),
	}

	for name, gate := range cases {
		t.Run(name, func(t *testing.T) {
			unsealed := false
			d, err := runConnectGates(context.Background(), gate, sub, gatewayapi.StageIssue,
				func() (gatewayapi.ResolvedConnectObject, error) {
					unsealed = true
					return gatewayapi.ResolvedConnectObject{}, nil
				})
			if err != nil {
				t.Fatalf("消費端不應出錯: %v", err)
			}
			if d == nil {
				t.Fatal("前階段拒絕未被消費端回傳")
			}
			if d.Decision.Code != "PRE_DENIED" || d.Status != http.StatusForbidden {
				t.Fatalf("拒絕碼／狀態未原樣穿過介面: code=%q status=%d", d.Decision.Code, d.Status)
			}
			if d.Decision.Allowed {
				t.Fatal("拒絕結果的 Decision.Allowed 必須為 false")
			}
			// 這一條是紅線：前階段被拒時憑證**不得**被解封
			if unsealed {
				t.Fatal("前階段已拒，解封仍被執行——解封位置不變式破損")
			}
		})
	}
}

func TestPolicyGateConsumerPassesResolvedObjectToSecondStage(t *testing.T) {
	sub := gatewayapi.ConnectSubject{UserID: 7, ClaimedRole: "admin"}
	obj := gatewayapi.ResolvedConnectObject{
		ConnectObjectRef: gatewayapi.ConnectObjectRef{AssetID: 3, AccountID: 0, Protocol: "ssh"},
		Username:         "root",
	}

	// (1) 替身：直接檢查介面把主體與已解析客體原樣交到後階段
	stub := &stubGate{}
	if _, err := runConnectGates(context.Background(), stub, sub, gatewayapi.StageRedeemTerminal,
		func() (gatewayapi.ResolvedConnectObject, error) { return obj, nil }); err != nil {
		t.Fatalf("消費端不應出錯: %v", err)
	}
	if !reflect.DeepEqual(stub.calls, []string{"pre", "post"}) {
		t.Fatalf("兩階段呼叫序不符: %v", stub.calls)
	}
	if stub.sawObject.Username != "root" || stub.sawObject.AssetID != 3 {
		t.Fatalf("已解析客體未原樣穿過介面: %+v", stub.sawObject)
	}
	if stub.sawSubject.UserID != 7 {
		t.Fatalf("主體未原樣穿過介面: %+v", stub.sawSubject)
	}

	// (2) 真實 Sequence：閘序建構子確實收到同一組契約入參，
	//     且判定可以只依它們做出（帳號範圍閘吃的正是 o.Username）
	var gotUser string
	var gotUserID uint
	gate := connectgate.NewSequence(nil,
		func(s gatewayapi.ConnectSubject, o gatewayapi.ResolvedConnectObject) []connectgate.Gate {
			gotUserID = s.UserID
			gotUser = o.Username
			return []connectgate.Gate{{Name: "G-SCOPE", Eval: func() *connectgate.Outcome {
				if o.Username != "app" {
					return connectgate.Deny(http.StatusNotFound, "ACCOUNT_NOT_AUTHORIZED", nil)
				}
				return nil
			}}}
		})
	d, err := runConnectGates(context.Background(), gate, sub, gatewayapi.StageRedeemTerminal,
		func() (gatewayapi.ResolvedConnectObject, error) { return obj, nil })
	if err != nil {
		t.Fatalf("消費端不應出錯: %v", err)
	}
	if gotUserID != 7 || gotUser != "root" {
		t.Fatalf("Sequence 未把契約入參交給閘序建構子: userID=%d username=%q", gotUserID, gotUser)
	}
	if d == nil || d.Gate != "G-SCOPE" {
		t.Fatalf("以 o.Username 判定的閘未拒絕: %+v", d)
	}
}

// TestPolicyGateConsumerSurfacesInternalFault 內部故障分支必須能穿過介面：
// 呼叫端據 Internal 非 nil 決定「伺服端記原始成因、對外只回碼」。
// 這正是 (Decision, error) 表達不了、因而契約回傳 *Denial 的那一件事。
func TestPolicyGateConsumerSurfacesInternalFault(t *testing.T) {
	cause := errors.New("db down")
	gate := connectgate.NewSequence(
		func(gatewayapi.ConnectSubject) []connectgate.Gate {
			return []connectgate.Gate{{Name: "G-Y", Eval: func() *connectgate.Outcome {
				return connectgate.DenyInternal(http.StatusInternalServerError, "INTERNAL_X", cause)
			}}}
		}, nil)

	var consumer gatewayapi.PolicyGate = gate
	d := consumer.AuthorizePreResolve(context.Background(), gatewayapi.ConnectSubject{}, gatewayapi.StageIssue)
	if d == nil || !errors.Is(d.Internal, cause) {
		t.Fatalf("內部故障成因未穿過介面: %+v", d)
	}
	if d.Meta != nil {
		t.Fatal("內部故障不得帶機器欄（會外洩內部狀態）")
	}
}
