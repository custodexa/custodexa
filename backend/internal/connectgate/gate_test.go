package connectgate

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 骨架本體的契約測試（modular-architecture W10）
//
// 只釘住**三處入口共用的骨架語義**，不重複驗各閘的內容——後者由
// `internal/sshproxy`／`internal/proxy` 的 characterization matrix 與
// failure-injection 以真實閘驗證。

// TestRunShortCircuitsAtFirstDenial 短路語義是契約的一部分：
// 第一個拒絕之後的閘 SHALL NOT 被執行（多執行一道＝多一次 DB 讀／多一筆副作用）
func TestRunShortCircuitsAtFirstDenial(t *testing.T) {
	var executed []string
	gates := []Gate{
		{Name: "A", Eval: func() *Outcome { executed = append(executed, "A"); return nil }},
		{Name: "B", Eval: func() *Outcome {
			executed = append(executed, "B")
			return Deny(403, "CODE_B", nil)
		}},
		{Name: "C", Eval: func() *Outcome { executed = append(executed, "C"); return nil }},
	}

	seq := NewSequence(func(gatewayapi.ConnectSubject) []Gate { return gates }, nil)
	out := seq.AuthorizePreResolve(context.Background(), gatewayapi.ConnectSubject{}, gatewayapi.StageIssue)
	if out == nil {
		t.Fatal("B 拒絕後應回傳 Outcome")
	}
	if !reflect.DeepEqual(executed, []string{"A", "B"}) {
		t.Fatalf("短路語義破損: executed=%v want=[A B]", executed)
	}
	// 拒絕者的閘名必須被填上——failure-injection 以此判定「拒的是哪一道閘」，
	// 空字串會讓那組斷言退化為只驗碼
	if out.Gate != "B" {
		t.Fatalf("Outcome.Gate 未填為拒絕者: got=%q want=B", out.Gate)
	}
	if out.Decision.Allowed {
		t.Fatal("拒絕結果的 Decision.Allowed 必須為 false")
	}
	if out.Decision.Code != "CODE_B" || out.Status != 403 {
		t.Fatalf("拒絕碼／狀態未原樣承載: code=%q status=%d", out.Decision.Code, out.Status)
	}
}

// TestRunAllPassReturnsNil 全通過回 nil（呼叫端據此進入下一段）
func TestRunAllPassReturnsNil(t *testing.T) {
	gates := []Gate{
		{Name: "A", Eval: func() *Outcome { return nil }},
		{Name: "B", Eval: nil}, // 未給 Eval 者視為通過，不得 panic
	}
	post := func(gs []Gate) ResolvedAccountGates {
		return func(gatewayapi.ConnectSubject, gatewayapi.ResolvedConnectObject) []Gate { return gs }
	}
	ctx, sub, obj := context.Background(), gatewayapi.ConnectSubject{}, gatewayapi.ResolvedConnectObject{}
	if out := NewSequence(nil, post(gates)).AuthorizeResolvedAccount(ctx, sub, obj,
		gatewayapi.StageRedeemTerminal); out != nil {
		t.Fatalf("全通過應回 nil: %+v", out)
	}
	if out := NewSequence(nil, post(nil)).AuthorizeResolvedAccount(ctx, sub, obj,
		gatewayapi.StageRedeemGraphical); out != nil {
		t.Fatalf("空閘序應回 nil: %+v", out)
	}
	// 未給 builder 的階段視為零閘、恆通過（呼叫端據此進入下一段）
	if out := NewSequence(nil, nil).AuthorizeResolvedAccount(ctx, sub, obj,
		gatewayapi.StageRedeemGraphical); out != nil {
		t.Fatalf("未繫結後階段應回 nil: %+v", out)
	}
}

// TestDenyInternalCarriesCause 內部故障分支：成因交給呼叫端以 RespondInternal 寫出
// （伺服端記原始成因、對外只回碼），不得混進一般 Write
func TestDenyInternalCarriesCause(t *testing.T) {
	cause := errors.New("db down")
	out := DenyInternal(500, "INTERNAL_X", cause)
	if out.Internal == nil || !errors.Is(out.Internal, cause) {
		t.Fatalf("成因未原樣承載: %+v", out.Internal)
	}
	if out.Meta != nil {
		t.Fatal("內部故障不得帶機器欄（會外洩內部狀態）")
	}
	if out.Decision.Code != "INTERNAL_X" || out.Status != 500 {
		t.Fatalf("碼／狀態不符: code=%q status=%d", out.Decision.Code, out.Status)
	}
}

// TestNamesMatchesDeclarationOrder 閘序名稱清單即等價表的比對依據
func TestNamesMatchesDeclarationOrder(t *testing.T) {
	got := Names([]Gate{{Name: "G-1"}, {Name: "G-2"}, {Name: "G-3"}})
	if !reflect.DeepEqual(got, []string{"G-1", "G-2", "G-3"}) {
		t.Fatalf("Names 未依宣告序: %v", got)
	}
}
