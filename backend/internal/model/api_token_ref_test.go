package model

import (
	"context"
	"testing"
)

// 帶 token 標示的稽核列，於入庫匯流點補上該次請求的識別與來源位址：三種 context 來源都補、
// 寫入端已帶值的欄位不覆寫、列上的標示與 context 不是同一把 token 時不補、親自操作的請求不動。

func tokenReqCtx(id uint, name string, o RequestOrigin) context.Context {
	ctx := WithRequestCredential(context.Background(), RequestCredentialAPIToken)
	ctx = WithAPITokenRef(ctx, APITokenRef{ID: id, Name: name})
	return WithRequestOrigin(ctx, o)
}

func TestAttributeAuditFromContextFillsRequestOrigin(t *testing.T) {
	origin := RequestOrigin{RequestID: "req-1", ClientIP: "192.0.2.10"}
	tok := func(id uint, name string) (*uint, *string) { return &id, &name }

	cases := []struct {
		name           string
		ctx            context.Context
		row            AuditLog
		wantToken      uint // 0＝不應帶標示
		wantID, wantIP string
	}{
		{"請求 context", tokenReqCtx(7, "ci", origin), AuditLog{}, 7, "req-1", "192.0.2.10"},
		{"只帶歸因標示的 context", AuditAttributionContext(tokenReqCtx(7, "ci", origin)), AuditLog{}, 7, "req-1", "192.0.2.10"},
		{"操作者組出的稽核請求脈絡", WithAuditRequest(context.Background(), AuditRequest{
			UserID: 3, Username: "admin", RequestID: "req-2", ClientIP: "192.0.2.20", APITokenID: 7, APITokenName: "ci"}),
			AuditLog{}, 7, "req-2", "192.0.2.20"},
		{"寫入端已標上同一把 token", WithAuditRequest(context.Background(), AuditRequest{
			UserID: 3, Username: "admin", RequestID: "req-2", ClientIP: "192.0.2.20", APITokenID: 7, APITokenName: "ci"}),
			func() AuditLog { a := AuditLog{}; a.APITokenID, a.APITokenName = tok(7, "ci"); return a }(), 7, "req-2", "192.0.2.20"},
		{"寫入端已帶的值不覆寫", tokenReqCtx(7, "ci", origin),
			AuditLog{RequestID: "own-req", ClientIP: "198.51.100.5"}, 7, "own-req", "198.51.100.5"},
		{"只缺請求識別時只補請求識別", tokenReqCtx(7, "ci", origin),
			AuditLog{ClientIP: "198.51.100.5"}, 7, "req-1", "198.51.100.5"},
		{"列上的標示與 context 不同把 token", tokenReqCtx(7, "ci", origin),
			func() AuditLog { a := AuditLog{}; a.APITokenID, a.APITokenName = tok(9, "other"); return a }(), 9, "", ""},
		{"親自操作的稽核請求脈絡", WithAuditRequest(context.Background(), AuditRequest{
			UserID: 3, Username: "admin", RequestID: "req-3", ClientIP: "192.0.2.30"}), AuditLog{}, 0, "", ""},
		{"親自操作的請求 context", WithRequestOrigin(context.Background(), origin), AuditLog{}, 0, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			row := c.row
			attributeAuditFromContext(&row, c.ctx)
			var got uint
			if row.APITokenID != nil {
				got = *row.APITokenID
			}
			if got != c.wantToken {
				t.Fatalf("token 標示 = %d，應為 %d", got, c.wantToken)
			}
			if row.RequestID != c.wantID || row.ClientIP != c.wantIP {
				t.Errorf("request_id=%q client_ip=%q，應為 %q %q", row.RequestID, row.ClientIP, c.wantID, c.wantIP)
			}
		})
	}
}

// TestAuditBeforeCreateFillsOriginBeforeStamp 入庫匯流點先補值再蓋章：蓋章時看到的列已帶請求識別與來源位址。
func TestAuditBeforeCreateFillsOriginBeforeStamp(t *testing.T) {
	var seenID, seenIP string
	SetAuditCreateHooks(func(a *AuditLog) { seenID, seenIP = a.RequestID, a.ClientIP }, nil)
	t.Cleanup(func() { SetAuditCreateHooks(nil, nil) })

	db := newRoleAuditDB(t)
	ctx := WithAuditRequest(context.Background(), AuditRequest{
		UserID: 3, Username: "admin", RequestID: "req-stamp", ClientIP: "192.0.2.40", APITokenID: 7, APITokenName: "ci"})
	if err := db.WithContext(ctx).Create(&AuditLog{Action: ActionCreate, Resource: ResourceUser,
		Status: StatusSuccess, Username: "system"}).Error; err != nil {
		t.Fatal(err)
	}
	if seenID != "req-stamp" || seenIP != "192.0.2.40" {
		t.Errorf("蓋章時的 request_id=%q client_ip=%q，應已補上 req-stamp 192.0.2.40", seenID, seenIP)
	}
}
