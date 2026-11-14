package model

import "context"

// APITokenRef 以 API token 認證的請求所經由的 token：識別與認證當下的名稱快照。
// 由 API token 閘門在認證成功後放進請求的 context，供稽核歸因取用；不含明文或雜湊。
type APITokenRef struct {
	ID   uint
	Name string
}

type apiTokenRefKey struct{}

// WithAPITokenRef 在 ctx 標示這次請求所經由的 API token；識別為零或名稱為空時原樣回傳 ctx。
func WithAPITokenRef(ctx context.Context, ref APITokenRef) context.Context {
	if ref.ID == 0 || ref.Name == "" {
		return ctx
	}
	return context.WithValue(ctx, apiTokenRefKey{}, ref)
}

// APITokenRefFrom 這次請求所經由的 API token；ctx 不是以 API token 認證的請求時回 (零值, false)。
// 只在 ctx 同時帶 API token 這個請求憑證種類時回 true，避免與其他憑證種類的脈絡混用。
func APITokenRefFrom(ctx context.Context) (APITokenRef, bool) {
	if ctx == nil {
		return APITokenRef{}, false
	}
	if kind, ok := RequestCredentialFrom(ctx); !ok || kind != RequestCredentialAPIToken {
		return APITokenRef{}, false
	}
	ref, ok := ctx.Value(apiTokenRefKey{}).(APITokenRef)
	return ref, ok && ref.ID != 0
}

// APITokenRefOf 由識別與名稱組出標示；識別為零或名稱為空時回 (零值, false)。
func APITokenRefOf(id *uint, name string) (APITokenRef, bool) {
	if id == nil || *id == 0 || name == "" {
		return APITokenRef{}, false
	}
	return APITokenRef{ID: *id, Name: name}, true
}

// AttributeToAPIToken 在稽核列填入經由的 token 識別與名稱快照。列已帶標示時不覆寫；
// ref 無效時不動。名稱一律非空：空字串在逐列完整性的涵蓋內容中等同沒有，不得寫入。
func (a *AuditLog) AttributeToAPIToken(ref APITokenRef) {
	if a == nil || ref.ID == 0 || ref.Name == "" || a.APITokenID != nil {
		return
	}
	id, name := ref.ID, ref.Name
	a.APITokenID, a.APITokenName = &id, &name
}

// attributeAuditFromContext 稽核列入庫前的歸因匯流點：寫入所在交易的 context 帶有 API token
// 請求的標示（請求 context 本身，或操作者組出的稽核請求脈絡）時，於蓋章之前填入。
// 已由寫入端明確帶標示的列不覆寫；只有識別沒有名稱的列視為無效標示並清空，
// 不留下涵蓋內容中無法驗證的半套值。
func attributeAuditFromContext(a *AuditLog, ctx context.Context) {
	if a.APITokenID != nil && (a.APITokenName == nil || *a.APITokenName == "") {
		a.APITokenID, a.APITokenName = nil, nil
	}
	if a.APITokenID == nil && a.APITokenName != nil {
		a.APITokenName = nil
	}
	if ref, ok := APITokenRefFrom(ctx); ok {
		a.AttributeToAPIToken(ref)
		return
	}
	if r, ok := AuditRequestFrom(ctx); ok && r.APITokenID != 0 {
		a.AttributeToAPIToken(APITokenRef{ID: r.APITokenID, Name: r.APITokenName})
		return
	}
	if ctx == nil {
		return
	}
	if ref, ok := ctx.Value(auditAttributionKey{}).(APITokenRef); ok {
		a.AttributeToAPIToken(ref)
	}
}

type auditAttributionKey struct{}

// AuditAttributionContext 只帶稽核歸因標示的乾淨 context，供服務層把交易綁上後由稽核列的入庫匯流點歸因。
// 標示放在只有入庫匯流點讀取的專用鍵：不帶請求憑證種類、操作者或原 ctx 的其他值與取消訊號，
// 交易內其他依 context 判斷的邏輯（掛鉤、主體重解）與綁定前相同，請求結束也不中斷交易。
// 非 API token 請求回 context.Background()。
func AuditAttributionContext(ctx context.Context) context.Context {
	ref, ok := APITokenRefFrom(ctx)
	if !ok {
		return context.Background()
	}
	return context.WithValue(context.Background(), auditAttributionKey{}, ref)
}
