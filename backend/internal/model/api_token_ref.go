package model

import "context"

// APITokenRef 以 API token 認證的請求所經由的 token：識別與認證當下的名稱快照。
// 由 API token 閘門在認證成功後放進請求的 context，供稽核歸因取用；不含明文或雜湊。
//
// RequestID、ClientIP 是經由這把 token 的那一次請求的識別與來源位址，由取用端（請求 context、
// 請求脈絡）帶上，供稽核列補值：凡因經 token 而標上標示的列，都帶同一次請求的這兩欄。
// 兩欄不屬於標示本身，不寫入 token 欄位。
type APITokenRef struct {
	ID        uint
	Name      string
	RequestID string
	ClientIP  string
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
	if !ok || ref.ID == 0 {
		return APITokenRef{}, false
	}
	if o, ok := RequestOriginFrom(ctx); ok {
		ref = ref.WithOrigin(o)
	}
	return ref, true
}

// WithOrigin 帶上這次請求的識別與來源位址；已有值的欄位不覆寫。
func (r APITokenRef) WithOrigin(o RequestOrigin) APITokenRef {
	if r.RequestID == "" {
		r.RequestID = o.RequestID
	}
	if r.ClientIP == "" {
		r.ClientIP = o.ClientIP
	}
	return r
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
// 請求的標示（請求 context 本身、操作者組出的稽核請求脈絡，或只帶歸因標示的 context）時，於蓋章之前填入。
// 已由寫入端明確帶標示的列不覆寫；只有識別沒有名稱的列視為無效標示並清空，
// 不留下涵蓋內容中無法驗證的半套值。
//
// 帶標示的列（不論由寫入端或此處標上）另補該次請求的識別與來源位址，寫入端已帶值的欄位不覆寫；
// 只在列上的標示與 context 的標示為同一把 token 時補。本函式在欄位收口與蓋章之前執行，
// 補上的兩欄在逐列完整性的涵蓋內容之內。
func attributeAuditFromContext(a *AuditLog, ctx context.Context) {
	if a.APITokenID != nil && (a.APITokenName == nil || *a.APITokenName == "") {
		a.APITokenID, a.APITokenName = nil, nil
	}
	if a.APITokenID == nil && a.APITokenName != nil {
		a.APITokenName = nil
	}
	ref, ok := apiTokenAttributionFrom(ctx)
	if !ok {
		return
	}
	a.AttributeToAPIToken(ref)
	if a.APITokenID != nil && *a.APITokenID == ref.ID && ref.RequestID != "" {
		a.fillRequestOrigin(RequestOrigin{RequestID: ref.RequestID, ClientIP: ref.ClientIP})
	}
}

// apiTokenAttributionFrom 交易 context 帶的 API token 標示與該次請求的識別、來源位址（依序取請求 context、
// 稽核請求脈絡、只帶歸因標示的 context）；都沒有時回 false。
func apiTokenAttributionFrom(ctx context.Context) (APITokenRef, bool) {
	if ref, ok := APITokenRefFrom(ctx); ok {
		return ref, true
	}
	if r, ok := AuditRequestFrom(ctx); ok && r.APITokenID != 0 {
		ref := APITokenRef{ID: r.APITokenID, Name: r.APITokenName}
		return ref.WithOrigin(RequestOrigin{RequestID: r.RequestID, ClientIP: r.ClientIP}), true
	}
	if ctx == nil {
		return APITokenRef{}, false
	}
	if at, ok := ctx.Value(auditAttributionKey{}).(auditAttribution); ok {
		return at.ref.WithOrigin(at.origin), true
	}
	return APITokenRef{}, false
}

type auditAttributionKey struct{}

// auditAttribution 歸因標示：經由的 token，以及這次請求的識別與來源位址（請求 context 沒有時為空）。
type auditAttribution struct {
	ref    APITokenRef
	origin RequestOrigin
}

// AuditAttributionContext 只帶稽核歸因標示的乾淨 context，供服務層把交易綁上後由稽核列的入庫匯流點歸因。
// 標示放在只有入庫匯流點讀取的專用鍵：不帶請求憑證種類、操作者或原 ctx 的其他值與取消訊號，
// 交易內其他依 context 判斷的邏輯（掛鉤、主體重解）與綁定前相同，請求結束也不中斷交易。
// 非 API token 請求回 context.Background()。標示另帶這次請求的識別與來源位址：交易內寫下的稽核列
// 沒有這兩欄時補上，與稽核中介層為同一次請求寫的那一列共用同一個 request_id。
func AuditAttributionContext(ctx context.Context) context.Context {
	ref, ok := APITokenRefFrom(ctx)
	if !ok {
		return context.Background()
	}
	origin, _ := RequestOriginFrom(ctx)
	return context.WithValue(context.Background(), auditAttributionKey{}, auditAttribution{ref: ref, origin: origin})
}
