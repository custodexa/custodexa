package model

import "context"

// AuditRequest 一次 HTTP 請求的審計脈絡：操作者與請求識別。
//
// 角色指派的審計列由資料層在交易內寫入，而交易的 context 原本不帶操作者，
// 所以經管理介面的指派、移除、範圍變更都被記成 system。把脈絡放在交易 context 上，
// 資料層就能把同一次請求的各列對上同一個操作者與 request_id。
type AuditRequest struct {
	UserID    uint
	Username  string
	ClientIP  string
	Method    string
	Path      string
	RequestID string
	// APITokenID、APITokenName 這次請求經由的 API token（親自操作的請求為零值與空字串）
	APITokenID   uint
	APITokenName string
}

// auditRequestKey 具型別的 context 鍵（不用字串鍵，避免與其他套件的鍵碰撞）。
type auditRequestKey struct{}

// WithAuditRequest 回傳帶有請求脈絡的 context。
func WithAuditRequest(ctx context.Context, r AuditRequest) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, auditRequestKey{}, r)
}

// AuditRequestFrom 取出請求脈絡；沒有（或沒有可指認的操作者）時 ok 為 false。
func AuditRequestFrom(ctx context.Context) (AuditRequest, bool) {
	if ctx == nil {
		return AuditRequest{}, false
	}
	r, ok := ctx.Value(auditRequestKey{}).(AuditRequest)
	if !ok || r.UserID == 0 {
		return AuditRequest{}, false
	}
	return r, true
}

// RequestOrigin 一次 HTTP 請求的識別與來源位址，由稽核中介層在請求開始時放進請求 context。
// 經由 API token 的請求，其交易內寫下的稽核列以此補上同一個 request_id 與來源位址，
// 使「同一次請求」的精確篩選能找齊這次請求寫下的每一列。
type RequestOrigin struct {
	RequestID string
	ClientIP  string
}

type requestOriginKey struct{}

// WithRequestOrigin 在 ctx 標示這次請求的識別與來源位址；請求識別為空時原樣回傳。
func WithRequestOrigin(ctx context.Context, o RequestOrigin) context.Context {
	if o.RequestID == "" {
		return ctx
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, requestOriginKey{}, o)
}

// RequestOriginFrom 取出請求的識別與來源位址；沒有時 ok 為 false。
func RequestOriginFrom(ctx context.Context) (RequestOrigin, bool) {
	if ctx == nil {
		return RequestOrigin{}, false
	}
	o, ok := ctx.Value(requestOriginKey{}).(RequestOrigin)
	return o, ok && o.RequestID != ""
}

// fillRequestOrigin 稽核列沒有請求識別或來源位址時補上；已有值的欄位不覆寫。
func (a *AuditLog) fillRequestOrigin(o RequestOrigin) {
	if a == nil {
		return
	}
	if a.RequestID == "" {
		a.RequestID = o.RequestID
	}
	if a.ClientIP == "" {
		a.ClientIP = o.ClientIP
	}
}
