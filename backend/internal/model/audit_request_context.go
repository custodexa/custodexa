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
