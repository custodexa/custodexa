package model

import "context"

// 請求憑證種類與背景發起者標示。
//
// 授權判定依路徑分三種，彼此不得互相冒用：
//   - 請求路徑：context 帶請求憑證種類（由認證中介層與閘門設定）與請求主體；缺主體一律拒絕，
//     判定處不得以「沒有某種標記」推定為人類工作階段。
//   - 背景作業（代表某個帳號執行的排程與重試）：只能經 WithBackgroundInitiator 建立，該入口的
//     呼叫點由守衛列管；授權轉接頭只在看到這個標示時以帳號編號重解完整身分。
//   - 系統路徑（沒有請求操作者）：沿用各模組既有且受列管的系統呼叫者標示，不要求請求主體。
//
// 型別放在 model 是因為各模組（含不得匯入授權模組的資產模組）都要讀得到。

// RequestCredential 這次請求以哪一種憑證認證。
type RequestCredential string

const (
	// RequestCredentialHumanSession 人類登入工作階段（JWT）
	RequestCredentialHumanSession RequestCredential = "human_session"
	// RequestCredentialAgentKey AI agent 鑰匙
	RequestCredentialAgentKey RequestCredential = "agent_key"
	// RequestCredentialAPIToken 個人 API token
	RequestCredentialAPIToken RequestCredential = "api_token"
)

// Valid 是否為已定義的種類。
func (k RequestCredential) Valid() bool {
	switch k {
	case RequestCredentialHumanSession, RequestCredentialAgentKey, RequestCredentialAPIToken:
		return true
	}
	return false
}

type requestCredentialKey struct{}

type backgroundInitiatorKey struct{}

// WithRequestCredential 標示這次請求的憑證種類；未定義的種類原樣回傳 ctx。
func WithRequestCredential(ctx context.Context, kind RequestCredential) context.Context {
	if !kind.Valid() {
		return ctx
	}
	return context.WithValue(ctx, requestCredentialKey{}, kind)
}

// RequestCredentialFrom 取這次請求的憑證種類；ctx 不是請求脈絡時回 ("", false)。
func RequestCredentialFrom(ctx context.Context) (RequestCredential, bool) {
	if ctx == nil {
		return "", false
	}
	k, ok := ctx.Value(requestCredentialKey{}).(RequestCredential)
	return k, ok && k.Valid()
}

// WithBackgroundInitiator 背景作業的發起者脈絡：帶發起者識別（沿審計 context 的既有鍵）與背景標示。
//
// 這是唯一能產生背景標示的入口。ctx 已帶請求憑證種類時（請求內呼叫）不加背景標示：請求路徑的
// 授權必須取請求主體，不能經這裡改以帳號完整身分判定；此時只覆寫發起者識別，轉接頭會因主體與
// 發起者不符而拒絕。發起者為零時原樣回傳 ctx（關卡把空主體當作拒絕）。
func WithBackgroundInitiator(ctx context.Context, userID uint, username string) context.Context {
	if userID == 0 {
		return ctx
	}
	ctx = context.WithValue(ctx, "userID", userID)     //nolint:staticcheck // 沿用既有審計 context 慣例
	ctx = context.WithValue(ctx, "username", username) //nolint:staticcheck
	if _, isRequest := RequestCredentialFrom(ctx); isRequest {
		return ctx
	}
	return context.WithValue(ctx, backgroundInitiatorKey{}, userID)
}

// BackgroundInitiatorFrom 背景標示上的發起者；沒有標示，或 ctx 帶請求憑證種類時回 (0, false)。
func BackgroundInitiatorFrom(ctx context.Context) (uint, bool) {
	if ctx == nil {
		return 0, false
	}
	if _, isRequest := RequestCredentialFrom(ctx); isRequest {
		return 0, false
	}
	id, ok := ctx.Value(backgroundInitiatorKey{}).(uint)
	return id, ok && id != 0
}
