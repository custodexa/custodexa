package gatewayapi

import (
	"context"
	"time"
)

// ConnectGrant connect-token 所攜帶的授權脈絡。
// 欄位對齊 internal/proxy/connect_token.go:11-33。
//
// # 為何不嵌 ConnectSubject（訂正原先的 `Subject ConnectSubject`）
//
// 現況 grant 刻意不帶角色：connect_token.go:11-14 自陳「快照 SHALL NOT 攜帶角色，
// 使『憑角色快照判定 admin 特權』成為編譯期不可能」。
// 若把整個 ConnectSubject 嵌進來，ClaimedRole 就進了 token 快照，於是
// 「SHALL NOT 判定」會由編譯期不可能退化為註解約定。介面不得使既有防線退步，
// 故此處逐欄複製 grant 真正攜帶的脈絡，角色欄一概不存在。
//
// # 為何客體是平鋪的 AssetID／AccountID 而非嵌 ConnectObjectRef
//
// 現行票證（`internal/proxy/connect_token.go`）只帶 asset_id 與 account_id 兩個選擇器，
// 沒有 Protocol／Channel——那兩欄要到兌換點讀資產列才存在。嵌 ConnectObjectRef 等於在
// 契約上宣稱票證帶著協議與通道，而實作永遠填不了，是**契約描述未實作能力**。
// 平鋪後 `internal/proxy.ConnectGrant` 得以直接別名到本型別，票證的形狀只有一份。
//
// Username 不在此：它憑證解封後才存在（見 ResolvedConnectObject.Username），簽發時
// 無從填、也不該填——填了等於把帳號解析結果凍結進票證，兌換側就失去現查的機會。
// 這與 PolicyGate 兩階段的分界是同一條理由。
type ConnectGrant struct {
	UserID uint

	// AssetID／AccountID 客體選擇器（AccountID 0＝預設帳號）。
	// **定位是憑證選擇器、不是授權快照**——簽發與兌換點皆以
	// (account_id, asset_id, deleted_at IS NULL) DB 現查客體綁定，
	// 失效一律 fail-close，絕不靜默退回預設帳號。
	AssetID   uint
	AccountID uint

	// 認證脈絡：簽發階段自請求脈絡取得，兌換時寫入 session 作溯源快照並複查
	// provider 啟用與世代相符。**授權本身仍一律 DB 現查——這四欄不是授權快照。**
	AuthMethod string
	ProviderID uint
	AuthEpoch  int
	CredEpoch  int

	// ExpiresAt 票證到期時刻，由簽發實作統一填寫（TTL 不進契約）。
	//
	// **刻意不含 Limits SessionLimits**：現行票證零限制欄位，
	// 兌換側亦零強制（尚未拍板）。留著就是契約描述未實作能力——本 change 的
	// 誠實性紀律不允許。拍板後另立行為修復 change 再加。
	ExpiresAt time.Time
}

// **SessionVerifier 與 Principal 已移除**：唯讀觀看的兩條 WebSocket 改以一次性
// 觀看票認證後，session JWT 驗證面的生產消費者歸零。契約包只描述有實作、有消費者
// 的能力——留著一個沒人用的「以 session JWT 換身分快照」介面，等於在公開契約上
// 保留一條看起來還活著的認證面。

// TokenService 一次性連線票的簽發與兌換面。
type TokenService interface {
	// IssueConnectToken 簽發一次性連線票（TTL 與容量上限由實作決定，不進契約）。
	IssueConnectToken(ctx context.Context, g ConnectGrant) (string, error)

	// RedeemConnectToken 兌換即焚。回傳 grant 供兌換側執行客體重查與限制強制。
	// 兌換成功 SHALL NOT 被解讀為「已授權」——兌換側仍須跑完自己的閘序。
	//
	// **第二回傳值是 bool 而非 error**：現行兌換只有一種失敗
	// ——票不存在／已被兌換／已過期，三者一律收斂為同一則「token 無效」回應
	// （`internal/proxy/handler.go`、`internal/sshproxy/handler.go` 皆如此）。
	// 宣告成 error 會讓呼叫端以為可以分辨成因並分流回應，而分流本身就是
	// 票證存在性探測面。
	RedeemConnectToken(ctx context.Context, token string) (ConnectGrant, bool)
}
