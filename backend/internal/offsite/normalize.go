package offsite

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"
)

// 端點淨化、正規化與設定指紋——**純函式**（世代判定要能逐格測試）。
//
// 這三組函式原本落在 `config/offsite.go` 並綁 env。設定全 UI 化
// 後來源改為 `offsite_profiles` 的欄位，故隨語義搬進本包；env 只在初次 seed
// 走同一組函式驗一次。搬遷不改任何規則。

// EndpointRejectReason 端點被拒的靜態次級原因（**不含使用者輸入值**）。
//
// 端點淨化的紅線：被拒絕的三個成分（userinfo／query／fragment）正是秘密唯一可能的
// 藏身之處，訊息只說「含哪一種成分」，值一律不回顯。
type EndpointRejectReason string

const (
	// EndpointRejectNotURL 不是合法的 http(s) URL
	EndpointRejectNotURL EndpointRejectReason = "not_url"
	// EndpointRejectScheme scheme 不是 http／https
	EndpointRejectScheme EndpointRejectReason = "scheme"
	// EndpointRejectNoHost 缺主機名
	EndpointRejectNoHost EndpointRejectReason = "no_host"
	// EndpointRejectUserinfo 含 userinfo（`https://AKIA:secret@host` 形態）
	EndpointRejectUserinfo EndpointRejectReason = "userinfo"
	// EndpointRejectQuery 含 query（`?X-Amz-Token=...` 形態）
	EndpointRejectQuery EndpointRejectReason = "query"
	// EndpointRejectFragment 含 fragment
	EndpointRejectFragment EndpointRejectReason = "fragment"
)

// ValidateEndpoint 端點淨化：合法 http(s) URL、host 非空，
// 且 **userinfo／query／fragment 任一存在即拒**。
//
// path 允許（反向代理下的物件儲存可能掛在路徑前綴）。
// 回傳的是**靜態原因碼**而非帶值的錯誤字串——呼叫端據以組出不回顯值的訊息。
// 多個成分同時出現時回傳的順序固定（userinfo → query → fragment），使測試可逐格斷言。
func ValidateEndpoint(raw string) (EndpointRejectReason, bool) {
	u, reason, ok := parseEndpoint(raw)
	if !ok {
		return reason, false
	}
	if u.User != nil {
		return EndpointRejectUserinfo, false
	}
	if u.RawQuery != "" {
		return EndpointRejectQuery, false
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return EndpointRejectFragment, false
	}
	return "", true
}

// NormalizeEndpointFull 端點的正規化**完整**形態（指紋成分與 driver 建構用）：
// scheme 與 host 小寫、該 scheme 的預設埠省略、**path 原樣保留**。
// 解析失敗回空字串與 false。
func NormalizeEndpointFull(raw string) (string, bool) {
	u, _, ok := parseEndpoint(raw)
	if !ok {
		return "", false
	}
	return endpointOrigin(u) + u.Path, true
}

// NormalizeEndpointOrigin 端點的**顯示**形態：`scheme://host[:port]`，
// **不含 path**——設定頁摘要、啟動日誌、測試連線結果與審計唯一使用的端點形態。
// 解析失敗回空字串（顯示面不承載錯誤，錯誤由驗證面承載）。
func NormalizeEndpointOrigin(raw string) string {
	u, _, ok := parseEndpoint(raw)
	if !ok {
		return ""
	}
	return endpointOrigin(u)
}

func endpointOrigin(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		return scheme + "://" + host + ":" + port
	}
	return scheme + "://" + host
}

func parseEndpoint(raw string) (*url.URL, EndpointRejectReason, bool) {
	u, err := url.Parse(raw)
	if err != nil {
		// **不回傳原始 parse 錯誤**：url.Error 內嵌整個輸入值（不回顯）
		return nil, EndpointRejectNotURL, false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, EndpointRejectScheme, false
	}
	if u.Hostname() == "" {
		return nil, EndpointRejectNoHost, false
	}
	return u, "", true
}

// gcsEmptyEndpointFingerprintToken gcs 未指定端點時的指紋成分常數。
//
// 不用空字串：s3 未指定端點（走 AWS 預設解析）與 gcs 未指定端點是**不同落點**，
// 兩者若都以空字串入雜湊，只改 provider 而 bucket／prefix 相同的設定會算出相同指紋
// ——那正好是「落點變了卻不觸發世代確認」。
const gcsEmptyEndpointFingerprintToken = "gcs"

// ComputeProfileID 儲存設定指紋（2026-08-31 外部審查修訂版）：
// hex(sha256(provider + "\n" + endpointFull + "\n" + bucket + "\n" + prefix +
// "\n" + region))[:16]。
//
// 成分即「物件落點」：provider／完整端點（**含 path**——反向代理前綴不同＝落點不同）／
// bucket／prefix／region。**不入指紋**：path-style 與憑證——它們不改變物件在哪裡
// （憑證輪替不得觸發世代變更）。
//
// **指紋不是識別**：它是參數的函數，故可重複——「A→B→切回 A」的第三個世代
// 與第一個世代指紋相同。識別一律用 `generation_id`；指紋只作世代切換的觸發判準與顯示。
// 指紋不是機密（設定頁與啟動日誌顯示）；端點 path 只入雜湊，顯示面仍只印 origin。
func ComputeProfileID(provider, endpointFull, bucket, prefix, region string) string {
	sum := sha256.Sum256([]byte(provider + "\n" + endpointFull + "\n" + bucket + "\n" + prefix + "\n" + region))
	return hex.EncodeToString(sum[:])[:16]
}

// FingerprintEndpointToken 指紋的端點成分：正規化 full endpoint；
// 空端點時 s3 為空字串、gcs 為常數（見 gcsEmptyEndpointFingerprintToken）。
// 端點非法時回原值——非法端點在寫入路徑早已被拒，此處不吞事實。
func FingerprintEndpointToken(provider, endpoint string) string {
	if endpoint == "" {
		if provider == ProviderGCS {
			return gcsEmptyEndpointFingerprintToken
		}
		return ""
	}
	if n, ok := NormalizeEndpointFull(endpoint); ok {
		return n
	}
	return endpoint
}
