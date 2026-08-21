package kms

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// 建構期 DescribeKey 的有界重試（D11.1 裁決 1「有界重試」＋round-2 精確化
// ＋round-4 codex med #1／#2）。
//
// **為何需要重試**：C 模式沒有 B 模式的段 1，建構期單次失敗即 fail-close＝
// 連 /healthz 都起不來，一次節流或區域抖動就是 crash loop 且零可觀測面。
//
// **為何必須有界**：無界重試等於把「金鑰組態錯誤」拖成「服務永遠不就緒」，
// 操作者看不到根因。故總嘗試上限 3 次、總時間預算 <10s。
//
// **「3 次」必須是實際 HTTP 請求數，不是本層的迴圈次數（codex med #1）**：
// AWS SDK v2 的預設 retryer 自帶 3 次嘗試，與本層的 3 次相乘＝最多 9 個 HTTP
// 請求、退避總長遠超本層預算，且啟動風暴放大三倍。故 describeCallOptions 於
// **呼叫點**把 SDK 內層重試關掉（RetryMaxAttempts=1），由本層獨佔重試語義。
// 只關 DescribeKey 一個操作：Encrypt／Decrypt 走執行期路徑，SDK 重試對它們有益。
// describeMaxAttempts 總嘗試上限（＝首次＋最多 2 次重試）＝實際 HTTP 請求數
const describeMaxAttempts = 3

// **時間參數為 var 而非 const**：終止條件的測試（預算耗盡 vs 次數耗盡）
// 必須能在秒級以下完成，否則單一測試就要跑滿 9 秒而沒有人會保留它。
// 產品路徑永不改寫這兩個值——TestRetryBudgetConstantsAreProductionValues 釘住其預設。
var (
	// describeTotalBudget 總時間預算；SHALL < 10s
	describeTotalBudget = 9 * time.Second
	// describeBaseBackoff 首次退避間隔（第 n 次重試為 base * 3^(n-1)）
	describeBaseBackoff = 200 * time.Millisecond
)

// ErrKMSUnavailable KMS 於建構期不可達（含節流重試耗盡）：拒絕啟動，不降級。
var ErrKMSUnavailable = errors.New("KMS 不可達：拒絕啟動")

// ErrKMSRejected KMS 明確拒絕（權限不足／金鑰不存在／金鑰不合用）：立即失敗，不重試。
var ErrKMSRejected = errors.New("KMS 拒絕請求")

// retryableCodes **允許清單**：確定屬瞬時、且重試確實可能改變結果的錯誤碼
// （round-4 codex med #2 收窄）。
//
// **LimitExceededException 已移出（codex med #2）**：它在 KMS 是「已達帳號資源
// 配額」（如金鑰數、grant 數上限），屬需要人介入的組態問題而非瞬時節流——
// 對它重試只是把一個明確錯誤延後 9 秒，訊息還一模一樣。
//
// 分三類，每類都必須能回答「重試為何可能成功」：
//   - 節流：服務端要求降速，退避後配額恢復；
//   - 逾時：本次請求超時，下次可能不會；
//   - 明確 5xx：服務端內部錯誤／暫時不可用，通常是單一節點問題。
var retryableCodes = map[string]bool{
	// 節流
	"ThrottlingException":      true,
	"ThrottledException":       true,
	"Throttling":               true,
	"TooManyRequestsException": true,
	"RequestLimitExceeded":     true,
	// 逾時
	"RequestTimeout":             true,
	"RequestTimeoutException":    true,
	"DependencyTimeoutException": true,
	// 明確 5xx
	"KMSInternalException":        true,
	"InternalFailure":             true,
	"InternalServerError":         true,
	"ServiceUnavailable":          true,
	"ServiceUnavailableException": true,
}

// retryDecision 錯誤分流結果。
//
// **為何需要三分而非二分（codex med #2 的連帶修正）**：原實作把「不可重試」
// 一律包成 ErrKMSRejected（「遭拒」），但 DNS NXDOMAIN、TLS 憑證錯誤這些
// **非 API 層**的永久性失敗根本不是 KMS 拒絕了我們——把它們說成「遭拒」會讓
// 操作者去查 IAM policy，而根因在 DNS／網路組態。
type retryDecision int

const (
	// decisionRetry 瞬時錯誤，退避後重試
	decisionRetry retryDecision = iota
	// decisionRejected KMS 於 API 層明確拒絕（權限／金鑰狀態／請求內容）
	decisionRejected
	// decisionPermanent 非 API 層的永久性失敗（憑證鏈、DNS、TLS、端點、序列化）
	decisionPermanent
)

// transientSyscallErrs 連線層的瞬時失敗（區域抖動／LB 換節點的實際長相）。
//
// 逐一列舉而非「凡 net.Error 皆重試」（codex med #2）：後者會把
// **DNS NXDOMAIN**（region 拼錯）、憑證驗證失敗這類永久性問題也重試三輪，
// 把一個一秒可見的組態錯誤變成九秒的啟動延遲。
var transientSyscallErrs = []error{
	syscall.ECONNREFUSED,
	syscall.ECONNRESET,
	syscall.ECONNABORTED,
	syscall.EPIPE,
	syscall.EHOSTUNREACH,
	syscall.ENETUNREACH,
	syscall.ENETDOWN,
	syscall.ETIMEDOUT,
}

// classifyKMSError 判定錯誤的處置方式。
//
// 分流原則（一律**允許清單**，未知即不重試）：
//   - 呼叫端取消 → 永不重試；
//   - API 錯誤 → 查 retryableCodes；命中即重試，其餘一律 decisionRejected
//     （錯誤碼原樣保留給操作者）；
//   - 帶 HTTP 狀態碼的傳輸錯誤 → 5xx 重試、其餘不重試；
//   - 連線層錯誤 → 只有 timeout 與 transientSyscallErrs 重試；
//   - 其他（憑證鏈解析失敗、序列化錯誤、TLS 驗證失敗…）→ decisionPermanent。
func classifyKMSError(err error) retryDecision {
	if err == nil {
		return decisionPermanent
	}
	if errors.Is(err, context.Canceled) {
		return decisionPermanent
	}

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		if retryableCodes[apiErr.ErrorCode()] {
			return decisionRetry
		}
		return decisionRejected
	}

	// 帶 HTTP 狀態碼但無可辨識錯誤碼者（例如 LB／代理回的裸回應）依狀態碼分流：
	// 5xx 屬服務端暫時性問題可重試；4xx 是服務端**確實回應並拒絕**了，
	// 歸「遭拒」而非「非瞬時錯誤」——後者的錯誤訊息會叫人去查 DNS／TLS，指錯方向。
	var respErr *smithyhttp.ResponseError
	if errors.As(err, &respErr) {
		if code := respErr.HTTPStatusCode(); code >= 500 {
			return decisionRetry
		} else if code >= 400 {
			return decisionRejected
		}
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return decisionRetry
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return decisionRetry
	}
	for _, se := range transientSyscallErrs {
		if errors.Is(err, se) {
			return decisionRetry
		}
	}
	// DNS NXDOMAIN、TLS 驗證失敗、憑證鏈解析失敗、序列化錯誤等：重試不會改變結果
	return decisionPermanent
}

// retryDescribe 以有界退避重試執行建構期探測。
//
// 四個終止條件互斥且各有專屬訊息：
//   - 呼叫端 context 取消 → 回原因，**不吞成逾時**（round-2 codex low 明列）；
//   - 錯誤不可重試 → 依 API／非 API 分別回 ErrKMSRejected／ErrKMSUnavailable；
//   - 總時間預算耗盡 → 明示預算；
//   - 嘗試次數用盡 → 明示次數。
//
// **預算檢查置於「次數用盡」之前（round-4 codex low #1）**：最後一次呼叫若正好
// 把 9s 預算耗光，原實作會報「重試 3 次仍失敗」——那是誤導，真因是預算耗盡
// （操作者該調的是網路而不是次數）。故每次呼叫返回後先看預算 context 的 Err()。
func retryDescribe[T any](ctx context.Context, label string, call func(context.Context) (T, error)) (T, error) {
	var zero T
	budgetCtx, cancel := context.WithTimeout(ctx, describeTotalBudget)
	defer cancel()

	backoff := describeBaseBackoff
	var lastErr error
	for attempt := 1; attempt <= describeMaxAttempts; attempt++ {
		out, err := call(budgetCtx)
		if err == nil {
			return out, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			// 呼叫端取消優先於一切：不得回報為逾時
			return zero, fmt.Errorf("%s 於呼叫端取消時中止: %w", label, ctx.Err())
		}
		switch classifyKMSError(err) {
		case decisionRejected:
			return zero, fmt.Errorf("%w：%s 遭拒（不重試）: %v", ErrKMSRejected, label, err)
		case decisionPermanent:
			return zero, fmt.Errorf("%w：%s 遇非瞬時錯誤（不重試——重試不會改變結果，"+
				"請檢查 region／DNS／TLS 與憑證鏈）: %v", ErrKMSUnavailable, label, err)
		}
		if budgetCtx.Err() != nil {
			return zero, fmt.Errorf("%w：%s 於總時間預算 %s 內未成功（末次錯誤: %v）",
				ErrKMSUnavailable, label, describeTotalBudget, lastErr)
		}
		if attempt == describeMaxAttempts {
			break
		}
		select {
		case <-ctx.Done():
			return zero, fmt.Errorf("%s 於呼叫端取消時中止: %w", label, ctx.Err())
		case <-budgetCtx.Done():
			return zero, fmt.Errorf("%w：%s 於總時間預算 %s 內未成功（末次錯誤: %v）",
				ErrKMSUnavailable, label, describeTotalBudget, lastErr)
		case <-time.After(backoff):
		}
		backoff *= 3
	}
	return zero, fmt.Errorf("%w：%s 重試 %d 次仍失敗（末次錯誤: %v）",
		ErrKMSUnavailable, label, describeMaxAttempts, lastErr)
}
