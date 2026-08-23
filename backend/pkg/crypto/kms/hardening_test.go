package kms

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// 安全審查與獨立驗收的修補驗證。
// 每一格對應一條 finding，且各自能在把修補改回原狀時轉紅。

// ---- 跨帳號重包目標未受限 ----

const (
	trustedAccount    = "123456789012"
	foreignAccount    = "999999999999"
	foreignAccountARN = "arn:aws:kms:ap-northeast-1:999999999999:key/abcd1234-12ab-34cd-56ef-1234567890ab"
	foreignAccountID  = "abcd1234-12ab-34cd-56ef-1234567890ab"
	foreignAlias      = "alias/attacker-owned"
	govPartitionARN   = "arn:aws-us-gov:kms:ap-northeast-1:123456789012:key/abcd1234-12ab-34cd-56ef-1234567890ab"
)

func trustedScope() AccountScope {
	return AccountScope{Partition: "aws", Account: trustedAccount}
}

// TestNewRejectsKeyOutsideTrustedAccount **跨帳號限制的 fail-close 測試**：
// 目標 ARN 與部署宣告的信任帳號不同時，建構期即拒絕。
//
// 這正是「region 沿用不足以防跨帳號重包」的直接對應：本格的目標與信任範圍
// **region 完全相同**，只有帳號不同——修補前這條路徑一路暢通。
func TestNewRejectsKeyOutsideTrustedAccount(t *testing.T) {
	f := newFakeKMS()
	f.addKey(foreignAlias, foreignAccountID, foreignAccountARN)

	_, err := New(context.Background(), Settings{
		Provider: ProviderAWS, KeyID: foreignAlias, Region: testRegion,
		Client: f, Scope: trustedScope(),
	})
	if !errors.Is(err, ErrKeyOutsideTrustedAccount) {
		t.Fatalf("同 region 的外部帳號金鑰 MUST 被拒（ErrKeyOutsideTrustedAccount），得 %v", err)
	}
	// 錯誤 SHALL 明確指出是哪個帳號、以及信任範圍是什麼（否則操作者無從判斷是誤設還是攻擊）
	for _, want := range []string{foreignAccount, trustedAccount, "KEK_KMS_KEY_ID"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("錯誤訊息未指出 %q：%v", want, err)
		}
	}
	// fail-close 須發生在任何加解密之前
	if len(f.encryptCalls) != 0 || len(f.decryptCalls) != 0 {
		t.Fatalf("拒絕路徑 SHALL NOT 送出任何加解密請求：encrypt=%d decrypt=%d",
			len(f.encryptCalls), len(f.decryptCalls))
	}
}

// TestNewRejectsKeyOutsidePartition partition 也在比對範圍內：
// 只比帳號號碼會讓 `aws-us-gov` 的同號帳號通過，那是另一個主權雲的信任域。
func TestNewRejectsKeyOutsidePartition(t *testing.T) {
	f := newFakeKMS()
	f.addKey("alias/gov", "abcd1234-12ab-34cd-56ef-1234567890ab", govPartitionARN)
	_, err := New(context.Background(), Settings{
		Provider: ProviderAWS, KeyID: "alias/gov", Region: testRegion,
		Client: f, Scope: trustedScope(),
	})
	if !errors.Is(err, ErrKeyOutsideTrustedAccount) {
		t.Fatalf("跨 partition 的同號帳號 MUST 被拒，得 %v", err)
	}
}

// TestNewAcceptsKeyInsideTrustedAccount 正向控制：信任範圍內的金鑰照常可建構。
// 沒有這一格，「一律拒絕」也會讓上面兩格全綠。
func TestNewAcceptsKeyInsideTrustedAccount(t *testing.T) {
	f := newFakeKMS()
	f.addKey(testKeyAlias, testKeyID, testKeyARN) // testKeyARN 屬 123456789012
	p, err := New(context.Background(), Settings{
		Provider: ProviderAWS, KeyID: testKeyAlias, Region: testRegion,
		Client: f, Scope: trustedScope(),
	})
	if err != nil {
		t.Fatalf("信任範圍內的金鑰不得被拒: %v", err)
	}
	if p.Account() != trustedAccount {
		t.Fatalf("Account() 應為 %s，得 %s", trustedAccount, p.Account())
	}
}

// TestNewSkipsScopeCheckWhenUndeclared 未宣告範圍時不檢查——啟動期建構的目標
// 就是組態自身，拿組態去驗組態沒有意義（檢查只施加於請求可指定目標的重包路徑）。
func TestNewSkipsScopeCheckWhenUndeclared(t *testing.T) {
	f := newFakeKMS()
	f.addKey(foreignAlias, foreignAccountID, foreignAccountARN)
	if _, err := New(context.Background(), Settings{
		Provider: ProviderAWS, KeyID: foreignAlias, Region: testRegion, Client: f,
	}); err != nil {
		t.Fatalf("未宣告信任範圍時不應做帳號檢查: %v", err)
	}
}

// TestResolveAccountScopeFromARNMakesNoCall KEK_KMS_KEY_ID 已是完整 ARN 時
// 零 KMS 呼叫即可推導信任範圍
func TestResolveAccountScopeFromARNMakesNoCall(t *testing.T) {
	f := newFakeKMS()
	scope, err := ResolveAccountScope(context.Background(), Settings{
		Provider: ProviderAWS, KeyID: testKeyARN, Region: testRegion, Client: f,
	})
	if err != nil {
		t.Fatalf("ResolveAccountScope: %v", err)
	}
	if scope != trustedScope() {
		t.Fatalf("信任範圍應為 %v，得 %v", trustedScope(), scope)
	}
	if len(f.describeCalls) != 0 {
		t.Fatalf("ARN 形式 SHALL NOT 觸發 DescribeKey，得 %d 次", len(f.describeCalls))
	}
}

// TestResolveAccountScopeFromAlias alias／裸 key-id 形式以一次 DescribeKey 正規化
func TestResolveAccountScopeFromAlias(t *testing.T) {
	f := newFakeKMS()
	f.addKey(testKeyAlias, testKeyID, testKeyARN)
	scope, err := ResolveAccountScope(context.Background(), Settings{
		Provider: ProviderAWS, KeyID: testKeyAlias, Region: testRegion, Client: f,
	})
	if err != nil {
		t.Fatalf("ResolveAccountScope: %v", err)
	}
	if scope != trustedScope() {
		t.Fatalf("信任範圍應為 %v，得 %v", trustedScope(), scope)
	}
	if len(f.describeCalls) != 1 {
		t.Fatalf("alias 形式應恰一次 DescribeKey，得 %d", len(f.describeCalls))
	}
	// **只做 DescribeKey**：不得順帶跑 canary（那是三倍成本，而此處只需要帳號段）
	if len(f.encryptCalls) != 0 {
		t.Fatalf("推導信任範圍 SHALL NOT 觸發 canary，得 %d 次 Encrypt", len(f.encryptCalls))
	}
}

// TestResolveAccountScopeRequiresAnchor 沒有 KEK_KMS_KEY_ID 就沒有信任範圍可言，
// SHALL NOT 靜默回落成「不檢查」
func TestResolveAccountScopeRequiresAnchor(t *testing.T) {
	_, err := ResolveAccountScope(context.Background(), Settings{
		Provider: ProviderAWS, KeyID: "", Region: testRegion, Client: newFakeKMS(),
	})
	if err == nil {
		t.Fatal("缺信任錨點時 MUST 回錯，SHALL NOT 回零值 scope（那等同不檢查）")
	}
	if !strings.Contains(err.Error(), "KEK_KMS_KEY_ID") {
		t.Fatalf("錯誤未指名 KEK_KMS_KEY_ID：%v", err)
	}
}

// ---- 端點覆寫仍然可能 ----

// TestProductionPathRejectsEndpointOverrideEnv **端點覆寫的 fail-close 測試**。
//
// 立論的糾正：實作者原本主張「不新增產品 env 鍵即消除端點覆寫」。實測
// （見 TestEndpointOverrideEnvActuallyRedirects）證明 AWS_ENDPOINT_URL_KMS
// 會被 SDK 直接吃進 client.Options().BaseEndpoint——含明文 DEK 的 Encrypt
// 請求因此可被導向任意主機。故生產路徑必須主動拒絕。
func TestProductionPathRejectsEndpointOverrideEnv(t *testing.T) {
	for _, key := range endpointOverrideEnvKeys {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, "http://attacker.example:4566")
			_, err := newAWSClient(context.Background(), Settings{
				Provider: ProviderAWS, KeyID: testKeyAlias, Region: testRegion,
			})
			if !errors.Is(err, ErrEndpointOverride) {
				t.Fatalf("生產路徑 MUST 拒絕端點覆寫（ErrEndpointOverride），得 %v", err)
			}
			if !strings.Contains(err.Error(), key) {
				t.Fatalf("錯誤未指名觸發的變數 %s：%v", key, err)
			}
		})
	}
}

// TestProductionPathAcceptsCleanEnv 正向控制：無覆寫時生產路徑照常建構客戶端。
// 沒有這一格，「一律回錯」也會讓上面全綠。
func TestProductionPathAcceptsCleanEnv(t *testing.T) {
	t.Setenv("AWS_ENDPOINT_URL_KMS", "")
	t.Setenv("AWS_ENDPOINT_URL", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	c, err := newAWSClient(context.Background(), Settings{
		Provider: ProviderAWS, KeyID: testKeyAlias, Region: testRegion,
	})
	if err != nil {
		t.Fatalf("無端點覆寫時不得拒絕: %v", err)
	}
	if c == nil {
		t.Fatal("應回傳可用客戶端")
	}
}

// TestTestHarnessPathStillAllowsEndpoint 測試靶機路徑（程式注入 Settings.Endpoint）
// 維持可用——否則 localstack 那一整組實測就沒得跑了。
// 該路徑的「不可由生產碼觸及」由 TestNoProductionEndpointOverride 從結構面保證。
func TestTestHarnessPathStillAllowsEndpoint(t *testing.T) {
	t.Setenv("AWS_ENDPOINT_URL_KMS", "http://anything.example:1")
	c, err := newAWSClient(context.Background(), Settings{
		Provider: ProviderAWS, KeyID: testKeyAlias, Region: testRegion,
		Endpoint: "http://localstack:4566",
	})
	if err != nil {
		t.Fatalf("測試靶機路徑不得被端點守衛擋下: %v", err)
	}
	if c == nil {
		t.Fatal("應回傳可用客戶端")
	}
}

// TestEndpointOverrideEnvActuallyRedirects **證明端點覆寫真的可行**（而非理論風險）：
// 在沒有本產品守衛的情況下，AWS_ENDPOINT_URL_KMS 會讓 SDK 客戶端的
// BaseEndpoint 指向任意位址。本格直接呼叫 SDK，不經 newAWSClient——
// 它記錄的是「SDK 的行為」，而那正是原註解宣稱不存在的東西。
func TestEndpointOverrideEnvActuallyRedirects(t *testing.T) {
	t.Setenv("AWS_ENDPOINT_URL_KMS", "http://attacker.example:4566")
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion(testRegion))
	if err != nil {
		t.Fatalf("載入組態: %v", err)
	}
	client := awskms.NewFromConfig(cfg)
	be := client.Options().BaseEndpoint
	if be == nil || *be != "http://attacker.example:4566" {
		t.Fatalf("預期 SDK 會把 AWS_ENDPOINT_URL_KMS 解析進 BaseEndpoint，得 %v", be)
	}
}

// TestRequireHTTPSEndpoint 明文 DEK 不得走 HTTP。
//
// 真實 region 的預設解析器恆回 https，沿呼叫鏈構造不出 http 的情形——
// 故以獨立接縫直接測，否則這條規則會是一段永不執行的程式碼。
func TestRequireHTTPSEndpoint(t *testing.T) {
	if err := requireHTTPSEndpoint("https", "https://kms.ap-northeast-1.amazonaws.com"); err != nil {
		t.Fatalf("https 端點不得被拒: %v", err)
	}
	for _, scheme := range []string{"http", "ws", ""} {
		err := requireHTTPSEndpoint(scheme, scheme+"://kms.example")
		if !errors.Is(err, ErrEndpointOverride) {
			t.Fatalf("scheme=%q MUST 被拒，得 %v", scheme, err)
		}
	}
}

// ---- 重試疊加 ----

// TestDescribeIssuesExactlyThreeHTTPRequests **重試疊加的實證**：以真 SDK 打一個會數
// 請求的 httptest 伺服器，斷言建構期節流重試共送出**恰 3 個 HTTP 請求**。
//
// 修補前 SDK 預設 retryer（3 次）與本層迴圈（3 次）相乘＝最多 9 個請求；
// 本測試是唯一能分辨 3 與 9 的證據——fake client 看不到 HTTP 層。
func TestDescribeIssuesExactlyThreeHTTPRequests(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"__type":"ThrottlingException","message":"slow down"}`))
	}))
	defer srv.Close()

	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")

	_, err := New(context.Background(), Settings{
		Provider: ProviderAWS, KeyID: testKeyAlias, Region: testRegion,
		Endpoint: srv.URL,
	})
	if !errors.Is(err, ErrKMSUnavailable) {
		t.Fatalf("持續節流應以 ErrKMSUnavailable 收場，得 %v", err)
	}
	if got := atomic.LoadInt64(&hits); got != describeMaxAttempts {
		t.Fatalf("建構期 DescribeKey 的實際 HTTP 請求數應為 %d，得 %d"+
			"（SDK 內層 retryer 未關閉時會是 %d）",
			describeMaxAttempts, got, describeMaxAttempts*3)
	}
}

// TestEncryptKeepsSDKRetry 關閉 SDK 重試的作用域**只限 DescribeKey**：
// Encrypt／Decrypt 走執行期路徑，SDK 重試對它們是淨益，不得一併關掉。
func TestEncryptKeepsSDKRetry(t *testing.T) {
	var describeHits, encryptHits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.Header.Get("X-Amz-Target")
		switch {
		case strings.HasSuffix(target, "DescribeKey"):
			atomic.AddInt64(&describeHits, 1)
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			_, _ = w.Write([]byte(`{"KeyMetadata":{"Arn":"` + testKeyARN + `","KeyId":"` + testKeyID +
				`","KeySpec":"SYMMETRIC_DEFAULT","KeyUsage":"ENCRYPT_DECRYPT","KeyState":"Enabled","Enabled":true}}`))
		default:
			atomic.AddInt64(&encryptHits, 1)
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"__type":"ThrottlingException","message":"slow down"}`))
		}
	}))
	defer srv.Close()

	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")

	// canary 的 Encrypt 會被節流 → New 失敗，但 Encrypt 應已由 SDK 重試 3 次
	_, err := New(context.Background(), Settings{
		Provider: ProviderAWS, KeyID: testKeyAlias, Region: testRegion, Endpoint: srv.URL,
	})
	if err == nil {
		t.Fatal("canary 的 Encrypt 持續節流時 New MUST 失敗")
	}
	if got := atomic.LoadInt64(&describeHits); got != 1 {
		t.Fatalf("DescribeKey 成功時應恰 1 個請求，得 %d", got)
	}
	if got := atomic.LoadInt64(&encryptHits); got != 3 {
		t.Fatalf("Encrypt 應保有 SDK 預設 3 次重試，得 %d", got)
	}
}

// ---- 重試分類過寬 ----

// TestRetryClassificationIsAllowlisted 分流是**允許清單**：只有確定屬瞬時、
// 且重試確實可能改變結果的錯誤才重試。
func TestRetryClassificationIsAllowlisted(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want retryDecision
	}{
		// 重試：節流
		{"ThrottlingException", &smithy.GenericAPIError{Code: "ThrottlingException"}, decisionRetry},
		{"TooManyRequestsException", &smithy.GenericAPIError{Code: "TooManyRequestsException"}, decisionRetry},
		{"RequestLimitExceeded", &smithy.GenericAPIError{Code: "RequestLimitExceeded"}, decisionRetry},
		// 重試：逾時
		{"RequestTimeout", &smithy.GenericAPIError{Code: "RequestTimeout"}, decisionRetry},
		{"DependencyTimeoutException", &smithy.GenericAPIError{Code: "DependencyTimeoutException"}, decisionRetry},
		{"context.DeadlineExceeded", context.DeadlineExceeded, decisionRetry},
		{"net timeout", &net.OpError{Err: &timeoutErr{}}, decisionRetry},
		// 重試：明確 5xx
		{"KMSInternalException", &smithy.GenericAPIError{Code: "KMSInternalException"}, decisionRetry},
		{"裸 503", &smithyhttp.ResponseError{Response: &smithyhttp.Response{
			Response: &http.Response{StatusCode: 503}}, Err: errors.New("unavailable")}, decisionRetry},
		// 重試：暫時性連線層
		{"ECONNREFUSED", &net.OpError{Err: syscall.ECONNREFUSED}, decisionRetry},
		{"ECONNRESET", &net.OpError{Err: syscall.ECONNRESET}, decisionRetry},

		// **不重試（本次修補的核心）**：配額問題非瞬時節流
		{"LimitExceededException（配額，非節流）",
			&smithy.GenericAPIError{Code: "LimitExceededException"}, decisionRejected},
		// 不重試：API 層明確拒絕
		{"AccessDeniedException", &smithy.GenericAPIError{Code: "AccessDeniedException"}, decisionRejected},
		{"NotFoundException", &smithy.GenericAPIError{Code: "NotFoundException"}, decisionRejected},
		{"未知 API 錯誤碼", &smithy.GenericAPIError{Code: "SomeBrandNewException"}, decisionRejected},
		{"4xx 傳輸錯誤", &smithyhttp.ResponseError{Response: &smithyhttp.Response{
			Response: &http.Response{StatusCode: 403}}, Err: errors.New("forbidden")}, decisionRejected},

		// **不重試：未知非 API 錯誤一律立即失敗**（修補前這些全部會被重試三輪）
		{"DNS NXDOMAIN（region 拼錯）",
			&net.DNSError{Err: "no such host", Name: "kms.nowhere.amazonaws.com", IsNotFound: true}, decisionPermanent},
		{"TLS 憑證驗證失敗",
			&tls.CertificateVerificationError{Err: errors.New("x509: certificate signed by unknown authority")}, decisionPermanent},
		{"憑證鏈解析失敗", errors.New("failed to refresh cached credentials"), decisionPermanent},
		{"序列化錯誤", fmt.Errorf("serialization failed: %w", errors.New("bad input")), decisionPermanent},
		{"呼叫端取消", context.Canceled, decisionPermanent},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyKMSError(c.err); got != c.want {
				t.Fatalf("分流錯誤：want %v got %v（err=%v）", c.want, got, c.err)
			}
		})
	}
}

// timeoutErr 實作 net.Error 的逾時錯誤（標準庫沒有可直接構造的公開型別）
type timeoutErr struct{}

func (*timeoutErr) Error() string   { return "i/o timeout" }
func (*timeoutErr) Timeout() bool   { return true }
func (*timeoutErr) Temporary() bool { return true }

// TestPermanentNonAPIErrorFailsImmediately 未知非 API 錯誤**一次就停**，
// 且以 ErrKMSUnavailable（不可達）而非 ErrKMSRejected（遭拒）回報——
// DNS 拼錯不是 KMS 拒絕了我們，把它說成「遭拒」會讓操作者去查 IAM policy。
func TestPermanentNonAPIErrorFailsImmediately(t *testing.T) {
	f := newFakeKMS()
	f.addKey(testKeyAlias, testKeyID, testKeyARN)
	dnsErr := &net.DNSError{Err: "no such host", Name: "kms.bad.amazonaws.com", IsNotFound: true}
	f.describeErrs = []error{dnsErr, dnsErr, dnsErr}

	_, err := New(context.Background(), Settings{
		Provider: ProviderAWS, KeyID: testKeyAlias, Region: testRegion, Client: f,
	})
	if !errors.Is(err, ErrKMSUnavailable) {
		t.Fatalf("非瞬時網路錯誤應回 ErrKMSUnavailable，得 %v", err)
	}
	if errors.Is(err, ErrKMSRejected) {
		t.Fatal("DNS 錯誤 SHALL NOT 被說成「KMS 拒絕請求」（會誤導去查 IAM）")
	}
	if len(f.describeCalls) != 1 {
		t.Fatalf("非瞬時錯誤 SHALL NOT 重試：嘗試了 %d 次", len(f.describeCalls))
	}
}

// TestQuotaErrorFailsImmediately LimitExceededException 屬配額問題，
// 重試 9 秒後訊息一模一樣——立即失敗才是對操作者有用的行為
func TestQuotaErrorFailsImmediately(t *testing.T) {
	f := newFakeKMS()
	f.addKey(testKeyAlias, testKeyID, testKeyARN)
	quota := &smithy.GenericAPIError{Code: "LimitExceededException", Message: "quota reached"}
	f.describeErrs = []error{quota, quota, quota}

	_, err := New(context.Background(), Settings{
		Provider: ProviderAWS, KeyID: testKeyAlias, Region: testRegion, Client: f,
	})
	if !errors.Is(err, ErrKMSRejected) {
		t.Fatalf("配額錯誤應立即失敗，得 %v", err)
	}
	if len(f.describeCalls) != 1 {
		t.Fatalf("配額錯誤 SHALL NOT 重試：嘗試了 %d 次", len(f.describeCalls))
	}
}

// ---- MRK 身分（已知限制的釘住）----

const (
	mrkKeyID      = "mrk-1234567890abcdef1234567890abcdef"
	mrkPrimaryARN = "arn:aws:kms:ap-northeast-1:123456789012:key/mrk-1234567890abcdef1234567890abcdef"
	mrkReplicaARN = "arn:aws:kms:us-east-1:123456789012:key/mrk-1234567890abcdef1234567890abcdef"
)

// TestMultiRegionKeyIsRegionScopedIdentity **釘住已知限制**（安全審查 med #4，取 (c)）：
// MRK 可作為 KEK 使用，但本版把 primary 與 replica 視為**兩把不同的鑰**。
//
// **為何要有這一格**：限制若只寫在註解裡，日後第一個試著把 KEK_KMS_REGION 切到
// replica 的人會在生產環境撞上 ErrKEKMismatch 才知道。本測試把「切區＝換鑰」
// 這件事變成一條會被執行的斷言；哪天真的實作了跨區身分，本格必然轉紅，
// 逼人回來把註解與限制一併更新。
func TestMultiRegionKeyIsRegionScopedIdentity(t *testing.T) {
	f := newFakeKMS()
	f.addKey("alias/mrk-primary", mrkKeyID, mrkPrimaryARN)
	f.addKey("alias/mrk-replica", mrkKeyID+"-replica", mrkReplicaARN)

	primary, err := New(context.Background(), Settings{
		Provider: ProviderAWS, KeyID: "alias/mrk-primary", Region: "ap-northeast-1", Client: f,
	})
	if err != nil {
		t.Fatalf("MRK primary 應可作為 KEK 建構: %v", err)
	}
	replica, err := New(context.Background(), Settings{
		Provider: ProviderAWS, KeyID: "alias/mrk-replica", Region: "us-east-1", Client: f,
	})
	if err != nil {
		t.Fatalf("MRK replica 應可作為 KEK 建構: %v", err)
	}

	// 語法守衛認得 MRK（不得因為 mrk- 形狀就 fail-close）
	if err := primary.ValidateKeyIDSyntax(mrkPrimaryARN); err != nil {
		t.Fatalf("MRK ARN 不得判為非正規: %v", err)
	}

	// **已知限制**：落庫身分含 region，故 primary 與 replica 的 kek_id 不同。
	// 若哪天實作了「落庫邏輯身分 / 本區操作 ARN」分離，本斷言會轉紅。
	if primary.KeyRef().KeyID == replica.KeyRef().KeyID {
		t.Fatal("本版尚未支援 MRK 跨區身分等價；若已實作，請一併更新 Provider 型別註解的" +
			"「MRK 已知限制」段")
	}
	pp, _ := ParseKeyARN(primary.KeyRef().KeyID)
	rp, _ := ParseKeyARN(replica.KeyRef().KeyID)
	if !pp.IsMultiRegion() || !rp.IsMultiRegion() || pp.KeyID != rp.KeyID {
		t.Fatalf("兩者應是同一把 MRK 的不同區副本：%s / %s", pp.KeyID, rp.KeyID)
	}
	if pp.Region == rp.Region {
		t.Fatal("測試前提失效：兩個副本應處於不同 region")
	}
	// 非同族（region 不同）⇒ 換區必須走重包，而非原生 ReEncrypt
	if primary.sameFamily(replica) {
		t.Fatal("跨區 MRK 副本 SHALL NOT 被視為同族（切區等同換鑰，須重包）")
	}
}

// ---- DescribeKey 不證明可用 ----

// TestNewRunsEncryptDecryptCanary 建構期 SHALL 跑一次真實往返：
// DescribeKey 過得去不代表有 kms:Encrypt／kms:Decrypt 權限
func TestNewRunsEncryptDecryptCanary(t *testing.T) {
	f := newFakeKMS()
	f.addKey(testKeyAlias, testKeyID, testKeyARN)
	if _, err := New(context.Background(), Settings{
		Provider: ProviderAWS, KeyID: testKeyAlias, Region: testRegion, Client: f,
	}); err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(f.encryptCalls) != 1 || len(f.decryptCalls) != 1 {
		t.Fatalf("建構期應各跑一次 Encrypt／Decrypt，得 %d／%d",
			len(f.encryptCalls), len(f.decryptCalls))
	}
	// canary **必須帶 AAD**，否則會撞上自身的 len(aad)==0 fail-close 而什麼都沒驗到
	ec := f.encryptCalls[0].EncryptionContext
	if len(ec) != 1 || ec[EncryptionContextAADKey] == "" {
		t.Fatalf("canary SHALL 帶 AAD（EncryptionContext），得 %v", ec)
	}
}

// TestNewFailsWhenEncryptPermissionMissing **本節的核心**：metadata 全部合格
// （Enabled＋SYMMETRIC_DEFAULT＋ENCRYPT_DECRYPT），但角色沒有 kms:Encrypt——
// 修補前這種部署會「驗證通過」，直到第一次真的要包裹金鑰才爆。
func TestNewFailsWhenEncryptPermissionMissing(t *testing.T) {
	f := newFakeKMS()
	f.addKey(testKeyAlias, testKeyID, testKeyARN)
	f.encryptErr = &smithy.GenericAPIError{
		Code: "AccessDeniedException", Message: "not authorized to perform kms:Encrypt"}

	_, err := New(context.Background(), Settings{
		Provider: ProviderAWS, KeyID: testKeyAlias, Region: testRegion, Client: f,
	})
	if err == nil {
		t.Fatal("缺 kms:Encrypt 權限時 MUST 於建構期 fail-close（DescribeKey 過得去不等於可用）")
	}
	if !strings.Contains(err.Error(), "kms:Encrypt") {
		t.Fatalf("錯誤未指出缺的是 kms:Encrypt：%v", err)
	}
}

// TestNewFailsWhenDecryptPermissionMissing 解密權限同理（XKS 不可達亦落於此面）
func TestNewFailsWhenDecryptPermissionMissing(t *testing.T) {
	f := newFakeKMS()
	f.addKey(testKeyAlias, testKeyID, testKeyARN)
	f.decryptErr = &smithy.GenericAPIError{
		Code: "KMSInvalidStateException", Message: "external key store unavailable"}

	_, err := New(context.Background(), Settings{
		Provider: ProviderAWS, KeyID: testKeyAlias, Region: testRegion, Client: f,
	})
	if err == nil {
		t.Fatal("缺 kms:Decrypt／XKS 不可達時 MUST 於建構期 fail-close")
	}
	if !strings.Contains(err.Error(), "kms:Decrypt") {
		t.Fatalf("錯誤未指出缺的是 kms:Decrypt：%v", err)
	}
}

// ---- 預算耗盡誤報為次數耗盡 ----

// TestBudgetExhaustionReportedAsBudgetNotAttempts 最後一次呼叫把預算耗光時，
// 錯誤 SHALL 明示「總時間預算」而非「重試 N 次」——操作者該調的是網路，不是次數。
func TestBudgetExhaustionReportedAsBudgetNotAttempts(t *testing.T) {
	withRetryTiming(t, 500*time.Millisecond, time.Millisecond)

	var calls int
	_, err := retryDescribe(context.Background(), "DescribeKey",
		func(ctx context.Context) (int, error) {
			calls++
			time.Sleep(200 * time.Millisecond) // 三次呼叫共 600ms > 500ms 預算
			return 0, &smithy.GenericAPIError{Code: "ThrottlingException"}
		})
	if err == nil {
		t.Fatal("應失敗")
	}
	if !errors.Is(err, ErrKMSUnavailable) {
		t.Fatalf("應回 ErrKMSUnavailable，得 %v", err)
	}
	if !strings.Contains(err.Error(), "總時間預算") {
		t.Fatalf("預算耗盡 SHALL 明示預算而非次數，得：%v", err)
	}
	if strings.Contains(err.Error(), "重試 3 次") {
		t.Fatalf("預算耗盡時 SHALL NOT 誤報為「重試次數耗盡」，得：%v", err)
	}
	if calls != describeMaxAttempts {
		t.Fatalf("應跑滿 %d 次呼叫才耗盡預算，得 %d", describeMaxAttempts, calls)
	}
}

// TestAttemptExhaustionStillReportedAsAttempts 對照組：預算充裕而次數用盡時，
// 訊息仍須是「重試 N 次」。沒有這一格，把訊息一律改成「預算」也會讓上一格全綠。
func TestAttemptExhaustionStillReportedAsAttempts(t *testing.T) {
	withRetryTiming(t, 5*time.Second, time.Millisecond)

	_, err := retryDescribe(context.Background(), "DescribeKey",
		func(ctx context.Context) (int, error) {
			return 0, &smithy.GenericAPIError{Code: "ThrottlingException"}
		})
	if !strings.Contains(err.Error(), "重試 3 次") {
		t.Fatalf("次數耗盡 SHALL 明示次數，得：%v", err)
	}
	if strings.Contains(err.Error(), "總時間預算") {
		t.Fatalf("預算充裕時 SHALL NOT 報預算耗盡，得：%v", err)
	}
}

// TestRetryBudgetConstantsAreProductionValues 時間參數改為 var 是為了可測；
// 本格釘住產品預設值不被順手改掉（總預算 SHALL < 10s）。
func TestRetryBudgetConstantsAreProductionValues(t *testing.T) {
	if describeTotalBudget != 9*time.Second {
		t.Fatalf("describeTotalBudget 產品值應為 9s，得 %s", describeTotalBudget)
	}
	if describeTotalBudget >= 10*time.Second {
		t.Fatalf("總時間預算 SHALL < 10s，得 %s", describeTotalBudget)
	}
	if describeBaseBackoff != 200*time.Millisecond {
		t.Fatalf("describeBaseBackoff 產品值應為 200ms，得 %s", describeBaseBackoff)
	}
	if describeMaxAttempts != 3 {
		t.Fatalf("describeMaxAttempts 應為 3，得 %d", describeMaxAttempts)
	}
}

// withRetryTiming 暫時縮短重試時間參數（測試結束自動還原）
func withRetryTiming(t *testing.T, budget, backoff time.Duration) {
	t.Helper()
	oldBudget, oldBackoff := describeTotalBudget, describeBaseBackoff
	describeTotalBudget, describeBaseBackoff = budget, backoff
	t.Cleanup(func() { describeTotalBudget, describeBaseBackoff = oldBudget, oldBackoff })
}
