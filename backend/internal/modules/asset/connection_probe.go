package asset

// 撥測（test-connection）的協議分派對照表與各協議 probe（db-protocol-connection-test）。
//
// 為何獨立成檔：分派曾是「白名單 SSH ＋ else 一律送 guacd」的**否定式**結構，
// 於是 mysql／postgres／redis／k8s 四種協議被 else 靜默吞進 guacd——guacd 沒有這些
// client library，回應是「不回 error 指令也不關 socket」，撥測永不返回並固定洩漏
// 一條 TCP 連線與 2 個 fd。同型缺陷在 e09658d（2026-06-12）以「再加一個 case」修過一次，
// 隔天新協議上線即復發。本檔把分派改成資料結構，並以雙向完備性守衛
// （TestConnectionProbeTableComplete）釘住 assetProtocols ⇔ connectionProbes。

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"syscall"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/k8sproxy"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/guacamole"
)

// 撥測逾時夾制區間（D5）：呼叫端可傳 timeout，但服務層只接受 1..30 秒。
// 上界的存在是為了「撥測不長佔」；前端 per-request timeout 必須大於本上界。
const (
	testTimeoutDefaultSeconds = 10
	testTimeoutMinSeconds     = 1
	testTimeoutMaxSeconds     = 30
)

// clampTestTimeout 夾制撥測逾時：<=0 取預設 10；>30 取 30；其餘原值。
func clampTestTimeout(timeout int) int {
	if timeout <= 0 {
		return testTimeoutDefaultSeconds
	}
	if timeout < testTimeoutMinSeconds {
		return testTimeoutMinSeconds
	}
	if timeout > testTimeoutMaxSeconds {
		return testTimeoutMaxSeconds
	}
	return timeout
}

// connectionProbe 一種協議的撥測方式。
// name 是穩定的分派識別字（供分派快照測試斷言，不外洩到 API）。
// run 收到的 timeout 已由 testConnection 夾制，且必須涵蓋撥測全程而非僅撥號。
type connectionProbe struct {
	name string
	run  func(s *AssetService, ctx context.Context, creds *AssetCredentials, timeout int) *ConnectionTestResult
}

// probe 識別字（分派快照測試的斷言對象）
const (
	probeNameSSHDirect = "ssh_direct"
	probeNameGuacd     = "guacd"
	probeNameTCPDial   = "tcp_dial"
	probeNameK8sExec   = "k8s_can_exec"
)

// connectionProbes 協議 → 撥測方式的**顯式對照表**（D1）。
//
// 與 assetProtocols 互為雙向完備：兩邊都不得單方面增刪。未登記的協議在
// testConnection 一律回 protocol_unsupported，不進 guacd 也不進任何中介。
//
// 驗證深度逐協議不同，spec（asset-connection-test）已逐條寫明：
//
//	ssh                     完整登入（host key 驗證 + 密碼認證）
//	rdp / vnc               guacd 完成協議連線握手
//	mysql/postgres/redis/mssql  僅 TCP 埠可達（刻意不做握手與認證，見 D2）
//	k8s                     API server 可達 + TLS 通過 + token 具 pods/exec 權限
var connectionProbes = map[model.ProtocolType]connectionProbe{
	model.ProtocolSSH: {name: probeNameSSHDirect, run: func(s *AssetService, _ context.Context, creds *AssetCredentials, timeout int) *ConnectionTestResult {
		return s.testSSHDirect(creds.Asset.ID, creds, timeout)
	}},
	model.ProtocolRDP:      {name: probeNameGuacd, run: (*AssetService).probeGuacd},
	model.ProtocolVNC:      {name: probeNameGuacd, run: (*AssetService).probeGuacd},
	model.ProtocolMySQL:    {name: probeNameTCPDial, run: (*AssetService).probeTCP},
	model.ProtocolPostgres: {name: probeNameTCPDial, run: (*AssetService).probeTCP},
	model.ProtocolRedis:    {name: probeNameTCPDial, run: (*AssetService).probeTCP},
	model.ProtocolMSSQL:    {name: probeNameTCPDial, run: (*AssetService).probeTCP},
	model.ProtocolK8s:      {name: probeNameK8sExec, run: (*AssetService).probeK8s},
}

// probeGuacd rdp／vnc 撥測：經 guacd 完成協議握手（自舊 testConnection 原樣抽出）。
//
// 誠實邊界：params.Timeout 只涵蓋 TCP 撥號，guacd 讀取路徑無 deadline
// （pkg/guacamole/client.go 刻意移除，見 D8 backlog）。本 change 不宣稱此路徑有
// 逾時保障——它只是不再收到 guacd 不支援的協議。
func (s *AssetService) probeGuacd(ctx context.Context, creds *AssetCredentials, timeout int) *ConnectionTestResult {
	asset := creds.Asset
	params := guacamole.TestConnectionParams{
		Protocol: string(asset.Protocol),
		Host:     asset.Host,
		Port:     asset.Port,
		// username 與密碼同取自 default 帳號（D6：憑證與 username 必須同帳號）
		Username: creds.Username,
		Password: creds.Password,
		Timeout:  time.Duration(timeout) * time.Second,
		Width:    1024,
		Height:   768,
	}
	// 私鑰：test_helper 的 BuildConnectionParams 不支援 private-key；撥測用 password 已足夠
	_ = creds.PrivateKey

	raw := guacamole.TestGuacamoleConnection(ctx, s.guacdHost, s.guacdPort, params)

	result := &ConnectionTestResult{
		Success:   raw.Success,
		LatencyMs: int64(raw.Latency.Milliseconds()),
		Protocol:  string(asset.Protocol),
		TestedAt:  time.Now(),
	}
	if !result.Success {
		// D9：guacd 原始訊息不外洩，只落伺服端日誌
		errorCode := mapGuacamoleErrorType(raw.ErrorType)
		result.setFailure(testResultCodeFor(errorCode), errorCode)
		log.Printf("[TestConnection] guacd 撥測失敗: Asset ID=%d Detail=%s", asset.ID, raw.Message)
	}
	return result
}

// mapGuacamoleErrorType 將 guacamole.ErrorType 映射到 ConnectionTestResult.ErrorCode
func mapGuacamoleErrorType(errorType string) string {
	switch errorType {
	case guacamole.ErrorTypeConnectionRefused:
		return ErrorCodeConnectionRefused
	case guacamole.ErrorTypeAuthenticationFailed:
		return ErrorCodeAuthFailed
	case guacamole.ErrorTypeTimeout:
		return ErrorCodeTimeout
	case guacamole.ErrorTypeProtocolError:
		return ErrorCodeProtocolError
	case "": // 成功時 ErrorType 為空
		return ""
	default:
		return ErrorCodeUnknown
	}
}

// probeTCP 資料庫協議（mysql／postgres／redis）撥測：只驗 host:port 的 TCP 可達性。
//
// **刻意不做協議握手與認證**（D2，使用者拍板）：真登入會在目標端留下失敗認證記錄
// （MySQL max_connect_errors、Redis AUTH 稽核），且要新增 2-3 個直接相依。
// 代價是「成功」僅代表埠可達，不代表對面是預期的 DB、更不代表憑證有效——
// 此侷限已寫進 spec 並由前端徽章 tooltip 就地揭露。
func (s *AssetService) probeTCP(_ context.Context, creds *AssetCredentials, timeout int) *ConnectionTestResult {
	asset := creds.Asset
	result := &ConnectionTestResult{Protocol: string(asset.Protocol), TestedAt: time.Now()}

	addr := net.JoinHostPort(asset.Host, fmt.Sprintf("%d", asset.Port))
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, time.Duration(timeout)*time.Second)
	result.LatencyMs = time.Since(start).Milliseconds()
	if err != nil {
		result.setFailure(tcpFailureCode(err))
		log.Printf("[TestConnection] TCP 探測失敗: Asset ID=%d addr=%s err=%v", asset.ID, addr, err)
		return result
	}
	_ = conn.Close()
	result.Success = true
	return result
}

// tcpFailureCode TCP 撥號錯誤三分類：逾時、連線被拒、其餘（DNS 等）。
func tcpFailureCode(err error) (apierror.ErrCode, string) {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return apierror.CodeAssetTestTimeout, ErrorCodeTimeout
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return apierror.CodeAssetTestConnectionRefused, ErrorCodeConnectionRefused
	}
	return apierror.CodeAssetTestConnectionFailed, ErrorCodeConnectionFailed
}

// probeK8s k8s 撥測：SelfSubjectAccessReview 預檢 token 是否可對 namespace 開 pods/exec。
//
// 複用 k8sproxy.CanExec（正式路徑同一函式，內建 listTimeout 與 classifyErr 五類分類）。
// 順帶消除「我方常數為 k8s、guacd client library 名為 kubernetes」的字串錯配——
// k8s 撥測從此不經 guacd。
func (s *AssetService) probeK8s(ctx context.Context, creds *AssetCredentials, timeout int) *ConnectionTestResult {
	asset := creds.Asset
	result := &ConnectionTestResult{Protocol: string(asset.Protocol), TestedAt: time.Now()}

	target, err := s.k8sTarget(asset.ID, "", "")
	if err != nil {
		switch {
		case errors.Is(err, ErrAssetNoUsableAccount):
			result.setFailure(apierror.CodeAssetTestNoAccount, ErrorCodeNoUsableAccount)
		default:
			result.setFailure(apierror.CodeAssetTestUnknownError, ErrorCodeUnknown)
		}
		log.Printf("[TestConnection] k8s target 組裝失敗: Asset ID=%d err=%v", asset.ID, err)
		return result
	}

	// 夾制後的 timeout 與 k8sproxy 內部 listTimeout() 取較小值：兩層都有 deadline
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	start := time.Now()
	allowed, err := k8sproxy.CanExec(ctx, target)
	result.LatencyMs = time.Since(start).Milliseconds()
	if err != nil {
		result.setFailure(k8sFailureCode(err))
		log.Printf("[TestConnection] k8s 撥測失敗: Asset ID=%d err=%v", asset.ID, err)
		return result
	}
	if !allowed {
		// RBAC 明確拒絕：與「連不上」必須可區分
		result.setFailure(apierror.CodeAssetTestExecForbidden, ErrorCodeExecForbidden)
		return result
	}
	result.Success = true
	return result
}

// k8sFailureCode 把 k8sproxy.K8sError 的五類 Kind 映到撥測機器碼（D6）。
// 非 K8sError（如 context deadline）歸逾時或未分類。
func k8sFailureCode(err error) (apierror.ErrCode, string) {
	var ke *k8sproxy.K8sError
	if errors.As(err, &ke) {
		switch ke.Kind {
		case k8sproxy.KindUnauthorized:
			return apierror.CodeAssetTestAuthFailed, ErrorCodeAuthFailed
		case k8sproxy.KindForbidden:
			return apierror.CodeAssetTestExecForbidden, ErrorCodeExecForbidden
		case k8sproxy.KindNotFound:
			return apierror.CodeAssetTestNamespaceNotFound, ErrorCodeNamespaceNotFound
		case k8sproxy.KindTLS:
			return apierror.CodeAssetTestTLSFailed, ErrorCodeTLSFailed
		case k8sproxy.KindUnreachable:
			return apierror.CodeAssetTestConnectionFailed, ErrorCodeConnectionFailed
		}
		return apierror.CodeAssetTestUnknownError, ErrorCodeUnknown
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return apierror.CodeAssetTestTimeout, ErrorCodeTimeout
	}
	return apierror.CodeAssetTestUnknownError, ErrorCodeUnknown
}
