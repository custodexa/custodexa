package asset

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/masterzen/winrm/soap"
)

// WinRM 傳輸層：每一個 SOAP 訊息都經 NTLM 訊息層加密送出，且不存在任何明文路徑。
//
// 本產品用的 WinRM 函式庫只負責 WS-Man 訊息的組裝與解析（`winrm.New*Request`／
// `winrm.Parse*Response`）；HTTP 傳輸、認證與加密由本檔承擔。理由有三，皆為讀碼所得：
//
//   - 函式庫的加密傳輸自建裸 `http.Client`，TLS 設定與 RoundTripper 都無從注入，
//     https 的三種憑證驗證模式在那條路上等於沒有設定；
//   - 它在加密交握失敗時會**靜默退回明文 NTLM** 送出同一份載荷——而載荷的下一個
//     封包就是新密碼；
//   - 它的 context 取消與逾時在加密路徑上不產生錯誤，逾時的執行看起來像成功。
//
// 三條在這裡的對應：TLS 由 winrmTLSConfig 承載；winrmEncryptionGuard 在 HTTP 層拒絕任何
// 帶明文載荷的請求（機器可見的不變式，不倚賴上層寫對）；每個請求都綁 context，
// 逾時由 winrm_session.go 的計時器取消。

var (
	// errWinRMEncryptionUnavailable 目標無法建立訊息層加密的安全工作階段
	// （不提供 Negotiate、或未經認證即接受請求）。這是拒連，不是降級。
	errWinRMEncryptionUnavailable = errors.New("winrm: message-layer encryption unavailable")
	// errWinRMAuthFailed 交握完成但目標拒絕了憑證
	errWinRMAuthFailed = errors.New("winrm: authentication rejected")
	// errWinRMPlaintextRefused 傳輸守衛攔下一個帶明文載荷的請求。包著
	// errWinRMEncryptionUnavailable，使上層的分流不必認識守衛
	errWinRMPlaintextRefused = fmt.Errorf("winrm: refusing to send an unencrypted payload: %w", errWinRMEncryptionUnavailable)
)

// winrmPostMu 全行程一把鎖：同一時刻只有一個 WinRM 請求在飛。
//
// NTLM 的封裝／解封是綁在單一 TCP 連線上的有序串流；並發請求（同一目標或不同目標）
// 實測會互相撿到對方的連線而 401。批次改密不靠並行提速——序列化後每次請求約
// 100ms，遠低於一次改密的固定成本。
var winrmPostMu sync.Mutex

const (
	winrmUserAgent            = "WinRM client"
	winrmSOAPContentType      = "application/soap+xml;charset=UTF-8"
	winrmEncryptedProtocol    = "application/HTTP-SPNEGO-session-encrypted"
	winrmEncryptedContentType = `multipart/encrypted;protocol="` + winrmEncryptedProtocol + `";boundary="Encrypted Boundary"`
	winrmMIMEBoundary         = "--Encrypted Boundary"
	winrmOctetStreamHeader    = "\tContent-Type: application/octet-stream\r\n"
	// winrmMaxResponseBytes 單一回應的讀取上限；改密的回應都是幾 KB 的 SOAP
	winrmMaxResponseBytes = 4 << 20
)

// winrmSecurity 一次 SOAP 往返所用的安全工作階段：先交握、再封裝請求、解封回應。
//
// 介面存在是為了讓 WS-Man 序列、逾時、TLS 與傳輸守衛可以在不實作 NTLM 伺服端的
// 情況下被 httptest 假端點測到；正式實作只有 winrmNTLMSecurity。
type winrmSecurity interface {
	// handshake 以空載荷請求完成認證並建立安全工作階段；失敗即不得送出任何載荷
	handshake(ctx context.Context, hc *http.Client, url string) error
	// seal 封裝明文（回傳 長度前綴＋簽章＋密文）
	seal(plain []byte) ([]byte, error)
	// unseal 解封並驗章
	unseal(sealed []byte) ([]byte, error)
}

// winrmSecurityFactory 以憑證建立安全工作階段；每個 SOAP 往返一個（NTLM 交握綁連線）。
type winrmSecurityFactory func(username, password string) winrmSecurity

// winrmEncryptionGuard HTTP 層的不變式：凡帶載荷的請求，Content-Type 必須是
// multipart/encrypted，否則拒絕送出。交握請求沒有載荷，不受影響。
//
// 這一層不是給正常路徑用的——正常路徑永遠送密文。它擋的是任何日後把明文塞進
// 傳輸的回歸（包含「先送明文試試」這種函式庫式的便宜行事）。
type winrmEncryptionGuard struct {
	next http.RoundTripper
}

func (g winrmEncryptionGuard) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasPrefix(req.Header.Get("Authorization"), "Basic ") {
		return nil, errWinRMPlaintextRefused
	}
	if req.Body != nil && req.Body != http.NoBody &&
		!strings.HasPrefix(req.Header.Get("Content-Type"), "multipart/encrypted;") {
		return nil, errWinRMPlaintextRefused
	}
	return g.next.RoundTrip(req)
}

// CloseIdleConnections 轉發到底層 transport。http.Client.CloseIdleConnections 只呼叫
// 實作了此方法的 RoundTripper；守衛包在 transport 外，若不轉發，關閉閒置連線即靜默失效
// （交握前無法保證取得全新連線）。
func (g winrmEncryptionGuard) CloseIdleConnections() {
	type closeIdler interface{ CloseIdleConnections() }
	if c, ok := g.next.(closeIdler); ok {
		c.CloseIdleConnections()
	}
}

// winrmTLSConfig 依資產的 TLS 模式產生設定；http 通道回 nil。
//
// system＝作業系統信任錨；ca＝只信任資產上傳的 PEM；insecure＝不驗證（傳輸階梯標風險）。
// 模式值域已在資產儲存時驗過，這裡遇到未知值是資料損毀，直接回錯而不猜。
func winrmTLSConfig(asset *model.Asset) (*tls.Config, error) {
	if asset.WinrmScheme != model.WinrmSchemeHTTPS {
		return nil, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	switch asset.WinrmTLSMode {
	case model.WinrmTLSModeSystem:
	case model.WinrmTLSModeCA:
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(asset.WinrmCACert)) {
			return nil, errors.New("winrm: CA certificate is not parseable")
		}
		cfg.RootCAs = pool
	case model.WinrmTLSModeInsecure:
		cfg.InsecureSkipVerify = true //nolint:gosec // 管理員顯式選擇的模式，且在傳輸階梯標為風險
	default:
		return nil, fmt.Errorf("winrm: unknown tls mode %q", asset.WinrmTLSMode)
	}
	return cfg, nil
}

// newWinRMHTTPClient 每個工作階段自己的連線池（不與行程內其他 HTTP 共用），
// 只走 HTTP/1.1（NTLM 認證綁連線，h2 多工會讓它失效），不跟隨轉址，不讀 proxy 環境變數。
func newWinRMHTTPClient(tlsCfg *tls.Config, dialTimeout time.Duration) *http.Client {
	transport := &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:     tlsCfg,
		TLSHandshakeTimeout: dialTimeout,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     90 * time.Second,
		TLSNextProto:        map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	return &http.Client{
		Transport: winrmEncryptionGuard{next: transport},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// winrmEndpointURL 資產的 WS-Man 端點。
func winrmEndpointURL(asset *model.Asset) string {
	return asset.WinrmScheme + "://" + net.JoinHostPort(asset.Host, strconv.Itoa(asset.EffectiveWinrmPort())) + "/wsman"
}

// winrmTransport 一個工作階段的傳輸：綁定 context、連線池、端點與憑證。
type winrmTransport struct {
	ctx         context.Context
	hc          *http.Client
	url         string
	username    string
	password    string
	newSecurity winrmSecurityFactory
}

// post 送出一則 SOAP 訊息並回傳解封後的回應本文。
//
// 每次都重新交握：NTLM 的安全工作階段綁在連線與序號上，沿用上一輪的工作階段
// 會在連線被回收後拿到 401。回應不論 HTTP 狀態碼都回本文——WS-Man 的 fault
// （含 OperationTimeout）以 500 附加密的 SOAP 送回，由呼叫端解析 action 判定。
func (t *winrmTransport) post(msg *soap.SoapMessage) (string, error) {
	winrmPostMu.Lock()
	defer winrmPostMu.Unlock()

	sec := t.newSecurity(t.username, t.password)
	if err := sec.handshake(t.ctx, t.hc, t.url); err != nil {
		return "", err
	}
	plain := []byte(msg.String())
	sealed, err := sec.seal(plain)
	if err != nil {
		return "", fmt.Errorf("winrm: seal: %w", err)
	}
	req, err := http.NewRequestWithContext(t.ctx, http.MethodPost, t.url, bytes.NewReader(frameEncrypted(sealed, len(plain))))
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", winrmUserAgent)
	req.Header.Set("Connection", "Keep-Alive")
	req.Header.Set("Content-Type", winrmEncryptedContentType)

	resp, err := t.hc.Do(req)
	if err != nil {
		return "", err
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, winrmMaxResponseBytes))
	_ = resp.Body.Close()
	if err != nil {
		return "", fmt.Errorf("winrm: read response: %w", err)
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), `protocol="`+winrmEncryptedProtocol+`"`) {
		// 對加密請求回了未加密的內容：不解讀、不重試明文
		return "", fmt.Errorf("winrm: response without message-layer encryption (http %d)", resp.StatusCode)
	}
	sealedResp, wantLen, err := unframeEncrypted(raw)
	if err != nil {
		return "", err
	}
	plainResp, err := sec.unseal(sealedResp)
	if err != nil {
		return "", fmt.Errorf("winrm: unseal: %w", err)
	}
	if len(plainResp) != wantLen {
		return "", errors.New("winrm: decrypted length does not match the declared length")
	}
	return string(plainResp), nil
}

// frameEncrypted 把密文包進 WinRM 的 multipart/encrypted 框架。
//
// 格式逐位元組沿 WS-Management 加密訊息的慣例（標頭行以 tab 起始、不留空行、
// 結尾 boundary 帶 `--`），這是真機驗證過的形狀，不改用標準 MIME 寫法。
func frameEncrypted(sealed []byte, plainLen int) []byte {
	var b bytes.Buffer
	b.WriteString(winrmMIMEBoundary + "\r\n")
	b.WriteString("\tContent-Type: " + winrmEncryptedProtocol + "\r\n")
	b.WriteString("\tOriginalContent: type=" + winrmSOAPContentType + ";Length=" + strconv.Itoa(plainLen) + "\r\n")
	b.WriteString(winrmMIMEBoundary + "\r\n")
	b.WriteString(winrmOctetStreamHeader)
	b.Write(sealed)
	b.WriteString(winrmMIMEBoundary + "--\r\n")
	return b.Bytes()
}

// unframeEncrypted 自框架取出密文與宣告的明文長度。
func unframeEncrypted(body []byte) ([]byte, int, error) {
	var parts [][]byte
	for _, p := range bytes.Split(body, []byte(winrmMIMEBoundary+"\r\n")) {
		if len(p) > 0 {
			parts = append(parts, p)
		}
	}
	// NTLM 封裝恆為單一區段（多區段只出現在本產品不支援的 CredSSP 分塊）
	if len(parts) != 2 {
		return nil, 0, errors.New("winrm: malformed encrypted response")
	}
	header, payload := parts[0], parts[1]
	idx := bytes.Index(header, []byte("Length="))
	if idx < 0 {
		return nil, 0, errors.New("winrm: encrypted response lacks OriginalContent length")
	}
	n, err := strconv.Atoi(string(bytes.TrimSpace(header[idx+len("Length="):])))
	if err != nil {
		return nil, 0, fmt.Errorf("winrm: encrypted response length: %w", err)
	}
	payload = bytes.TrimSuffix(payload, []byte(winrmMIMEBoundary+"--\r\n"))
	payload = bytes.TrimPrefix(payload, []byte(winrmOctetStreamHeader))
	return payload, n, nil
}
