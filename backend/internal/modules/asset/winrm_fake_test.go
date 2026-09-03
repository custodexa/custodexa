package asset

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// 行程內的假 WinRM 端點：最小 WS-Man（Create Shell／Command／Send／Receive／Signal／Delete）
// ＋可注入的故障（退出碼、斷線、停頓、拒認證、只收明文）。
//
// 它不實作 NTLM 伺服端——那是數百行的密碼學而且測不到我方的東西。加密路徑的
// 「封裝／解封／框架／守衛／逾時／序列」以 fakeWinRMSecurity（可逆的假封裝）驗；
// 真 NTLM 交握對「不提供 Negotiate」與「未認證即接受」兩種目標的拒連則以正式的
// winrmNTLMSecurity 對本端點實跑（那兩條路在交握就結束，不需要伺服端密碼學）。
// 真機上的完整路徑由 loopback 回歸承擔。

const (
	fakeWinRMModeNormal    = "normal"
	fakeWinRMModeBasicOnly = "basic_only"
	fakeWinRMModeAnonymous = "anonymous"
	// fakeWinRMModeForbidden 對每個請求回 403：不是 WinRM 服務的目標（反向代理、別的 HTTP 服務）
	fakeWinRMModeForbidden = "forbidden"
	fakeWinRMSealPrefix    = "SEALED:"
	fakeWinRMAuthHeader    = "X-Test-Auth"
)

type fakeWinRMServer struct {
	t   *testing.T
	srv *httptest.Server

	mu sync.Mutex
	// mode 見 fakeWinRMMode*；normal 以 fakeWinRMAuthHeader 認證
	mode string
	// password 目前可用的密碼；改密成功後由伺服端自行更新（模擬真的改掉了）
	password string
	// exitCode Receive 回報的退出碼
	exitCode int
	// exitCodeFirstCommandOnly true＝exitCode 只套在第一個指令（改密）上，之後的指令（驗證）退出 0
	exitCodeFirstCommandOnly bool
	// omitResultMarker true＝stdout 不印腳本契約的結果標記（模擬標準輸出遺失或非本契約的目標）；
	// 預設照契約印 `ROTATION_RESULT=<退出碼>`
	omitResultMarker bool
	// stderr Receive 附帶的 stderr
	stderr string
	// dropOnReceive true＝收到 Receive 即斷線（狀態不可知）
	dropOnReceive bool
	// stallReceive Receive 前停頓（測逾時）
	stallReceive time.Duration
	// stallCreate Create Shell 前停頓（測建立 shell 逾時）
	stallCreate time.Duration
	// failHandshakes 前 N 次交握一律 401（測驗證重試）
	failHandshakes int
	// timeoutFaultOnce 第一次 Receive 回 OperationTimeout fault（合法，應繼續等）
	timeoutFaultOnce bool
	// faultOnReceive Receive 回非逾時的 fault
	faultOnReceive bool

	// --- 記錄 ---
	handshakes      int
	bodyRequests    int
	plaintextBodies int
	receives        int
	commands        []string
	stdin           bytes.Buffer
	stdinEOF        bool
	timeoutFaulted  bool
}

func newFakeWinRMServer(t *testing.T, password string) *fakeWinRMServer {
	t.Helper()
	f := &fakeWinRMServer{t: t, mode: fakeWinRMModeNormal, password: password}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

// newFakeWinRMTLSServer 自簽憑證的 https 端點。
func newFakeWinRMTLSServer(t *testing.T, password string) *fakeWinRMServer {
	t.Helper()
	f := &fakeWinRMServer{t: t, mode: fakeWinRMModeNormal, password: password}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.handle))
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

// certPEM 伺服端憑證的 PEM（供 ca 模式）。
func (f *fakeWinRMServer) certPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw}))
}

// hostPort 端點的 host 與 port。
func (f *fakeWinRMServer) hostPort() (string, int) {
	u := strings.TrimPrefix(strings.TrimPrefix(f.srv.URL, "http://"), "https://")
	host, portStr, err := net.SplitHostPort(u)
	if err != nil {
		f.t.Fatalf("split %s: %v", u, err)
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}

// asset 指向本端點的 rdp 資產（http）。
func (f *fakeWinRMServer) asset() *model.Asset {
	host, port := f.hostPort()
	scheme := model.WinrmSchemeHTTP
	if strings.HasPrefix(f.srv.URL, "https://") {
		scheme = model.WinrmSchemeHTTPS
	}
	return &model.Asset{
		Name: "win", Protocol: model.ProtocolRDP, Host: host, Port: 3389,
		RotationChannel: model.RotationChannelWindowsWinRM, WinrmScheme: scheme, WinrmPort: port,
	}
}

func (f *fakeWinRMServer) set(mut func(*fakeWinRMServer)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	mut(f)
}

func (f *fakeWinRMServer) snapshot() fakeWinRMServer {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fakeWinRMServer{
		handshakes: f.handshakes, bodyRequests: f.bodyRequests, plaintextBodies: f.plaintextBodies,
		receives: f.receives, commands: append([]string(nil), f.commands...), stdinEOF: f.stdinEOF,
		password: f.password,
	}
}

func (f *fakeWinRMServer) stdinText() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stdin.String()
}

// security 本端點對應的 winrmSecurityFactory（假封裝）。
func (f *fakeWinRMServer) security(username, password string) winrmSecurity {
	return &fakeWinRMSecurity{username: username, password: password}
}

// fakeWinRMSecurity 可逆的假封裝：交握以標頭送憑證，seal 只加前綴。
// 它保留與正式實作相同的錯誤語義（401 → errWinRMAuthFailed）。
type fakeWinRMSecurity struct {
	username, password string
	established        bool
}

func (s *fakeWinRMSecurity) handshake(ctx context.Context, hc *http.Client, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set(fakeWinRMAuthHeader, s.username+":"+s.password)
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		s.established = true
		return nil
	case http.StatusUnauthorized:
		return errWinRMAuthFailed
	default:
		return fmt.Errorf("fake winrm: handshake http %d", resp.StatusCode)
	}
}

func (s *fakeWinRMSecurity) seal(plain []byte) ([]byte, error) {
	if !s.established {
		return nil, errWinRMEncryptionUnavailable
	}
	return append([]byte(fakeWinRMSealPrefix), plain...), nil
}

func (s *fakeWinRMSecurity) unseal(sealed []byte) ([]byte, error) {
	if !bytes.HasPrefix(sealed, []byte(fakeWinRMSealPrefix)) {
		return nil, errors.New("fake winrm: payload not sealed")
	}
	return sealed[len(fakeWinRMSealPrefix):], nil
}

var (
	fakeActionRe  = regexp.MustCompile(`<a:Action[^>]*>([^<]+)</a:Action>`)
	fakeCommandRe = regexp.MustCompile(`(?s)<rsp:Command>(.*?)</rsp:Command>`)
	// 空內容的 Stream（EOF 訊息）可能被序列化為自閉合元素
	fakeStreamRe = regexp.MustCompile(`<rsp:Stream([^>]*?)(?:/>|>([^<]*)</rsp:Stream>)`)
)

const fakeEnvelope = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><s:Header><a:Action>%s</a:Action></s:Header><s:Body>%s</s:Body></s:Envelope>`

const (
	fakeShellID   = "SHELL-1"
	fakeCommandID = "CMD-1"
)

func (f *fakeWinRMServer) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	if len(body) > 0 {
		f.bodyRequests++
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/encrypted;") {
			f.plaintextBodies++
		}
	}
	mode := f.mode
	f.mu.Unlock()

	switch mode {
	case fakeWinRMModeBasicOnly:
		w.Header().Set("WWW-Authenticate", `Basic realm="WSMAN"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	case fakeWinRMModeAnonymous:
		w.Header().Set("Content-Type", winrmSOAPContentType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<s:Envelope/>"))
		return
	case fakeWinRMModeForbidden:
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if len(body) == 0 {
		f.handleHandshake(w, r)
		return
	}
	sealed, wantLen, err := unframeEncrypted(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	plain, err := (&fakeWinRMSecurity{}).unseal(sealed)
	if err != nil || len(plain) != wantLen {
		http.Error(w, "bad seal", http.StatusBadRequest)
		return
	}
	resp, hijack := f.dispatch(string(plain))
	if hijack {
		hj, ok := w.(http.Hijacker)
		if !ok {
			f.t.Fatal("responsewriter cannot hijack")
		}
		conn, _, err := hj.Hijack()
		if err == nil {
			_ = conn.Close()
		}
		return
	}
	sealedResp, _ := (&fakeWinRMSecurity{established: true}).seal([]byte(resp))
	w.Header().Set("Content-Type", winrmEncryptedContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(frameEncrypted(sealedResp, len(resp)))
}

func (f *fakeWinRMServer) handleHandshake(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.handshakes++
	n := f.handshakes
	want := ":" + f.password
	failFirst := f.failHandshakes
	f.mu.Unlock()

	got := r.Header.Get(fakeWinRMAuthHeader)
	if got == "" {
		w.Header().Set("WWW-Authenticate", "Negotiate")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if !strings.HasSuffix(got, want) || n <= failFirst {
		w.Header().Set("WWW-Authenticate", "Negotiate")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// dispatch 依 action 產生回應；hijack 為真代表要斷線。
func (f *fakeWinRMServer) dispatch(req string) (string, bool) {
	m := fakeActionRe.FindStringSubmatch(req)
	if m == nil {
		return fmt.Sprintf(fakeEnvelope, "http://schemas.dmtf.org/wbem/wsman/1/wsman/fault", "<s:Fault/>"), false
	}
	action := m[1]
	switch {
	case strings.HasSuffix(action, "transfer/Create"):
		f.mu.Lock()
		stall := f.stallCreate
		f.mu.Unlock()
		time.Sleep(stall)
		return fmt.Sprintf(fakeEnvelope, "http://schemas.xmlsoap.org/ws/2004/09/transfer/CreateResponse",
			`<rsp:Shell><rsp:ShellId>`+fakeShellID+`</rsp:ShellId></rsp:Shell>`), false
	case strings.HasSuffix(action, "shell/Command"):
		cmd := ""
		if cm := fakeCommandRe.FindStringSubmatch(req); cm != nil {
			cmd = strings.TrimSuffix(strings.TrimPrefix(cm[1], "<![CDATA["), "]]>")
		}
		f.mu.Lock()
		f.commands = append(f.commands, cmd)
		f.mu.Unlock()
		return fmt.Sprintf(fakeEnvelope, "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandResponse",
			`<rsp:CommandResponse><rsp:CommandId>`+fakeCommandID+`</rsp:CommandId></rsp:CommandResponse>`), false
	case strings.HasSuffix(action, "shell/Send"):
		if sm := fakeStreamRe.FindStringSubmatch(req); sm != nil {
			data, _ := base64.StdEncoding.DecodeString(sm[2])
			f.mu.Lock()
			f.stdin.Write(data)
			if strings.Contains(sm[1], `End="true"`) {
				f.stdinEOF = true
			}
			f.mu.Unlock()
		}
		return fmt.Sprintf(fakeEnvelope, "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/SendResponse", `<rsp:SendResponse/>`), false
	case strings.HasSuffix(action, "shell/Receive"):
		return f.receive()
	case strings.HasSuffix(action, "shell/Signal"):
		return fmt.Sprintf(fakeEnvelope, "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/SignalResponse", `<rsp:SignalResponse/>`), false
	case strings.HasSuffix(action, "transfer/Delete"):
		return fmt.Sprintf(fakeEnvelope, "http://schemas.xmlsoap.org/ws/2004/09/transfer/DeleteResponse", ``), false
	}
	return fmt.Sprintf(fakeEnvelope, "http://schemas.dmtf.org/wbem/wsman/1/wsman/fault", "<s:Fault/>"), false
}

func (f *fakeWinRMServer) receive() (string, bool) {
	f.mu.Lock()
	f.receives++
	stall := f.stallReceive
	drop := f.dropOnReceive
	exit := f.exitCode
	if f.exitCodeFirstCommandOnly && len(f.commands) > 1 {
		exit = 0
	}
	stderr := f.stderr
	omitMarker := f.omitResultMarker
	fault := f.faultOnReceive
	timeoutOnce := f.timeoutFaultOnce && !f.timeoutFaulted
	if timeoutOnce {
		f.timeoutFaulted = true
	}
	// 腳本契約：標準輸入第一行是新密碼（第二行是舊密碼，只供目標端回滾）
	stdinLine, _, _ := strings.Cut(f.stdin.String(), "\n")
	f.mu.Unlock()

	time.Sleep(stall)
	if drop {
		return "", true
	}
	if timeoutOnce {
		return fmt.Sprintf(fakeEnvelope, "http://schemas.dmtf.org/wbem/wsman/1/wsman/fault",
			`<s:Fault><s:Code><s:Value>s:Receiver</s:Value><s:Subcode><s:Value>w:TimedOut</s:Value></s:Subcode></s:Code></s:Fault>`), false
	}
	if fault {
		return fmt.Sprintf(fakeEnvelope, "http://schemas.dmtf.org/wbem/wsman/1/wsman/fault",
			`<s:Fault><s:Code><s:Value>s:Receiver</s:Value><s:Subcode><s:Value>w:InvalidSelectors</s:Value></s:Subcode></s:Code></s:Fault>`), false
	}
	// 改密成功（退出碼 0）或已改密但目標端自驗不可用（退出碼 6）：
	// 伺服端真的把密碼換掉，其後只有新密可交握
	if (exit == 0 || exit == windowsExitSelfVerifyUnavailable) && stdinLine != "" {
		f.mu.Lock()
		f.password = stdinLine
		f.mu.Unlock()
	}
	body := `<rsp:ReceiveResponse>`
	if !omitMarker {
		// 腳本契約：每個結束點先在 stdout 印結果標記再退出（Windows 的行尾是 CRLF）
		marker := windowsResultMarkerPrefix + strconv.Itoa(exit) + "\r\n"
		body += `<rsp:Stream Name="stdout" CommandId="` + fakeCommandID + `">` + base64.StdEncoding.EncodeToString([]byte(marker)) + `</rsp:Stream>`
	}
	if stderr != "" {
		body += `<rsp:Stream Name="stderr" CommandId="` + fakeCommandID + `">` + base64.StdEncoding.EncodeToString([]byte(stderr)) + `</rsp:Stream>`
	}
	body += `<rsp:CommandState CommandId="` + fakeCommandID + `" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"><rsp:ExitCode>` +
		strconv.Itoa(exit) + `</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>`
	return fmt.Sprintf(fakeEnvelope, "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/ReceiveResponse", body), false
}

// testWinRMExecutor 指向假端點的執行器：假封裝、短逾時、不真的睡。
func testWinRMExecutor(f *fakeWinRMServer, slept *[]time.Duration) windowsWinRMExecutor {
	e := newWindowsWinRMExecutor()
	e.newSecurity = f.security
	e.dialTimeout = 5 * time.Second
	e.commandTimeout = 5 * time.Second
	e.sleep = func(_ context.Context, d time.Duration) error {
		if slept != nil {
			*slept = append(*slept, d)
		}
		return nil
	}
	return e
}

// parseCertPool 供 TLS 測試確認 PEM 可解析。
func parseCertPool(t *testing.T, pemText string) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pemText)) {
		t.Fatal("cert PEM not parseable")
	}
	return pool
}

// unrelatedCertPEM 一張與任何端點無關的自簽憑證（httptest 的 TLS 端點共用同一張內建憑證，
// 「配錯的 CA」必須另外產生）。
func unrelatedCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "unrelated-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
