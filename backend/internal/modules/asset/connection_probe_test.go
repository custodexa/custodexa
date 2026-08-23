package asset

// 撥測分派的守衛測試。
//
// 這裡的雙向完備性守衛是**唯一能阻止同型缺陷復發的機制**：
// e09658d（2026-06-12）以「白名單 SSH ＋ else 送 guacd」修過一次撥測盲區，
// 隔天 dbproxy／k8sproxy 上線時只在 validateProtocol 加放行、沒動撥測分派，
// 四個協議立刻掉回 else 並在零測試覆蓋下存活兩個月。

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/k8sproxy"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConnectionProbeTableComplete 協議清單 ⇔ 撥測對照表的**雙向**完備性。
//
// 方向 A（清單 ⊆ 對照表）擋「新增協議忘了登記撥測方式」——即本 change 修的缺陷。
// 方向 B（對照表 ⊆ 清單）擋「移除協議後遺留死 probe」與鍵拼錯
// （例如把 k8s 誤登記成 kubernetes——現況 guacd 錯配正是這個形狀）。
// 兩個方向都是本專案實際發生過的失敗模式，缺一不可。
func TestConnectionProbeTableComplete(t *testing.T) {
	// 方向 A：可建立資產的每個協議都必須有撥測方式
	for _, p := range assetProtocols {
		probe, ok := connectionProbes[p]
		if !ok {
			t.Errorf("協議 %q 在 assetProtocols 中但未於 connectionProbes 登記撥測方式："+
				"新增協議必須同時登記 probe，否則撥測會落入未支援分支", p)
			continue
		}
		if probe.name == "" {
			t.Errorf("協議 %q 的 probe 缺少識別字（name）", p)
		}
		if probe.run == nil {
			t.Errorf("協議 %q 的 probe 未指定實作（run 為 nil）", p)
		}
	}

	// 方向 B：對照表不得含不可建立的協議
	allowed := make(map[model.ProtocolType]bool, len(assetProtocols))
	for _, p := range assetProtocols {
		allowed[p] = true
	}
	for p := range connectionProbes {
		if !allowed[p] {
			t.Errorf("connectionProbes 含多餘的鍵 %q：該協議不在 assetProtocols 清單中"+
				"（拼寫錯誤，或協議已移除但 probe 未清）", p)
		}
	}

	// 字面釘子：兩邊數量都必須等於現況七種協議。
	// 只比對「集合相等」擋不住兩邊同時漏掉同一個協議。
	assert.Equal(t, 8, len(assetProtocols), "assetProtocols 現況為八種協議；增刪協議須同步更新本斷言與 spec")
	assert.Equal(t, 8, len(connectionProbes), "connectionProbes 現況為八筆登記")
}

// TestCreateAssetProtocolBindingMatchesTable 釘住 gin binding 的 oneof 清單 ⇔ assetProtocols。
//
// 為何需要第三道守衛：協議放行其實有**兩層**——gin 的 `binding:"oneof=..."` 在
// handler 綁定階段先擋，服務層的 validateProtocol 才查 assetProtocols。上面兩個守衛
// 只覆蓋服務層，binding 的字面清單是完全獨立的第二份事實源。
// mssql 上線時只改了 assetProtocols 與 connectionProbes，binding 清單沒動，
// 結果 POST /api/v1/assets 一律回 VALIDATION_BAD_REQUEST——整條建資產路徑不可用，
// 而既有的雙向完備性守衛全綠。此測試由結構標籤反射取清單，杜絕同型復發。
func TestCreateAssetProtocolBindingMatchesTable(t *testing.T) {
	field, ok := reflect.TypeOf(CreateAssetRequest{}).FieldByName("Protocol")
	require.True(t, ok, "CreateAssetRequest 應有 Protocol 欄位")

	var oneof string
	for _, rule := range strings.Split(field.Tag.Get("binding"), ",") {
		if strings.HasPrefix(rule, "oneof=") {
			oneof = strings.TrimPrefix(rule, "oneof=")
		}
	}
	require.NotEmpty(t, oneof, "CreateAssetRequest.Protocol 的 binding 應含 oneof 清單")

	inBinding := make(map[string]bool)
	for _, p := range strings.Fields(oneof) {
		inBinding[p] = true
	}
	inTable := make(map[string]bool, len(assetProtocols))
	for _, p := range assetProtocols {
		inTable[string(p)] = true
		assert.True(t, inBinding[string(p)],
			"協議 %q 在 assetProtocols 但不在 binding 的 oneof 清單：API 會在綁定階段回 VALIDATION_BAD_REQUEST", p)
	}
	for p := range inBinding {
		assert.True(t, inTable[p],
			"binding 的 oneof 含 %q 但 assetProtocols 沒有：綁定放行後服務層仍會拒絕（或協議已移除未清）", p)
	}
}

// TestConnectionDispatchSnapshot 分派快照：每個協議對應的 probe 識別字。
// 不實際撥號，故不依賴靶機、不 flaky。
func TestConnectionDispatchSnapshot(t *testing.T) {
	want := map[model.ProtocolType]string{
		model.ProtocolSSH:      probeNameSSHDirect,
		model.ProtocolRDP:      probeNameGuacd,
		model.ProtocolVNC:      probeNameGuacd,
		model.ProtocolMySQL:    probeNameTCPDial,
		model.ProtocolPostgres: probeNameTCPDial,
		model.ProtocolRedis:    probeNameTCPDial,
		model.ProtocolMSSQL:    probeNameTCPDial,
		model.ProtocolK8s:      probeNameK8sExec,
	}
	for _, p := range assetProtocols {
		expected, ok := want[p]
		require.True(t, ok, "協議 %q 未列於分派快照，請補上預期的 probe 識別字", p)
		assert.Equal(t, expected, connectionProbes[p].name, "協議 %q 的撥測方式與快照不符", p)
	}
	// 反向：快照不得含清單外的協議（與完備性守衛同軸，避免快照自身漂移）
	assert.Equal(t, len(assetProtocols), len(want))

	// guacd 只剩 rdp／vnc 兩種協議會進入——這是本 change 的核心不變式：
	// guacd 沒有 mysql/postgres/redis client library，送過去會永不返回。
	viaGuacd := []model.ProtocolType{}
	for p, probe := range connectionProbes {
		if probe.name == probeNameGuacd {
			viaGuacd = append(viaGuacd, p)
		}
	}
	assert.ElementsMatch(t, []model.ProtocolType{model.ProtocolRDP, model.ProtocolVNC}, viaGuacd,
		"僅 rdp／vnc 得經 guacd 撥測")
}

// TestConnectionDispatchUnsupportedProtocolNeverReachesGuacd 走**生產入口**
// （TestConnection → testConnection → 對照表分派）驗證未登記協議：
// 回 protocol_unsupported，且對 guacd **零連線**。
//
// guacd 位址指向本測試自建的 listener，以「接受連線數」當名稱無關的 oracle——
// 若哪天分派又回退成 else fallback，這格會因 accepted>0 而紅。
func TestConnectionDispatchUnsupportedProtocolNeverReachesGuacd(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	var accepted int64
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt64(&accepted, 1)
			_ = conn.Close()
		}
	}()

	host, port := splitHostPortForTest(t, ln.Addr().String())

	_, mock, _ := setupAssetMockDB(t)
	service, err := NewAssetService(aesColumnCodec(t, make([]byte, 32)), host, port, audit.NewTxSink())
	require.NoError(t, err)

	expectAssetWithDefaultAccount(t, mock, service, "ftp", "127.0.0.1", 21)

	result, err := service.testConnection(context.Background(), 1, 5)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.False(t, result.Success)
	assert.Equal(t, ErrorCodeProtocolUnsupport, result.ErrorCode)
	assert.Equal(t, apierror.CodeAssetTestProtocolUnsupported, result.Code)
	assert.Equal(t, "ftp", result.Protocol)
	assert.Equal(t, int64(0), atomic.LoadInt64(&accepted),
		"未登記協議不得建立任何往 guacd 的連線")
}

// TestClampTestTimeout 逾時夾制：呼叫端可傳任意值，服務層只接受 1..30 秒。
func TestClampTestTimeout(t *testing.T) {
	cases := []struct {
		in, want int
	}{
		{0, 10},   // 未指定 → 預設
		{-1, 10},  // 非法 → 預設
		{600, 30}, // 超上界 → 夾到 30（現況無上界，呼叫端可傳 600 造成長佔）
		{1, 1},
		{5, 5},
		{30, 30},
		{31, 30},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, clampTestTimeout(c.in), "clampTestTimeout(%d)", c.in)
	}
}

// TestConnectionProbeTCPReachable DB probe 對真實 listener 回成功（僅埠可達，無握手）。
func TestConnectionProbeTCPReachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	host, port := splitHostPortForTest(t, ln.Addr().String())
	svc := &AssetService{}
	result := svc.probeTCP(context.Background(), credsForProbe(model.ProtocolPostgres, host, port), 5)

	assert.True(t, result.Success, "埠可達應判成功")
	assert.Empty(t, result.ErrorCode)
	assert.Equal(t, "postgres", result.Protocol)
}

// TestConnectionProbeTCPRefused 埠關閉 → connection_refused（非 protocol_unsupported）。
func TestConnectionProbeTCPRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	host, port := splitHostPortForTest(t, ln.Addr().String())
	require.NoError(t, ln.Close()) // 關掉才撥，確保是 refused 而非 timeout

	svc := &AssetService{}
	start := time.Now()
	result := svc.probeTCP(context.Background(), credsForProbe(model.ProtocolMySQL, host, port), 5)
	elapsed := time.Since(start)

	assert.False(t, result.Success)
	assert.Equal(t, ErrorCodeConnectionRefused, result.ErrorCode)
	assert.Equal(t, apierror.CodeAssetTestConnectionRefused, result.Code)
	assert.Less(t, elapsed, 5*time.Second, "被拒應立即返回，不等到逾時")
}

// TestConnectionProbeTCPFailureClassification 撥號錯誤三分類。
// 逾時分支以偽造的 net.Error 驅動——真黑洞位址在容器網路內不可靠
// （可能立即回 network unreachable），會讓這格變成計時 flaky。
func TestConnectionProbeTCPFailureClassification(t *testing.T) {
	code, ec := tcpFailureCode(&net.OpError{Op: "dial", Err: timeoutErrForTest{}})
	assert.Equal(t, apierror.CodeAssetTestTimeout, code)
	assert.Equal(t, ErrorCodeTimeout, ec)

	code, ec = tcpFailureCode(&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED})
	assert.Equal(t, apierror.CodeAssetTestConnectionRefused, code)
	assert.Equal(t, ErrorCodeConnectionRefused, ec)

	// 其餘（DNS 等）→ 協議中性的連線失敗，不得落入 protocol_unsupported
	code, ec = tcpFailureCode(&net.OpError{Op: "dial", Err: errors.New("no such host")})
	assert.Equal(t, apierror.CodeAssetTestConnectionFailed, code)
	assert.Equal(t, ErrorCodeConnectionFailed, ec)
}

// TestK8sFailureCodeMapping k8sproxy 五類 Kind → 撥測機器碼（2.3）。
func TestK8sFailureCodeMapping(t *testing.T) {
	cases := []struct {
		kind     string
		wantCode apierror.ErrCode
		wantEC   string
	}{
		{k8sproxy.KindUnauthorized, apierror.CodeAssetTestAuthFailed, ErrorCodeAuthFailed},
		{k8sproxy.KindForbidden, apierror.CodeAssetTestExecForbidden, ErrorCodeExecForbidden},
		{k8sproxy.KindNotFound, apierror.CodeAssetTestNamespaceNotFound, ErrorCodeNamespaceNotFound},
		{k8sproxy.KindTLS, apierror.CodeAssetTestTLSFailed, ErrorCodeTLSFailed},
		{k8sproxy.KindUnreachable, apierror.CodeAssetTestConnectionFailed, ErrorCodeConnectionFailed},
		{k8sproxy.KindUnknown, apierror.CodeAssetTestUnknownError, ErrorCodeUnknown},
	}
	for _, c := range cases {
		code, ec := k8sFailureCode(&k8sproxy.K8sError{Kind: c.kind, Message: "x"})
		assert.Equal(t, c.wantCode, code, "kind=%s", c.kind)
		assert.Equal(t, c.wantEC, ec, "kind=%s", c.kind)
	}

	// 非 K8sError：context deadline → 逾時；其餘 → 未分類
	code, ec := k8sFailureCode(context.DeadlineExceeded)
	assert.Equal(t, apierror.CodeAssetTestTimeout, code)
	assert.Equal(t, ErrorCodeTimeout, ec)

	code, ec = k8sFailureCode(errors.New("boom"))
	assert.Equal(t, apierror.CodeAssetTestUnknownError, code)
	assert.Equal(t, ErrorCodeUnknown, ec)
}

// --- 測試輔助 ---

type timeoutErrForTest struct{}

func (timeoutErrForTest) Error() string { return "i/o timeout" }
func (timeoutErrForTest) Timeout() bool { return true }
func (timeoutErrForTest) Temporary() bool {
	return true
}

func credsForProbe(protocol model.ProtocolType, host string, port int) *AssetCredentials {
	return &AssetCredentials{
		Asset:     &model.Asset{Protocol: protocol, Host: host, Port: port},
		AccountID: 7,
		Username:  "probe",
		Password:  "secret",
	}
}

func splitHostPortForTest(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return host, port
}

// expectAssetWithDefaultAccount 鋪 GetWithCredentialsDefault 的三段查詢
// （資產本體 → 節點成員 → 預設帳號），使 testConnection 能走完整生產入口。
func expectAssetWithDefaultAccount(t *testing.T, mock sqlmock.Sqlmock, service *AssetService, protocol, host string, port int) {
	t.Helper()
	enc, err := service.crypto.EncryptFor(context.Background(), keyvault.RefAccountPassword, "secret")
	require.NoError(t, err)

	mock.ExpectQuery(`SELECT .+ FROM "assets"`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "protocol", "host", "port"}).
			AddRow(1, "probe-target", protocol, host, port))
	mock.ExpectQuery(`SELECT .+ FROM "asset_nodes"`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "node_id"}))
	mock.ExpectQuery(`SELECT .+ FROM "asset_accounts"`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "username", "password_enc", "is_default"}).
			AddRow(7, 1, "svc", enc, true))
}
