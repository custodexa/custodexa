package api

import (
	"bytes"
	"encoding/json"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupSyslogGateEnv syslog 存檔閘測試環境：
// 真 sqlite＋真政策服務，僅省略 JWT middleware（直接掛路由）
func setupSyslogGateEnv(t *testing.T) (*gin.Engine, *policy.SecurityPolicyService, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.SyslogSetting{}, &model.SecurityPolicy{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	policies := policy.NewSecurityPolicyService(db)
	handler := NewSyslogSettingHandler(db, audit.NewSyslogForwarder(db), nil)
	handler.SetTransmissionPolicy(policy.NewTransmissionPolicyService(policies, nil))

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/syslog-settings", handler.Update)
	router.POST("/syslog-settings/test", handler.Test)
	return router, policies, db
}

func postSyslogTest(t *testing.T, router *gin.Engine, body map[string]interface{}) *httptest.ResponseRecorder {
	t.Helper()
	payload, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/syslog-settings/test", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// assertSyslogGatePassed 斷言「傳輸政策閘已放行」，且不把閘的判定與投遞結果混為
// 一談。閘放行後只有兩種合法結果：
//   - 200 + {data:{success:true}}（實際送達）
//   - 502 + code=INTERNAL_SYSLOG_TEST_FAILED（閘放行、投遞失敗）
//
// 採正向白名單而非「不是 ack_required／strict_reject」的負向斷言——後者會讓其他
// 400/500 或未來新增的拒絕碼從縫隙溜過去而假綠；也不可直接鎖定 502，那是把
// 「目的地必然不可達」寫成契約。
func assertSyslogGatePassed(t *testing.T, w *httptest.ResponseRecorder, ctx string) {
	t.Helper()
	switch w.Code {
	case http.StatusOK:
		// 200 必須是成功 envelope：否則 200＋{data:{success:false}} 的舊契約
		// 回歸會從這個分支溜過去
		var ok struct {
			Data struct {
				Success bool `json:"success"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &ok); err != nil {
			t.Fatalf("%s: 200 body 無法解析: %v (body=%s)", ctx, err, w.Body.String())
		}
		if !ok.Data.Success {
			t.Fatalf("%s: 200 必須帶 data.success=true（舊的 success:false 契約已廢除）: %s", ctx, w.Body.String())
		}
		return
	case http.StatusBadGateway:
		var resp struct {
			Code string `json:"code"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("%s: 502 body 無法解析: %v (body=%s)", ctx, err, w.Body.String())
		}
		if resp.Code != string(apierror.CodeSyslogTestFailed) {
			t.Fatalf("%s: 502 應帶 code=%s, got %q", ctx, apierror.CodeSyslogTestFailed, resp.Code)
		}
		return
	default:
		t.Fatalf("%s: 閘應放行（200 或 502＋投遞失敗碼）, code = %d body = %s", ctx, w.Code, w.Body.String())
	}
}

func putSyslogSetting(t *testing.T, router *gin.Engine, body map[string]interface{}) *httptest.ResponseRecorder {
	t.Helper()
	payload, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/syslog-settings", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestSyslogGateOffAllowsUDP(t *testing.T) {
	router, _, db := setupSyslogGateEnv(t)

	w := putSyslogSetting(t, router, map[string]interface{}{
		"enabled": true, "host": "log.internal", "port": 514, "protocol": "udp",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("off 檔存 UDP 應成功, code = %d body = %s", w.Code, w.Body.String())
	}
	var n int64
	db.Model(&model.SyslogSetting{}).Count(&n)
	if n != 1 {
		t.Errorf("設定列數 = %d, want 1", n)
	}
}

func TestSyslogGateWarnRequiresAck(t *testing.T) {
	router, policies, _ := setupSyslogGateEnv(t)
	policies.Update(policy.PolicyTransportSyslogLevel, policy.TransportLevelWarn, "admin")

	// 未附確認：400＋風險項
	w := putSyslogSetting(t, router, map[string]interface{}{
		"enabled": true, "host": "log.internal", "port": 514, "protocol": "tcp",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("warn 未確認應 400, code = %d", w.Code)
	}
	var resp struct {
		Code  string            `json:"code"`
		Risks []policy.RiskItem `json:"risks"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Code != string(apierror.CodeTransmissionAckRequired) || len(resp.Risks) != 1 {
		t.Errorf("resp = %+v, want ack_required＋1 風險項", resp)
	}

	// 附確認：通過
	w = putSyslogSetting(t, router, map[string]interface{}{
		"enabled": true, "host": "log.internal", "port": 514, "protocol": "tcp",
		"risk_acknowledged": true,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("warn＋確認應成功, code = %d body = %s", w.Code, w.Body.String())
	}

	// TLS 不受閘
	w = putSyslogSetting(t, router, map[string]interface{}{
		"enabled": true, "host": "log.internal", "port": 6514, "protocol": "tcp+tls",
	})
	if w.Code != http.StatusOK {
		t.Errorf("warn 檔存 TLS 不應受閘, code = %d", w.Code)
	}
}

func TestSyslogGateStrictRejects(t *testing.T) {
	router, policies, _ := setupSyslogGateEnv(t)
	policies.Update(policy.PolicyTransportSyslogLevel, policy.TransportLevelStrict, "admin")

	// strict：確認也無效
	w := putSyslogSetting(t, router, map[string]interface{}{
		"enabled": true, "host": "log.internal", "port": 514, "protocol": "udp",
		"risk_acknowledged": true,
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("strict 應拒絕, code = %d", w.Code)
	}

	// 停用轉發的存檔不受閘（沒有傳輸就沒有風險）
	w = putSyslogSetting(t, router, map[string]interface{}{
		"enabled": false, "host": "log.internal", "port": 514, "protocol": "udp",
	})
	if w.Code != http.StatusOK {
		t.Errorf("停用轉發的存檔不應受閘, code = %d body = %s", w.Code, w.Body.String())
	}
}

// TestSyslogTestEndpointGate 測試端點與存檔同受閘（6.5 收口）：
// 測試即對外實送，strict 不得發、warn 須確認；不受 enabled 影響
func TestSyslogTestEndpointGate(t *testing.T) {
	router, policies, _ := setupSyslogGateEnv(t)

	// off：非 TLS 測試放行（送達與否不在此測，僅驗不被閘擋）
	w := postSyslogTest(t, router, map[string]interface{}{
		"host": "log.internal", "port": 514, "protocol": "udp",
	})
	assertSyslogGatePassed(t, w, "off 檔測試應放行")

	// warn 未確認：400＋ack_required
	policies.Update(policy.PolicyTransportSyslogLevel, policy.TransportLevelWarn, "admin")
	w = postSyslogTest(t, router, map[string]interface{}{
		"host": "log.internal", "port": 514, "protocol": "udp",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("warn 未確認的測試應 400, code = %d", w.Code)
	}
	var resp struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Code != string(apierror.CodeTransmissionAckRequired) {
		t.Errorf("code = %q, want %q", resp.Code, apierror.CodeTransmissionAckRequired)
	}

	// warn＋確認：放行
	w = postSyslogTest(t, router, map[string]interface{}{
		"host": "log.internal", "port": 514, "protocol": "udp",
		"risk_acknowledged": true,
	})
	assertSyslogGatePassed(t, w, "warn＋確認的測試應放行")

	// strict：確認也無效
	policies.Update(policy.PolicyTransportSyslogLevel, policy.TransportLevelStrict, "admin")
	w = postSyslogTest(t, router, map[string]interface{}{
		"host": "log.internal", "port": 514, "protocol": "udp",
		"risk_acknowledged": true,
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("strict 檔測試應拒絕, code = %d", w.Code)
	}

	// TLS 端點不受任何檔位的閘
	w = postSyslogTest(t, router, map[string]interface{}{
		"host": "log.internal", "port": 6514, "protocol": "tcp+tls",
	})
	assertSyslogGatePassed(t, w, "strict 檔對 TLS 端點測試不應受閘")
}

// TestSyslogTestEndpointDeliveryResult 投遞結果與狀態碼語義：
// 成功回 200、送達失敗回 502＋registered code。與上面的閘測試分開——閘的
// 判定與投遞結果是兩件事，混在一起會讓任一方的迴歸被另一方遮蔽
func TestSyslogTestEndpointDeliveryResult(t *testing.T) {
	router, _, _ := setupSyslogGateEnv(t)

	// 成功路徑：本機可控 listener（政策預設 off 檔，非 TLS 不受閘）
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			io.Copy(io.Discard, conn)
			conn.Close()
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)

	w := postSyslogTest(t, router, map[string]interface{}{
		"host": "127.0.0.1", "port": addr.Port, "protocol": "tcp",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("可達目的地應回 200, code = %d body = %s", w.Code, w.Body.String())
	}
	var okResp struct {
		Data struct {
			Success bool `json:"success"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &okResp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !okResp.Data.Success {
		t.Errorf("成功回應應帶 data.success=true, body = %s", w.Body.String())
	}

	// 失敗路徑：關掉 listener 後同一位址連線被拒
	ln.Close()
	w = postSyslogTest(t, router, map[string]interface{}{
		"host": "127.0.0.1", "port": addr.Port, "protocol": "tcp",
	})
	if w.Code != http.StatusBadGateway {
		t.Fatalf("不可達目的地應回 502（非 200＋success:false）, code = %d body = %s", w.Code, w.Body.String())
	}
	var failResp struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &failResp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if failResp.Code != string(apierror.CodeSyslogTestFailed) {
		t.Errorf("code = %q, want %q", failResp.Code, apierror.CodeSyslogTestFailed)
	}
	if failResp.Error == "" {
		t.Error("error 欄應為非空 zh fallback")
	}
	// 泛化不洩漏：body 不得含 dial/write 原始錯誤字串
	for _, leak := range []string{"connection refused", "dial", "connect:", "127.0.0.1"} {
		if strings.Contains(w.Body.String(), leak) {
			t.Errorf("回應 body 洩漏內部錯誤細節 %q: %s", leak, w.Body.String())
		}
	}
}
