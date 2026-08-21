package guacamole

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// TestConnectionParams 連線測試參數
type TestConnectionParams struct {
	Protocol string        // ssh, rdp, vnc
	Host     string        // 主機地址
	Port     int           // 端口號
	Username string        // 用戶名
	Password string        // 密碼
	Timeout  time.Duration // 超時時間
	Width    int           // 畫面寬度（可選，默認 1024）
	Height   int           // 畫面高度（可選，默認 768）
}

// TestResult 測試結果
type TestResult struct {
	Success   bool          // 測試是否成功
	Latency   time.Duration // 延遲時間
	Message   string        // 結果訊息
	ErrorType string        // 錯誤類型：connection_refused, authentication_failed, timeout, protocol_error
}

// 錯誤類型常量
const (
	ErrorTypeConnectionRefused    = "connection_refused"
	ErrorTypeAuthenticationFailed = "authentication_failed"
	ErrorTypeTimeout              = "timeout"
	ErrorTypeProtocolError        = "protocol_error"
)

// TestGuacamoleConnection 測試 Guacamole 連線
// 這是主要的測試函數，執行完整的連線測試流程
func TestGuacamoleConnection(ctx context.Context, guacdHost string, guacdPort int, params TestConnectionParams) TestResult {
	start := time.Now()

	// 設置默認值
	if params.Width == 0 {
		params.Width = 1024
	}
	if params.Height == 0 {
		params.Height = 768
	}
	if params.Timeout == 0 {
		params.Timeout = 10 * time.Second
	}

	// 1. 連接到 guacd
	conn, err := connectToGuacd(ctx, guacdHost, guacdPort, params.Timeout)
	if err != nil {
		return TestResult{
			Success:   false,
			Latency:   time.Since(start),
			Message:   fmt.Sprintf("無法連接到 guacd: %v", err),
			ErrorType: ErrorTypeConnectionRefused,
		}
	}
	defer conn.Close()

	// 2. 執行握手
	client, err := performHandshake(conn, params)
	if err != nil {
		errorType := classifyError(err)
		return TestResult{
			Success:   false,
			Latency:   time.Since(start),
			Message:   err.Error(),
			ErrorType: errorType,
		}
	}

	// 3. 等待 ready 指令
	err = waitForReady(conn, client, params.Timeout)
	if err != nil {
		errorType := classifyError(err)
		return TestResult{
			Success:   false,
			Latency:   time.Since(start),
			Message:   fmt.Sprintf("未收到 ready 指令: %v", err),
			ErrorType: errorType,
		}
	}

	return TestResult{
		Success: true,
		Latency: time.Since(start),
		Message: "連線成功",
	}
}

// BuildConnectionParams 構建 Guacamole 連線參數 map
// 用於與現有的 proxy.Connection 兼容
func BuildConnectionParams(params TestConnectionParams) map[string]string {
	result := map[string]string{
		"hostname": params.Host,
		"port":     fmt.Sprintf("%d", params.Port),
		"username": params.Username,
	}

	switch params.Protocol {
	case "ssh":
		if params.Password != "" {
			result["password"] = params.Password
		}
		// 撥測不錄製（修復：寫死路徑於 guacd 容器不存在致連線中止）

	case "rdp":
		if params.Password != "" {
			result["password"] = params.Password
		}
		// RDP 基本參數
		result["security"] = "any"
		result["ignore-cert"] = "true"
		result["disable-gfx"] = "true"
		result["color-depth"] = "24"
		result["enable-wallpaper"] = "true"
		result["enable-theming"] = "true"
		result["enable-font-smoothing"] = "true"
		// 撥測不錄製（同上）

	case "vnc":
		if params.Password != "" {
			result["password"] = params.Password
		}
	}

	return result
}

// ParseGuacamoleError 解析 Guacamole 錯誤訊息
// 返回錯誤類型和人類可讀的錯誤訊息
func ParseGuacamoleError(errorMsg string) (errorType string, message string) {
	lowerMsg := strings.ToLower(errorMsg)

	// 常見錯誤模式匹配（按優先級順序）
	// 先檢查更具體的錯誤類型，避免被通用關鍵字誤判
	switch {
	case strings.Contains(lowerMsg, "upstream_timeout"):
		return ErrorTypeTimeout, "連線超時"

	case strings.Contains(lowerMsg, "client_unauthorized"):
		return ErrorTypeAuthenticationFailed, "認證失敗：用戶名或密碼錯誤"

	case strings.Contains(lowerMsg, "upstream_not_found"):
		return ErrorTypeConnectionRefused, "連線被拒絕：無法連接到主機"

	case strings.Contains(lowerMsg, "timeout"),
		strings.Contains(lowerMsg, "i/o timeout"):
		return ErrorTypeTimeout, "連線超時"

	case strings.Contains(lowerMsg, "authentication"),
		strings.Contains(lowerMsg, "login"):
		return ErrorTypeAuthenticationFailed, "認證失敗：用戶名或密碼錯誤"

	case strings.Contains(lowerMsg, "connection refused"),
		strings.Contains(lowerMsg, "connect"):
		return ErrorTypeConnectionRefused, "連線被拒絕：無法連接到主機"

	case strings.Contains(lowerMsg, "unauthorized"):
		return ErrorTypeAuthenticationFailed, "認證失敗：用戶名或密碼錯誤"

	default:
		return ErrorTypeProtocolError, errorMsg
	}
}

// connectToGuacd 連接到 guacd daemon
func connectToGuacd(ctx context.Context, host string, port int, timeout time.Duration) (net.Conn, error) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, fmt.Errorf("連接失敗: %w", err)
	}
	return conn, nil
}

// performHandshake 執行 Guacamole 握手流程；回傳已初始化的 client
// 供 ready 階段共用（reader 緩衝不可跨實例，否則 ready 指令可能遺失）
func performHandshake(conn net.Conn, params TestConnectionParams) (*Client, error) {
	// 完整初始化（修復：裸構造缺 writer/reader/connected，寫入即「連線已關閉」）
	client := &Client{
		conn:      conn,
		reader:    bufio.NewReader(conn),
		writer:    bufio.NewWriter(conn),
		connected: true,
	}

	// 1. 發送 select 指令
	selectInst := NewSelectInstruction(params.Protocol)
	if err := client.WriteInstruction(selectInst); err != nil {
		return nil, fmt.Errorf("發送 select 失敗: %w", err)
	}

	// 2. 接收 args 指令
	argsInst, err := client.ReadInstruction()
	if err != nil {
		return nil, fmt.Errorf("接收 args 失敗: %w", err)
	}

	if argsInst.Opcode != "args" {
		return nil, fmt.Errorf("預期收到 args，實際收到: %s", argsInst.Opcode)
	}

	// 3. 發送客戶端能力聲明
	// 3.1 size
	sizeInst := NewSizeInstruction(params.Width, params.Height)
	if err := client.WriteInstruction(sizeInst); err != nil {
		return nil, fmt.Errorf("發送 size 失敗: %w", err)
	}

	// 3.2 audio
	audioInst := NewAudioInstruction()
	if err := client.WriteInstruction(audioInst); err != nil {
		return nil, fmt.Errorf("發送 audio 失敗: %w", err)
	}

	// 3.3 video
	videoInst := NewVideoInstruction()
	if err := client.WriteInstruction(videoInst); err != nil {
		return nil, fmt.Errorf("發送 video 失敗: %w", err)
	}

	// 3.4 image
	imageInst := NewImageInstruction("image/png", "image/jpeg")
	if err := client.WriteInstruction(imageInst); err != nil {
		return nil, fmt.Errorf("發送 image 失敗: %w", err)
	}

	// 4. 構建並發送 connect 指令
	connectionParams := BuildConnectionParams(params)
	connectArgs := make([]string, len(argsInst.Args))

	// 第一個參數：VERSION
	connectArgs[0] = argsInst.Args[0]

	// 後續參數：根據參數名稱從 connectionParams 中取值
	for i := 1; i < len(argsInst.Args); i++ {
		paramName := argsInst.Args[i]
		if value, ok := connectionParams[paramName]; ok {
			connectArgs[i] = value
		} else {
			connectArgs[i] = "" // 空參數也要填入
		}
	}

	connectInst := NewInstruction("connect", connectArgs...)
	if err := client.WriteInstruction(connectInst); err != nil {
		return nil, fmt.Errorf("發送 connect 失敗: %w", err)
	}

	return client, nil
}

// waitForReady 等待 ready 指令
func waitForReady(conn net.Conn, client *Client, timeout time.Duration) error {
	conn.SetReadDeadline(time.Now().Add(timeout))
	defer conn.SetReadDeadline(time.Time{})

	readyInst, err := client.ReadInstruction()
	if err != nil {
		return fmt.Errorf("讀取 ready 失敗: %w", err)
	}

	// 檢查是否收到 error 指令
	if readyInst.Opcode == "error" {
		errorMsg := "未知錯誤"
		if len(readyInst.Args) > 0 {
			errorMsg = readyInst.Args[0]
		}
		errorType, message := ParseGuacamoleError(errorMsg)
		return fmt.Errorf("%s: %s", errorType, message)
	}

	// 檢查是否收到 ready 指令
	if readyInst.Opcode != "ready" {
		return fmt.Errorf("預期收到 ready，實際收到: %s", readyInst.Opcode)
	}

	return nil
}

// classifyError 錯誤分類
func classifyError(err error) string {
	errStr := strings.ToLower(err.Error())

	switch {
	case strings.Contains(errStr, "connection refused"),
		strings.Contains(errStr, "connection_refused"):
		return ErrorTypeConnectionRefused

	case strings.Contains(errStr, "timeout"),
		strings.Contains(errStr, "i/o timeout"):
		return ErrorTypeTimeout

	case strings.Contains(errStr, "authentication"),
		strings.Contains(errStr, "authentication_failed"),
		strings.Contains(errStr, "unauthorized"):
		return ErrorTypeAuthenticationFailed

	default:
		return ErrorTypeProtocolError
	}
}
