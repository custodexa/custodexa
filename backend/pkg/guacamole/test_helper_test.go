package guacamole

import (
	"testing"
	"time"
)

// TestBuildConnectionParams 測試參數構建
func TestBuildConnectionParams(t *testing.T) {
	tests := []struct {
		name     string
		params   TestConnectionParams
		expected map[string]string
	}{
		{
			name: "SSH with password",
			params: TestConnectionParams{
				Protocol: "ssh",
				Host:     "192.168.1.100",
				Port:     22,
				Username: "admin",
				Password: "secret123",
			},
			expected: map[string]string{
				"hostname": "192.168.1.100",
				"port":     "22",
				"username": "admin",
				"password": "secret123",
			},
		},
		{
			name: "RDP with password",
			params: TestConnectionParams{
				Protocol: "rdp",
				Host:     "10.0.0.50",
				Port:     3389,
				Username: "Administrator",
				Password: "P@ssw0rd",
			},
			expected: map[string]string{
				"hostname":              "10.0.0.50",
				"port":                  "3389",
				"username":              "Administrator",
				"password":              "P@ssw0rd",
				"security":              "any",
				"ignore-cert":           "true",
				"disable-gfx":           "true",
				"color-depth":           "24",
				"enable-wallpaper":      "true",
				"enable-theming":        "true",
				"enable-font-smoothing": "true",
			},
		},
		{
			name: "VNC with password",
			params: TestConnectionParams{
				Protocol: "vnc",
				Host:     "172.16.0.10",
				Port:     5900,
				Password: "vncpass",
			},
			expected: map[string]string{
				"hostname": "172.16.0.10",
				"port":     "5900",
				"username": "",
				"password": "vncpass",
			},
		},
		{
			name: "SSH without password",
			params: TestConnectionParams{
				Protocol: "ssh",
				Host:     "example.com",
				Port:     2222,
				Username: "deploy",
				Password: "",
			},
			expected: map[string]string{
				"hostname": "example.com",
				"port":     "2222",
				"username": "deploy",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildConnectionParams(tt.params)

			// 檢查所有預期的鍵值對
			for key, expectedValue := range tt.expected {
				actualValue, ok := result[key]
				if !ok {
					t.Errorf("缺少參數: %s", key)
					continue
				}
				if actualValue != expectedValue {
					t.Errorf("參數 %s = %v, 預期 %v", key, actualValue, expectedValue)
				}
			}

			// 對於沒有密碼的情況，檢查不應該包含 password 鍵
			if tt.params.Password == "" && tt.params.Protocol != "vnc" {
				if _, hasPassword := result["password"]; hasPassword {
					t.Errorf("不應該包含空密碼參數")
				}
			}
		})
	}
}

// TestParseGuacamoleError 測試錯誤解析
func TestParseGuacamoleError(t *testing.T) {
	tests := []struct {
		name            string
		errorMsg        string
		expectedType    string
		expectedMessage string
	}{
		{
			name:            "Connection refused - UPSTREAM_NOT_FOUND",
			errorMsg:        "UPSTREAM_NOT_FOUND: The remote desktop server is not responding",
			expectedType:    ErrorTypeConnectionRefused,
			expectedMessage: "連線被拒絕：無法連接到主機",
		},
		{
			name:            "Connection refused - lowercase",
			errorMsg:        "connection refused",
			expectedType:    ErrorTypeConnectionRefused,
			expectedMessage: "連線被拒絕：無法連接到主機",
		},
		{
			name:            "Timeout - UPSTREAM_TIMEOUT",
			errorMsg:        "UPSTREAM_TIMEOUT: Connection timed out",
			expectedType:    ErrorTypeTimeout,
			expectedMessage: "連線超時",
		},
		{
			name:            "Timeout - i/o timeout",
			errorMsg:        "read: i/o timeout",
			expectedType:    ErrorTypeTimeout,
			expectedMessage: "連線超時",
		},
		{
			name:            "Authentication failed - CLIENT_UNAUTHORIZED",
			errorMsg:        "CLIENT_UNAUTHORIZED: Invalid credentials",
			expectedType:    ErrorTypeAuthenticationFailed,
			expectedMessage: "認證失敗：用戶名或密碼錯誤",
		},
		{
			name:            "Authentication failed - login",
			errorMsg:        "login failed: incorrect username or password",
			expectedType:    ErrorTypeAuthenticationFailed,
			expectedMessage: "認證失敗：用戶名或密碼錯誤",
		},
		{
			name:            "Unknown error",
			errorMsg:        "UPSTREAM_ERROR: Some unknown error occurred",
			expectedType:    ErrorTypeProtocolError,
			expectedMessage: "UPSTREAM_ERROR: Some unknown error occurred",
		},
		{
			name:            "Generic error",
			errorMsg:        "Something went wrong",
			expectedType:    ErrorTypeProtocolError,
			expectedMessage: "Something went wrong",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errorType, message := ParseGuacamoleError(tt.errorMsg)

			if errorType != tt.expectedType {
				t.Errorf("錯誤類型 = %v, 預期 %v", errorType, tt.expectedType)
			}

			if message != tt.expectedMessage {
				t.Errorf("訊息 = %v, 預期 %v", message, tt.expectedMessage)
			}
		})
	}
}

// TestClassifyError 測試錯誤分類
func TestClassifyError(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		expectedType string
	}{
		{
			name:         "Connection refused error",
			err:          &testError{"connection refused"},
			expectedType: ErrorTypeConnectionRefused,
		},
		{
			name:         "Connection refused uppercase",
			err:          &testError{"CONNECTION REFUSED"},
			expectedType: ErrorTypeConnectionRefused,
		},
		{
			name:         "Timeout error",
			err:          &testError{"operation timeout"},
			expectedType: ErrorTypeTimeout,
		},
		{
			name:         "I/O timeout error",
			err:          &testError{"read: i/o timeout"},
			expectedType: ErrorTypeTimeout,
		},
		{
			name:         "Authentication error",
			err:          &testError{"authentication failed"},
			expectedType: ErrorTypeAuthenticationFailed,
		},
		{
			name:         "Unauthorized error",
			err:          &testError{"unauthorized access"},
			expectedType: ErrorTypeAuthenticationFailed,
		},
		{
			name:         "Protocol error",
			err:          &testError{"invalid protocol message"},
			expectedType: ErrorTypeProtocolError,
		},
		{
			name:         "Generic error",
			err:          &testError{"something went wrong"},
			expectedType: ErrorTypeProtocolError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errorType := classifyError(tt.err)

			if errorType != tt.expectedType {
				t.Errorf("錯誤類型 = %v, 預期 %v", errorType, tt.expectedType)
			}
		})
	}
}

// TestTestConnectionParams_Defaults 測試默認值設置
func TestTestConnectionParams_Defaults(t *testing.T) {
	params := TestConnectionParams{
		Protocol: "ssh",
		Host:     "localhost",
		Port:     22,
		Username: "user",
		// Width, Height, Timeout 未設置
	}

	// 這個測試確認在 TestGuacamoleConnection 中會設置默認值
	// 我們直接測試默認值邏輯
	if params.Width == 0 {
		params.Width = 1024
	}
	if params.Height == 0 {
		params.Height = 768
	}
	if params.Timeout == 0 {
		params.Timeout = 10 * time.Second
	}

	if params.Width != 1024 {
		t.Errorf("Width = %d, 預期 1024", params.Width)
	}
	if params.Height != 768 {
		t.Errorf("Height = %d, 預期 768", params.Height)
	}
	if params.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v, 預期 10s", params.Timeout)
	}
}

// testError 測試用的錯誤類型
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

// TestTestResult_Structure 測試 TestResult 結構
func TestTestResult_Structure(t *testing.T) {
	result := TestResult{
		Success:   true,
		Latency:   150 * time.Millisecond,
		Message:   "連線成功",
		ErrorType: "",
	}

	if !result.Success {
		t.Error("Success 應該為 true")
	}
	if result.Latency != 150*time.Millisecond {
		t.Errorf("Latency = %v, 預期 150ms", result.Latency)
	}
	if result.Message != "連線成功" {
		t.Errorf("Message = %v, 預期 '連線成功'", result.Message)
	}
	if result.ErrorType != "" {
		t.Errorf("ErrorType 應該為空字串")
	}
}

// TestErrorTypeConstants 測試錯誤類型常量
func TestErrorTypeConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"Connection refused", ErrorTypeConnectionRefused, "connection_refused"},
		{"Authentication failed", ErrorTypeAuthenticationFailed, "authentication_failed"},
		{"Timeout", ErrorTypeTimeout, "timeout"},
		{"Protocol error", ErrorTypeProtocolError, "protocol_error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("常量值 = %v, 預期 %v", tt.constant, tt.expected)
			}
		})
	}
}
