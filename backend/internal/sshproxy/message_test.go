package sshproxy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/notifycat"
)

func TestEncodeMessage(t *testing.T) {
	tests := []struct {
		name    string
		msgType MessageType
		data    string
		want    string
	}{
		{name: "data 訊息", msgType: MsgData, data: "ls -la\r", want: `{"type":"data","data":"ls -la\r"}`},
		{name: "ping 無內容省略 data 欄位", msgType: MsgPing, data: "", want: `{"type":"ping"}`},
		{name: "connected", msgType: MsgConnected, data: "", want: `{"type":"connected"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeMessage(tt.msgType, tt.data)
			if err != nil {
				t.Fatalf("EncodeMessage 錯誤: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("EncodeMessage = %s, want %s", got, tt.want)
			}
		})
	}
}

// TestEncodeMessageRejectsCodedFrames MsgError／MsgNotice 不得由 EncodeMessage
// 產生（不變量的執行期半邊；靜態半邊見 TestNoUncodedErrorFrames）。
//
// 舊版此處還有一筆 `{MsgError, "認證失敗"} → {"type":"error","data":"認證失敗"}`
// 的期望——那正是要消滅的無碼幀形態，已改為斷言拒絕。
func TestEncodeMessageRejectsCodedFrames(t *testing.T) {
	for _, mt := range []MessageType{MsgError, MsgNotice} {
		raw, err := EncodeMessage(mt, "認證失敗")
		if err == nil {
			t.Errorf("EncodeMessage(%s) 應拒絕（無碼幀），實得 %s", mt, raw)
			continue
		}
		if raw != nil {
			t.Errorf("EncodeMessage(%s) 拒絕時不該回傳資料: %s", mt, raw)
		}
		if !strings.Contains(err.Error(), "EncodeErrorMessage") {
			t.Errorf("錯誤訊息應指向正確替代函式，實得: %v", err)
		}
	}
}

// TestEncodeErrorMessageRejectsEmptyCode ErrCode 的零值不得編出無碼 MsgError。
// 型別系統擋不住零值，故此處為 fail-closed 的最後一道。
func TestEncodeErrorMessageRejectsEmptyCode(t *testing.T) {
	var zero apierror.ErrCode
	raw, err := EncodeErrorMessage(zero, "任意文案")
	if err == nil {
		t.Fatalf("空 code 應被拒絕，實得 %s", raw)
	}
	if raw != nil {
		t.Errorf("拒絕時不該回傳資料: %s", raw)
	}
}

func TestEncodeErrorMessage(t *testing.T) {
	tests := []struct {
		name string
		code apierror.ErrCode
		data string
		want string
	}{
		{
			name: "帶 code 的撥號失敗",
			code: apierror.CodeSSHHostKeyChanged,
			data: "主機金鑰已變更",
			want: `{"type":"error","data":"主機金鑰已變更","code":"RULE_SSH_HOST_KEY_CHANGED"}`,
		},
		{
			name: "k8s 撥號失敗已 code 化（原空 code 分支）",
			code: apierror.CodeK8sStartFailed,
			data: "K8s 連線啟動失敗",
			want: `{"type":"error","data":"K8s 連線啟動失敗","code":"RULE_K8S_START_FAILED"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeErrorMessage(tt.code, tt.data)
			if err != nil {
				t.Fatalf("EncodeErrorMessage 錯誤: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("EncodeErrorMessage = %s, want %s", got, tt.want)
			}
		})
	}
}

// TestEncodeCodedErrorMessage Data 取 registry 的 zh fallback（呼叫點不碰文案）
func TestEncodeCodedErrorMessage(t *testing.T) {
	for _, code := range []apierror.ErrCode{
		apierror.CodeSessionEnded,
		apierror.CodeSessionIdleTimeout,
		apierror.CodeSessionMaxDuration,
		apierror.CodeSessionTerminated,
		apierror.CodeAccountDisabled,
	} {
		raw, err := EncodeCodedErrorMessage(code)
		if err != nil {
			t.Fatalf("EncodeCodedErrorMessage(%s) 錯誤: %v", code, err)
		}
		var msg Message
		if err := json.Unmarshal(raw, &msg); err != nil {
			t.Fatalf("非合法 JSON: %v (%s)", err, raw)
		}
		d, ok := apierror.DescriptorOf(code)
		if !ok {
			t.Fatalf("碼 %s 未註冊", code)
		}
		if msg.Type != MsgError {
			t.Errorf("Type = %q, want %q", msg.Type, MsgError)
		}
		if msg.Code != string(code) {
			t.Errorf("Code = %q, want %q", msg.Code, code)
		}
		if msg.Data != d.ZhFallback || msg.Data == "" {
			t.Errorf("Data = %q, want registry zh fallback %q", msg.Data, d.ZhFallback)
		}
	}
}

// TestEncodeNoticeMessage MsgNotice 幀：Code＋zh fallback Data＋params。
// Data 的 zh fallback 是安全 UX 要求——譯文漏鍵時阻斷不可靜默無提示。
func TestEncodeNoticeMessage(t *testing.T) {
	raw, err := EncodeNoticeMessage(apierror.CodeCommandBlocked, map[string]string{"rule": "禁止刪根目錄"})
	if err != nil {
		t.Fatalf("EncodeNoticeMessage 錯誤: %v", err)
	}
	var msg Message
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatalf("非合法 JSON: %v (%s)", err, raw)
	}
	if msg.Type != MsgNotice {
		t.Errorf("Type = %q, want %q", msg.Type, MsgNotice)
	}
	if msg.Code != string(apierror.CodeCommandBlocked) {
		t.Errorf("Code = %q, want %q", msg.Code, apierror.CodeCommandBlocked)
	}
	d, _ := apierror.DescriptorOf(apierror.CodeCommandBlocked)
	if msg.Data != d.ZhFallback || msg.Data == "" {
		t.Errorf("Data = %q, want zh fallback %q（漏 fallback＝阻斷靜默）", msg.Data, d.ZhFallback)
	}
	if msg.Params["rule"] != "禁止刪根目錄" {
		t.Errorf("Params[rule] = %q, want 原規則名", msg.Params["rule"])
	}

	// 無 params 時該欄省略（omitempty）
	bare, err := EncodeNoticeMessage(apierror.CodeCommandBlocked, nil)
	if err != nil {
		t.Fatalf("EncodeNoticeMessage(nil) 錯誤: %v", err)
	}
	if strings.Contains(string(bare), `"params"`) {
		t.Errorf("無參數時不應輸出 params 欄: %s", bare)
	}
}

// TestEncodeNoticeMessageSanitizesParams params 值一律過 notifycat.SanitizeOpaque：
// AlertRule.Name 僅驗 required，可含 ANSI 逸出序列與控制字元，直送終端即為注入面
func TestEncodeNoticeMessageSanitizesParams(t *testing.T) {
	dirty := "rm\x1b[31m -rf\r\n/\x07"
	raw, err := EncodeNoticeMessage(apierror.CodeCommandBlocked, map[string]string{"rule": dirty})
	if err != nil {
		t.Fatalf("EncodeNoticeMessage 錯誤: %v", err)
	}
	var msg Message
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatalf("非合法 JSON: %v (%s)", err, raw)
	}
	got := msg.Params["rule"]
	if got != notifycat.SanitizeOpaque(dirty) {
		t.Errorf("Params[rule] = %q, want SanitizeOpaque 結果 %q", got, notifycat.SanitizeOpaque(dirty))
	}
	for _, bad := range []string{"\x1b", "\r", "\n", "\x07"} {
		if strings.Contains(got, bad) {
			t.Errorf("淨化後仍含控制字元 %q: %q", bad, got)
		}
	}

	// 超長值可見截斷而非拒發（合規通知不因單一長值消失）
	long, err := EncodeNoticeMessage(apierror.CodeCommandBlocked,
		map[string]string{"rule": strings.Repeat("規", notifycat.MaxOpaqueRunes+50)})
	if err != nil {
		t.Fatalf("EncodeNoticeMessage(long) 錯誤: %v", err)
	}
	var longMsg Message
	if err := json.Unmarshal(long, &longMsg); err != nil {
		t.Fatalf("非合法 JSON: %v", err)
	}
	if n := len([]rune(longMsg.Params["rule"])); n != notifycat.MaxOpaqueRunes {
		t.Errorf("截斷後 rune 數 = %d, want %d", n, notifycat.MaxOpaqueRunes)
	}
}

func TestDecodeMessage(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		wantType MessageType
		wantData string
		wantErr  string
	}{
		{name: "data 訊息", raw: `{"type":"data","data":"pwd\r"}`, wantType: MsgData, wantData: "pwd\r"},
		{name: "resize 訊息", raw: `{"type":"resize","data":"{\"cols\":120,\"rows\":40}"}`, wantType: MsgResize, wantData: `{"cols":120,"rows":40}`},
		{name: "ping 訊息", raw: `{"type":"ping"}`, wantType: MsgPing},
		{name: "未知類型拒絕", raw: `{"type":"exec"}`, wantErr: "未知的訊息類型"},
		{name: "非 JSON 拒絕", raw: `2ls`, wantErr: "訊息格式錯誤"},
		{name: "空字串拒絕", raw: ``, wantErr: "訊息格式錯誤"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeMessage([]byte(tt.raw))

			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("DecodeMessage 錯誤 = %v, want 含 %q", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("DecodeMessage 錯誤: %v", err)
			}
			if got.Type != tt.wantType {
				t.Errorf("Type = %q, want %q", got.Type, tt.wantType)
			}
			if got.Data != tt.wantData {
				t.Errorf("Data = %q, want %q", got.Data, tt.wantData)
			}
		})
	}
}

func TestParseResizePayload(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		wantCols int
		wantRows int
		wantErr  string
	}{
		{name: "正常尺寸", data: `{"cols":120,"rows":40}`, wantCols: 120, wantRows: 40},
		{name: "邊界下限", data: `{"cols":1,"rows":1}`, wantCols: 1, wantRows: 1},
		{name: "cols 為零拒絕", data: `{"cols":0,"rows":24}`, wantErr: "cols 超出範圍"},
		{name: "rows 超上限拒絕", data: `{"cols":80,"rows":501}`, wantErr: "rows 超出範圍"},
		{name: "cols 超上限拒絕", data: `{"cols":1001,"rows":24}`, wantErr: "cols 超出範圍"},
		{name: "負值拒絕", data: `{"cols":-80,"rows":24}`, wantErr: "cols 超出範圍"},
		{name: "非 JSON 拒絕", data: `120x40`, wantErr: "resize 內容格式錯誤"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseResizePayload(tt.data)

			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ParseResizePayload 錯誤 = %v, want 含 %q", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseResizePayload 錯誤: %v", err)
			}
			if got.Cols != tt.wantCols || got.Rows != tt.wantRows {
				t.Errorf("payload = %+v, want cols=%d rows=%d", got, tt.wantCols, tt.wantRows)
			}
		})
	}
}
