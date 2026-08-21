package proxy

import (
	"testing"

	"github.com/custodexa/backend/internal/modules/policy"
)

func allAllowed() policy.TransferCapabilities {
	return policy.TransferCapabilities{
		ClipboardSend: true, ClipboardRecv: true,
		FileUpload: true, FileDownload: true, FileDelete: true,
	}
}

// TestTransferParamsDirectionMapping 剪貼簿方向映射（data-transfer-control 3.2）。
//
// **這是本 change 最易錯處**，且錯了仍可能通過只驗單邊的測試：
//
//	clipboard_send（貼進資產）↔ disable-paste
//	clipboard_recv（自資產抄出）↔ disable-copy
//
// 每個案例都同時斷言「該關的關了」與「另一邊沒被連坐」——後半句才是抓對調的關鍵。
// 自證：把 applyTransferParams 的兩個映射對調，本測試的**兩個子案例各自都必須紅**。
func TestTransferParamsDirectionMapping(t *testing.T) {
	for _, protocol := range []string{"rdp", "vnc"} {
		t.Run(protocol+"/只關 send", func(t *testing.T) {
			caps := allAllowed()
			caps.ClipboardSend = false
			params := map[string]string{}
			applyTransferParams(params, protocol, caps)

			if params["disable-paste"] != "true" {
				t.Errorf("clipboard_send=false 時 disable-paste = %q, want true"+
					"（send＝貼進資產＝paste；若此處為 false 而 disable-copy 為 true，映射被對調了）",
					params["disable-paste"])
			}
			if params["disable-copy"] != "false" {
				t.Errorf("只關 send 時 disable-copy = %q, want false"+
					"（recv 未關，複製出資產不該被連坐）", params["disable-copy"])
			}
		})

		t.Run(protocol+"/只關 recv", func(t *testing.T) {
			caps := allAllowed()
			caps.ClipboardRecv = false
			params := map[string]string{}
			applyTransferParams(params, protocol, caps)

			if params["disable-copy"] != "true" {
				t.Errorf("clipboard_recv=false 時 disable-copy = %q, want true"+
					"（recv＝自資產抄出＝copy；若此處為 false 而 disable-paste 為 true，映射被對調了）",
					params["disable-copy"])
			}
			if params["disable-paste"] != "false" {
				t.Errorf("只關 recv 時 disable-paste = %q, want false"+
					"（send 未關，貼進資產不該被連坐）", params["disable-paste"])
			}
		})
	}
}

// TestTransferParamsClipboardBothProtocols RDP 與 VNC 兩分支皆送剪貼簿參數
// （改動前 RDP 分支完全不設，吃 guacd 預設＝允許）。
func TestTransferParamsClipboardBothProtocols(t *testing.T) {
	caps := policy.TransferCapabilities{} // 全禁
	for _, protocol := range []string{"rdp", "vnc"} {
		params := map[string]string{}
		applyTransferParams(params, protocol, caps)
		if params["disable-paste"] != "true" || params["disable-copy"] != "true" {
			t.Errorf("%s 全禁時 disable-paste=%q disable-copy=%q, want 皆 true",
				protocol, params["disable-paste"], params["disable-copy"])
		}
	}
}

// TestTransferParamsFileKeysPerProtocol 檔案類參數依協議分流（3.3）：
// RDP 磁碟走 disable-upload／disable-download，VNC SFTP 側車走 sftp- 前綴版。
func TestTransferParamsFileKeysPerProtocol(t *testing.T) {
	cases := []struct {
		protocol   string
		upKey      string
		downKey    string
		absentKeys []string
	}{
		{"rdp", "disable-upload", "disable-download", []string{"sftp-disable-upload", "sftp-disable-download"}},
		{"vnc", "sftp-disable-upload", "sftp-disable-download", []string{"disable-upload", "disable-download"}},
	}
	for _, tc := range cases {
		t.Run(tc.protocol, func(t *testing.T) {
			caps := allAllowed()
			caps.FileUpload = false
			params := map[string]string{}
			applyTransferParams(params, tc.protocol, caps)

			if params[tc.upKey] != "true" {
				t.Errorf("%s = %q, want true", tc.upKey, params[tc.upKey])
			}
			if params[tc.downKey] != "false" {
				t.Errorf("%s = %q, want false（download 未關不該被連坐）", tc.downKey, params[tc.downKey])
			}
			for _, k := range tc.absentKeys {
				if _, ok := params[k]; ok {
					t.Errorf("%s 協議不該送 %s（那是另一協議的參數名）", tc.protocol, k)
				}
			}
		})
	}
}

// TestTransferParamsSurvivesFillDefaults 政策值不被 fillDefaults 覆蓋（3.1）。
//
// fillDefaults 的 VNC 分支原本硬寫 disable-copy／disable-paste = "false"，
// 那兩行已刪；本測試守住「刪掉了且沒被加回來」。
func TestTransferParamsSurvivesFillDefaults(t *testing.T) {
	caps := policy.TransferCapabilities{} // 全禁
	for _, protocol := range []string{"rdp", "vnc"} {
		params := map[string]string{"protocol": protocol}
		applyTransferParams(params, protocol, caps)
		result := fillDefaults(params, protocol)
		if result["disable-copy"] != "true" {
			t.Errorf("%s: fillDefaults 後 disable-copy = %q, want true"+
				"（政策值被預設值蓋掉＝控制失效）", protocol, result["disable-copy"])
		}
		if result["disable-paste"] != "true" {
			t.Errorf("%s: fillDefaults 後 disable-paste = %q, want true", protocol, result["disable-paste"])
		}
	}
}

// TestFillDefaultsNoClipboardDefault 未注入政策時 fillDefaults 不再自行填剪貼簿參數
// （零影響驗證：兩個參數皆不出現，guacd 吃自身預設＝允許，與改動前一致）。
func TestFillDefaultsNoClipboardDefault(t *testing.T) {
	for _, protocol := range []string{"rdp", "vnc"} {
		result := fillDefaults(map[string]string{"protocol": protocol}, protocol)
		for _, k := range []string{"disable-copy", "disable-paste"} {
			if v, ok := result[k]; ok {
				t.Errorf("%s: fillDefaults 仍在填 %s=%q——那會與政策值形成兩個寫入者",
					protocol, k, v)
			}
		}
	}
}
