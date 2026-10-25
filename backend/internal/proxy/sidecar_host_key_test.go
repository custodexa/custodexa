package proxy

import (
	"errors"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

type fakeSidecarLookup struct {
	rec      *model.AssetHostKey
	err      error
	lastHost string
	lastPort int
}

func (f *fakeSidecarLookup) LookupAddress(host string, port int) (*model.AssetHostKey, error) {
	f.lastHost, f.lastPort = host, port
	return f.rec, f.err
}

// TestVNCSidecarHostKeyParam VNC 檔案傳輸側車：同位址有已記錄的主機金鑰時帶 sftp-host-key（known_hosts 一列），
// 沒有記錄、查詢失敗或未注入時不帶參數、其餘參數不變。
func TestVNCSidecarHostKeyParam(t *testing.T) {
	base := func() map[string]string {
		return map[string]string{"enable-sftp": "true", "sftp-hostname": "10.0.0.5", "sftp-port": "2222", "sftp-username": "files"}
	}
	rec := &model.AssetHostKey{Algorithm: "ssh-ed25519", Fingerprint: "SHA256:abc", PublicKey: "AAAAC3NzaC1lZDI1NTE5AAAAIFAKE"}

	t.Run("有記錄：帶 sftp-host-key，非 22 埠寫成 [host]:port", func(t *testing.T) {
		lookup := &fakeSidecarLookup{rec: rec}
		params := base()
		applySidecarHostKey(params, lookup, "10.0.0.5", 2222)
		if lookup.lastHost != "10.0.0.5" || lookup.lastPort != 2222 {
			t.Fatalf("應以側車撥號位址查記錄，實查 %s:%d", lookup.lastHost, lookup.lastPort)
		}
		if got := params["sftp-host-key"]; got != "[10.0.0.5]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKE" {
			t.Fatalf("sftp-host-key = %q", got)
		}
		if len(params) != 5 {
			t.Fatalf("其餘參數不得改變: %v", params)
		}
		p22 := base()
		applySidecarHostKey(p22, &fakeSidecarLookup{rec: rec}, "10.0.0.5", 22)
		if got := p22["sftp-host-key"]; got != "10.0.0.5 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKE" {
			t.Fatalf("22 埠不加方括號: %q", got)
		}
	})

	for name, lookup := range map[string]SidecarHostKeyLookup{
		"無記錄":   &fakeSidecarLookup{err: gorm.ErrRecordNotFound},
		"查詢失敗":  &fakeSidecarLookup{err: errors.New("db down")},
		"記錄無公鑰": &fakeSidecarLookup{rec: &model.AssetHostKey{Algorithm: "ssh-ed25519", Fingerprint: "SHA256:x"}},
		"未注入":   nil,
	} {
		t.Run(name+"：不帶參數、行為不變", func(t *testing.T) {
			params := base()
			applySidecarHostKey(params, lookup, "10.0.0.5", 2222)
			if _, has := params["sftp-host-key"]; has {
				t.Fatalf("不得帶 sftp-host-key: %v", params)
			}
			if len(params) != 4 || params["enable-sftp"] != "true" {
				t.Fatalf("其餘參數不得改變: %v", params)
			}
		})
	}
}
