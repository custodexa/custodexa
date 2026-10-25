package proxy

import (
	"fmt"
	"log"

	"github.com/custodexa/backend/internal/model"
)

// SidecarHostKeyLookup 依撥號位址查已記錄的 SSH 主機金鑰（host-key-verification 的 LookupAddress）。
type SidecarHostKeyLookup interface {
	LookupAddress(host string, port int) (*model.AssetHostKey, error)
}

// sidecarHostKeyParam guacd 的 SFTP 主機金鑰參數名（guacamole/guacd 1.6.0：VNC／RDP 的 sftp-host-key，
// 值為 known_hosts 格式的一列；有值時 guacd 以 libssh2 known hosts 驗證，不符即拒絕 SFTP 連線）。
const sidecarHostKeyParam = "sftp-host-key"

// knownHostsEntry 把記錄轉成 ssh-keyscan 形式的 known_hosts 列：非 22 埠寫成 [host]:port。
func knownHostsEntry(host string, port int, rec *model.AssetHostKey) string {
	target := host
	if port != 22 {
		target = fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s %s %s", target, rec.Algorithm, rec.PublicKey)
}

// applySidecarHostKey 有同位址記錄時帶 sftp-host-key 給 guacd；沒有記錄或查詢失敗時不帶參數、維持現況
// （guacd 不驗主機身分）。平台側拿不到 guacd 的驗證結果：不符由 guacd 拒絕 SFTP，不會產生本機制的審計與告警，
// 這是已知限制（ops 文件寫明）。
func applySidecarHostKey(params map[string]string, lookup SidecarHostKeyLookup, host string, port int) {
	if lookup == nil {
		return
	}
	rec, err := lookup.LookupAddress(host, port)
	if err != nil || rec == nil || rec.PublicKey == "" || rec.Algorithm == "" {
		return
	}
	params[sidecarHostKeyParam] = knownHostsEntry(host, port, rec)
	log.Printf("[Handler] VNC 檔案傳輸側車帶已記錄主機金鑰: host=%s port=%d %s %s", host, port, rec.Algorithm, rec.Fingerprint)
}
