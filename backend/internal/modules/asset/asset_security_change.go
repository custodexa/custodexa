package asset

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
)

// 位址與傳輸放寬的變更分類（純函式，不碰資料庫）。
//
// 只在「更新既有資產」時使用：輸入交易內舊值與套用後新值，輸出每個命中的告警類型各一個事件
// 與該類型的全部命中欄位（欄位 JSON 名稱，固定順序）。收緊（反方向）與表外欄位不產生事件，
// 只進審計 diff。

// AssetSecurityChange 一個告警類型的命中結果。
type AssetSecurityChange struct {
	Type   port.SystemAlertType
	Fields []string
}

// rdpSecurityRank 傳輸安全強度序：nla > tls > 未設定（自動協商）。
func rdpSecurityRank(v string) int {
	switch v {
	case model.RDPSecurityNLA:
		return 3
	case model.RDPSecurityTLS:
		return 2
	default:
		return 1
	}
}

// dbTLSRank 強度序：verify-full > verify-ca > require > 未設定（用戶端預設）> disable。
func dbTLSRank(v string) int {
	switch v {
	case "verify-full":
		return 5
	case "verify-ca":
		return 4
	case "require":
		return 3
	case "disable":
		return 1
	default:
		return 2
	}
}

// ClassifyAssetSecurityChange 見檔頭。回傳依「位址類型、傳輸放寬類型」固定順序，未命中的類型不出現。
func ClassifyAssetSecurityChange(old, new *model.Asset) []AssetSecurityChange {
	var addr, relax []string

	// 位址：host、port、protocol 任何變更
	if old.Host != new.Host {
		addr = append(addr, "host")
	}
	if old.Port != new.Port {
		addr = append(addr, "port")
	}
	if old.Protocol != new.Protocol {
		addr = append(addr, "protocol")
	}
	// 目的地：改密通道與其附屬埠、SFTP 埠任何變更；sftp_enabled 由關到開
	if old.RotationChannel != new.RotationChannel {
		addr = append(addr, "rotation_channel")
	}
	if old.WinrmScheme != new.WinrmScheme {
		addr = append(addr, "winrm_scheme")
	}
	if old.WinrmPort != new.WinrmPort {
		addr = append(addr, "winrm_port")
	}
	if old.RotationSSHPort != new.RotationSSHPort {
		addr = append(addr, "rotation_ssh_port")
	}
	if old.SftpPort != new.SftpPort {
		addr = append(addr, "sftp_port")
	}
	if !old.SftpEnabled && new.SftpEnabled {
		addr = append(addr, "sftp_enabled")
	}

	// 傳輸放寬：只有降級方向
	if old.RDPVerifyCert && !new.RDPVerifyCert {
		relax = append(relax, "rdp_verify_cert")
	}
	if rdpSecurityRank(new.RDPSecurity) < rdpSecurityRank(old.RDPSecurity) {
		relax = append(relax, "rdp_security")
	}
	if dbTLSRank(new.DBTLSMode) < dbTLSRank(old.DBTLSMode) {
		relax = append(relax, "db_tls_mode")
	}
	if !old.K8sInsecureSkipTLS && new.K8sInsecureSkipTLS {
		relax = append(relax, "k8s_insecure_skip_tls")
	}
	if old.WinrmTLSMode != model.WinrmTLSModeInsecure && new.WinrmTLSMode == model.WinrmTLSModeInsecure {
		relax = append(relax, "winrm_tls_mode")
	}
	// CA：設定、替換、清除都算
	if old.DBCACert != new.DBCACert {
		relax = append(relax, "db_ca_cert")
	}
	if old.K8sCACert != new.K8sCACert {
		relax = append(relax, "k8s_ca_cert")
	}
	if old.WinrmCACert != new.WinrmCACert {
		relax = append(relax, "winrm_ca_cert")
	}

	var out []AssetSecurityChange
	if len(addr) > 0 {
		out = append(out, AssetSecurityChange{Type: port.SystemAlertAssetAddressChanged, Fields: addr})
	}
	if len(relax) > 0 {
		out = append(out, AssetSecurityChange{Type: port.SystemAlertTransportVerificationRelaxed, Fields: relax})
	}
	return out
}

// newAssetCorrelationID 產生審計列與系統告警共用的關聯識別。
func newAssetCorrelationID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("產生關聯識別失敗: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// raiseAssetSecurityEvents 在更新交易內為每個命中類型寫入一個系統告警事件。
//
// 事件只帶資產 ID、名稱、操作者與命中欄位清單（欄位 JSON 名稱）；前後值留在同交易的資產變更
// 審計 diff（CA 為摘要、秘密欄只記已變更），帳號與密碼不進事件。落地面未注入或寫入失敗即回錯，
// 呼叫端讓錯誤逸出交易閉包，整筆回滾。
func raiseAssetSecurityEvents(sink port.SystemAlertSink, tx *gorm.DB, asset *model.Asset,
	events []AssetSecurityChange, userID uint, username, correlationID string) error {
	for _, ev := range events {
		key := "changed_fields"
		if ev.Type == port.SystemAlertTransportVerificationRelaxed {
			key = "relaxed_settings"
		}
		id := asset.ID
		_, err := port.RaiseInTx(sink, tx, port.SystemAlertEvent{
			Type:          ev.Type,
			Actor:         port.SystemAlertActor{UserID: userID, Username: username},
			Target:        port.SystemAlertTarget{Kind: port.SystemAlertTargetAsset, ID: strconv.FormatUint(uint64(id), 10)},
			AssetID:       &id,
			CorrelationID: correlationID,
			Params: map[string]string{
				key:          strings.Join(ev.Fields, ","),
				"asset_name": asset.Name,
			},
		})
		if err != nil {
			return fmt.Errorf("產生資產安全變更告警失敗: %w", err)
		}
	}
	return nil
}
