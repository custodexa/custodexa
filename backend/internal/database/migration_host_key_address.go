package database

import (
	"encoding/json"
	"fmt"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 主機指紋記錄的撥號位址增量。
//
// 內容：asset_host_keys 加入撥號位址（host、port）與「重置待記錄」旗標，並對 (host, port)
// 建索引；既有指紋列以撥號位址輔助函式（model.Asset.HostKeyAddress）回填，含已軟刪資產的列。
// 推不出位址的列（資產已不存在、或資產協定沒有 SSH 撥號）留空並計入報告，留空列在下一次
// 自身列相符時補上。
//
// 回填只動 host、port 兩欄且只動仍為空的列，可重入；asset_id、指紋與公鑰一律不動。
// 隔離環境的 dry-run 報告（PlanHostKeyAddressReport）與正式報告（回填回傳值）以同一分類計算，可逐項比對。
//
// # Down 契約
//
// 不提供回滾：回退只走升級前備份。
func hostKeyAddressDDL() []string {
	return []string{
		`ALTER TABLE asset_host_keys ADD COLUMN host character varying(255) DEFAULT ''::character varying NOT NULL`,
		`ALTER TABLE asset_host_keys ADD COLUMN port bigint DEFAULT 0 NOT NULL`,
		`ALTER TABLE asset_host_keys ADD COLUMN reset_pending boolean DEFAULT false NOT NULL`,
		`CREATE INDEX idx_asset_host_keys_address ON asset_host_keys USING btree (host, port)`,
	}
}

func applyHostKeyAddress(db *gorm.DB) error {
	for _, stmt := range hostKeyAddressDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 host_key_address DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	_, err := BackfillHostKeyAddress(db)
	return err
}

// rollbackHostKeyAddress 只供 parity 守衛與開發環境；生產沒有回滾入口。
func rollbackHostKeyAddress(db *gorm.DB) error {
	for _, stmt := range []string{
		`DROP INDEX idx_asset_host_keys_address`,
		`ALTER TABLE asset_host_keys DROP COLUMN reset_pending`,
		`ALTER TABLE asset_host_keys DROP COLUMN port`,
		`ALTER TABLE asset_host_keys DROP COLUMN host`,
	} {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("回滾 host_key_address 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// HostKeyAddressReport 回填（或 dry-run）的分類計數。
type HostKeyAddressReport struct {
	// Total 納入判定的指紋列數（回填時只含 host 仍為空者；dry-run 含全部列）
	Total int `json:"total"`
	// SSH 協定 ssh 的資產列（含已軟刪）
	SSH int `json:"ssh"`
	// RDPWindowsSSH 協定 rdp 且改密通道為 windows_ssh 的資產列，依 rotation_ssh_port 是否為 0 分計
	RDPWindowsSSHDefaultPort int `json:"rdp_windows_ssh_default_port"`
	RDPWindowsSSHCustomPort  int `json:"rdp_windows_ssh_custom_port"`
	// SoftDeleted 其中擁有者資產已軟刪的列（已計入上列各類）
	SoftDeleted int `json:"soft_deleted"`
	// Unresolved 推不出位址而留空的列數（擁有者已不存在或沒有 SSH 撥號）
	Unresolved int `json:"unresolved"`
}

// JSON 報告的決定性文字。
func (r HostKeyAddressReport) JSON() (string, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("序列化指紋位址回填報告失敗: %w", err)
	}
	return string(b), nil
}

type hostKeyAddressRow struct {
	ID              uint
	AssetFound      bool
	Protocol        string
	Host            string
	Port            int
	RotationChannel string
	RotationSSHPort int
	AssetDeleted    bool
}

func loadHostKeyAddressRows(db *gorm.DB, onlyEmpty bool) ([]hostKeyAddressRow, error) {
	// LEFT JOIN 不過濾 deleted_at：已軟刪資產的指紋列同樣要回填，位址記錄正是為刪除重建而留
	q := `SELECT hk.id AS id, (a.id IS NOT NULL) AS asset_found, COALESCE(a.protocol, '') AS protocol,
		COALESCE(a.host, '') AS host, COALESCE(a.port, 0) AS port,
		COALESCE(a.rotation_channel, '') AS rotation_channel, COALESCE(a.rotation_ssh_port, 0) AS rotation_ssh_port,
		(a.deleted_at IS NOT NULL) AS asset_deleted
		FROM asset_host_keys hk LEFT JOIN assets a ON a.id = hk.asset_id`
	if onlyEmpty {
		q += ` WHERE hk.host = ''`
	}
	q += ` ORDER BY hk.id`
	var rows []hostKeyAddressRow
	if err := db.Raw(q).Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("讀取指紋列與擁有者資產失敗: %w", err)
	}
	return rows, nil
}

func classifyHostKeyAddress(rows []hostKeyAddressRow) (HostKeyAddressReport, map[uint][2]interface{}) {
	rep := HostKeyAddressReport{Total: len(rows)}
	resolved := map[uint][2]interface{}{}
	for _, r := range rows {
		if !r.AssetFound {
			rep.Unresolved++
			continue
		}
		a := model.Asset{Protocol: model.ProtocolType(r.Protocol), Host: r.Host, Port: r.Port,
			RotationChannel: r.RotationChannel, RotationSSHPort: r.RotationSSHPort}
		host, port, ok := a.HostKeyAddress()
		if !ok {
			rep.Unresolved++
			continue
		}
		switch {
		case a.Protocol == model.ProtocolSSH:
			rep.SSH++
		case r.RotationSSHPort > 0:
			rep.RDPWindowsSSHCustomPort++
		default:
			rep.RDPWindowsSSHDefaultPort++
		}
		if r.AssetDeleted {
			rep.SoftDeleted++
		}
		resolved[r.ID] = [2]interface{}{host, port}
	}
	return rep, resolved
}

// PlanHostKeyAddressReport 唯讀計算報告（可在升級前備份還原的隔離資料庫演練）：
// 以全部指紋列為對象，分類與正式回填相同。需要 host 欄已存在者請改用回填本身的回傳值。
func PlanHostKeyAddressReport(db *gorm.DB) (HostKeyAddressReport, error) {
	rows, err := loadHostKeyAddressRows(db, false)
	if err != nil {
		return HostKeyAddressReport{}, err
	}
	rep, _ := classifyHostKeyAddress(rows)
	return rep, nil
}

// BackfillHostKeyAddress 回填仍為空的指紋列位址，回傳分類報告。可重入：第二次沒有空列可處理，
// 但「推不出位址而留空」的列每次都會被重新判定（擁有者資產之後變更時仍可補上）。
func BackfillHostKeyAddress(db *gorm.DB) (HostKeyAddressReport, error) {
	rows, err := loadHostKeyAddressRows(db, true)
	if err != nil {
		return HostKeyAddressReport{}, err
	}
	rep, resolved := classifyHostKeyAddress(rows)
	for id, addr := range resolved {
		if err := db.Exec(`UPDATE asset_host_keys SET host = ?, port = ? WHERE id = ? AND host = ''`,
			addr[0], addr[1], id).Error; err != nil {
			return rep, fmt.Errorf("回填指紋位址失敗（id=%d）: %w", id, err)
		}
	}
	return rep, nil
}
