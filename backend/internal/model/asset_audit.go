package model

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"gorm.io/gorm"
)

// AssetDiffClass 更新請求欄位在資產變更審計中的表示方式。
type AssetDiffClass string

const (
	// AssetDiffValue 前後值直接進審計明細。
	AssetDiffValue AssetDiffClass = "value"
	// AssetDiffDigest 前後值的 SHA-256 摘要（空字串＝未設定）；CA 不是秘密，
	// 但全文會撐爆審計明細上界。
	AssetDiffDigest AssetDiffClass = "digest"
	// AssetDiffChangedFlag 只記「已變更」，不記任何值或長度。
	AssetDiffChangedFlag AssetDiffClass = "changed"
	// AssetDiffExcluded 不進資產 diff，由各自的既有審計承擔（見 AssetDiffExcludedOwner）。
	AssetDiffExcluded AssetDiffClass = "excluded"
)

// AssetUpdateFieldClasses 資產更新請求的每個 JSON 欄位及其審計表示。
// 資產模組的測試以反射比對更新請求結構與本表，可改欄位新增而本表未跟上即失敗。
var AssetUpdateFieldClasses = map[string]AssetDiffClass{
	"name": AssetDiffValue, "protocol": AssetDiffValue, "host": AssetDiffValue, "port": AssetDiffValue,
	"username": AssetDiffValue, "description": AssetDiffValue, "tags": AssetDiffValue, "active": AssetDiffValue,
	"access_policy": AssetDiffValue, "rdp_security": AssetDiffValue, "rdp_verify_cert": AssetDiffValue,
	"db_name": AssetDiffValue, "db_tls_mode": AssetDiffValue, "allowed_databases": AssetDiffValue,
	"k8s_namespace": AssetDiffValue, "k8s_pod": AssetDiffValue, "k8s_container": AssetDiffValue,
	"k8s_insecure_skip_tls": AssetDiffValue, "sftp_enabled": AssetDiffValue, "sftp_port": AssetDiffValue,
	"sftp_username": AssetDiffValue, "rotation_channel": AssetDiffValue, "winrm_scheme": AssetDiffValue,
	"winrm_port": AssetDiffValue, "winrm_tls_mode": AssetDiffValue, "rotation_ssh_port": AssetDiffValue,

	"db_ca_cert": AssetDiffDigest, "k8s_ca_cert": AssetDiffDigest, "winrm_ca_cert": AssetDiffDigest,

	"sftp_password": AssetDiffChangedFlag,

	"password": AssetDiffExcluded, "private_key": AssetDiffExcluded, "node_ids": AssetDiffExcluded,
}

// AssetDiffExcludedOwner 明列排除欄位的審計承擔者。
var AssetDiffExcludedOwner = map[string]string{
	"password":    "預設帳號同步的帳號審計",
	"private_key": "預設帳號同步的帳號審計",
	"node_ids":    "節點掛載審計",
}

// AssetCertDigest CA 憑證的審計摘要：空字串＝未設定，否則為 PEM 全文的 SHA-256 十六進位。
func AssetCertDigest(pem string) string {
	if pem == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(pem))
	return hex.EncodeToString(sum[:])
}

// DiffAsset 比較兩個 Asset 物件的差異。
//
// **由 diffAsset 匯出**：T-2 的服務側審計（`writeAssetChangeAudit`）與
// T-3 的 GORM hook（`AfterUpdate`，維持直寫）共用同一份 diff 規則。
// hook 走不掉 `internal/model`（model 不得 import 模組），故規則必須留在此處；
// 複製一份到 asset 側等於製造第二個會漂移的變更判定。
//
// 涵蓋更新請求的每一個可改欄位，表示方式見 AssetUpdateFieldClasses。
func DiffAsset(old, new *Asset) []AssetChange {
	changes := []AssetChange{}
	val := func(field string, o, n interface{}, differ bool) {
		if differ {
			changes = append(changes, AssetChange{Field: field, Old: o, New: n})
		}
	}

	val("name", old.Name, new.Name, old.Name != new.Name)
	val("protocol", old.Protocol, new.Protocol, old.Protocol != new.Protocol)
	val("host", old.Host, new.Host, old.Host != new.Host)
	val("port", old.Port, new.Port, old.Port != new.Port)
	val("description", old.Description, new.Description, old.Description != new.Description)
	val("active", old.Active, new.Active, old.Active != new.Active)
	val("username", old.Username, new.Username, old.Username != new.Username)
	val("tags", old.Tags, new.Tags, old.Tags != new.Tags)

	// 節點掛載為 M2M 非資產欄位，不經 hook diff——
	// 成員變更審計在 asset service 的節點同步邏輯落（node_ids 差集）

	// AccessPolicy nil＝跟隨全域，審計以空字串表示
	oldPolicy, newPolicy := "", ""
	if old.AccessPolicy != nil {
		oldPolicy = *old.AccessPolicy
	}
	if new.AccessPolicy != nil {
		newPolicy = *new.AccessPolicy
	}
	val("access_policy", oldPolicy, newPolicy, oldPolicy != newPolicy)

	// 允許資料庫清單：以項數與逐項內容比對（清單是有序的字串集，
	// 順序變動也算變動——管理者看到的表單順序就是儲存順序）。
	// 值直接進 Old/New：名稱是管理者自己輸入的設定，不是憑證也不是資料內容
	val("allowed_databases", []string(old.AllowedDatabases), []string(new.AllowedDatabases),
		!stringListEqual(old.AllowedDatabases, new.AllowedDatabases))

	// 改密通道與其附屬欄位：附屬欄位是憑證與埠的投遞目的地，必須逐欄可查。
	val("rotation_channel", old.RotationChannel, new.RotationChannel, old.RotationChannel != new.RotationChannel)
	val("winrm_scheme", old.WinrmScheme, new.WinrmScheme, old.WinrmScheme != new.WinrmScheme)
	val("winrm_port", old.WinrmPort, new.WinrmPort, old.WinrmPort != new.WinrmPort)
	val("winrm_tls_mode", old.WinrmTLSMode, new.WinrmTLSMode, old.WinrmTLSMode != new.WinrmTLSMode)
	val("rotation_ssh_port", old.RotationSSHPort, new.RotationSSHPort, old.RotationSSHPort != new.RotationSSHPort)

	// RDP 傳輸安全
	val("rdp_security", old.RDPSecurity, new.RDPSecurity, old.RDPSecurity != new.RDPSecurity)
	val("rdp_verify_cert", old.RDPVerifyCert, new.RDPVerifyCert, old.RDPVerifyCert != new.RDPVerifyCert)

	// DB 連線目標與 TLS
	val("db_name", old.DBName, new.DBName, old.DBName != new.DBName)
	val("db_tls_mode", old.DBTLSMode, new.DBTLSMode, old.DBTLSMode != new.DBTLSMode)

	// K8s 目標與 TLS
	val("k8s_namespace", old.K8sNamespace, new.K8sNamespace, old.K8sNamespace != new.K8sNamespace)
	val("k8s_pod", old.K8sPod, new.K8sPod, old.K8sPod != new.K8sPod)
	val("k8s_container", old.K8sContainer, new.K8sContainer, old.K8sContainer != new.K8sContainer)
	val("k8s_insecure_skip_tls", old.K8sInsecureSkipTLS, new.K8sInsecureSkipTLS,
		old.K8sInsecureSkipTLS != new.K8sInsecureSkipTLS)

	// VNC SFTP 側車
	val("sftp_enabled", old.SftpEnabled, new.SftpEnabled, old.SftpEnabled != new.SftpEnabled)
	val("sftp_port", old.SftpPort, new.SftpPort, old.SftpPort != new.SftpPort)
	val("sftp_username", old.SftpUsername, new.SftpUsername, old.SftpUsername != new.SftpUsername)

	// CA 憑證：只記 SHA-256 摘要，不含 PEM
	for _, c := range []struct {
		field    string
		old, new string
	}{
		{"db_ca_cert", old.DBCACert, new.DBCACert},
		{"k8s_ca_cert", old.K8sCACert, new.K8sCACert},
		{"winrm_ca_cert", old.WinrmCACert, new.WinrmCACert},
	} {
		val(c.field, AssetCertDigest(c.old), AssetCertDigest(c.new), c.old != c.new)
	}

	// SFTP 密碼：只記已變更，不記任何值或長度
	if old.SftpPasswordEnc != new.SftpPasswordEnc {
		changes = append(changes, AssetChange{Field: "sftp_password", Changed: true})
	}

	return changes
}

func stringListEqual(a, b StringList) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// getUserFromContext 從 context 提取用戶資訊
func getUserFromContext(ctx context.Context) (userID uint, username string) {
	if ctx == nil {
		return 0, "system"
	}

	// 嘗試提取 userID
	if val := ctx.Value("userID"); val != nil {
		if id, ok := val.(uint); ok {
			userID = id
		}
	}

	// 嘗試提取 username
	if val := ctx.Value("username"); val != nil {
		if name, ok := val.(string); ok {
			username = name
		}
	}

	// 如果沒有用戶資訊，使用系統
	if userID == 0 {
		userID = 0
		username = "system"
	}

	return userID, username
}

// AfterCreate Hook - 記錄資產創建
func (a *Asset) AfterCreate(tx *gorm.DB) error {
	userID, username := getUserFromContext(tx.Statement.Context)

	// 創建操作不需要 diff，只記錄創建事件
	auditLog := &AuditLog{
		CreatedAt:  time.Now(),
		UserID:     userID,
		Username:   username,
		Action:     ActionCreate,
		Resource:   ResourceAsset,
		ResourceID: &a.ID,
		// 主體鍵與 ResourceID 同值仍要各記一次（auditor-workbench）：資產樞紐只認
		// AssetID，靠 (Resource, ResourceID) 反推會把改密計畫／授權列的同號 id 一併撈進來
		AssetID: &a.ID,
		Status:  StatusSuccess,
		Details: "", // 創建操作不需要詳情
	}

	// 使用新的 session 避免嵌套事務問題
	return tx.Session(&gorm.Session{NewDB: true}).Create(auditLog).Error
}

// AfterUpdate Hook - 記錄資產變更
func (a *Asset) AfterUpdate(tx *gorm.DB) error {
	userID, username := getUserFromContext(tx.Statement.Context)

	// 從 Statement.Dest 獲取更新前的值
	// 注意：GORM 在 AfterUpdate 時，Statement.Dest 包含更新後的值
	// 我們需要從 Statement.Changed 獲取變更的欄位
	// 但 Statement.Changed 在 GORM v2 中不可用
	// 因此我們需要在 BeforeUpdate 中保存原始值

	// 簡化方案：只記錄更新事件，不做 diff
	// 完整 diff 需要在 Service 層實作
	auditLog := &AuditLog{
		CreatedAt:  time.Now(),
		UserID:     userID,
		Username:   username,
		Action:     ActionUpdate,
		Resource:   ResourceAsset,
		ResourceID: &a.ID,
		AssetID:    &a.ID,
		Status:     StatusSuccess,
		Details:    "", // 簡化版本先不做 diff
	}

	return tx.Session(&gorm.Session{NewDB: true}).Create(auditLog).Error
}

// AfterDelete Hook - 記錄資產刪除
func (a *Asset) AfterDelete(tx *gorm.DB) error {
	userID, username := getUserFromContext(tx.Statement.Context)

	auditLog := &AuditLog{
		CreatedAt:  time.Now(),
		UserID:     userID,
		Username:   username,
		Action:     ActionDelete,
		Resource:   ResourceAsset,
		ResourceID: &a.ID,
		AssetID:    &a.ID,
		Status:     StatusSuccess,
		Details:    "", // 刪除操作不需要詳情
	}

	return tx.Session(&gorm.Session{NewDB: true}).Create(auditLog).Error
}

// `RecordAssetChange` 與 `RecordAssetNodeChange` 已隨 T-2 收口
// 遷入 asset 模組（`internal/modules/asset/asset_audit_events.go` 的
// `writeAssetChangeAudit`／`writeAssetNodeChangeAudit`），落地一律經
// `audit/port.WriteInTx`。`internal/model` 自此只留資料型別與 T-3 的 GORM hook
// （後者維持直寫），不再是第四個審計落地入口。
