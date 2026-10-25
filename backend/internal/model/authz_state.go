package model

import "time"

// 權限模型的資料表宣告。
// 三張表歸授權模組（authz）所有；其他模組只經 authz 的對外函式寫入。

// 範圍種類：全域，或一組節點（各含子樹）。
const (
	ScopeKindGlobal = "global"
	ScopeKindNodes  = "nodes"
)

// 內建範本識別（roles.builtin_key 非空即為鎖定的內建範本）。
const (
	BuiltinSuperAdmin = "super_admin"
	BuiltinAuditor    = "auditor"
	BuiltinUser       = "user"
	BuiltinApprover   = "approver"
	// 自訂角色定義所需的兩個鎖定管理範本。
	BuiltinIdentityAdmin = "identity_admin"
	BuiltinSecurityAdmin = "security_admin"
	// 兩個範圍化管理範本（可限定節點指派）。
	BuiltinAssetAdmin = "asset_admin"
	BuiltinAuthzAdmin = "authz_admin"
)

// RolePermission 自訂角色的明確權限集合（角色 × 權限鍵）。內建範本的集合在程式中，不存此表。
type RolePermission struct {
	RoleID        uint   `gorm:"primaryKey;autoIncrement:false"`
	PermissionKey string `gorm:"primaryKey;size:64;not null"`
}

// TableName 指定表名
func (RolePermission) TableName() string { return "role_permissions" }

// 角色指派主體種類（role_binding_nodes.subject_kind）。
const (
	BindingSubjectUser      = "user"
	BindingSubjectUserGroup = "user_group"
)

// UserGroupRole 使用者群組 × 角色指派。
type UserGroupRole struct {
	UserGroupID uint      `gorm:"primaryKey;autoIncrement:false"`
	RoleID      uint      `gorm:"primaryKey;autoIncrement:false"`
	ScopeKind   string    `gorm:"size:8;not null;default:global"`
	CreatedAt   time.Time `gorm:"not null"`
	CreatedBy   *uint
}

// TableName 指定表名
func (UserGroupRole) TableName() string { return "user_group_roles" }

// RoleBindingNode 範圍為節點的指派所涵蓋的節點（各含子樹）。
type RoleBindingNode struct {
	SubjectKind string `gorm:"primaryKey;size:16;not null"`
	SubjectID   uint   `gorm:"primaryKey;autoIncrement:false"`
	RoleID      uint   `gorm:"primaryKey;autoIncrement:false"`
	NodeID      uint   `gorm:"primaryKey;autoIncrement:false"`
}

// TableName 指定表名
func (RoleBindingNode) TableName() string { return "role_binding_nodes" }

// AuthzState 權限狀態（單列）：權限版本與權限模型遷移報告。
type AuthzState struct {
	ID                   int   `gorm:"primaryKey;autoIncrement:false;default:1;type:integer"`
	Version              int64 `gorm:"not null;default:0"`
	ModelMigratedAt      *time.Time
	ModelMigrationReport *string `gorm:"type:text"`

	// 恢復世代。RestoreGeneration 為 256-bit 隨機 hex，
	// 空字串＝legacy 世代（從未還原過）。RestoreOpID／RestoreInputDigest／RestoreStatus 記錄
	// 最近一次恢復交易，供接續判定（pending＝已提交、尚待腳本確認放行；done＝已完成放行）。
	RestoreGeneration  string `gorm:"size:64;not null;default:''"`
	RestoreOpID        string `gorm:"size:64;not null;default:''"`
	RestoreInputDigest string `gorm:"size:64;not null;default:''"`
	RestoreStatus      string `gorm:"size:16;not null;default:''"`
	RestoredAt         *time.Time
}

// TableName 指定表名
func (AuthzState) TableName() string { return "authz_state" }
