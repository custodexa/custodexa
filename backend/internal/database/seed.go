package database

import (
	"errors"
	"log"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// SeedDatabase 初始化資料庫資料（角色、初始管理員）。
// adminInitialPassword 為建立初始 admin 用的密碼：
// 呼叫端（main.go）已於空 DB 時驗證其 byte 契約；非空 DB 時傳空字串，seedAdmin 依 count>0 略過。
func SeedDatabase(adminInitialPassword string) error {
	log.Println("開始初始化資料庫資料...")

	// 1. 建立預設角色（冪等，既有安裝亦補齊缺角色）
	if err := seedRoles(); err != nil {
		return err
	}

	// 2. 建立初始管理員帳號（僅空 DB）
	if err := seedAdmin(adminInitialPassword); err != nil {
		return err
	}

	log.Println("資料庫資料初始化完成")
	return nil
}

// CountUsers 回傳使用者總數（deployment-hardening：main.go 據以判定全新/既有安裝）
func CountUsers() (int64, error) {
	var count int64
	if err := DB.Model(&model.User{}).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

// ScanLegacyDefaultAdmins 掃描所有具 admin 角色的帳號，回傳密碼仍為出廠預設 admin123 的帳號 ID
// （deployment-hardening 的 legacy 掃描）。不依賴 username／資料列排序／單一 admin 假設／
// must_change_password 篩選；涵蓋 active 與 inactive（inactive 亦不得保留公開已知憑證）。
// LDAP 用戶密碼在目錄端、空密碼無從比對，皆跳過。
func ScanLegacyDefaultAdmins() ([]uint, error) {
	var users []model.User
	if err := DB.Preload("Roles").Find(&users).Error; err != nil {
		return nil, err
	}
	var hits []uint
	for i := range users {
		u := &users[i]
		if u.IsLDAP || u.Password == "" || !userHasAdminRole(u) {
			continue
		}
		// 走 Verifier 而非單一演算法：
		// 它依雜湊前綴分派，故**掃描自動涵蓋全部支援的演算法**。
		// 只比對當前演算法會讓舊雜湊的帳號逃過掃描，而那正是最可能中招的
		// ——久未登入所以從未被漸進遷移升級。
		if crypto.DefaultPasswordVerifier().Verify(u.Password, []byte("admin123")) == nil {
			hits = append(hits, u.ID)
		}
	}
	return hits, nil
}

// userHasAdminRole 判定使用者是否具 admin 角色（legacy 掃描用；不靠 primaryRoleOf 折疊，
// 只要掛有 admin 角色即納入，避免多角色/職能疊加時漏掉）
func userHasAdminRole(u *model.User) bool {
	for _, r := range u.Roles {
		if r.Name == model.RoleAdmin {
			return true
		}
	}
	return false
}

// seedRoles 建立預設角色
func seedRoles() error {
	roles := []model.Role{
		{
			Name:        model.RoleAdmin,
			Description: "系統管理員，擁有所有權限",
		},
		{
			Name:        model.RoleUser,
			Description: "一般使用者，可以連線到已授權的資產",
		},
		{
			Name:        model.RoleAuditor,
			Description: "稽核人員，可以檢視所有審計日誌和連線記錄",
		},
		{
			// 可疊加職能角色：僅授予審核職能，
			// 不改變 primaryRoleOf 判定。seedRoles 逐角色補建，既有部署升級即生效
			Name:        model.RoleApprover,
			Description: "審核人員，可核准/拒絕審核範圍內的連線申請",
		},
	}

	for _, role := range roles {
		// 檢查角色是否已存在
		var existing model.Role
		result := DB.Where("name = ?", role.Name).First(&existing)

		if result.Error == gorm.ErrRecordNotFound {
			// 角色不存在，建立新角色
			if err := DB.Create(&role).Error; err != nil {
				return err
			}
			log.Printf("建立角色: %s", role.Name)
		} else {
			log.Printf("角色已存在: %s", role.Name)
		}
	}

	return nil
}

// seedAdmin 建立初始管理員帳號。
// 僅在空 DB（count==0）建立；密碼取自部署方 .env 的 ADMIN_INITIAL_PASSWORD（呼叫端已驗證 byte 契約），
// 不再有硬編碼公開預設值。首登強制改密後該值退役（見 main.go 退役告警與 QUICKSTART）。
func seedAdmin(adminInitialPassword string) error {
	// 檢查是否已有使用者
	var count int64
	DB.Model(&model.User{}).Count(&count)

	if count > 0 {
		log.Println("已存在使用者，跳過初始管理員建立")
		return nil
	}

	// 防禦性檢查：空 DB 建立初始 admin 必須有已驗證的初始密碼（呼叫端保證，
	// 此處再擋一層，避免誤以空字串建帳號）
	if adminInitialPassword == "" {
		return errors.New("拒絕以空的初始密碼建立管理員：ADMIN_INITIAL_PASSWORD 未提供或未通過驗證")
	}

	// 密碼不落日誌（PCI 8.3.5/2.2.2）；驗證與 hash 使用相同 bytes
	hashedPassword, err := crypto.DefaultPasswordHasher().Hash([]byte(adminInitialPassword))
	if err != nil {
		return err
	}

	adminEmail := "admin@custodexa.local"
	admin := model.User{
		Username: "admin",
		Email:    &adminEmail,
		Password: string(hashedPassword),
		FullName: "Administrator",
		Active:   true,
		IsLDAP:   false,
		// 身分欄位顯式賦值：seed admin 是本地帳號，
		// 且必須保有本地密碼——它是封印狀態下唯一能解封的憑證來源
		ProvisioningOrigin: model.AuthSourceLocal,
		ExternalCredential: false,
		// 首次登入強制改密
		MustChangePassword: true,
		// 閒置停用豁免：避免唯一管理員因久未登入被自動停用鎖死系統
		InactivityExempt: true,
	}

	// 建立管理員、初始歷史與 admin 角色須原子（PW-4 + deployment-hardening）：任一步失敗全回滾，
	// 避免留下「已建 admin 但無歷史列」或「已建 admin 但未掛 admin 角色」的半初始化——下次啟動
	// count>0 永久跳過 seed，導致可 serving 卻無有效管理員，或瓦解「首次強制改密不可設回 vendor default」這條規則。
	if err := DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&admin).Error; err != nil {
			return err
		}
		if err := tx.Create(&model.PasswordHistory{
			UserID:       admin.ID,
			PasswordHash: string(hashedPassword),
		}).Error; err != nil {
			return err
		}
		var adminRole model.Role
		if err := tx.Where("name = ?", model.RoleAdmin).First(&adminRole).Error; err != nil {
			return err
		}
		return tx.Model(&admin).Association("Roles").Append(&adminRole)
	}); err != nil {
		return err
	}

	log.Printf("建立初始管理員帳號 admin（密碼取自 ADMIN_INITIAL_PASSWORD；首次登入須改密後該值退役）")

	return nil
}
