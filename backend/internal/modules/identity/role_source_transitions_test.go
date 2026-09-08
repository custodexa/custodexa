package identity

import (
	"sort"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 來源三態的四種狀態轉移。
//
// 表驅動的理由：轉移是「事件 × 起始態」的矩陣，逐格寫成獨立測試會讓漏格
// 看不出來——矩陣寫成資料之後，少一格是肉眼可見的。

var roleSourceMatchedAt = time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

// roleSourceDB 帶四張表的單連線 :memory: fixture。
func roleSourceDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db handle: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	// UserRole 必須排在 User／Role 之後：many2many 標籤自動建出的關聯表只有兩欄，
	// 而 GORM 的處理會蓋掉排在它之前的關聯 model 宣告
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.AuditLog{},
		&model.UserRole{}, &model.UserRoleMapping{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })
	return db
}

// seedRoleSourceSubject 一個帳號與一個角色。
func seedRoleSourceSubject(t *testing.T, db *gorm.DB) (userID, roleID uint) {
	t.Helper()
	u := &model.User{Username: "transition-subject", Password: "x", Active: true}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("建帳號: %v", err)
	}
	r := &model.Role{Name: "transition-role"}
	if err := db.Create(r).Error; err != nil {
		t.Fatalf("建角色: %v", err)
	}
	return u.ID, r.ID
}

// setupRoleState 把（帳號，角色）擺成指定的起始態。
//
// `absent` 代表關聯列不存在；其餘三個值是來源三態。`mapped` 與 `both` 一併
// 落一筆本通道的映射事實——來源欄與映射事實表不一致的起始態不是合法狀態，
// 拿它當起點測出來的結論不能推廣。
func setupRoleState(t *testing.T, db *gorm.DB, userID, roleID uint, state, channel string) {
	t.Helper()
	switch state {
	case "absent":
		return
	case model.RoleSourceManual, model.RoleSourceMapped, model.RoleSourceBoth:
	default:
		t.Fatalf("未知的起始態: %s", state)
	}
	if err := db.Create(&model.UserRole{
		UserID: userID, RoleID: roleID, Source: state,
	}).Error; err != nil {
		t.Fatalf("建關聯列(%s): %v", state, err)
	}
	if state == model.RoleSourceMapped || state == model.RoleSourceBoth {
		if err := db.Create(&model.UserRoleMapping{
			UserID: userID, RoleID: roleID, Channel: channel, MatchedAt: roleSourceMatchedAt,
		}).Error; err != nil {
			t.Fatalf("建映射事實(%s): %v", state, err)
		}
	}
}

// readRoleState 讀回關聯列的來源（不存在時回 "absent"）。
func readRoleState(t *testing.T, db *gorm.DB, userID, roleID uint) string {
	t.Helper()
	source, exists, err := model.UserRoleSourceOf(db, userID, roleID)
	if err != nil {
		t.Fatalf("讀來源: %v", err)
	}
	if !exists {
		return "absent"
	}
	return source
}

// countMappingFacts 該（帳號，角色）在映射事實表上的列數（跨通道）。
func countMappingFacts(t *testing.T, db *gorm.DB, userID, roleID uint) int64 {
	t.Helper()
	var n int64
	if err := db.Model(&model.UserRoleMapping{}).
		Where("user_id = ? AND role_id = ?", userID, roleID).Count(&n).Error; err != nil {
		t.Fatalf("數映射事實: %v", err)
	}
	return n
}

// TestRoleSourceTransitions 四種轉移 × 三種起始態（外加「列不存在」）。
func TestRoleSourceTransitions(t *testing.T) {
	const channel = "directory:1"

	cases := []struct {
		name string
		// event 走哪一種轉移
		event string
		from  string
		// wantState 轉移後的來源（"absent" 代表列被刪或本來就不在）
		wantState string
		// wantEffectiveChange 有效角色集是否真的變動（授予或撤除）
		wantEffectiveChange bool
		// wantFacts 轉移後該角色在映射事實表上的列數
		wantFacts int64
	}{
		// 轉移一：映射命中該角色
		{"命中/列不存在", "grant", "absent", model.RoleSourceMapped, true, 1},
		{"命中/manual", "grant", model.RoleSourceManual, model.RoleSourceBoth, false, 1},
		{"命中/mapped", "grant", model.RoleSourceMapped, model.RoleSourceMapped, false, 1},
		{"命中/both", "grant", model.RoleSourceBoth, model.RoleSourceBoth, false, 1},

		// 轉移二：本通道不再命中
		{"不再命中/列不存在", "unmatch", "absent", "absent", false, 0},
		{"不再命中/manual", "unmatch", model.RoleSourceManual, model.RoleSourceManual, false, 0},
		{"不再命中/mapped", "unmatch", model.RoleSourceMapped, "absent", true, 0},
		{"不再命中/both", "unmatch", model.RoleSourceBoth, model.RoleSourceManual, false, 0},

		// 轉移三：管理者把角色移出手動集
		{"移出手動集/列不存在", "removeManual", "absent", "absent", false, 0},
		{"移出手動集/manual", "removeManual", model.RoleSourceManual, "absent", true, 0},
		{"移出手動集/mapped", "removeManual", model.RoleSourceMapped, model.RoleSourceMapped, false, 1},
		{"移出手動集/both", "removeManual", model.RoleSourceBoth, model.RoleSourceMapped, false, 1},

		// 轉移四：管理者把角色加入手動集（含固定映射來的角色）
		{"加入手動集/列不存在", "addManual", "absent", model.RoleSourceManual, true, 0},
		{"加入手動集/manual", "addManual", model.RoleSourceManual, model.RoleSourceManual, false, 0},
		{"加入手動集/mapped", "addManual", model.RoleSourceMapped, model.RoleSourceBoth, false, 1},
		{"加入手動集/both", "addManual", model.RoleSourceBoth, model.RoleSourceBoth, false, 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := roleSourceDB(t)
			userID, roleID := seedRoleSourceSubject(t, db)
			setupRoleState(t, db, userID, roleID, tc.from, channel)

			var changed bool
			err := db.Transaction(func(tx *gorm.DB) error {
				switch tc.event {
				case "grant":
					granted, err := GrantMappedRole(tx, userID, roleID, channel, roleSourceMatchedAt)
					changed = granted
					return err
				case "unmatch":
					// 本次一個也沒命中之外的形態：命中集非空但不含本角色
					revoked, err := RevokeMappedRolesForChannel(tx, userID, channel, []uint{roleID + 100})
					changed = len(revoked) > 0
					return err
				case "removeManual":
					removed, err := RemoveManualRole(tx, userID, roleID)
					changed = removed
					return err
				case "addManual":
					granted, err := AddManualRole(tx, userID, roleID)
					changed = granted
					return err
				}
				t.Fatalf("未知事件 %s", tc.event)
				return nil
			})
			if err != nil {
				t.Fatalf("%s: %v", tc.event, err)
			}

			if got := readRoleState(t, db, userID, roleID); got != tc.wantState {
				t.Errorf("來源 = %s, want %s", got, tc.wantState)
			}
			if changed != tc.wantEffectiveChange {
				t.Errorf("有效集變動 = %v, want %v："+
					"這個回傳值是世代推進的判準，錯了就是無故把人踢下線或漏撤",
					changed, tc.wantEffectiveChange)
			}
			if got := countMappingFacts(t, db, userID, roleID); got != tc.wantFacts {
				t.Errorf("映射事實列數 = %d, want %d", got, tc.wantFacts)
			}
		})
	}

	// 轉移二只動本通道的列。做成子測試而非獨立函式：它多帶一個「另一條通道」
	// 的維度，併進上面的表會讓每一格都得帶著那一欄，而只有這一件事需要它
	t.Run("不再命中/另一條通道仍命中", func(t *testing.T) {
		db := roleSourceDB(t)
		userID, roleID := seedRoleSourceSubject(t, db)
		setupRoleState(t, db, userID, roleID, model.RoleSourceMapped, channel)
		if err := db.Create(&model.UserRoleMapping{
			UserID: userID, RoleID: roleID, Channel: "provider:2", MatchedAt: roleSourceMatchedAt,
		}).Error; err != nil {
			t.Fatalf("建第二通道映射事實: %v", err)
		}
		err := db.Transaction(func(tx *gorm.DB) error {
			revoked, err := RevokeMappedRolesForChannel(tx, userID, channel, nil)
			if err != nil {
				return err
			}
			if len(revoked) != 0 {
				t.Errorf("撤除 %v, want 空：另一條通道仍命中該角色，關聯列不該被刪", revoked)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("重算: %v", err)
		}
		if got := readRoleState(t, db, userID, roleID); got != model.RoleSourceMapped {
			t.Errorf("來源 = %s, want %s：另一條通道的映射成分被誤刪", got, model.RoleSourceMapped)
		}
		if got := countMappingFacts(t, db, userID, roleID); got != 1 {
			t.Errorf("映射事實列數 = %d, want 1（只剩另一條通道那筆）", got)
		}
	})
}

// TestMappedDeleteEmptyMatchSet 本次一個群組都沒命中時，本通道的映射列全數刪除。
//
// 這一格單獨存在的理由：空集合是刪除語句的分支點。ORM 對空清單產生的
// `NOT IN (NULL)` 不報錯、也不匹配任何列，於是「全部撤除」靜默變成「什麼都沒做」
// ——被移出全部群組的人保留原有權限，而且沒有任何錯誤可查。
func TestMappedDeleteEmptyMatchSet(t *testing.T) {
	db := roleSourceDB(t)
	userID, roleID := seedRoleSourceSubject(t, db)
	second := &model.Role{Name: "transition-role-2"}
	if err := db.Create(second).Error; err != nil {
		t.Fatalf("建第二角色: %v", err)
	}
	const channel = "provider:7"
	setupRoleState(t, db, userID, roleID, model.RoleSourceMapped, channel)
	setupRoleState(t, db, userID, second.ID, model.RoleSourceBoth, channel)
	// 另一條通道的列不得受影響
	third := &model.Role{Name: "transition-role-3"}
	if err := db.Create(third).Error; err != nil {
		t.Fatalf("建第三角色: %v", err)
	}
	setupRoleState(t, db, userID, third.ID, model.RoleSourceMapped, "directory:1")

	var revoked []uint
	err := db.Transaction(func(tx *gorm.DB) error {
		var err error
		revoked, err = RevokeMappedRolesForChannel(tx, userID, channel, nil)
		return err
	})
	if err != nil {
		t.Fatalf("空命中集重算: %v", err)
	}

	sort.Slice(revoked, func(i, j int) bool { return revoked[i] < revoked[j] })
	if len(revoked) != 1 || revoked[0] != roleID {
		t.Fatalf("撤除 = %v, want [%d]：僅由映射賦予的那一個角色才會被刪", revoked, roleID)
	}
	if got := readRoleState(t, db, userID, roleID); got != "absent" {
		t.Errorf("僅映射的角色來源 = %s, want absent：空命中集沒有真的刪到列", got)
	}
	if got := readRoleState(t, db, userID, second.ID); got != model.RoleSourceManual {
		t.Errorf("並存的角色來源 = %s, want %s：管理者指派的那一半被連坐刪除",
			got, model.RoleSourceManual)
	}
	if got := readRoleState(t, db, userID, third.ID); got != model.RoleSourceMapped {
		t.Errorf("另一通道的角色來源 = %s, want %s：空命中集把別條通道的列一起刪了",
			got, model.RoleSourceMapped)
	}
	var left int64
	if err := db.Model(&model.UserRoleMapping{}).
		Where("user_id = ? AND channel = ?", userID, channel).Count(&left).Error; err != nil {
		t.Fatalf("數本通道殘留: %v", err)
	}
	if left != 0 {
		t.Errorf("本通道映射事實殘留 %d 列, want 0", left)
	}
}

// TestRoleSourceProjectionMatchesFacts 投影對帳：任一轉移之後，來源欄與兩個事實源一致。
//
// 判準（三者必須自洽）：
//
//	關聯列在不在  ↔  手動成分或映射成分至少有一個在
//	來源含 manual ↔  手動成分在（本測試以「這一格是不是由管理者動的」追蹤）
//	來源含 mapped ↔  映射事實表有對應列
//
// 投影錯了不會有任何 SQL 報錯——它只是讓本地管理員計數與列表查詢給出錯的答案。
func TestRoleSourceProjectionMatchesFacts(t *testing.T) {
	const chA = "directory:1"
	const chB = "provider:2"

	db := roleSourceDB(t)
	userID, roleID := seedRoleSourceSubject(t, db)

	// 事件序列刻意把四種轉移交錯排，讓每一步的起始態都不同
	steps := []struct {
		name string
		run  func(tx *gorm.DB) error
		// wantManual 這一步之後，手動成分應不應該在
		wantManual bool
	}{
		{"甲通道命中", func(tx *gorm.DB) error {
			_, err := GrantMappedRole(tx, userID, roleID, chA, roleSourceMatchedAt)
			return err
		}, false},
		{"管理者固定下來", func(tx *gorm.DB) error {
			_, err := AddManualRole(tx, userID, roleID)
			return err
		}, true},
		{"乙通道也命中", func(tx *gorm.DB) error {
			_, err := GrantMappedRole(tx, userID, roleID, chB, roleSourceMatchedAt)
			return err
		}, true},
		{"甲通道不再命中", func(tx *gorm.DB) error {
			_, err := RevokeMappedRolesForChannel(tx, userID, chA, nil)
			return err
		}, true},
		{"管理者移出手動集", func(tx *gorm.DB) error {
			_, err := RemoveManualRole(tx, userID, roleID)
			return err
		}, false},
		{"乙通道不再命中", func(tx *gorm.DB) error {
			_, err := RevokeMappedRolesForChannel(tx, userID, chB, nil)
			return err
		}, false},
		{"管理者重新指派", func(tx *gorm.DB) error {
			_, err := AddManualRole(tx, userID, roleID)
			return err
		}, true},
	}

	for _, step := range steps {
		if err := db.Transaction(step.run); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		source := readRoleState(t, db, userID, roleID)
		mappedFact := countMappingFacts(t, db, userID, roleID) > 0

		wantSource := "absent"
		switch {
		case step.wantManual && mappedFact:
			wantSource = model.RoleSourceBoth
		case step.wantManual:
			wantSource = model.RoleSourceManual
		case mappedFact:
			wantSource = model.RoleSourceMapped
		}
		if source != wantSource {
			t.Fatalf("%s 之後：來源 = %s, want %s（手動成分=%v、映射事實=%v）。"+
				"投影與事實源分岔，本地管理員計數與列表查詢會據此給出錯的答案",
				step.name, source, wantSource, step.wantManual, mappedFact)
		}
		if model.IsManualSource(source) != step.wantManual {
			t.Fatalf("%s 之後：IsManualSource(%s) = %v, want %v",
				step.name, source, model.IsManualSource(source), step.wantManual)
		}
	}
}
