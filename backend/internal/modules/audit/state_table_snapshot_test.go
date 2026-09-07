package audit

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 狀態表快照的釘定測試（role-assignment-integrity 第 1 組）。
//
// **本檔同時是登記清單守衛的事實源**：`stateSnapshotCases()` 每一項對應
// 一張登記表，守衛比對它與 `StateTableRegistry()` 的差集（雙向）。
// 因此本檔的案例表不是說明性的清單，而是**真的被下面三個測試 range 過**的
// 資料——自我宣告式的 `map[string]bool{"user_roles": true}` 會在快照測試被
// 刪掉之後繼續宣稱有覆蓋。

// stateSnapshotCase 一張登記狀態表的快照測試案例
type stateSnapshotCase struct {
	// table 登記清單內的表名
	table string
	// createDDL sqlite 上重建該表的最小結構
	createDDL string
	// insert 寫入一筆狀態列（快照的元素）
	insert func(db *gorm.DB, a, b uint64) error
	// snapshot 受測的快照函式（登記清單登記的就是它）
	snapshot func(ctx context.Context, tx *gorm.DB) (StateSnapshot, error)
}

// stateSnapshotCases 每張登記表一項。新增登記表未補本表即由守衛擋下
func stateSnapshotCases() []stateSnapshotCase {
	return []stateSnapshotCase{
		{
			table: StateTableUserRoles,
			createDDL: `CREATE TABLE user_roles (
				role_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
				PRIMARY KEY (role_id, user_id))`,
			insert: func(db *gorm.DB, userID, roleID uint64) error {
				return db.Exec("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)",
					userID, roleID).Error
			},
			snapshot: SnapshotUserRoles,
		},
	}
}

// stateSnapshotDB 每個案例一個乾淨的 sqlite
func stateSnapshotDB(t *testing.T, c stateSnapshotCase) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db handle: %v", err)
	}
	// `:memory:` 配連線池＝每條連線各自一個空 DB（本專案踩過的既有坑）
	sqlDB.SetMaxOpenConns(1)
	if err := db.Exec(c.createDDL).Error; err != nil {
		t.Fatalf("建表 %s: %v", c.table, err)
	}
	return db
}

// stateSnapshotBodyRe 快照本體的合法形狀：只有中括號、逗號與十進位數字。
//
// 這條正則就是「快照不含個資」的機械判準——比對「本體不含某個特定帳號名」
// 只能證明那一個字串不在裡面，而白名單式的形狀比對是**寫不進去**才對
var stateSnapshotBodyRe = regexp.MustCompile(`^\[(\[[0-9]+,[0-9]+\](,\[[0-9]+,[0-9]+\])*)?\]$`)

// TestStateSnapshotOrderIndependent 任意順序讀出得同一雜湊。
//
// 這是本機制的地基：兩台機器、兩個時點、兩種讀取順序，同一組角色指派
// 必得逐位元組相同的快照。不成立的話，每次封章都會產生一個「看起來像
// 被改過」的雜湊，而真正的竄改反而淹沒在雜訊裡
func TestStateSnapshotOrderIndependent(t *testing.T) {
	for _, c := range stateSnapshotCases() {
		t.Run(c.table, func(t *testing.T) {
			pairs := [][2]uint64{{7, 2}, {1, 3}, {1, 1}, {5, 9}}

			forward := stateSnapshotDB(t, c)
			for _, p := range pairs {
				if err := c.insert(forward, p[0], p[1]); err != nil {
					t.Fatalf("insert: %v", err)
				}
			}
			reverse := stateSnapshotDB(t, c)
			for i := len(pairs) - 1; i >= 0; i-- {
				if err := c.insert(reverse, pairs[i][0], pairs[i][1]); err != nil {
					t.Fatalf("insert: %v", err)
				}
			}

			a, err := c.snapshot(context.Background(), forward)
			if err != nil {
				t.Fatalf("snapshot: %v", err)
			}
			b, err := c.snapshot(context.Background(), reverse)
			if err != nil {
				t.Fatalf("snapshot: %v", err)
			}
			if string(a.Body) != string(b.Body) {
				t.Fatalf("快照本體因讀取順序而異：\n順向 %s\n逆向 %s", a.Body, b.Body)
			}
			if a.Hash != b.Hash {
				t.Fatalf("快照雜湊因讀取順序而異：%s ≠ %s", a.Hash, b.Hash)
			}
			if a.Count != int64(len(pairs)) {
				t.Errorf("筆數 = %d, want %d", a.Count, len(pairs))
			}
			if got := string(a.Body); got != "[[1,1],[1,3],[5,9],[7,2]]" {
				t.Errorf("canonical 本體 = %s, want 升冪排序後的固定編碼", got)
			}
			t.Logf("%s 快照＝%s hash=%s…", c.table, a.Body, a.Hash[:16])
		})
	}
}

// TestStateSnapshotOnePairDiffers 一筆之差即不同雜湊，且差集指得出是哪一筆
func TestStateSnapshotOnePairDiffers(t *testing.T) {
	for _, c := range stateSnapshotCases() {
		t.Run(c.table, func(t *testing.T) {
			base := [][2]uint64{{1, 1}, {2, 2}, {3, 3}}

			before := stateSnapshotDB(t, c)
			for _, p := range base {
				if err := c.insert(before, p[0], p[1]); err != nil {
					t.Fatalf("insert: %v", err)
				}
			}
			after := stateSnapshotDB(t, c)
			for _, p := range base {
				if err := c.insert(after, p[0], p[1]); err != nil {
					t.Fatalf("insert: %v", err)
				}
			}
			// 多一筆「4 號帳號掛上 1 號角色」＝提權的最小形態
			if err := c.insert(after, 4, 1); err != nil {
				t.Fatalf("insert: %v", err)
			}

			sBefore, err := c.snapshot(context.Background(), before)
			if err != nil {
				t.Fatalf("snapshot: %v", err)
			}
			sAfter, err := c.snapshot(context.Background(), after)
			if err != nil {
				t.Fatalf("snapshot: %v", err)
			}
			if sBefore.Hash == sAfter.Hash {
				t.Fatalf("一筆之差雜湊相同（%s）：快照對提權無偵測力", sBefore.Hash)
			}

			expected, err := DecodeRolePairs(sBefore.Body)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			actual, err := DecodeRolePairs(sAfter.Body)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			missing, extra := DiffRolePairs(expected, actual)
			if len(missing) != 0 {
				t.Errorf("缺少集合 = %v, want 空", missing)
			}
			if len(extra) != 1 || extra[0] != (RolePair{UserID: 4, RoleID: 1}) {
				t.Fatalf("多出集合 = %v, want [{4 1}]：差集指不出是哪一筆就只能說「有問題」", extra)
			}

			// 反向：少一筆時 missing 指得出來（撤銷被直寫抹掉的形態）
			missing, extra = DiffRolePairs(actual, expected)
			if len(extra) != 0 || len(missing) != 1 || missing[0] != (RolePair{UserID: 4, RoleID: 1}) {
				t.Fatalf("反向差集 missing=%v extra=%v, want missing=[{4 1}]", missing, extra)
			}
		})
	}
}

// TestStateSnapshotHasNoPersonalData 快照不含帳號名、電子郵件或任何個資。
//
// 快照會進檢查點、會離機轉發、會被稽核方拿去離線驗章——它是本系統
// **主動送出**的資料，形狀必須是白名單而非「檢查過沒有問題」
func TestStateSnapshotHasNoPersonalData(t *testing.T) {
	for _, c := range stateSnapshotCases() {
		t.Run(c.table, func(t *testing.T) {
			db := stateSnapshotDB(t, c)
			if err := db.Exec(`CREATE TABLE users (
				id INTEGER PRIMARY KEY, username TEXT, email TEXT)`).Error; err != nil {
				t.Fatalf("users: %v", err)
			}
			const secretName = "alice.chen"
			const secretMail = "alice.chen@example.com"
			if err := db.Exec("INSERT INTO users (id, username, email) VALUES (?, ?, ?)",
				1, secretName, secretMail).Error; err != nil {
				t.Fatalf("seed user: %v", err)
			}
			if err := c.insert(db, 1, 1); err != nil {
				t.Fatalf("insert: %v", err)
			}

			snap, err := c.snapshot(context.Background(), db)
			if err != nil {
				t.Fatalf("snapshot: %v", err)
			}
			body := string(snap.Body)
			if !stateSnapshotBodyRe.MatchString(body) {
				t.Fatalf("快照本體 %q 不符合白名單形狀（只允許中括號、逗號與十進位數字）", body)
			}
			for _, leaked := range []string{secretName, secretMail} {
				if strings.Contains(body, leaked) {
					t.Fatalf("快照本體洩漏 %q", leaked)
				}
			}
		})
	}
}

// TestStateSnapshotColumnCanonical 快照本體欄的組裝形狀與雜湊推導。
//
// 釘住兩件離線驗證者要重建的事：欄位是以表名為鍵的 JSON 物件（表名升冪），
// 且每張表的雜湊＝該表本體的長度前綴 SHA-256
func TestStateSnapshotColumnCanonical(t *testing.T) {
	c := stateSnapshotCases()[0]
	db := stateSnapshotDB(t, c)
	for _, p := range [][2]uint64{{2, 1}, {1, 2}} {
		if err := c.insert(db, p[0], p[1]); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	column, snaps, err := SnapshotStateTables(context.Background(), db)
	if err != nil {
		t.Fatalf("SnapshotStateTables: %v", err)
	}
	want := `{"user_roles":[[1,2],[2,1]]}`
	if column != want {
		t.Fatalf("快照欄 = %s, want %s", column, want)
	}
	if len(snaps) != 1 || snaps[0].Table != StateTableUserRoles {
		t.Fatalf("快照數 = %d（%v）, want 只有 user_roles", len(snaps), snaps)
	}
	tables, err := DecodeStateSnapshotColumn(column)
	if err != nil {
		t.Fatalf("decode column: %v", err)
	}
	if got := stateHash([]byte(tables[StateTableUserRoles])); got != snaps[0].Hash {
		t.Fatalf("由欄位重算的雜湊 %s ≠ 快照雜湊 %s：離線驗證者重建不出同一組位元組", got, snaps[0].Hash)
	}
	// 長度前綴：不同長度的本體不得因串接而碰撞
	if stateHash([]byte("[[1,2]]")) == stateHash([]byte("[[1,2]] ")) {
		t.Fatal("長度前綴失效：不同本體得到同一雜湊")
	}
}
