package database

import (
	"fmt"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/testgate"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func openObservationTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`CREATE TABLE users (id integer primary key, group_snapshot_channel text, group_snapshot_at datetime)`,
		`CREATE TABLE user_role_mapping_rule_supports (user_id integer, role_id integer, channel text, rule_id integer)`,
		`CREATE TABLE user_group_mapping_rule_supports (user_id integer, user_group_id integer, channel text, rule_id integer)`,
		mappingObservationTimesDDL()[0], // 建表；外鍵約束的 ALTER 為 PostgreSQL 語法
	} {
		if err := db.Exec(stmt).Error; err != nil {
			t.Fatalf("%.60s: %v", stmt, err)
		}
	}
	return db
}

func seedUser(t *testing.T, db *gorm.DB, id int, channel any, at any) {
	t.Helper()
	if err := db.Exec(`INSERT INTO users(id,group_snapshot_channel,group_snapshot_at) VALUES (?,?,?)`, id, channel, at).Error; err != nil {
		t.Fatal(err)
	}
}

func seedRoleSupport(t *testing.T, db *gorm.DB, uid int, channel string) {
	t.Helper()
	if err := db.Exec(`INSERT INTO user_role_mapping_rule_supports VALUES (?,1,?,1)`, uid, channel).Error; err != nil {
		t.Fatal(err)
	}
}

func seedGroupSupport(t *testing.T, db *gorm.DB, uid int, channel string) {
	t.Helper()
	if err := db.Exec(`INSERT INTO user_group_mapping_rule_supports VALUES (?,1,?,1)`, uid, channel).Error; err != nil {
		t.Fatal(err)
	}
}

type obsRow struct {
	UserID  int
	Channel string
	At      string
}

// parseObsTime 讀回 SQLite 以文字存放的時間（MAX 結果不帶欄位型別）。
func parseObsTime(t *testing.T, s string) time.Time {
	t.Helper()
	for _, layout := range []string{"2006-01-02 15:04:05.999999999-07:00", "2006-01-02 15:04:05.999999999 -0700 MST", time.RFC3339Nano, "2006-01-02 15:04:05"} {
		if v, err := time.Parse(layout, s); err == nil {
			return v.UTC()
		}
	}
	t.Fatalf("無法解析時間 %q", s)
	return time.Time{}
}

func readObs(t *testing.T, db *gorm.DB) map[string]time.Time {
	t.Helper()
	var rows []obsRow
	if err := db.Raw(`SELECT user_id, channel, last_known_at AS at FROM user_channel_observations`).Scan(&rows).Error; err != nil {
		t.Fatal(err)
	}
	out := map[string]time.Time{}
	for _, r := range rows {
		out[string(rune('0'+r.UserID))+"|"+r.Channel] = parseObsTime(t, r.At)
	}
	return out
}

// TestMappingObservationBackfill 回填取「既有快照時間」與「升級時刻」較晚者，讓有界重新驗證的時限從升級起算。
func TestMappingObservationBackfill(t *testing.T) {
	upgrade := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	older := upgrade.Add(-48 * time.Hour)
	newer := upgrade.Add(2 * time.Hour)

	t.Run("a 有支持且無快照 補列為升級時刻", func(t *testing.T) {
		db := openObservationTestDB(t)
		seedUser(t, db, 1, nil, nil)
		seedRoleSupport(t, db, 1, "provider:2")
		if n, err := backfillChannelObservations(db, upgrade); err != nil || n != 1 {
			t.Fatalf("n=%d err=%v", n, err)
		}
		if got := readObs(t, db)["1|provider:2"]; !got.Equal(upgrade) {
			t.Fatalf("補列時間 = %v，應為升級時刻 %v", got, upgrade)
		}
	})

	t.Run("b 快照較舊 取升級時刻；快照較新 取快照", func(t *testing.T) {
		db := openObservationTestDB(t)
		seedUser(t, db, 1, "provider:2", older)
		seedRoleSupport(t, db, 1, "provider:2")
		seedUser(t, db, 2, "directory:1", newer)
		seedGroupSupport(t, db, 2, "directory:1")
		if _, err := backfillChannelObservations(db, upgrade); err != nil {
			t.Fatal(err)
		}
		got := readObs(t, db)
		if !got["1|provider:2"].Equal(upgrade) {
			t.Fatalf("快照較舊應取升級時刻，得 %v", got["1|provider:2"])
		}
		if !got["2|directory:1"].Equal(newer) {
			t.Fatalf("快照較新應取快照，得 %v", got["2|directory:1"])
		}
	})

	t.Run("c 快照通道與支持通道不同 支持的通道補列", func(t *testing.T) {
		db := openObservationTestDB(t)
		seedUser(t, db, 1, "provider:2", older)
		seedRoleSupport(t, db, 1, "directory:1")
		if _, err := backfillChannelObservations(db, upgrade); err != nil {
			t.Fatal(err)
		}
		got := readObs(t, db)
		if !got["1|directory:1"].Equal(upgrade) {
			t.Fatalf("支持的通道應補列為升級時刻，得 %v", got["1|directory:1"])
		}
		if !got["1|provider:2"].Equal(older) {
			t.Fatalf("快照通道照舊回填快照時間，得 %v", got["1|provider:2"])
		}
	})

	t.Run("d 無支持且無快照 不補列", func(t *testing.T) {
		db := openObservationTestDB(t)
		seedUser(t, db, 1, nil, nil)
		seedUser(t, db, 2, "", older)
		seedUser(t, db, 3, "provider:2", nil)
		if n, err := backfillChannelObservations(db, upgrade); err != nil || n != 0 {
			t.Fatalf("n=%d err=%v，應為 0 列", n, err)
		}
	})

	t.Run("e 重跑不覆蓋較新值且列數不變", func(t *testing.T) {
		db := openObservationTestDB(t)
		seedUser(t, db, 1, "provider:2", older)
		seedRoleSupport(t, db, 1, "provider:2")
		if _, err := backfillChannelObservations(db, upgrade); err != nil {
			t.Fatal(err)
		}
		if err := db.Exec(`UPDATE user_channel_observations SET last_known_at = ? WHERE user_id = 1`, newer).Error; err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			if n, err := backfillChannelObservations(db, upgrade.Add(24*time.Hour)); err != nil || n != 0 {
				t.Fatalf("重跑 #%d n=%d err=%v，應為 0 列", i+1, n, err)
			}
		}
		got := readObs(t, db)
		if len(got) != 1 || !got["1|provider:2"].Equal(newer) {
			t.Fatalf("較新的觀測被重跑覆蓋或列數改變: %+v", got)
		}
	})

	t.Run("f 只有使用者群組支持 快照較舊或無快照 補列為升級時刻", func(t *testing.T) {
		db := openObservationTestDB(t)
		seedUser(t, db, 1, "provider:2", older) // 快照較舊，同通道只有使用者群組支持
		seedGroupSupport(t, db, 1, "provider:2")
		seedUser(t, db, 2, nil, nil) // 無快照，只有使用者群組支持
		seedGroupSupport(t, db, 2, "directory:1")
		if n, err := backfillChannelObservations(db, upgrade); err != nil || n != 2 {
			t.Fatalf("n=%d err=%v，應為 2 列", n, err)
		}
		got := readObs(t, db)
		if !got["1|provider:2"].Equal(upgrade) {
			t.Fatalf("只有群組支持、快照較舊應取升級時刻，得 %v", got["1|provider:2"])
		}
		if !got["2|directory:1"].Equal(upgrade) {
			t.Fatalf("只有群組支持、無快照應補列為升級時刻，得 %v", got["2|directory:1"])
		}
	})

	t.Run("版本已登記且 Down 不提供", func(t *testing.T) {
		found := false
		for _, v := range MigrationVersions() {
			if v == "20261020_mapping_observation_times" {
				found = true
			}
		}
		if !found {
			t.Fatal("migration 版本未登記")
		}
		if rollbackMappingObservationTimes(nil) == nil {
			t.Fatal("本 migration 不提供回滾")
		}
	})
}

// TestMappingObservationBackfillPostgres 回填語句在真的 postgres 上取較晚者、遇既有列不覆蓋。
// （gating：未設 TEST_PG_DSN 即 skip；REQUIRE_INTEGRATION=1 時 skip 轉 fail）
func TestMappingObservationBackfillPostgres(t *testing.T) {
	db := freshSchema(t, testgate.Value(t, testgate.EnvPGDSN),
		fmt.Sprintf("obs_backfill_%d", time.Now().UnixNano()))
	for _, stmt := range []string{
		`CREATE TABLE users (id bigint PRIMARY KEY, group_snapshot_channel varchar(64), group_snapshot_at timestamptz)`,
		`CREATE TABLE user_role_mapping_rule_supports (user_id bigint, role_id bigint, channel varchar(64), rule_id bigint)`,
		`CREATE TABLE user_group_mapping_rule_supports (user_id bigint, user_group_id bigint, channel varchar(64), rule_id bigint)`,
	} {
		if err := db.Exec(stmt).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, stmt := range mappingObservationTimesDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			t.Fatal(err)
		}
	}
	upgrade := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	older, newer := upgrade.Add(-48*time.Hour), upgrade.Add(2*time.Hour)
	seedUser(t, db, 1, "provider:2", older) // 快照較舊、有支持
	seedRoleSupport(t, db, 1, "provider:2")
	seedUser(t, db, 2, "directory:1", newer) // 快照較新、有支持
	seedGroupSupport(t, db, 2, "directory:1")
	seedUser(t, db, 3, "provider:2", older) // 支持在另一條通道
	seedRoleSupport(t, db, 3, "directory:1")
	seedUser(t, db, 4, nil, nil)            // 無支持無快照
	seedUser(t, db, 5, "provider:2", older) // 快照較舊、只有使用者群組支持
	seedGroupSupport(t, db, 5, "provider:2")
	seedUser(t, db, 6, nil, nil) // 無快照、只有使用者群組支持
	seedGroupSupport(t, db, 6, "directory:1")
	if n, err := backfillChannelObservations(db, upgrade); err != nil || n != 6 {
		t.Fatalf("n=%d err=%v，應為 6 列", n, err)
	}
	var rows []struct {
		UserID  int
		Channel string
		At      time.Time
	}
	if err := db.Raw(`SELECT user_id, channel, last_known_at AS at FROM user_channel_observations`).Scan(&rows).Error; err != nil {
		t.Fatal(err)
	}
	want := map[string]time.Time{"1|provider:2": upgrade, "2|directory:1": newer, "3|directory:1": upgrade, "3|provider:2": older,
		"5|provider:2": upgrade, "6|directory:1": upgrade}
	if len(rows) != len(want) {
		t.Fatalf("列數 %d，應為 %d: %+v", len(rows), len(want), rows)
	}
	for _, r := range rows {
		if w, ok := want[fmt.Sprintf("%d|%s", r.UserID, r.Channel)]; !ok || !r.At.Equal(w) {
			t.Fatalf("%d|%s = %v，應為 %v", r.UserID, r.Channel, r.At, w)
		}
	}
	if n, err := backfillChannelObservations(db, upgrade.Add(24*time.Hour)); err != nil || n != 0 {
		t.Fatalf("重跑 n=%d err=%v，應為 0 列", n, err)
	}
}
