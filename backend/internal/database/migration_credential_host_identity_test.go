package database

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/testgate"
)

// sqlCapture 記錄經由它執行的全部 SQL，供「不讀寫秘密欄位」的斷言。
type sqlCapture struct {
	mu    sync.Mutex
	stmts []string
}

func (c *sqlCapture) LogMode(logger.LogLevel) logger.Interface { return c }
func (c *sqlCapture) Info(context.Context, string, ...any)     {}
func (c *sqlCapture) Warn(context.Context, string, ...any)     {}
func (c *sqlCapture) Error(context.Context, string, ...any)    {}
func (c *sqlCapture) Trace(_ context.Context, _ time.Time, fc func() (string, int64), _ error) {
	sql, _ := fc()
	c.mu.Lock()
	c.stmts = append(c.stmts, sql)
	c.mu.Unlock()
}

func (c *sqlCapture) assertNoSecretColumns(t *testing.T) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.stmts) == 0 {
		t.Fatal("攔截器沒有記錄到任何語句")
	}
	for _, s := range c.stmts {
		low := strings.ToLower(s)
		for _, col := range []string{"password_enc", "private_key_enc", "public_key"} {
			if strings.Contains(low, col) {
				t.Errorf("升級語句不應讀寫 %s: %.120s", col, s)
			}
		}
	}
}

type hiFixture struct {
	// 預期派送標記非空的成員帳號與必為空者
	marked, unmarked []int
	// 非 legacy 的成員帳號（不得被標記）
	nonLegacy []int
}

// seedHostIdentityLegacyFixture 以 INSERT 寫入升級前形態的資料：只用升級前就存在的欄位，
// 所以同時適用於「新欄尚未建立的 PG」與「模型建出新欄的 SQLite」（新欄靠預設值成為 legacy）。
// 非 legacy 的控制列要在新欄存在之後由 addNonLegacyControl 寫入。
func seedHostIdentityLegacyFixture(t *testing.T, db *gorm.DB) hiFixture {
	t.Helper()
	t0 := time.Now().UTC().Truncate(time.Second).Add(-72 * time.Hour)
	exec := func(q string, args ...any) {
		t.Helper()
		if err := db.Exec(q, args...).Error; err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	for _, r := range []struct {
		id         int
		mode       string
		credential int
	}{{1, "group", 10}, {2, "split", 20}} {
		exec(`INSERT INTO credential_rotations(id, created_at, updated_at, credential_id, epoch, mode, status, started_at) VALUES(?,?,?,?,1,?,'running',?)`,
			r.id, t0, t0, r.credential, r.mode, t0)
	}
	member := func(rotation, account, credential int, state string, target any) {
		t.Helper()
		exec(`INSERT INTO credential_rotation_members(created_at, updated_at, rotation_id, account_id, credential_id, asset_id, state, target_version_id) VALUES(?,?,?,?,?,?,?,?)`,
			t0, t0, rotation, account, credential, account, state, target)
	}
	candidate := func(account int) {
		t.Helper()
		exec(`INSERT INTO change_secret_candidates(created_at, updated_at, account_id, asset_id, secret_type) VALUES(?,?,?,?,'password')`, t0, t0, account, account)
	}
	record := func(account, credential, target int, status string, at time.Time) {
		t.Helper()
		exec(`INSERT INTO change_secret_records(plan_id, asset_id, account_id, credential_id, target_version_id, status, executed_at) VALUES(0,?,?,?,?,?,?)`,
			account, account, credential, target, status, at)
	}

	// 整組：目標版本 500
	member(1, 101, 10, "changed_unverified", 500)
	member(1, 102, 10, "changing", 500)
	member(1, 103, 10, "applied", 500)
	member(1, 104, 10, "terminal_failed", 500)
	candidate(104) // 有候選列
	member(1, 105, 10, "terminal_failed", 500)
	record(105, 10, 500, "unverified", t0.Add(time.Hour)) // 同帳號同目標版本的 unverified
	member(1, 106, 10, "terminal_failed", 500)
	record(106, 10, 500, "success", t0.Add(time.Hour)) // 成員狀態被覆寫為 terminal_failed 的 success 紀錄
	member(1, 107, 10, "terminal_failed", 500)
	record(107, 10, 500, "failed", t0.Add(time.Hour)) // 只有 failed 且無候選列
	member(1, 108, 10, "queued", 500)
	// 拆分：目標版本為空，每個成員都有起始交易建好的候選列
	member(2, 201, 20, "changed_unverified", nil)
	member(2, 202, 20, "terminal_failed", nil)
	member(2, 203, 20, "queued", nil)
	member(2, 204, 20, "retry_wait", nil)
	member(2, 205, 20, "terminal_failed", nil)
	for _, a := range []int{201, 202, 203, 204, 205} {
		candidate(a)
	}
	record(202, 20, 0, "unverified", t0.Add(time.Hour))     // 本輪開始之後
	record(204, 20, 0, "failed", t0.Add(time.Hour))         // 乾淨失敗
	record(205, 20, 0, "unverified", t0.Add(-24*time.Hour)) // 同一憑證前一輪

	return hiFixture{
		marked:   []int{101, 102, 103, 104, 105, 106, 201, 202},
		unmarked: []int{107, 108, 203, 204, 205},
	}
}

// addNonLegacyControl 在正式新增欄之後才寫入的控制列：新版建立的 pending 成員，
// 狀態雖為 changed_unverified 也不得被資料步驟標記。舊 schema 沒有該欄，所以不能在升級前寫。
func addNonLegacyControl(t *testing.T, db *gorm.DB, fx *hiFixture) {
	t.Helper()
	t0 := time.Now().UTC().Truncate(time.Second).Add(-72 * time.Hour)
	if err := db.Exec(`INSERT INTO credential_rotation_members(created_at, updated_at, rotation_id, account_id, credential_id, asset_id, state, target_version_id, host_key_binding) VALUES(?,?,1,109,10,109,'changed_unverified',500,'pending')`,
		t0, t0).Error; err != nil {
		t.Fatal(err)
	}
	fx.nonLegacy = append(fx.nonLegacy, 109)
}

func readSecretSent(t *testing.T, db *gorm.DB) map[int]*time.Time {
	t.Helper()
	var rows []struct {
		AccountID    int
		SecretSentAt *time.Time
	}
	if err := db.Raw(`SELECT account_id, secret_sent_at FROM credential_rotation_members ORDER BY account_id`).Scan(&rows).Error; err != nil {
		t.Fatal(err)
	}
	out := map[int]*time.Time{}
	for _, r := range rows {
		out[r.AccountID] = r.SecretSentAt
	}
	return out
}

func checkSecretSent(t *testing.T, db *gorm.DB, fx hiFixture) map[int]*time.Time {
	t.Helper()
	got := readSecretSent(t, db)
	for _, a := range fx.marked {
		if got[a] == nil {
			t.Errorf("帳號 %d 應被標記派送標記", a)
		}
	}
	for _, a := range append(append([]int{}, fx.unmarked...), fx.nonLegacy...) {
		if got[a] != nil {
			t.Errorf("帳號 %d 不應被標記", a)
		}
	}
	return got
}

// checkLegacyUntouched 升級後既有候選與成員仍是 legacy、快照欄全為零值、停止通知去重鍵為 NULL。
func checkLegacyUntouched(t *testing.T, db *gorm.DB, wantMemberNonLegacy int64) {
	t.Helper()
	for _, tb := range []string{"change_secret_candidates", "credential_rotation_members"} {
		var bad int64
		if err := db.Raw(`SELECT count(*) FROM ` + tb + ` WHERE host_key_transport <> '' OR host_key_record_id <> 0 OR host_key_algorithm <> ''
			OR host_key_fingerprint <> '' OR host_key_generation <> 0 OR host_key_bound_at IS NOT NULL OR host_identity_alerted_key IS NOT NULL`).Scan(&bad).Error; err != nil || bad != 0 {
			t.Errorf("%s 快照欄應全為零值: bad=%d err=%v", tb, bad, err)
		}
		var nonLegacy int64
		if err := db.Raw(`SELECT count(*) FROM ` + tb + ` WHERE host_key_binding <> 'legacy'`).Scan(&nonLegacy).Error; err != nil {
			t.Fatal(err)
		}
		want := int64(0)
		if tb == "credential_rotation_members" {
			want = wantMemberNonLegacy
		}
		if nonLegacy != want {
			t.Errorf("%s 非 legacy 列數 %d，應為 %d", tb, nonLegacy, want)
		}
	}
}

func triggerCount(t *testing.T, db *gorm.DB, pg bool) int64 {
	t.Helper()
	var n int64
	q := `SELECT count(*) FROM sqlite_master WHERE tbl_name='asset_host_keys' AND type NOT IN ('table','index')`
	if pg {
		q = `SELECT count(*) FROM pg_trigger WHERE tgrelid='asset_host_keys'::regclass AND NOT tgisinternal`
	}
	if err := db.Raw(q).Scan(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

// generationOnlyFromApplication 世代只由應用程式的欄位運算推進；不經服務的改寫不推進（斷言它以免被誤當保證）。
func generationOnlyFromApplication(t *testing.T, db *gorm.DB, pg bool) {
	t.Helper()
	now := time.Now().UTC()
	if err := db.Exec(`INSERT INTO asset_host_keys(asset_id, algorithm, fingerprint, public_key, created_at, updated_at) VALUES(7001,'ssh-ed25519','SHA256:a','pkA',?,?)`, now, now).Error; err != nil {
		t.Fatal(err)
	}
	gen := func() int64 {
		var g int64
		if err := db.Raw(`SELECT trust_generation FROM asset_host_keys WHERE asset_id = 7001`).Scan(&g).Error; err != nil {
			t.Fatal(err)
		}
		return g
	}
	if g := gen(); g != 1 {
		t.Fatalf("新列世代 = %d，應為 1", g)
	}
	if n := triggerCount(t, db, pg); n != 0 {
		t.Fatalf("asset_host_keys 不應有任何觸發器: %d", n)
	}
	if err := db.Exec(`UPDATE asset_host_keys SET trust_generation = trust_generation + 1, fingerprint = ?, algorithm = ?, public_key = ? WHERE asset_id = 7001`,
		"SHA256:b", "ssh-rsa", "pkB").Error; err != nil {
		t.Fatal(err)
	}
	if g := gen(); g != 2 {
		t.Fatalf("應用程式欄位運算後世代 = %d，應恰 +1 為 2", g)
	}
	// 不經新版服務的改寫：三步後世代不動
	for _, q := range []string{
		`UPDATE asset_host_keys SET reset_pending = true WHERE asset_id = 7001`,
		`UPDATE asset_host_keys SET reset_pending = false WHERE asset_id = 7001`,
		`UPDATE asset_host_keys SET fingerprint = 'SHA256:c', algorithm = 'ssh-ed25519', public_key = 'pkC' WHERE asset_id = 7001`,
	} {
		if err := db.Exec(q).Error; err != nil {
			t.Fatal(err)
		}
	}
	if g := gen(); g != 2 {
		t.Fatalf("不經服務的改寫不應推進世代，實為 %d", g)
	}
	if n := triggerCount(t, db, pg); n != 0 {
		t.Fatalf("改寫之後仍不應有觸發器: %d", n)
	}
	if err := db.Exec(`DELETE FROM asset_host_keys WHERE asset_id = 7001`).Error; err != nil {
		t.Fatal(err)
	}

	// 另一筆初始世代為 1 的列：不經服務的三步改寫後仍為 1（直接改寫不會推進世代，不是保證）
	if err := db.Exec(`INSERT INTO asset_host_keys(asset_id, algorithm, fingerprint, public_key, created_at, updated_at) VALUES(7002,'ssh-ed25519','SHA256:d','pkD',?,?)`, now, now).Error; err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`UPDATE asset_host_keys SET reset_pending = true WHERE asset_id = 7002`,
		`UPDATE asset_host_keys SET reset_pending = false WHERE asset_id = 7002`,
		`UPDATE asset_host_keys SET fingerprint = 'SHA256:e', algorithm = 'ssh-rsa', public_key = 'pkE' WHERE asset_id = 7002`,
	} {
		if err := db.Exec(q).Error; err != nil {
			t.Fatal(err)
		}
	}
	var g1 int64
	if err := db.Raw(`SELECT trust_generation FROM asset_host_keys WHERE asset_id = 7002`).Scan(&g1).Error; err != nil {
		t.Fatal(err)
	}
	if g1 != 1 {
		t.Fatalf("初始世代為 1 的列經三步直接改寫後應仍為 1，實為 %d", g1)
	}
	if err := db.Exec(`DELETE FROM asset_host_keys WHERE asset_id = 7002`).Error; err != nil {
		t.Fatal(err)
	}
}

// TestHostKeyTrustGenerationMigration 憑證主機身分增量：既有列不動、legacy 成員保守標記（整組與拆分各一組）、
// 世代只由應用程式路徑推進（不建觸發器）、重跑不改內容、升級過程不碰秘密欄位。
// sqlite 子測試以模型建出新欄驗資料步驟與世代規則；postgres 子測試走真 DDL（PG-gated）。
func TestHostKeyTrustGenerationMigration(t *testing.T) {
	t.Run("DDL 宣告與登記", func(t *testing.T) {
		found := false
		for _, v := range MigrationVersions() {
			if v == "20261027_credential_host_identity" {
				found = true
			}
		}
		if !found {
			t.Fatal("migration 版本未登記")
		}
		if rollbackCredentialHostIdentity(nil) == nil {
			t.Fatal("本 migration 不提供回滾")
		}
		joined := strings.ToLower(strings.Join(credentialHostIdentityDDL(), "\n"))
		if strings.Contains(joined, "trigger") || strings.Contains(joined, "foreign key") || strings.Contains(joined, "references") {
			t.Fatal("DDL 不得含觸發器或外鍵")
		}
		for _, col := range []string{"trust_generation", "host_key_binding", "host_key_transport", "host_key_record_id",
			"host_key_algorithm", "host_key_fingerprint", "host_key_generation", "host_key_bound_at", "host_identity_alerted_key", "secret_sent_at"} {
			if !strings.Contains(joined, col) {
				t.Errorf("DDL 缺欄位 %s", col)
			}
		}
	})

	t.Run("sqlite：legacy 保守標記、世代只由應用程式推進、重跑不改內容", func(t *testing.T) {
		db := newAuthzSQLite(t)
		if err := db.AutoMigrate(&model.CredentialRotation{}, &model.CredentialRotationMember{}, &model.ChangeSecretRecord{},
			&model.ChangeSecretCandidate{}, &model.AssetHostKey{}, &model.CredentialHostIdentityConfirmation{}); err != nil {
			t.Fatal(err)
		}
		fx := seedHostIdentityLegacyFixture(t, db)
		cap := &sqlCapture{}
		capDB := db.Session(&gorm.Session{Logger: cap})
		if err := backfillMemberSecretSent(capDB, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		first := checkSecretSent(t, db, fx)
		checkLegacyUntouched(t, db, 0)
		addNonLegacyControl(t, db, &fx)
		firstDump := dumpTables(t, db, "credential_rotation_members", "change_secret_candidates", "credential_host_identity_confirmations")
		time.Sleep(20 * time.Millisecond)
		if err := backfillMemberSecretSent(capDB, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		if err := backfillMemberSecretSent(capDB, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		if dumpTables(t, db, "credential_rotation_members", "change_secret_candidates", "credential_host_identity_confirmations") != firstDump {
			t.Fatal("重跑改動了成員、候選或承接表的內容")
		}
		second := checkSecretSent(t, db, fx)
		checkLegacyUntouched(t, db, int64(len(fx.nonLegacy)))
		for a, v := range first {
			if v != nil && (second[a] == nil || !second[a].Equal(*v)) {
				t.Errorf("帳號 %d 的派送標記被覆寫", a)
			}
		}
		cap.assertNoSecretColumns(t)
		generationOnlyFromApplication(t, db, false)

		// 新建列與 legacy 可區分：未明寫者得預設 legacy，明寫 pending 者為 pending
		now := time.Now()
		if err := db.Create(&model.ChangeSecretCandidate{AccountID: 9001, AssetID: 1, SecretType: "password", HostKeyBinding: model.HostKeyBindingPending, NextAttemptAt: now}).Error; err != nil {
			t.Fatal(err)
		}
		if err := db.Create(&model.ChangeSecretCandidate{AccountID: 9002, AssetID: 1, SecretType: "password", NextAttemptAt: now}).Error; err != nil {
			t.Fatal(err)
		}
		var binding []string
		if err := db.Raw(`SELECT host_key_binding FROM change_secret_candidates WHERE account_id IN (9001, 9002) ORDER BY account_id`).Scan(&binding).Error; err != nil {
			t.Fatal(err)
		}
		if strings.Join(binding, ",") != "pending,legacy" {
			t.Fatalf("host_key_binding = %v", binding)
		}
	})

	// 子測試名固定為 postgres，供逐名收證；內容：真 DDL 升級、世代只由應用程式路徑推進、重跑。
	t.Run("postgres", func(t *testing.T) {
		dsn := testgate.Value(t, testgate.EnvPGDSN)
		fmt.Println("EVIDENCE dialect=postgres")
		t.Log("EVIDENCE dialect=postgres")
		db := freshSchema(t, dsn, fmt.Sprintf("hk_gen_%d", time.Now().UnixNano()))
		if db.Dialector.Name() != "postgres" {
			t.Fatalf("方言 = %s", db.Dialector.Name())
		}
		idx := -1
		for i, m := range migrations {
			if m.Version == "20261027_credential_host_identity" {
				idx = i
			}
		}
		if idx < 0 {
			t.Fatal("找不到本增量")
		}
		// 修正前 schema：本增量之前的全部 migration
		for _, m := range migrations[:idx] {
			if err := m.Up(db); err != nil {
				t.Fatal(m.Version, err)
			}
		}
		fx := seedHostIdentityLegacyFixture(t, db)
		now := time.Now().UTC()
		for i := 1; i <= 3; i++ {
			if err := db.Exec(`INSERT INTO asset_host_keys(asset_id, algorithm, fingerprint, public_key, host, port, reset_pending, created_at, updated_at) VALUES(?, 'ssh-ed25519', ?, 'pk', '10.0.0.1', 22, ?, ?, ?)`,
				i, fmt.Sprintf("SHA256:fp%d", i), i == 2, now, now).Error; err != nil {
				t.Fatal(err)
			}
		}
		const hostKeyCols = `id, asset_id, algorithm, fingerprint, public_key, host, port, reset_pending, created_at, updated_at`
		dumpKeys := func() string {
			var rows []map[string]any
			if err := db.Raw(`SELECT ` + hostKeyCols + ` FROM asset_host_keys ORDER BY id`).Scan(&rows).Error; err != nil {
				t.Fatal(err)
			}
			return fmt.Sprint(rows)
		}
		before := dumpKeys()

		cap := &sqlCapture{}
		if err := migrations[idx].Up(db.Session(&gorm.Session{Logger: cap})); err != nil {
			t.Fatal(err)
		}
		cap.assertNoSecretColumns(t)
		if after := dumpKeys(); after != before {
			t.Fatalf("升級改動了既有主機金鑰列\nbefore=%s\nafter=%s", before, after)
		}
		var gens []int64
		if err := db.Raw(`SELECT trust_generation FROM asset_host_keys ORDER BY id`).Scan(&gens).Error; err != nil || len(gens) != 3 {
			t.Fatalf("世代讀取失敗: %v err=%v", gens, err)
		}
		for _, g := range gens {
			if g != 1 {
				t.Fatalf("既有列世代應為 1: %v", gens)
			}
		}
		first := checkSecretSent(t, db, fx)
		checkLegacyUntouched(t, db, 0)

		// 新表：無外鍵、兩個索引、0 列
		var n int64
		if err := db.Raw(`SELECT count(*) FROM credential_host_identity_confirmations`).Scan(&n).Error; err != nil || n != 0 {
			t.Fatalf("承接表應為 0 列: n=%d err=%v", n, err)
		}
		if err := db.Raw(`SELECT count(*) FROM pg_constraint WHERE contype = 'f' AND (conrelid = 'credential_host_identity_confirmations'::regclass OR confrelid = 'credential_host_identity_confirmations'::regclass)`).Scan(&n).Error; err != nil || n != 0 {
			t.Fatalf("承接表不得有外鍵: n=%d err=%v", n, err)
		}
		var idxNames []string
		if err := db.Raw(`SELECT indexname FROM pg_indexes WHERE tablename = 'credential_host_identity_confirmations' AND schemaname = current_schema() AND indexname <> 'credential_host_identity_confirmations_pkey' ORDER BY indexname`).Scan(&idxNames).Error; err != nil {
			t.Fatal(err)
		}
		sort.Strings(idxNames)
		if strings.Join(idxNames, ",") != "idx_credential_host_identity_confirmations_consumed,idx_credential_host_identity_confirmations_job" {
			t.Fatalf("索引 = %v", idxNames)
		}

		generationOnlyFromApplication(t, db, true)

		// 資料步驟重跑：不覆寫第一次寫入的時刻、不標記非 legacy 列
		addNonLegacyControl(t, db, &fx)
		time.Sleep(20 * time.Millisecond)
		if err := backfillMemberSecretSent(db, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		second := checkSecretSent(t, db, fx)
		checkLegacyUntouched(t, db, int64(len(fx.nonLegacy)))
		for a, v := range first {
			if v != nil && (second[a] == nil || !second[a].Equal(*v)) {
				t.Errorf("帳號 %d 的派送標記被覆寫", a)
			}
		}
		if err := db.Raw(`SELECT count(*) FROM credential_host_identity_confirmations`).Scan(&n).Error; err != nil || n != 0 {
			t.Fatalf("重跑後承接表應仍為 0 列: n=%d err=%v", n, err)
		}

		// 全新庫走 RunMigrations 兩次：內容相同、仍無觸發器、世代預設 1
		run := freshSchema(t, dsn, fmt.Sprintf("hk_gen_run_%d", time.Now().UnixNano()))
		prev := DB
		DB = run
		t.Cleanup(func() { DB = prev })
		if err := RunMigrations(); err != nil {
			t.Fatalf("第一次 RunMigrations: %v", err)
		}
		firstRun := dumpTables(t, run, "schema_migrations", "credential_host_identity_confirmations", "asset_host_keys")
		if err := RunMigrations(); err != nil {
			t.Fatalf("第二次 RunMigrations: %v", err)
		}
		if secondRun := dumpTables(t, run, "schema_migrations", "credential_host_identity_confirmations", "asset_host_keys"); secondRun != firstRun {
			t.Fatal("第二次 RunMigrations 改動了內容")
		}
		if n := triggerCount(t, run, true); n != 0 {
			t.Fatalf("RunMigrations 後 asset_host_keys 不應有觸發器: %d", n)
		}
	})
}
