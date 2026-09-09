package policy

import (
	"errors"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func newPolicyGroupRepo(t *testing.T) (*PolicyGroupRepository, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	// :memory: 連線池陷阱：多條連線各自是一個空庫，寫在 A 讀在 B 會偶發查無資料
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })

	if err := db.AutoMigrate(&model.PolicyGroup{}, &model.PolicyClause{},
		&model.PolicyClauseControl{}, &model.PolicyClauseAnnotation{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewPolicyGroupRepository(db), db
}

// requireGroupErrCode 斷言錯誤是政策組的具名錯誤且碼相符。
func requireGroupErrCode(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("預期回錯誤碼 %s，卻成功了", want)
	}
	var ge *PolicyGroupError
	if !errors.As(err, &ge) {
		t.Fatalf("錯誤不是 *PolicyGroupError（呼叫端無從分辨原因）: %v", err)
	}
	if ge.Code != want {
		t.Fatalf("錯誤碼 = %s, want %s（%v）", ge.Code, want, err)
	}
}

// seedBuiltinFixture 造一個內建組加一條條文與一個控制（不經公開寫入路徑）。
func seedBuiltinFixture(t *testing.T, db *gorm.DB) {
	t.Helper()
	rows := []interface{}{
		&model.PolicyGroup{Code: "builtin_demo", Name: "內建示範", Version: "1.0",
			Source: model.PolicyGroupSourceBuiltin, Enabled: true},
		&model.PolicyClause{GroupCode: "builtin_demo", ClauseNo: "1-1", Title: "內建條文",
			Kind: model.PolicyClauseKindSetting},
		&model.PolicyClauseControl{GroupCode: "builtin_demo", ClauseNo: "1-1",
			PolicyKey: PolicyPasswordMinLength, Comparator: model.PolicyControlComparatorMin,
			ExpectedValue: "12"},
	}
	for _, r := range rows {
		if err := db.Create(r).Error; err != nil {
			t.Fatalf("seed 內建列: %v", err)
		}
	}
}

// TestPolicyGroupRepoRejectsBuiltinWrites 內建組的內容不接受管理面寫入。
//
// 生效開關與備註**刻意**放行：前者由機構決定（升級不得改動它），後者是機構
// 自己的資料。兩者若一併擋下，機構就沒有辦法在內建條文上留下任何說明。
func TestPolicyGroupRepoRejectsBuiltinWrites(t *testing.T) {
	repo, db := newPolicyGroupRepo(t)
	seedBuiltinFixture(t, db)

	t.Run("改名被拒", func(t *testing.T) {
		requireGroupErrCode(t, repo.RenameCustomGroup("builtin_demo", "改過的名字"),
			ErrCodePolicyGroupBuiltinReadOnly)
	})

	t.Run("刪組被拒", func(t *testing.T) {
		requireGroupErrCode(t, repo.DeleteCustomGroup("builtin_demo"),
			ErrCodePolicyGroupBuiltinReadOnly)
	})

	t.Run("寫條文被拒", func(t *testing.T) {
		_, _, err := repo.UpsertCustomClause(
			model.PolicyClause{GroupCode: "builtin_demo", ClauseNo: "1-2",
				Title: "插進內建組的條文", Kind: model.PolicyClauseKindSelfAttested},
			nil)
		requireGroupErrCode(t, err, ErrCodePolicyGroupBuiltinReadOnly)
		var n int64
		db.Model(&model.PolicyClause{}).Where("group_code = ?", "builtin_demo").Count(&n)
		if n != 1 {
			t.Fatalf("被拒之後內建組的條文數 = %d, want 1（拒寫必須零落庫）", n)
		}
	})

	t.Run("刪條文被拒", func(t *testing.T) {
		requireGroupErrCode(t, repo.DeleteCustomClause("builtin_demo", "1-1"),
			ErrCodePolicyGroupBuiltinReadOnly)
	})

	t.Run("生效開關放行", func(t *testing.T) {
		if err := repo.SetGroupEnabled("builtin_demo", false); err != nil {
			t.Fatalf("內建組的生效開關由機構決定，不得擋下: %v", err)
		}
		g, err := repo.GetGroup("builtin_demo")
		if err != nil {
			t.Fatalf("讀回內建組: %v", err)
		}
		if g.Enabled {
			t.Fatal("生效開關沒有寫進去")
		}
	})

	t.Run("備註放行", func(t *testing.T) {
		if err := repo.UpsertAnnotation("builtin_demo", "1-1", "機構的說明"); err != nil {
			t.Fatalf("內建條文的機構備註不得擋下: %v", err)
		}
		notes, err := repo.ListAnnotations("builtin_demo")
		if err != nil {
			t.Fatalf("讀備註: %v", err)
		}
		if len(notes) != 1 || notes[0].Note != "機構的說明" {
			t.Fatalf("備註未寫入: %+v", notes)
		}
	})
}

// TestPolicyGroupRepoDeleteCustomGroupCascades 刪自建組連帶清除條文、控制與備註。
//
// 沒有資料庫層的 ON DELETE CASCADE（見 migration 檔頭），所以這件事只由這裡的
// 交易保證；漏刪的殘留列會在下一次建立同代號的組時，以「莫名其妙冒出來的舊條文」
// 現形。
func TestPolicyGroupRepoDeleteCustomGroupCascades(t *testing.T) {
	repo, db := newPolicyGroupRepo(t)

	if err := repo.CreateCustomGroup("house_rules", "內規", "zh-TW"); err != nil {
		t.Fatalf("建自建組: %v", err)
	}
	if _, _, err := repo.UpsertCustomClause(
		model.PolicyClause{GroupCode: "house_rules", ClauseNo: "A-1",
			Title: "密碼長度", Kind: model.PolicyClauseKindSetting},
		[]model.PolicyClauseControl{{
			PolicyKey: PolicyPasswordMinLength, Comparator: model.PolicyControlComparatorMin,
			ExpectedValue: "14",
		}}); err != nil {
		t.Fatalf("建條文: %v", err)
	}
	if err := repo.UpsertAnnotation("house_rules", "A-1", "內規備註"); err != nil {
		t.Fatalf("建備註: %v", err)
	}
	// 另一個組的資料必須原封不動——連帶清除只准清自己的
	if err := repo.CreateCustomGroup("other", "另一組", "zh-TW"); err != nil {
		t.Fatalf("建第二組: %v", err)
	}
	if _, _, err := repo.UpsertCustomClause(
		model.PolicyClause{GroupCode: "other", ClauseNo: "B-1",
			Title: "旁觀者", Kind: model.PolicyClauseKindSelfAttested}, nil); err != nil {
		t.Fatalf("建第二組的條文: %v", err)
	}
	if err := repo.UpsertAnnotation("other", "B-1", "旁觀者備註"); err != nil {
		t.Fatalf("建第二組的備註: %v", err)
	}

	if err := repo.DeleteCustomGroup("house_rules"); err != nil {
		t.Fatalf("刪自建組: %v", err)
	}

	count := func(m interface{}, groupCode string) int64 {
		t.Helper()
		var n int64
		if err := db.Model(m).Where("group_code = ?", groupCode).Count(&n).Error; err != nil {
			t.Fatalf("計數: %v", err)
		}
		return n
	}
	if n := count(&model.PolicyClause{}, "house_rules"); n != 0 {
		t.Errorf("刪組後仍有 %d 條條文", n)
	}
	if n := count(&model.PolicyClauseControl{}, "house_rules"); n != 0 {
		t.Errorf("刪組後仍有 %d 筆控制", n)
	}
	if n := count(&model.PolicyClauseAnnotation{}, "house_rules"); n != 0 {
		t.Errorf("刪組後仍有 %d 筆備註", n)
	}
	if _, err := repo.GetGroup("house_rules"); err == nil {
		t.Error("刪組後仍讀得到組本身")
	}

	if n := count(&model.PolicyClause{}, "other"); n != 1 {
		t.Errorf("另一組的條文被連帶刪掉了（剩 %d）", n)
	}
	if n := count(&model.PolicyClauseAnnotation{}, "other"); n != 1 {
		t.Errorf("另一組的備註被連帶刪掉了（剩 %d）", n)
	}
}

// TestPolicyGroupRepoValidatesControls 要求值與比較方式依設定鍵的型別受限。
func TestPolicyGroupRepoValidatesControls(t *testing.T) {
	repo, _ := newPolicyGroupRepo(t)
	if err := repo.CreateCustomGroup("house_rules", "內規", "zh-TW"); err != nil {
		t.Fatalf("建自建組: %v", err)
	}

	write := func(ctl model.PolicyClauseControl) error {
		_, _, err := repo.UpsertCustomClause(
			model.PolicyClause{GroupCode: "house_rules", ClauseNo: "A-1",
				Title: "測試條文", Kind: model.PolicyClauseKindSetting},
			[]model.PolicyClauseControl{ctl})
		return err
	}

	cases := []struct {
		name string
		ctl  model.PolicyClauseControl
		code string
	}{
		{"未定義的鍵", model.PolicyClauseControl{
			PolicyKey: "no_such_key", Comparator: model.PolicyControlComparatorMin,
			ExpectedValue: "1"}, ErrCodePolicyGroupUnknownKey},
		{"開關型用 min", model.PolicyClauseControl{
			PolicyKey: PolicyForceChangeOnReset, Comparator: model.PolicyControlComparatorMin,
			ExpectedValue: "true"}, ErrCodePolicyGroupComparator},
		{"整數型用 equals", model.PolicyClauseControl{
			PolicyKey: PolicyPasswordMinLength, Comparator: model.PolicyControlComparatorEquals,
			ExpectedValue: "12"}, ErrCodePolicyGroupComparator},
		{"要求值超出鍵的值域", model.PolicyClauseControl{
			PolicyKey: PolicyPasswordMinLength, Comparator: model.PolicyControlComparatorMin,
			ExpectedValue: "999"}, ErrCodePolicyGroupExpectedValue},
		{"文字型鍵不可作為設定要求對象", model.PolicyClauseControl{
			PolicyKey: PolicyLoginBannerTitle, Comparator: model.PolicyControlComparatorEquals,
			ExpectedValue: "任意"}, ErrCodePolicyGroupKeyType},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			requireGroupErrCode(t, write(c.ctl), c.code)
		})
	}

	t.Run("同組同鍵兩條要求被拒", func(t *testing.T) {
		if _, _, err := repo.UpsertCustomClause(
			model.PolicyClause{GroupCode: "house_rules", ClauseNo: "A-1",
				Title: "第一條", Kind: model.PolicyClauseKindSetting},
			[]model.PolicyClauseControl{{
				PolicyKey: PolicyPasswordMinLength, Comparator: model.PolicyControlComparatorMin,
				ExpectedValue: "14"}}); err != nil {
			t.Fatalf("第一條應可寫入: %v", err)
		}
		_, _, err := repo.UpsertCustomClause(
			model.PolicyClause{GroupCode: "house_rules", ClauseNo: "A-2",
				Title: "第二條", Kind: model.PolicyClauseKindSetting},
			[]model.PolicyClauseControl{{
				PolicyKey: PolicyPasswordMinLength, Comparator: model.PolicyControlComparatorMin,
				ExpectedValue: "16"}})
		requireGroupErrCode(t, err, ErrCodePolicyGroupDuplicateKey)
	})

	t.Run("由機構自行確認型不得帶控制", func(t *testing.T) {
		_, _, err := repo.UpsertCustomClause(
			model.PolicyClause{GroupCode: "house_rules", ClauseNo: "A-3",
				Title: "自行確認", Kind: model.PolicyClauseKindSelfAttested},
			[]model.PolicyClauseControl{{
				PolicyKey: PolicyMFARequired, Comparator: model.PolicyControlComparatorEquals,
				ExpectedValue: MFARequiredAll}})
		requireGroupErrCode(t, err, ErrCodePolicyGroupClauseKind)
	})

	t.Run("系統內建保護型不得帶控制", func(t *testing.T) {
		_, _, err := repo.UpsertCustomClause(
			model.PolicyClause{GroupCode: "house_rules", ClauseNo: "A-4",
				Title: "內建保護", Kind: model.PolicyClauseKindBuiltinProtection},
			[]model.PolicyClauseControl{{
				PolicyKey: PolicyMFARequired, Comparator: model.PolicyControlComparatorEquals,
				ExpectedValue: MFARequiredAll}})
		requireGroupErrCode(t, err, ErrCodePolicyGroupClauseKind)
	})

	t.Run("系統內建保護型不帶控制時可寫入", func(t *testing.T) {
		if _, _, err := repo.UpsertCustomClause(
			model.PolicyClause{GroupCode: "house_rules", ClauseNo: "A-5",
				Title: "產品直接承擔", Kind: model.PolicyClauseKindBuiltinProtection}, nil); err != nil {
			t.Fatalf("內建保護型條文應可寫入: %v", err)
		}
	})
}

// TestPolicyGroupRepoConfirmOverwritesPrevious 再次確認覆蓋前次。
func TestPolicyGroupRepoConfirmOverwritesPrevious(t *testing.T) {
	repo, db := newPolicyGroupRepo(t)
	seedBuiltinFixture(t, db)

	first := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	second := first.Add(48 * time.Hour)
	if err := repo.ConfirmClause("builtin_demo", "1-1", "admin", "第一次", first); err != nil {
		t.Fatalf("第一次確認: %v", err)
	}
	if err := repo.UpsertAnnotation("builtin_demo", "1-1", "備註不受確認影響"); err != nil {
		t.Fatalf("寫備註: %v", err)
	}
	if err := repo.ConfirmClause("builtin_demo", "1-1", "auditor", "第二次", second); err != nil {
		t.Fatalf("第二次確認: %v", err)
	}

	notes, err := repo.ListAnnotations("builtin_demo")
	if err != nil {
		t.Fatalf("讀備註: %v", err)
	}
	if len(notes) != 1 {
		t.Fatalf("備註列數 = %d, want 1（確認與備註同屬一列，不得各自成列）", len(notes))
	}
	got := notes[0]
	if got.ConfirmedBy != "auditor" || got.ConfirmationNote != "第二次" {
		t.Errorf("再次確認未覆蓋前次: %+v", got)
	}
	if got.ConfirmedAt == nil || !got.ConfirmedAt.UTC().Equal(second) {
		t.Errorf("確認時刻未更新: %+v", got.ConfirmedAt)
	}
	if got.Note != "備註不受確認影響" {
		t.Errorf("確認把機構備註蓋掉了: %q", got.Note)
	}
}
