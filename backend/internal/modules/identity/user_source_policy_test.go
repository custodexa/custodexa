package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/sourceip"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 使用者允許來源網段清單的 service 層行為：驗證與正規化、Update 的 presence
// 三態（舊形狀 payload 不得靜默清空既有限制）、欄位級審計 diff、衍生狀態三態。

func sourcePolicyTestService(t *testing.T) (*UserService, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.PasswordHistory{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewUserService(db, authz.NewAssetAuthorizationService(db)), db
}

func createWithCIDRs(t *testing.T, svc *UserService, name string, cidrs []string) *model.User {
	t.Helper()
	u, err := svc.Create(&CreateUserRequest{
		Username: name, Password: "Str0ng!pass", Email: name + "@example.com",
		AllowedCIDRs: cidrs,
	})
	if err != nil {
		t.Fatalf("Create(%s): %v", name, err)
	}
	return u
}

func TestUserSourcePolicyCreateNormalizesAndRejects(t *testing.T) {
	svc, db := sourcePolicyTestService(t)

	// 合法：正規化（遮罩、裸位址補長、去重、排序穩定）後入庫；回應攤成陣列＋狀態
	u := createWithCIDRs(t, svc, "alice", []string{"10.1.2.3/8", "10.1.2.3", "10.1.2.3", "2001:0db8::/32"})
	wantList := []string{"10.0.0.0/8", "10.1.2.3/32", "2001:db8::/32"}
	if !reflect.DeepEqual(u.AllowedCIDRList, wantList) {
		t.Errorf("回應清單 = %v, want %v", u.AllowedCIDRList, wantList)
	}
	if u.AllowedCIDRsStatus != sourceip.StatusRestricted {
		t.Errorf("狀態 = %q, want restricted", u.AllowedCIDRsStatus)
	}
	var stored string
	if err := db.Raw(`SELECT allowed_cidrs FROM users WHERE id = ?`, u.ID).Scan(&stored).Error; err != nil {
		t.Fatalf("讀儲存值: %v", err)
	}
	if stored != "10.0.0.0/8,10.1.2.3/32,2001:db8::/32" {
		t.Errorf("儲存形式 = %q（應為逗號分隔的正規化前綴）", stored)
	}

	// 非法項：整體拒絕，不靜默丟棄
	if _, err := svc.Create(&CreateUserRequest{
		Username: "bad", Password: "Str0ng!pass", Email: "bad@example.com",
		AllowedCIDRs: []string{"10.0.0.0/8", "not-an-address"},
	}); !errors.Is(err, sourceip.ErrPrefixInvalid) {
		t.Errorf("非法項應回 ErrPrefixInvalid，實得: %v", err)
	}
	// 上限：去重後 33 項拒絕
	over := make([]string, 0, 33)
	for i := 0; i < 33; i++ {
		over = append(over, fmt.Sprintf("10.0.1.%d", i))
	}
	if _, err := svc.Create(&CreateUserRequest{
		Username: "over", Password: "Str0ng!pass", Email: "over@example.com",
		AllowedCIDRs: over,
	}); !errors.Is(err, sourceip.ErrTooManyPrefixes) {
		t.Errorf("超上限應回 ErrTooManyPrefixes，實得: %v", err)
	}
	// 省略＝不限
	free := createWithCIDRs(t, svc, "free", nil)
	if free.AllowedCIDRsStatus != sourceip.StatusUnrestricted || len(free.AllowedCIDRList) != 0 {
		t.Errorf("省略清單應為不限，實得 status=%q list=%v", free.AllowedCIDRsStatus, free.AllowedCIDRList)
	}
}

func TestUserSourcePolicyUpdatePresenceSemantics(t *testing.T) {
	svc, db := sourcePolicyTestService(t)
	u := createWithCIDRs(t, svc, "alice", []string{"10.0.0.0/8"})

	storedCIDRs := func() string {
		var s string
		if err := db.Raw(`SELECT allowed_cidrs FROM users WHERE id = ?`, u.ID).Scan(&s).Error; err != nil {
			t.Fatalf("讀儲存值: %v", err)
		}
		return s
	}

	// 三態的 JSON 解析前提：省略與 null 皆為 nil 指標、[] 為非 nil 空切片——
	// presence 語義建立在這條型別事實上，先釘住它
	for _, tc := range []struct {
		payload string
		wantNil bool
	}{
		{`{"email":"a@example.com","full_name":"A"}`, true},
		{`{"allowed_cidrs":null}`, true},
		{`{"allowed_cidrs":[]}`, false},
	} {
		var req UpdateUserRequest
		if err := json.Unmarshal([]byte(tc.payload), &req); err != nil {
			t.Fatalf("unmarshal %s: %v", tc.payload, err)
		}
		if (req.AllowedCIDRs == nil) != tc.wantNil {
			t.Fatalf("payload %s 的指標態 = %v, want nil=%v", tc.payload, req.AllowedCIDRs, tc.wantNil)
		}
	}

	// 態 1：舊形狀 payload（只帶 email／full_name）→ 清單不變、diff 無該欄
	_, diff, err := svc.Update(u.ID, &UpdateUserRequest{Email: "alice2@example.com", FullName: "Alice"})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if _, ok := diff["allowed_cidrs.before"]; ok {
		t.Error("未帶清單欄的更新不得產生 allowed_cidrs diff")
	}
	if storedCIDRs() != "10.0.0.0/8" {
		t.Errorf("舊形狀 payload 後清單被改動: %q", storedCIDRs())
	}

	// 態 2：JSON null → 同保留
	var reqNull UpdateUserRequest
	if err := json.Unmarshal([]byte(`{"allowed_cidrs":null}`), &reqNull); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	_, diff, err = svc.Update(u.ID, &reqNull)
	if err != nil {
		t.Fatalf("Update(null): %v", err)
	}
	if len(diff) != 0 || storedCIDRs() != "10.0.0.0/8" {
		t.Errorf("null 應保留現值且零 diff，實得 diff=%v stored=%q", diff, storedCIDRs())
	}

	// 態 3：[] → 清空且 diff 記前後
	empty := []string{}
	updated, diff, err := svc.Update(u.ID, &UpdateUserRequest{AllowedCIDRs: &empty})
	if err != nil {
		t.Fatalf("Update([]): %v", err)
	}
	if storedCIDRs() != "" {
		t.Errorf("[] 應清空清單，實得 %q", storedCIDRs())
	}
	if diff["allowed_cidrs.before"] != "10.0.0.0/8" || diff["allowed_cidrs.after"] != "" {
		t.Errorf("清空的 diff 應記前後值，實得 %v", diff)
	}
	if updated.AllowedCIDRsStatus != sourceip.StatusUnrestricted {
		t.Errorf("清空後狀態應 unrestricted，實得 %q", updated.AllowedCIDRsStatus)
	}

	// 取代：非空清單整體取代＋diff；同值更新零 diff
	repl := []string{"192.0.2.0/24", "10.9.9.9/8"}
	updated, diff, err = svc.Update(u.ID, &UpdateUserRequest{AllowedCIDRs: &repl})
	if err != nil {
		t.Fatalf("Update(replace): %v", err)
	}
	if storedCIDRs() != "10.0.0.0/8,192.0.2.0/24" {
		t.Errorf("取代後儲存 = %q", storedCIDRs())
	}
	if diff["allowed_cidrs.after"] != "10.0.0.0/8,192.0.2.0/24" || diff["allowed_cidrs.before"] != "" {
		t.Errorf("取代的 diff 不符: %v", diff)
	}
	same := []string{"10.0.0.0/8", "192.0.2.0/24"}
	_, diff, err = svc.Update(u.ID, &UpdateUserRequest{AllowedCIDRs: &same})
	if err != nil {
		t.Fatalf("Update(same): %v", err)
	}
	if len(diff) != 0 {
		t.Errorf("同值（正規化後相同）更新不得產生 diff: %v", diff)
	}
	_ = updated

	// 非法項：整體拒、狀態未變
	badList := []string{"10.0.0.0/33"}
	if _, _, err := svc.Update(u.ID, &UpdateUserRequest{AllowedCIDRs: &badList}); !errors.Is(err, sourceip.ErrPrefixInvalid) {
		t.Errorf("非法項應回 ErrPrefixInvalid，實得: %v", err)
	}
	if storedCIDRs() != "10.0.0.0/8,192.0.2.0/24" {
		t.Errorf("拒絕後清單不得變動: %q", storedCIDRs())
	}
}

func TestUserSourcePolicyStatusThreeStates(t *testing.T) {
	svc, _ := sourcePolicyTestService(t)

	empty := createWithCIDRs(t, svc, "u-empty", nil)
	if empty.AllowedCIDRsStatus != sourceip.StatusUnrestricted || len(empty.AllowedCIDRFamilies) != 0 {
		t.Errorf("空清單: status=%q families=%v", empty.AllowedCIDRsStatus, empty.AllowedCIDRFamilies)
	}

	global := createWithCIDRs(t, svc, "u-global", []string{"0.0.0.0/0"})
	if global.AllowedCIDRsStatus != sourceip.StatusEffectivelyUnrestricted ||
		!reflect.DeepEqual(global.AllowedCIDRFamilies, []string{sourceip.FamilyV4}) {
		t.Errorf("全域 v4 前綴: status=%q families=%v", global.AllowedCIDRsStatus, global.AllowedCIDRFamilies)
	}

	restricted := createWithCIDRs(t, svc, "u-restricted", []string{"10.0.0.0/8"})
	if restricted.AllowedCIDRsStatus != sourceip.StatusRestricted || len(restricted.AllowedCIDRFamilies) != 0 {
		t.Errorf("一般前綴: status=%q families=%v", restricted.AllowedCIDRsStatus, restricted.AllowedCIDRFamilies)
	}

	// 列表面消費同一衍生欄：GetByID 與 List 皆已裝飾
	got, err := svc.GetByID(global.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.AllowedCIDRsStatus != sourceip.StatusEffectivelyUnrestricted {
		t.Errorf("GetByID 未裝飾狀態: %q", got.AllowedCIDRsStatus)
	}
	list, err := svc.List(&ListUsersRequest{Page: 1, PageSize: 50})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	seen := map[string]string{}
	for _, u := range list.Data {
		seen[u.Username] = u.AllowedCIDRsStatus
	}
	if seen["u-empty"] != sourceip.StatusUnrestricted ||
		seen["u-global"] != sourceip.StatusEffectivelyUnrestricted ||
		seen["u-restricted"] != sourceip.StatusRestricted {
		t.Errorf("List 三態不符: %v", seen)
	}
}
