package identity

import (
	"errors"
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// 目錄登入名稱的同名判定與目錄端一致：去前後空白、相容正規化（NFKC）、
// 不分大小寫。名稱只在這些面向上不同時，對應到既有帳號並套用其停用與鎖定，
// 不另建帳號。全部走真 sqlite 與真登入流程。

// 目錄端視為同名、但與保存的 "alice" 字面不同的輸入形態
var directoryEquivalentForms = []string{
	" alice",
	"alice ",
	"　alice",
	"alice ",
	"ａｌｉｃｅ",
	" ＡＬＩＣＥ ",
}

func TestDirectoryLoginNameKey_Equivalence(t *testing.T) {
	base := directoryLoginNameKey("alice")
	for _, f := range directoryEquivalentForms {
		if got := directoryLoginNameKey(f); got != base {
			t.Errorf("key(%q) = %q, want %q", f, got, base)
		}
	}
	for _, f := range []string{"alic e", "alice2", "alce", "a lice"} {
		if directoryLoginNameKey(f) == base {
			t.Errorf("key(%q) 不應與 alice 相同", f)
		}
	}
	if directoryLoginNameKey("a  b") != directoryLoginNameKey("a b") {
		t.Error("內部連續空白應壓成一個")
	}
}

func TestDirectoryLoginName_StoredForm(t *testing.T) {
	cases := map[string]string{
		"alice":    "alice",
		"  Alice ": "Alice",
		"ＡＬＩＣＥ":    "ALICE",
		"　bob ":    "bob",
		"a   b":    "a b",
	}
	for in, want := range cases {
		if got := directoryLoginName(in); got != want {
			t.Errorf("directoryLoginName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDirectoryLoginNameForms_InactiveAccountRejected(t *testing.T) {
	for _, form := range directoryEquivalentForms {
		t.Run(form, func(t *testing.T) {
			auth, _, db := setupRoleMappingEnv(t)
			caseVariantUser(t, db, "alice", false, false)
			before := caseVariantUserCount(t, db)

			resp, err, _, after := caseVariantLogin(t, auth, db, form)
			if !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("err = %v, want ErrInvalidCredentials（resp=%v）", err, resp != nil)
			}
			if after != before {
				t.Fatalf("帳號數 %d -> %d，不應新增帳號", before, after)
			}
		})
	}
}

func TestDirectoryLoginNameForms_LockedAccountRejectedBeforeDirectory(t *testing.T) {
	for _, form := range directoryEquivalentForms {
		t.Run(form, func(t *testing.T) {
			auth, _, db := setupRoleMappingEnv(t)
			caseVariantUser(t, db, "alice", true, true)
			before := caseVariantUserCount(t, db)

			resp, err, calls, after := caseVariantLogin(t, auth, db, form)
			if !errors.Is(err, ErrAccountLocked) {
				t.Fatalf("err = %v, want ErrAccountLocked（resp=%v）", err, resp != nil)
			}
			if calls != 0 {
				t.Fatalf("目錄被呼叫 %d 次，鎖定須在目錄認證前拒絕", calls)
			}
			if after != before {
				t.Fatalf("帳號數 %d -> %d，不應新增帳號", before, after)
			}
		})
	}
}

func TestDirectoryLoginNameForms_ActiveAccountNotAdopted(t *testing.T) {
	for _, form := range directoryEquivalentForms {
		t.Run(form, func(t *testing.T) {
			auth, _, db := setupRoleMappingEnv(t)
			caseVariantUser(t, db, "alice", true, false)
			before := caseVariantUserCount(t, db)

			resp, err, calls, after := caseVariantLogin(t, auth, db, form)
			if !errors.Is(err, ErrInvalidCredentials) || resp != nil {
				t.Fatalf("resp=%+v err=%v, want ErrInvalidCredentials", resp, err)
			}
			if calls != 0 || after != before {
				t.Fatalf("calls=%d 帳號數 %d -> %d", calls, before, after)
			}
		})
	}
}

// 只差 ASCII 大小寫：照舊沿用既有帳號。
func TestDirectoryLoginNameForms_ASCIICaseAdopted(t *testing.T) {
	auth, _, db := setupRoleMappingEnv(t)
	existing := caseVariantUser(t, db, "alice", true, false)
	before := caseVariantUserCount(t, db)

	resp, err, calls, after := caseVariantLogin(t, auth, db, "ALICE")
	if err != nil || resp == nil || resp.User.ID != existing.ID || calls != 1 || after != before {
		t.Fatalf("resp=%+v err=%v calls=%d 帳號數 %d -> %d", resp, err, calls, before, after)
	}
}

// 兩個名稱只在非 ASCII 摺疊上相同（ß 與 ss）：不得沿用。
func TestDirectoryLoginNameForms_NonASCIIFoldNotAdopted(t *testing.T) {
	for _, pair := range [][2]string{{"strasse", "straße"}, {"straße", "STRASSE"}} {
		auth, _, db := setupRoleMappingEnv(t)
		caseVariantUser(t, db, pair[0], true, false)
		before := caseVariantUserCount(t, db)

		resp, err, calls, after := caseVariantLogin(t, auth, db, pair[1])
		if !errors.Is(err, ErrInvalidCredentials) || resp != nil || calls != 0 || after != before {
			t.Fatalf("%q 對 %q: resp=%+v err=%v calls=%d 帳號數 %d -> %d", pair[1], pair[0], resp, err, calls, before, after)
		}
	}
}

// 回歸：與保存名稱完全相同的輸入照常登入。
func TestDirectoryLoginNameForms_ExactNameUnchanged(t *testing.T) {
	auth, _, db := setupRoleMappingEnv(t)
	existing := caseVariantUser(t, db, "alice", true, false)

	resp, err, calls, _ := caseVariantLogin(t, auth, db, "alice")
	if err != nil || resp == nil || resp.User.ID != existing.ID || calls != 1 {
		t.Fatalf("resp=%+v err=%v calls=%d", resp, err, calls)
	}
}

// 首次登入供應的帳號名稱存保存形；之後只有完全相同或只差 ASCII 大小寫的輸入回到同一帳號。
func TestDirectoryLoginNameForms_ProvisionStoresCanonicalForm(t *testing.T) {
	auth, _, db := setupRoleMappingEnv(t)

	resp, err, calls, after := caseVariantLogin(t, auth, db, "  Ｄａｖｅ ")
	if err != nil || resp == nil || calls != 1 {
		t.Fatalf("resp=%+v err=%v calls=%d", resp, err, calls)
	}
	if resp.User.Username != "Dave" {
		t.Fatalf("帳號名稱 = %q, want %q", resp.User.Username, "Dave")
	}
	if after != 1 {
		t.Fatalf("帳號數 = %d, want 1", after)
	}
	id := resp.User.ID

	// 只差 ASCII 大小寫：回到同一帳號
	resp, err, _, after = caseVariantLogin(t, auth, db, "dave")
	if err != nil || resp == nil || resp.User.ID != id || after != 1 {
		t.Fatalf("以 dave 登入: resp=%+v err=%v 帳號數=%d", resp, err, after)
	}
	// 空白或全形：拒絕，不沿用也不另建帳號
	for _, form := range []string{" DAVE", "ｄａｖｅ"} {
		resp, err, _, after := caseVariantLogin(t, auth, db, form)
		if !errors.Is(err, ErrInvalidCredentials) || resp != nil || after != 1 {
			t.Fatalf("以 %q 登入: resp=%+v err=%v 帳號數=%d", form, resp, err, after)
		}
	}
}

// 已存在多筆同名帳號（只差空白或全形）：任一筆停用即整組拒絕；
// 皆啟用且無精確命中時沿用多筆同名的既有處置（拒絕、待管理員整併）。
func TestDirectoryLoginNameForms_ExistingDuplicates(t *testing.T) {
	t.Run("停用帳號與另一筆同名帳號並存", func(t *testing.T) {
		auth, _, db := setupRoleMappingEnv(t)
		caseVariantUser(t, db, "alice", false, false)
		caseVariantUser(t, db, " alice", true, false)
		before := caseVariantUserCount(t, db)

		// 精確命中任一筆：整組套用停用判定
		for _, form := range []string{"alice", " alice"} {
			_, err, _, after := caseVariantLogin(t, auth, db, form)
			if !errors.Is(err, ErrUserInactive) {
				t.Fatalf("以 %q 登入: err = %v, want ErrUserInactive", form, err)
			}
			if after != before {
				t.Fatalf("帳號數 %d -> %d", before, after)
			}
		}
		// 無精確命中且組內多筆：沿用多筆同名的處置
		_, err, _, after := caseVariantLogin(t, auth, db, "ａｌｉｃｅ")
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("以全形登入: err = %v, want ErrInvalidCredentials", err)
		}
		if after != before {
			t.Fatalf("帳號數 %d -> %d", before, after)
		}
	})

	t.Run("鎖定帳號與另一筆同名帳號並存", func(t *testing.T) {
		auth, _, db := setupRoleMappingEnv(t)
		caseVariantUser(t, db, "alice", true, true)
		caseVariantUser(t, db, "ａｌｉｃｅ", true, false)

		_, err, calls, _ := caseVariantLogin(t, auth, db, "ａｌｉｃｅ")
		if !errors.Is(err, ErrAccountLocked) || calls != 0 {
			t.Fatalf("err = %v calls=%d, want ErrAccountLocked 且不打目錄", err, calls)
		}
	})

	t.Run("多筆皆啟用且無精確命中", func(t *testing.T) {
		auth, _, db := setupRoleMappingEnv(t)
		caseVariantUser(t, db, "carol", true, false)
		caseVariantUser(t, db, "carol ", true, false)
		before := caseVariantUserCount(t, db)

		_, err, _, after := caseVariantLogin(t, auth, db, "ｃａｒｏｌ")
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("err = %v, want ErrInvalidCredentials", err)
		}
		if after != before {
			t.Fatalf("帳號數 %d -> %d，不應新增帳號", before, after)
		}
	})
}

// 本地帳號：精確命中照舊走本地密碼路徑；只在空白或全形上不同的輸入，
// 與只差大小寫的處置一致（不打目錄、不建帳號）。
func TestDirectoryLoginNameForms_LocalAccount(t *testing.T) {
	auth, _, db := setupRoleMappingEnv(t)
	local := &model.User{Username: "bob", Password: "not-a-hash", Active: true}
	if err := db.Create(local).Error; err != nil {
		t.Fatal(err)
	}
	wide := &model.User{Username: "ｗｉｄｅ", Password: "not-a-hash", Active: true}
	if err := db.Create(wide).Error; err != nil {
		t.Fatal(err)
	}
	before := caseVariantUserCount(t, db)

	for _, form := range []string{"bob", "ｗｉｄｅ", " bob", "ｂｏｂ", "bob　", "wide"} {
		_, err, calls, after := caseVariantLogin(t, auth, db, form)
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("以 %q 登入: err = %v, want ErrInvalidCredentials", form, err)
		}
		if calls != 0 {
			t.Fatalf("以 %q 登入: 目錄被呼叫 %d 次", form, calls)
		}
		if after != before {
			t.Fatalf("以 %q 登入: 帳號數 %d -> %d", form, before, after)
		}
	}
}

// 與 agent 主體同名：視同非目錄來源，不打目錄、不建帳號。
func TestDirectoryLoginNameForms_AgentPrincipal(t *testing.T) {
	auth, _, db := setupRoleMappingEnv(t)
	agent := &model.User{Username: "robot", Password: "irrelevant", Active: true, Kind: model.KindAgent}
	if err := db.Create(agent).Error; err != nil {
		t.Fatal(err)
	}
	before := caseVariantUserCount(t, db)

	for _, form := range []string{" robot", "ＲＯＢＯＴ"} {
		_, err, calls, after := caseVariantLogin(t, auth, db, form)
		if !errors.Is(err, ErrInvalidCredentials) || calls != 0 || after != before {
			t.Fatalf("以 %q 登入: err=%v calls=%d 帳號數 %d -> %d", form, err, calls, before, after)
		}
	}
}
