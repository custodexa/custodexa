package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// soKeyset 回應遞迴鍵集（只比鍵、不比值；陣列以 [] 合併）。
func soKeyset(t *testing.T, raw string) []string {
	t.Helper()
	var v any
	require.NoError(t, json.Unmarshal([]byte(raw), &v))
	set := map[string]bool{}
	var walk func(prefix string, x any)
	walk = func(prefix string, x any) {
		switch tv := x.(type) {
		case map[string]any:
			for k, c := range tv {
				p := prefix + "." + k
				set[p] = true
				walk(p, c)
			}
		case []any:
			for _, c := range tv {
				walk(prefix+"[]", c)
			}
		}
	}
	walk("", v)
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// soGoldenLog 把鍵集印成一行，供先紅紀錄擷取成不回退比對的基準。
func soGoldenLog(t *testing.T, name string, keys []string) {
	t.Helper()
	t.Logf("GOLDEN %s %s", name, strings.Join(keys, ","))
}

// soDecode 取 JSON 物件。
func soDecode(t *testing.T, raw string) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw), &m), raw)
	return m
}

// soRotationMembers 解析輪替回應 data.members。
func soRotationMembers(t *testing.T, raw string) []map[string]any {
	t.Helper()
	data, _ := soDecode(t, raw)["data"].(map[string]any)
	require.NotNil(t, data, raw)
	arr, _ := data["members"].([]any)
	out := make([]map[string]any, 0, len(arr))
	for _, a := range arr {
		m, _ := a.(map[string]any)
		out = append(out, m)
	}
	return out
}

// soBumpRotationIDs 讓輪替與成員識別從較大的數字開始，避免成員識別與輪替識別數字相撞
// （序號不隨刪除回收）。
func (e *outEnv) soBumpRotationIDs() {
	e.t.Helper()
	rot := model.CredentialRotation{CredentialID: e.rotCred, Epoch: 99, Mode: model.CredentialRotationModeGroup,
		Status: model.CredentialRotationCompleted}
	require.NoError(e.t, e.db.Create(&rot).Error)
	for i := 0; i < 12; i++ {
		m := model.CredentialRotationMember{RotationID: rot.ID, AccountID: uint(900 + i), CredentialID: e.rotCred,
			AssetID: uint(900 + i), State: model.CredentialMemberApplied}
		require.NoError(e.t, e.db.Create(&m).Error)
	}
	require.NoError(e.t, e.db.Exec("DELETE FROM credential_rotation_members WHERE rotation_id = ?", rot.ID).Error)
	require.NoError(e.t, e.db.Exec("DELETE FROM credential_rotations WHERE id = ?", rot.ID).Error)
}

func TestScopedRotationMemberProjection(t *testing.T) {
	e := newOutEnv(t, soWithRotation())
	e.soBumpRotationIDs()
	credBase := credPath(e.rotCred)
	mgrR := e.soRotationRouter(e.mgr)

	// 起跑前：取影響確認
	code, raw := soServe(mgrR, http.MethodPost, credBase+"/impact-confirmations", `{"operation":"rotate"}`)
	soAssertOK(t, code, raw, http.StatusOK, []string{"confirmation_id"})
	confirmID, _ := soDecode(t, raw)["confirmation_id"].(string)
	require.NotEmpty(t, confirmID, raw)

	// 起跑
	code, raw = soServe(mgrR, http.MethodPost, credBase+"/rotations",
		fmt.Sprintf(`{"mode":"group","impact_confirmation_id":%q}`, confirmID))
	soAssertOK(t, code, raw, http.StatusAccepted, []string{"data"})
	rotData, _ := soDecode(t, raw)["data"].(map[string]any)
	rid := uint(rotData["id"].(float64))
	require.NotZero(t, rid)
	rotPath := fmt.Sprintf("%s/rotations/%d", credBase, rid)

	var members []model.CredentialRotationMember
	require.NoError(t, e.db.Where("rotation_id = ?", rid).Order("id asc").Find(&members).Error)
	if len(members) != 5 {
		t.Fatalf("PRECONDITION: 該輪成員列應為 5 筆，實際 %d", len(members))
	}
	inSet := map[uint]bool{}
	for _, a := range e.rotIn {
		inSet[a] = true
	}
	var outMembers []model.CredentialRotationMember
	var inMemberIDs []uint
	var inMember0 model.CredentialRotationMember
	for _, m := range members {
		if inSet[m.AssetID] {
			inMemberIDs = append(inMemberIDs, m.ID)
			if m.AssetID == e.rotIn[0] {
				inMember0 = m
			}
		} else {
			outMembers = append(outMembers, m)
		}
	}
	require.Len(t, outMembers, 3)
	require.NotZero(t, inMember0.ID)

	// 禁止內容：範圍外三台的資產名、asset_id、account_id、成員 id
	var forbidden, visible []soToken
	for i, m := range outMembers {
		forbidden = append(forbidden, soName(fmt.Sprintf("zz-so-out-asset-%d", i)),
			soNum("asset_id", m.AssetID), soNum("account_id", m.AccountID), soNum("id", m.ID))
	}
	visible = append(visible, soName("zz-so-asset-in-0"), soName("zz-so-asset-in-1"), soNum("id", rid))
	for _, m := range members {
		if inSet[m.AssetID] {
			visible = append(visible, soNum("asset_id", m.AssetID), soNum("account_id", m.AccountID), soNum("id", m.ID))
		}
	}
	soCheckFixture(t, forbidden, visible)

	// 受限回應的共通斷言：外框、無外洩、合法欄位保留
	restricted := func(t *testing.T, code int, raw string, wantCode int) {
		t.Helper()
		soAssertOK(t, code, raw, wantCode, []string{"data"})
		soAssertNoLeak(t, raw, forbidden, []string{"zz-so-asset-in-0", `"out_of_scope_asset_count":3`})
		if got := strings.Count(raw, `"username":"zz-so-rot-user"`); got != 2 {
			t.Fatalf("PRECONDITION: 共用帳號名出現 %d 次，預期 2（列出的成員數）\n本文: %s", got, raw)
		}
	}

	t.Run("start", func(t *testing.T) {
		restricted(t, http.StatusAccepted, raw, http.StatusAccepted)
	})

	t.Run("get", func(t *testing.T) {
		code, raw := soServe(mgrR, http.MethodGet, rotPath, "")
		restricted(t, code, raw, http.StatusOK)
	})

	t.Run("retry_visible", func(t *testing.T) {
		code, raw := soServe(mgrR, http.MethodPost, fmt.Sprintf("%s/members/%d/retry", rotPath, inMember0.ID), "")
		restricted(t, code, raw, http.StatusOK)
		if strings.Count(raw, `"host_identity"`) != 1 || strings.Count(raw, "zz-so-hostid") != 1 {
			t.Fatalf("PRECONDITION: 可見成員的補跑應恰帶一次 host_identity 與 zz-so-hostid\n本文: %s", raw)
		}
		var carrier int
		for _, m := range soRotationMembers(t, raw) {
			if _, ok := m["host_identity"]; ok {
				carrier++
				if uint(m["id"].(float64)) != inMember0.ID {
					t.Fatalf("PRECONDITION: host_identity 應掛在被補跑的成員上\n本文: %s", raw)
				}
			}
		}
		require.Equal(t, 1, carrier, raw)
	})

	t.Run("retry_hidden", func(t *testing.T) {
		code, raw := soServe(mgrR, http.MethodPost, fmt.Sprintf("%s/members/%d/retry", rotPath, outMembers[0].ID), "")
		soAssertOK(t, code, raw, http.StatusOK, []string{"data"})
		soAssertNoLeak(t, raw, append(append([]soToken{}, forbidden...),
			soName("zz-so-hostid"), soName(`"host_identity"`)), []string{"zz-so-asset-in-0"})
	})

	t.Run("rotate_wider_than_view", func(t *testing.T) {
		code, raw := soServe(e.soRotationRouter(e.rotWide), http.MethodGet, rotPath, "")
		soAssertOK(t, code, raw, http.StatusOK, []string{"data"})
		soAssertNoLeak(t, raw, forbidden, []string{"zz-so-asset-in-0", `"out_of_scope_asset_count":3`})
		if n := len(soRotationMembers(t, raw)); n != 2 {
			t.Fatalf("PRECONDITION: 輪替能力較寬的主體應只列 2 個範圍內成員，實際 %d\n本文: %s", n, raw)
		}
	})

	t.Run("global_unchanged", func(t *testing.T) {
		code, raw := soServe(e.soRotationRouter(e.glb), http.MethodGet, rotPath, "")
		soAssertOK(t, code, raw, http.StatusOK, []string{"data"})
		if n := len(soRotationMembers(t, raw)); n != 5 {
			t.Fatalf("PRECONDITION: 全域檢視者應看到 5 個成員，實際 %d\n本文: %s", n, raw)
		}
		for i := 0; i < 3; i++ {
			if !strings.Contains(raw, fmt.Sprintf("zz-so-out-asset-%d", i)) {
				t.Fatalf("PRECONDITION: 全域檢視者應看得到範圍外資產 zz-so-out-asset-%d\n本文: %s", i, raw)
			}
		}
		if strings.Contains(raw, "out_of_scope_asset_count") {
			t.Fatalf("PRECONDITION: 全域檢視者的回應不應帶 out_of_scope_asset_count\n本文: %s", raw)
		}
		soGoldenLog(t, "rotation", soKeyset(t, raw))
	})

	t.Run("abandon", func(t *testing.T) {
		code, raw := soServe(mgrR, http.MethodPost, rotPath+"/abandon", "")
		var n int64
		require.NoError(t, e.db.Model(&model.CredentialRotationMember{}).
			Where("rotation_id = ? AND state = ?", rid, model.CredentialMemberAbandoned).Count(&n).Error)
		if n != 5 {
			t.Fatalf("PRECONDITION: 放棄應作用於全部 5 個成員，實際收束 %d", n)
		}
		restricted(t, code, raw, http.StatusOK)
	})

	// 脫離會在請求內以真實通道登入遠端；夾具不提供遠端，所以成功回應不可達。
	// 這裡只證明請求確實走進脫離服務（建立拆分輪次、遠端步驟失敗而回該端點既有的內部錯誤碼），
	// 且失敗回應不含任何範圍外內容。成功路徑的回應形狀由其他測試涵蓋。
	t.Run("detach_nonregression", func(t *testing.T) {
		code, raw := soServe(mgrR, http.MethodPost,
			fmt.Sprintf("%s/bindings/%d/detach", credBase, e.rotInAcc[1]), `{"source":"random"}`)
		var split model.CredentialRotation
		if err := e.db.Where("credential_id = ? AND mode = ?", e.rotCred, model.CredentialRotationModeSplit).
			Order("id desc").First(&split).Error; err != nil {
			t.Fatalf("PRECONDITION: 脫離請求未走進服務（找不到拆分輪次）: %v\n狀態碼 %d 本文: %s", err, code, raw)
		}
		t.Logf("detach 狀態碼 %d，拆分輪次 %d，本文 %s", code, split.ID, raw)
		soAssertNoLeak(t, raw, forbidden, nil)
	})
}
