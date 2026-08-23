package model

import "testing"

// TestDiffAssetAccessPolicy 政策覆寫變更須產生欄位級審計明細
// （nil＝跟隨全域以空字串入審計）
func TestDiffAssetAccessPolicy(t *testing.T) {
	approval := AccessPolicyApproval
	reason := AccessPolicyReason

	cases := []struct {
		name     string
		old, new *string
		wantOld  string
		wantNew  string
		wantDiff bool
	}{
		{"設定覆寫", nil, &approval, "", "approval", true},
		{"清除覆寫", &approval, nil, "approval", "", true},
		{"段位變更", &approval, &reason, "approval", "reason", true},
		{"未變更（同值）", &approval, &approval, "", "", false},
		{"未變更（皆 nil）", nil, nil, "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			oldAsset := &Asset{Name: "a", AccessPolicy: tc.old}
			newAsset := &Asset{Name: "a", AccessPolicy: tc.new}
			changes := DiffAsset(oldAsset, newAsset)

			var got *AssetChange
			for i := range changes {
				if changes[i].Field == "access_policy" {
					got = &changes[i]
				}
			}
			if !tc.wantDiff {
				if got != nil {
					t.Fatalf("不應產生 access_policy diff, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("應產生 access_policy diff")
			}
			if got.Old != tc.wantOld || got.New != tc.wantNew {
				t.Errorf("diff 值錯誤: old=%v new=%v, want old=%s new=%s", got.Old, got.New, tc.wantOld, tc.wantNew)
			}
		})
	}
}
