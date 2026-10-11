package policy

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// TestSignoffRecordRejectedForCustomGroups 擋：自建組選用運作紀錄判定後拿不到每日簽核
// 紀錄的語義，產生無意義的判定。寫入端、條文編輯器的儲存前預覽與種子三處同一套規則。
func TestSignoffRecordRejectedForCustomGroups(t *testing.T) {
	t.Run("自建組條文寫入拒收", func(t *testing.T) {
		repo, _ := newPolicyGroupRepo(t)
		if err := repo.CreateCustomGroup("inhouse", "內部基準", "zh-TW"); err != nil {
			t.Fatal(err)
		}
		_, _, err := repo.UpsertCustomClause(
			model.PolicyClause{GroupCode: "inhouse", ClauseNo: "1", Title: "每日審閱", Kind: model.PolicyClauseKindSetting},
			[]model.PolicyClauseControl{{PolicyKey: PolicyDailyReviewEnabled,
				Comparator: model.PolicyControlComparatorSignoffRecord, ExpectedValue: "true"}})
		requireGroupErrCode(t, err, ErrCodePolicyGroupComparator)
		controls, err := repo.ListControls("inhouse")
		if err != nil {
			t.Fatal(err)
		}
		if len(controls) != 0 {
			t.Errorf("被拒的要求仍寫進去了：%+v", controls)
		}
	})

	t.Run("條文編輯器的儲存前預覽同樣拒收", func(t *testing.T) {
		_, repo, svc := newComplianceStack(t)
		if err := repo.CreateCustomGroup("inhouse", "內部基準", "zh-TW"); err != nil {
			t.Fatal(err)
		}
		_, err := svc.SnapshotWithTemp("inhouse", nil, []TempControl{{GroupCode: "inhouse", ClauseNo: "1",
			PolicyKey: PolicyDailyReviewEnabled, Comparator: model.PolicyControlComparatorSignoffRecord,
			ExpectedValue: "true"}})
		requireGroupErrCode(t, err, ErrCodePolicyGroupComparator)
	})

	t.Run("對照：自建組以 equals 要求同一個鍵仍可寫入", func(t *testing.T) {
		repo, _ := newPolicyGroupRepo(t)
		if err := repo.CreateCustomGroup("inhouse", "內部基準", "zh-TW"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := repo.UpsertCustomClause(
			model.PolicyClause{GroupCode: "inhouse", ClauseNo: "1", Title: "每日審閱", Kind: model.PolicyClauseKindSetting},
			[]model.PolicyClauseControl{{PolicyKey: PolicyDailyReviewEnabled,
				Comparator: model.PolicyControlComparatorEquals, ExpectedValue: "true"}}); err != nil {
			t.Errorf("equals 被拒: %v", err)
		}
	})

	t.Run("種子只准掛在每日審閱開關、要求值 true", func(t *testing.T) {
		for _, bad := range []policyControlSeed{
			{Key: PolicyFailureAlertEnabled, Comparator: model.PolicyControlComparatorSignoffRecord, ExpectedValue: "true"},
			{Key: PolicyDailyReviewEnabled, Comparator: model.PolicyControlComparatorSignoffRecord, ExpectedValue: "false"},
			{Key: PolicyDailyReviewEnabled, Comparator: model.PolicyControlComparatorSignoffRecord, ExpectedValue: "true", ReferenceOnly: true},
		} {
			seed := policyGroupSeed{Code: "demo", Name: "demo", Version: "1",
				Clauses: []policyClauseSeed{{ClauseNo: "1", Title: "t", Controls: []policyControlSeed{bad}}}}
			if _, err := buildSeedControls(seed); err == nil {
				t.Errorf("種子收下了 %+v", bad)
			}
		}
	})

	t.Run("升級：10.4.1 由 equals 改為 signoff_record，機構備註保留，電支組不變", func(t *testing.T) {
		db := newPolicyGroupSeedDB(t)
		// 模擬升級前：PCI 10.4.1 只看開關
		old := builtinPolicyGroupSeeds()
		for gi := range old {
			for ci := range old[gi].Clauses {
				c := &old[gi].Clauses[ci]
				if old[gi].Code == pciGroupCode && c.ClauseNo == "10.4.1" {
					c.Controls = []policyControlSeed{mustBe(PolicyDailyReviewEnabled, "true")}
				}
			}
		}
		if err := applyPolicyGroupSeeds(db, old); err != nil {
			t.Fatalf("舊版種子: %v", err)
		}
		repo := NewPolicyGroupRepository(db)
		if err := repo.UpsertAnnotation(pciGroupCode, "10.4.1", "資安室每日 10 點前簽核"); err != nil {
			t.Fatal(err)
		}
		if got := controlsByKey(t, db, pciGroupCode)[PolicyDailyReviewEnabled].Comparator; got != model.PolicyControlComparatorEquals {
			t.Fatalf("前提：升級前 10.4.1 為 equals，得 %s", got)
		}
		if err := SeedBuiltinPolicyGroups(db); err != nil {
			t.Fatalf("新版種子: %v", err)
		}
		if got := controlsByKey(t, db, pciGroupCode)[PolicyDailyReviewEnabled].Comparator; got != model.PolicyControlComparatorSignoffRecord {
			t.Errorf("升級後 PCI 10.4.1 = %s, want signoff_record", got)
		}
		if got := controlsByKey(t, db, ePaymentGroupCode)[PolicyDailyReviewEnabled].Comparator; got != model.PolicyControlComparatorEquals {
			t.Errorf("電支組 15-3(三) = %s, want equals", got)
		}
		anns, err := repo.ListAnnotations(pciGroupCode)
		if err != nil {
			t.Fatal(err)
		}
		kept := false
		for _, a := range anns {
			if a.ClauseNo == "10.4.1" && a.Note == "資安室每日 10 點前簽核" {
				kept = true
			}
		}
		if !kept {
			t.Errorf("升級後 10.4.1 的機構備註不見了：%+v", anns)
		}
	})
}
