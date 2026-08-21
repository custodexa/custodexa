package keyvault

import (
	"testing"

	"github.com/custodexa/backend/pkg/crypto"
)

// TestCipherRefsMatchMigrationTargets cipher_refs.go 與 envelopeMigrationTargets
// 的**雙向逐項對應**守衛（cipher_refs.go 文件註所指名的守衛）。
//
// 為何是雙向：登記表是 DEK 輪替重加密、legacy pending 判定、退役 DEK 銷毀前引用掃描
// 與 AAD 遷移的共同來源。
//   - 有 CipherRef 卻未登記 → AAD 遷移漏掉該欄，而「殘餘為 0」的把關會憑一個
//     不完整的掃描面放行 strict；
//   - 有登記卻無 CipherRef → 該欄的產品碼寫入路徑仍可能停在無 AAD 入口而無人察覺。
func TestCipherRefsMatchMigrationTargets(t *testing.T) {
	inRefs := map[crypto.CipherRef]bool{}
	for _, r := range allCipherRefs {
		if !r.Valid() {
			t.Errorf("登記的 CipherRef %+v 不完整（table／column 皆須非空）", r)
		}
		if inRefs[r] {
			t.Errorf("allCipherRefs 有重複項 %s", r)
		}
		inRefs[r] = true
	}

	inTargets := map[crypto.CipherRef]bool{}
	for _, tgt := range envelopeMigrationTargets {
		ref := tgt.cipherRef()
		inTargets[ref] = true
		if !inRefs[ref] {
			t.Errorf("envelopeMigrationTargets 有 %s 卻無對應的 CipherRef 常數："+
				"該欄的 AAD 綁定身分無單一事實源", ref)
		}
	}
	for ref := range inRefs {
		if !inTargets[ref] {
			t.Errorf("CipherRef %s 未登記於 envelopeMigrationTargets："+
				"AAD 遷移與退役 DEK 引用掃描都會漏掉該欄", ref)
		}
	}
}

// TestCipherRefAADIsColumnScopedNotRowScoped 釘住 A2 定案在**登記表層級**的後果：
// 每個登記欄位的 AAD 是常數，故 create 路徑無須兩階段寫入。
// 任一登記欄位若哪天取得「隨列而變」的身分，本測試會轉紅。
func TestCipherRefAADIsColumnScopedNotRowScoped(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range allCipherRefs {
		aad := string(r.AAD())
		// 同一 ref 值重建兩次必得同一份 AAD（無時間、無列、無隨機成分）
		if again := string(crypto.CipherRef{Table: r.Table, Column: r.Column}.AAD()); again != aad {
			t.Fatalf("%s 的 AAD 非確定性: %q vs %q", r, aad, again)
		}
		if seen[aad] {
			t.Fatalf("%s 與另一登記欄位共用同一份 AAD：跨欄搬移防護在此對命名上失效", r)
		}
		seen[aad] = true
	}
}
