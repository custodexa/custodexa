package keyvault

import (
	"github.com/custodexa/backend/pkg/crypto"
)

// 段 2 服務圖收束時，keyvault 側的資源歸零（自
// `internal/service/stage2_release.go:92-131` 拆出——
// 型別的方法必須與型別同包，故這兩個方法隨型別遷入 keyvault，
// 其餘 4 個 audit 側釋放函式留在原檔）。
//
// **拆檔不得改動釋放登記順序**：`keyManager.ZeroizeForRelease` 於組裝根
// （`cmd/server/stage2.go`）登記在 release 第 2 位（＝ ResourceBag 以 LIFO
// 釋放時倒數第 2 執行），是「封印」在記憶體層面唯一的實體動作。若被移到更晚
// 登記（＝更早執行），被丟棄的服務圖在其餘收束期間仍持有可用 codec，
// 「封印」即退化為路由層假象。登記序見
// `openspec/changes/archive/2026-08-11-modular-architecture/research/manifest-lifecycle.md`
//（隨公開快照出門的 lifecycle manifest）§7，
// 由 `cmd/server/lifecycle_manifest_guard_test.go` 與
// `cmd/server/lifecycle_startup_shutdown_test.go` 雙重把關。

// ZeroizeForRelease 歸零 KeyManagerService 持有的全部明文金鑰材料。
//
// 這是遷移表格 5b「清除已解封的 KEK」與「舊持有者釋放已建構資源」的
// 落點：B 模式的 KEK 只存在於記憶體，被丟棄的服務圖若仍持有它，
// 「封印」就只是路由層的假象。
//
// 逐位元組覆寫而非只丟參考：切片內容可能仍被其他結構引用（ciphers 快取），
// 覆寫才使材料真的不可讀。
func (s *KeyManagerService) ZeroizeForRelease() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for purpose, versions := range s.keys {
		for version, raw := range versions {
			for i := range raw {
				raw[i] = 0
			}
			delete(versions, version)
		}
		delete(s.keys, purpose)
	}
	s.ciphers = map[int]*crypto.AESCrypto{}
	s.active = map[string]int{}
	s.kek = nil
}

// ZeroizeForRelease 歸零匯出簽章服務持有的 Ed25519 私鑰。
// 私鑰是解密後常駐記憶體的 KEK 衍生材料，與 KEK 同級處理。
func (s *ExportSigningService) ZeroizeForRelease() {
	if s == nil {
		return
	}
	for i := range s.priv {
		s.priv[i] = 0
	}
	s.priv = nil
	s.pub = nil
}

// ZeroizeForRelease 歸零檢查點簽章服務持有的**全部版本** Ed25519 私鑰
// （audit-checkpoint-chain）。
//
// 與 ExportSigningService 的差異只有「多版本」：本服務自始帶版本欄，
// 記憶體內同時持有歷史版本的私鑰（供輪替後仍能重驗歷史檢查點），
// 故收束時必須逐版本覆寫——只清 active 版本會把舊版材料留在記憶體，
// 那些舊版鑰同樣能偽造歷史區間的檢查點。
func (s *CheckpointSigningService) ZeroizeForRelease() {
	if s == nil {
		return
	}
	for version, priv := range s.keys {
		for i := range priv {
			priv[i] = 0
		}
		delete(s.keys, version)
	}
	s.activeVersion = 0
}
