package identity

import (
	"errors"
	"testing"
)

// 啟用 provider 時重驗 issuer scheme（批 14 對抗審查 M5 / spec oidc-auth L67-69）。
//
// issuer 建立後不可變，但 `AllowInsecureHosts` 是**部署層狀態**：同一份資料庫
// 可以先在 dev（http 靶機列於允許清單）建立 provider，隨後升為 release 部署。
// 若只有 Create 呼叫 ValidateIssuerURL，release 下送 `{"enabled":true}` 就會被
// 接受——spec 要求的是「於 release 模式啟用 issuer 為 http 的 provider THEN
// 拒絕啟用並回明確錯誤」，不是「登入時 egress 會擋」（後者是第二道，不是本條）。
func TestOIDCProviderEnableRevalidatesIssuerScheme(t *testing.T) {
	_, _, db := setupOIDCEnv(t)

	// dev 部署：http 靶機列於允許清單，建立時通過（且刻意建成停用狀態）
	dev := newProviderSvcFor(db, &OIDCEgressPolicy{AllowInsecureHosts: []string{"127.0.0.1"}},
		nil, "https://bastion.example.com")
	dto := mustCreateProvider(t, dev, providerReq(func(r *OIDCProviderRequest) {
		r.Issuer = "http://127.0.0.1:5556/dex"
		r.Enabled = boolPtr(false)
	}))

	// 同一份 DB 升為 release 部署（無任何 http 例外主機）
	release := newProviderSvcFor(db, releaseEgress(), nil, "https://bastion.example.com")

	if _, err := release.Update(dto.ID, &OIDCProviderRequest{Enabled: boolPtr(true)}); !errors.Is(err, ErrOIDCIssuerScheme) {
		t.Errorf("release 模式啟用 http issuer 的 provider → %v, want ErrOIDCIssuerScheme", err)
	}
	if p := reloadProvider(t, db, dto.ID); p.Enabled {
		t.Error("被拒的啟用不得落庫，provider 已被啟用")
	}

	// 反面一：release 下**停用**同一個 provider 必須仍可行——否則管理者被鎖在
	// 「不能啟用也不能停用」的死角，而停用只會縮小攻擊面
	if _, err := release.Update(dto.ID, &OIDCProviderRequest{Enabled: boolPtr(false)}); err != nil {
		t.Errorf("release 下停用 http issuer 的 provider 應可行: %v", err)
	}

	// 反面二：不觸及 enabled 的更新不受 scheme 檢查影響
	if _, err := release.Update(dto.ID, &OIDCProviderRequest{Name: "renamed"}); err != nil {
		t.Errorf("不動 enabled 的更新不應被 issuer scheme 檢查擋下: %v", err)
	}

	// 反面三：https issuer 的啟用照常通過
	httpsDTO := mustCreateProvider(t, release, providerReq(func(r *OIDCProviderRequest) {
		r.ClientID = "cid-https"
		r.Enabled = boolPtr(false)
	}))
	if _, err := release.Update(httpsDTO.ID, &OIDCProviderRequest{Enabled: boolPtr(true)}); err != nil {
		t.Errorf("https issuer 的啟用應通過: %v", err)
	}

	// 反面四：dev 部署（issuer 主機仍在允許清單）下啟用照常通過
	if _, err := dev.Update(dto.ID, &OIDCProviderRequest{Enabled: boolPtr(true)}); err != nil {
		t.Errorf("dev 部署下啟用 dev 靶機 provider 應通過: %v", err)
	}
}
