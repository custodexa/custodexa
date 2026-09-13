package main

import (
	"context"
	"log"
	"errors"
	"fmt"
	"sort"
	"strings"

	"gorm.io/gorm"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/internal/seal"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/crypto/gcpkms"
	kmskek "github.com/custodexa/backend/pkg/crypto/kms"
	"github.com/custodexa/backend/pkg/crypto/vaulttransit"
)

// 委託模式的解封驗證（臨界區之內）。
//
// 兩條路徑以 data_keys 筆數分流，沿 InitKeyManager 既有的 count == 0 判定：
//
//   - count > 0 → 既有部署：核對拓撲摘要 → 以輸入憑證建構 provider →
//     實際解包現行代表列。
//   - count == 0 → 全新安裝：驗初始管理員 → 收拓撲並逐欄驗證 → 以輸入憑證建構
//     provider 並完成權限預檢；首批金鑰的產生、以外部 KEK 包裹、與拓撲同事務
//     落庫在段 2（同一臨界區內）。**拓撲於驗證段不落庫**——它與首批金鑰是同一次
//     初始化的兩半，分兩次寫即留下半套。
//
// **憑證只進世代持有者**：payload 的秘密位元組於此交出所有權（api.TakeSecret），
// 之後由 credentialOwner 負責歸零；封存時隨世代抹除。

// delegatedKeySets 各分支的精確鍵集（**單一事實源**）。
//
// 鍵集精確比對是混合分支的攔截點：多一鍵、少一鍵皆拒。union 不允許選填欄位，
// 否則「缺漏」與「刻意不帶」無從區分。
func delegatedKeySets(provider string, bootstrap bool) [][]string {
	if bootstrap {
		switch provider {
		case keyvault.TopologyProviderAWS:
			return [][]string{{"username", "password", "region", "key_ref", "access_key_id", "secret_access_key"}}
		case keyvault.TopologyProviderGCP:
			return [][]string{{"username", "password", "key_ref", "service_account_json"}}
		case keyvault.TopologyProviderVault:
			return [][]string{
				{"username", "password", "address", "transit_key_name", "role_id", "vault_secret_id"},
				{"username", "password", "address", "transit_key_name", "vault_token"},
			}
		}
		return nil
	}
	switch provider {
	case keyvault.TopologyProviderAWS:
		return [][]string{{"access_key_id", "secret_access_key", "topology_digest"}}
	case keyvault.TopologyProviderGCP:
		return [][]string{{"service_account_json", "topology_digest"}}
	case keyvault.TopologyProviderVault:
		return [][]string{
			{"vault_secret_id", "topology_digest"},
			{"vault_token", "topology_digest"},
		}
	}
	return nil
}

// matchDelegatedKeySet 比對本次請求的鍵集是否**精確等於**某一個允許的鍵集。
func matchDelegatedKeySet(present map[string]bool, sets [][]string) ([]string, error) {
	if len(sets) == 0 {
		return nil, fmt.Errorf("未知的委託服務商：無可用的鍵集")
	}
	for _, want := range sets {
		if len(present) != len(want) {
			continue
		}
		ok := true
		for _, k := range want {
			if !present[k] {
				ok = false
				break
			}
		}
		if ok {
			return want, nil
		}
	}
	got := make([]string, 0, len(present))
	for k := range present {
		got = append(got, k)
	}
	sort.Strings(got)
	// 只列**鍵名**（非秘密），不列任何值。
	return nil, fmt.Errorf("委託解封的欄位組合不符任一分支：收到 %s", strings.Join(got, "、"))
}

// takeDelegatedSecrets 自 payload 取走秘密的所有權。
func takeDelegatedSecrets(p *api.SealUnsealPayload) delegatedSecrets {
	return delegatedSecrets{
		awsAccessKeyID:        api.TakeSecret(&p.AccessKeyID),
		awsSecretAccessKey:    api.TakeSecret(&p.SecretAccessKey),
		gcpServiceAccountJSON: api.TakeSecret(&p.ServiceAccountJSON),
		vaultSecretID:         api.TakeSecret(&p.VaultSecretID),
		vaultToken:            api.TakeSecret(&p.VaultToken),
	}
}

// delegatedTopologySnapshot 讀出本部署的拓撲與金鑰識別，組出設定與呈現視圖。
//
// **封存狀態下必須可讀**：拓撲全部是明文欄位，金鑰識別讀自金鑰列的 kek_id
//（兩者皆不依賴資料金鑰）。
func delegatedTopologySnapshot(provider string) (api.SealTopologyView, config.KMSSettings, error) {
	row, err := keyvault.LoadKEKTopology(database.DB)
	if err != nil && !errors.Is(err, keyvault.ErrKEKTopologyNotConfigured) {
		return api.SealTopologyView{}, config.KMSSettings{}, err
	}
	keyRef, err := keyvault.CurrentKEKID(database.DB)
	if err != nil {
		return api.SealTopologyView{}, config.KMSSettings{}, err
	}
	view := api.SealTopologyView{Provider: provider, KeyRef: keyRef, Configured: row != nil}
	settings := config.KMSSettings{Provider: provider, KeyID: keyRef}
	if row != nil {
		view.Address, view.TransitKeyName, view.RoleID, view.Region = row.Address, row.TransitKeyName, row.RoleID, row.Region
		settings.Region = row.Region
		settings.Vault.Address, settings.Vault.RoleID = row.Address, row.RoleID
		if settings.KeyID == "" {
			// 尚無金鑰列（全新安裝的中途狀態）：Vault 分支以拓撲的 Transit
			// 金鑰名頂替，其餘服務商無可頂替之值。
			settings.KeyID = row.TransitKeyName
		}
	}
	// **尚未設定且尚無金鑰列時摘要為空字串**：此時沒有可核對的目的地，
	// 給一個「空拓撲的雜湊」只會讓前端把它當成一份已成立的核對基準。
	if row != nil || keyRef != "" {
		view.Digest = keyvault.TopologyDigest(row, keyRef)
	}
	return view, settings, nil
}

// delegatedTopologyProbe 供解封頁的唯讀呈現（非委託模式回 ok=false）。
func delegatedTopologyProbe(d *config.KEKDecision) func() (api.SealTopologyView, bool) {
	if d == nil || d.Mode != config.KEKModeKMS {
		return func() (api.SealTopologyView, bool) { return api.SealTopologyView{}, false }
	}
	provider := d.KMS.Provider
	return func() (api.SealTopologyView, bool) {
		view, _, err := delegatedTopologySnapshot(provider)
		if err != nil {
			// 讀不到就不以空值頂替未知狀態：回 false 使狀態端點不呈現拓撲區塊，
			// 前端據此阻擋而非顯示一份可能錯誤的目的地。
			return api.SealTopologyView{}, false
		}
		return view, true
	}
}

// classifyDelegatedFailure 把建構與預檢的失敗歸為三類可辨識成因。
//
// **只歸類，不轉呈**：回傳的是本系統自定的分類，原始回應留在 Cause 供伺服端
// 日誌，對外訊息由 apierror 的登記文案承擔。歸不了類的失敗維持原樣，於是它在
// HTTP 層收斂為材料無效——寧可少給一個細分，也不要給一個猜的。
func classifyDelegatedFailure(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, kmskek.ErrKMSUnavailable),
		errors.Is(err, gcpkms.ErrUnavailable),
		errors.Is(err, gcpkms.ErrEndpoint),
		errors.Is(err, vaulttransit.ErrTransport),
		errors.Is(err, vaulttransit.ErrResponse):
		return fmt.Errorf("%w: %v", seal.ErrCustodyUnreachable, err)
	case errors.Is(err, kmskek.ErrCredentialsMissing),
		errors.Is(err, kmskek.ErrKMSRejected),
		errors.Is(err, gcpkms.ErrAuthentication),
		errors.Is(err, gcpkms.ErrPermission),
		errors.Is(err, vaulttransit.ErrAuth),
		errors.Is(err, vaulttransit.ErrDenied):
		return fmt.Errorf("%w: %v", seal.ErrCredentialRejected, err)
	case errors.Is(err, kmskek.ErrKeyUnusable),
		errors.Is(err, kmskek.ErrKeyIDNotCanonical),
		errors.Is(err, kmskek.ErrKeyOutsideTrustedAccount),
		errors.Is(err, gcpkms.ErrKeyRef),
		errors.Is(err, gcpkms.ErrProjectScope),
		errors.Is(err, gcpkms.ErrMetadata),
		errors.Is(err, vaulttransit.ErrInvalidReference),
		errors.Is(err, vaulttransit.ErrOutsideScope):
		return fmt.Errorf("%w: %v", seal.ErrKeyMismatch, err)
	}
	return err
}

// verifyDelegatedUnseal 委託模式的解封驗證入口。
func verifyDelegatedUnseal(ctx context.Context, s1 *stage1, materialBytes []byte, pending *bootstrapPendingState) (*verifiedUnseal, error) {
	payload, err := api.DecodeSealMaterial(materialBytes)
	if err != nil {
		return nil, err
	}
	defer payload.Zeroize()

	provider := s1.kekDecision.KMS.Provider
	count, err := keyvault.CountDataKeys(database.DB)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		v, err := verifyDelegatedBootstrap(ctx, s1, payload, provider)
		if err != nil {
			return nil, err
		}
		pending.arm(v.adminUsername)
		return v, nil
	}
	v, err := verifyDelegatedRestore(ctx, s1, payload, provider)
	if err != nil {
		log.Printf("[Seal] 委託解封驗證失敗（對外收斂為單一失敗碼）: %v", err)
		return nil, err
	}
	if armed, username := pending.snapshot(); armed {
		v.bootstrap, v.adminUsername = true, username
	}
	return v, nil
}

// verifyDelegatedRestore 既有部署的委託解封。
func verifyDelegatedRestore(ctx context.Context, s1 *stage1, payload *api.SealUnsealPayload, provider string) (*verifiedUnseal, error) {
	if _, err := matchDelegatedKeySet(payload.Present(), delegatedKeySets(provider, false)); err != nil {
		return nil, err
	}
	view, settings, err := delegatedTopologySnapshot(provider)
	if err != nil {
		return nil, err
	}
	// 目的地必須可判定，但**判準隨服務商而不同**：Vault 與 AWS 靠拓撲列
	//（位址、角色識別、區域），GCP 沒有可設定的拓撲欄位——它的完整 CryptoKey
	// 資源名就是金鑰列的 KEK 引用，故以引用非空為準。
	// 兩者都不成立時是「連要送去哪裡都不知道」，不是憑證問題。
	if len(keyvault.EditableTopologyFields(provider)) > 0 && !view.Configured {
		return nil, fmt.Errorf("委託拓撲尚未設定：無法判定目的地")
	}
	if view.KeyRef == "" {
		return nil, fmt.Errorf("現行金鑰列無 KEK 引用：無法判定目的地")
	}
	// **舊核對結果不授權新目的地**：摘要不符即拒並要求重新核對。
	if payload.TopologyDigest == "" || payload.TopologyDigest != view.Digest {
		return nil, fmt.Errorf("%w", seal.ErrTopologyChanged)
	}
	owner := newCredentialOwner()
	owner.adopt(settings, takeDelegatedSecrets(payload))
	delivered := false
	defer func() {
		if !delivered {
			owner.Close()
		}
	}()
	kek, err := buildDelegatedKEK(ctx, s1, owner)
	if err != nil {
		return nil, classifyDelegatedFailure(err)
	}
	// 實際解包現行代表列：能解開才是最強的授權證明，指紋相等不足。
	if err := keyvault.ProbeKEKUnwrap(database.DB, kek); err != nil {
		return nil, fmt.Errorf("%w: %v", seal.ErrKeyMismatch, err)
	}
	delivered = true
	return &verifiedUnseal{kek: kek, credentials: owner}, nil
}

// verifyDelegatedBootstrap 全新安裝的委託初始化驗證。
//
// 本函式只做到「憑證可用、金鑰識別可解析、權限預檢通過」為止；首批資料金鑰的
// 產生、以外部 KEK 包裹、與拓撲同事務落庫由段 2 於**同一臨界區內**完成
//（見 stage2 的 InitKeyManagerWithBootstrap）。拓撲在此**只驗證不寫入**，
// 驗過的輸入隨 verifiedUnseal 帶到段 2——建構 provider 用的是本次請求的值，
// 不需要它先落庫。
func verifyDelegatedBootstrap(ctx context.Context, s1 *stage1, payload *api.SealUnsealPayload, provider string) (*verifiedUnseal, error) {
	if _, err := matchDelegatedKeySet(payload.Present(), delegatedKeySets(provider, true)); err != nil {
		return nil, err
	}
	// 初始管理員憑證：缺此項＝未認證的主金鑰領主權競賽。
	if err := identity.VerifyInitialAdminCredential(database.DB, payload.Username, payload.Password); err != nil {
		return nil, err
	}
	in := keyvault.KEKTopologyInput{Provider: provider, UpdatedBy: payload.Username}
	settings := config.KMSSettings{Provider: provider}
	switch provider {
	case keyvault.TopologyProviderAWS:
		in.Region, settings.Region, settings.KeyID = payload.Region, payload.Region, payload.KeyRef
	case keyvault.TopologyProviderGCP:
		settings.KeyID = payload.KeyRef
	case keyvault.TopologyProviderVault:
		in.Address, in.TransitKeyName, in.RoleID = payload.Address, payload.TransitKeyName, payload.RoleID
		settings.Vault.Address, settings.Vault.RoleID = payload.Address, payload.RoleID
		settings.KeyID = payload.TransitKeyName
	}
	// GCP 沒有可編輯的拓撲欄位，故不寫拓撲列（其金鑰識別於落金鑰表時成為 kek_id）。
	if provider != keyvault.TopologyProviderGCP {
		if err := keyvault.ValidateKEKTopology(in); err != nil {
			return nil, err
		}
	}
	owner := newCredentialOwner()
	owner.adopt(settings, takeDelegatedSecrets(payload))
	delivered := false
	defer func() {
		if !delivered {
			owner.Close()
		}
	}()
	// 建構即完成連通性與權限預檢（含解析金鑰識別所需的描述權限）。
	kek, err := buildDelegatedKEK(ctx, s1, owner)
	if err != nil {
		return nil, classifyDelegatedFailure(err)
	}
	delivered = true
	v := &verifiedUnseal{kek: kek, credentials: owner, bootstrap: true, adminUsername: payload.Username}
	// 拓撲**不在此落庫**：它要與首批金鑰列同一筆交易（見 delegatedTopologyBootstrapHook）。
	// GCP 無可編輯的拓撲欄位，故無列可寫。
	if provider != keyvault.TopologyProviderGCP {
		pendingTopology := in
		v.topology = &pendingTopology
	}
	return v, nil
}

// delegatedTopologyBootstrapHook 把拓撲寫入包成「首批金鑰交易內的一步」。
//
// **這是 6.1 所要求的同事務落點**：金鑰列的產生、以外部 KEK 包裹與落表都發生在
// keyvault 的 bootstrap 交易內，拓撲於同一筆交易的最後寫入。任一半失敗即整筆
// rollback——不會留下「拓撲已設定但無金鑰」（下一次進解封頁仍判為全新安裝、
// 卻拿著一份指向某處的目的地），也不會留下「金鑰已落表但無位址」（下一次啟動
// 建構不出 provider）。
//
// topology 為 nil（既有部署、GCP、非委託模式）時回 nil，InitKeyManager 行為逐字不變。
func delegatedTopologyBootstrapHook(in *keyvault.KEKTopologyInput) keyvault.BootstrapTxHook {
	if in == nil {
		return nil
	}
	pending := *in
	return func(tx *gorm.DB) error {
		_, _, err := keyvault.SaveKEKTopologyTx(tx, pending)
		return err
	}
}

// buildDelegatedKEK 以本世代的憑證建構委託 provider。
//
// 接縫（`stage1.delegatedProviderSource`）在正式路徑恆為 nil；它收的是**已 adopt
// 憑證的世代持有者**，故「憑證有沒有被交出去」在接縫上仍然看得見。
func buildDelegatedKEK(ctx context.Context, s1 *stage1, owner *credentialOwner) (crypto.KEKProvider, error) {
	if s1.delegatedProviderSource != nil {
		return s1.delegatedProviderSource(ctx, owner)
	}
	p, _, err := owner.buildStartup(ctx, s1.kekDecision)
	return p, err
}
