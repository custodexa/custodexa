package sshproxy

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/proxy"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// 連線閘序專項測試四組
//
//  1. Issue 與 Redeem **之間**的狀態改變（授權撤銷／資產停用／票證到期）——
//     走真實簽發端點取得 token，改狀態，再走真實兌換入口；
//  2. 並發兌換——同一張一次性 token 只能有一個贏家；
//  3. **憑證提前解封不得發生**——以計數式 codec 直接觀測 DecryptFor 的呼叫次數；
//  4. 副作用（審計標記與 session 建立）順序。

// ---------------------------------------------------------------------------
// 組 1：Issue 與 Redeem 之間的狀態改變
// ---------------------------------------------------------------------------

func TestStateChangeBetweenIssueAndRedeem(t *testing.T) {
	cases := []struct {
		name       string
		change     func(t *testing.T, h *Handler, db *gorm.DB)
		wantStatus int
		wantCode   apierror.ErrCode
	}{
		{
			name: "授權撤銷",
			change: func(t *testing.T, h *Handler, db *gorm.DB) {
				if err := db.Where("user_id = ?", 1).Delete(&model.AssetAuthorization{}).Error; err != nil {
					t.Fatalf("revoke: %v", err)
				}
			},
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeAssetConnectDenied,
		},
		{
			name: "資產停用",
			change: func(t *testing.T, h *Handler, db *gorm.DB) {
				if err := db.Model(&model.Asset{}).Where("id = ?", 1).
					Update("active", false).Error; err != nil {
					t.Fatalf("disable: %v", err)
				}
			},
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeAssetDisabled,
		},
		{
			name: "帳號移出授權範圍",
			change: func(t *testing.T, h *Handler, db *gorm.DB) {
				if err := db.Model(&model.AssetAuthorization{}).Where("user_id = ?", 1).
					Update("accounts", model.AccountScope{"app"}).Error; err != nil {
					t.Fatalf("narrow: %v", err)
				}
			},
			wantStatus: http.StatusForbidden, wantCode: apierror.CodeAssetConnectDenied,
		},
		{
			name: "使用者憑證世代被推進（改密／解綁外部身分）",
			change: func(t *testing.T, h *Handler, db *gorm.DB) {
				if err := db.Model(&model.User{}).Where("id = ?", 1).
					Update("credential_epoch", 3).Error; err != nil {
					t.Fatalf("bump: %v", err)
				}
			},
			wantStatus: http.StatusUnauthorized, wantCode: apierror.CodeConnectTokenInvalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, db := gateFixture(t)
			gateSeedAccount(t, db, 1, "root", true)

			status, resp, _ := gateIssueRequest(h, 1, model.RoleUser, 1, 0, "")
			if status != http.StatusOK {
				t.Fatalf("前提不成立：簽發應成功 status=%d resp=%v", status, resp)
			}
			token, _ := resp["connect_token"].(string)
			if token == "" {
				t.Fatalf("簽發未回 token: %v", resp)
			}

			tc.change(t, h, db)

			rStatus, rResp := gateRedeemSSH(h, token, "80", "24")
			if rStatus != tc.wantStatus {
				t.Fatalf("兌換狀態不符: got=%d want=%d resp=%v", rStatus, tc.wantStatus, rResp)
			}
			if got, _ := rResp["code"].(string); got != string(tc.wantCode) {
				t.Fatalf("兌換拒絕碼不符: got=%q want=%q", got, tc.wantCode)
			}
			var n int64
			if err := db.Model(&model.Session{}).Count(&n).Error; err != nil {
				t.Fatalf("count sessions: %v", err)
			}
			if n != 0 {
				t.Fatalf("簽發後狀態改變者不得建線，卻留下 %d 筆 session", n)
			}
		})
	}
}

// TestTicketExpiryBetweenIssueAndRedeem 票證到期：approval 段位下以時窗內 ticket
// 簽發成功，把 ticket 改為已到期後兌換即被政策閘擋下（token 未過期不構成放行理由）
func TestTicketExpiryBetweenIssueAndRedeem(t *testing.T) {
	h, db := gateFixture(t)
	gateSeedAccount(t, db, 1, "root", true)
	// 只留 ticket 來源授權：刪常設授權，否則到期後仍有常設可放行
	if err := db.Where("user_id = ?", 1).Delete(&model.AssetAuthorization{}).Error; err != nil {
		t.Fatalf("clear standing grant: %v", err)
	}
	setGroupPolicy(t, db, 1, model.AccessPolicyApproval)
	grantTicket(t, db, 1, 1)

	status, resp, _ := gateIssueRequest(h, 1, model.RoleUser, 1, 0, "")
	if status != http.StatusOK {
		t.Fatalf("時窗內 ticket 應可簽發: status=%d resp=%v", status, resp)
	}
	token, _ := resp["connect_token"].(string)

	// 簽發後、兌換前 ticket 到期
	expired := time.Now().Add(-time.Minute)
	if err := db.Model(&model.AssetAuthorization{}).
		Where("user_id = ? AND source = ?", 1, model.AuthorizationSourceTicket).
		Update("date_expired", expired).Error; err != nil {
		t.Fatalf("expire ticket: %v", err)
	}

	rStatus, rResp := gateRedeemSSH(h, token, "80", "24")
	if rStatus != http.StatusForbidden {
		t.Fatalf("到期 ticket 不得兌換建線: status=%d resp=%v", rStatus, rResp)
	}
	// 授權閘（G-S9）先於政策閘（G-S10）：ticket 到期後該使用者已無任何 connect 授權
	if got, _ := rResp["code"].(string); got != string(apierror.CodeAssetConnectDenied) {
		t.Fatalf("拒絕碼不符: got=%q want=%q", got, apierror.CodeAssetConnectDenied)
	}
	// 副作用（與本檔其餘各格同一紀律）：被閘擋下者不得留下 session 列。
	// 只驗碼會漏掉「先建 session 再拒」這種同碼不同義的退化
	var sessions int64
	if err := db.Model(&model.Session{}).Count(&sessions).Error; err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if sessions != 0 {
		t.Fatalf("政策／授權閘拒絕後不得留下 session 列，實得 %d", sessions)
	}
}

// ---------------------------------------------------------------------------
// 組 2：並發兌換
// ---------------------------------------------------------------------------

// TestConcurrentRedeemSingleWinner 一次性即焚在並發下仍只有一個贏家：
// 其餘一律 401 token 無效，且全程不得建立任何 session
func TestConcurrentRedeemSingleWinner(t *testing.T) {
	h, db := gateFixture(t)
	gateSeedAccount(t, db, 1, "root", true)

	status, resp, _ := gateIssueRequest(h, 1, model.RoleUser, 1, 0, "")
	if status != http.StatusOK {
		t.Fatalf("簽發應成功: status=%d resp=%v", status, resp)
	}
	token, _ := resp["connect_token"].(string)

	const n = 8
	var invalid, other int64
	// 贏家的實際回應：**「非 401」不等於成功**——若贏家其實是被某道閘以 403／500 擋下，
	// 只數「非 401」的版本照樣綠。故另記下贏家的狀態與碼，逐一斷言它真的走完整條閘序
	type result struct {
		status int
		code   string
	}
	var mu sync.Mutex
	var winners []result
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			code, body := gateRedeemSSH(h, token, "80", "24")
			if code == http.StatusUnauthorized &&
				body["code"] == string(apierror.CodeConnectTokenInvalid) {
				atomic.AddInt64(&invalid, 1)
				return
			}
			atomic.AddInt64(&other, 1)
			got, _ := body["code"].(string)
			mu.Lock()
			winners = append(winners, result{status: code, code: got})
			mu.Unlock()
		}()
	}
	wg.Wait()

	if other != 1 {
		t.Fatalf("一次性 token 的贏家必須恰為 1（其餘全 401）: winners=%d invalid=%d", other, invalid)
	}
	// 贏家必須走完全部閘序抵達撥號：撥號目標 host="h" 不可解析 ⇒ 502＋SSH_UNREACHABLE，
	// 與矩陣「全閘通過抵達撥號」格同一機器證據。任何其他狀態都代表贏家其實被閘擋下了
	if len(winners) != 1 {
		t.Fatalf("贏家紀錄數不符: got=%d want=1（%+v）", len(winners), winners)
	}
	if winners[0].status != http.StatusBadGateway ||
		winners[0].code != string(apierror.CodeSSHUnreachable) {
		t.Fatalf("贏家未走完閘序抵達撥號（「非 401」不等於成功）: status=%d code=%q want=502/%s",
			winners[0].status, winners[0].code, apierror.CodeSSHUnreachable)
	}
	if invalid != n-1 {
		t.Fatalf("落敗者應全部 401 token 無效: invalid=%d want=%d", invalid, n-1)
	}
	var sessions int64
	if err := db.Model(&model.Session{}).Count(&sessions).Error; err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if sessions != 0 {
		t.Fatalf("撥號失敗的情況下不得留下 session 列，實得 %d", sessions)
	}
}

// ---------------------------------------------------------------------------
// 組 3：憑證提前解封不得發生
// ---------------------------------------------------------------------------

// gateCountingCodec 計數式 column codec：直接觀測「明文憑證有沒有被產生」。
// **這是唯一能證明「沒有提前解封」的執行期訊號**——靜態守衛只能證明呼叫點位置，
// 證不了某條路徑在執行期真的沒走到解封
type gateCountingCodec struct {
	inner    crypto.ColumnCodec
	decrypts int64
}

func (c *gateCountingCodec) EncryptFor(ctx context.Context, ref crypto.CipherRef, plaintext string) (string, error) {
	return c.inner.EncryptFor(ctx, ref, plaintext)
}

func (c *gateCountingCodec) DecryptFor(ctx context.Context, ref crypto.CipherRef, ciphertext string) (string, error) {
	atomic.AddInt64(&c.decrypts, 1)
	return c.inner.DecryptFor(ctx, ref, ciphertext)
}

// gateCountingFixture 與 gateFixture 同構，但 AssetService 掛計數 codec
func gateCountingFixture(t *testing.T) (*Handler, *gorm.DB, *gateCountingCodec) {
	t.Helper()
	h, db, _ := setupPolicyGateTest(t)
	seedGateFixture(t, db)
	setGroupPolicy(t, db, 1, model.AccessPolicyOpen)

	codec := &gateCountingCodec{inner: aesColumnCodec(t, make([]byte, 32))}
	assetSvc, err := asset.NewAssetService(codec, "localhost", 4822, audit.NewTxSink())
	if err != nil {
		t.Fatalf("asset service: %v", err)
	}
	h.AssetService = assetSvc
	return h, db, codec
}

func TestNoEarlyCredentialUnseal(t *testing.T) {
	// 前置：帳號帶真實密文，否則「零解密」可能只是因為沒有東西可解
	seedEncrypted := func(t *testing.T, db *gorm.DB, codec crypto.ColumnCodec) {
		t.Helper()
		acct := model.AssetAccount{AssetID: 1, Username: "root", IsDefault: true}
		if err := db.Create(&acct).Error; err != nil {
			t.Fatalf("seed account: %v", err)
		}
		enc, err := codec.EncryptFor(context.Background(), keyvault.RefAccountPassword, "s3cret")
		if err != nil {
			t.Fatalf("encrypt seed password: %v", err)
		}
		if err := db.Model(&model.AssetAccount{}).Where("id = ?", acct.ID).
			Update("password_enc", enc).Error; err != nil {
			t.Fatalf("seed password_enc: %v", err)
		}
	}

	t.Run("對照組：一路走到解封點時 DecryptFor 必被呼叫", func(t *testing.T) {
		h, db, codec := gateCountingFixture(t)
		seedEncrypted(t, db, codec)
		token, err := h.ConnectTokens.IssueConnectToken(context.Background(), gateGrant(1, 1, 0))
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		gateRedeemSSH(h, token, "80", "24")
		if atomic.LoadInt64(&codec.decrypts) == 0 {
			t.Fatal("對照組不成立：走到解封點卻沒有任何 DecryptFor，計數器沒有偵測能力")
		}
	})

	for _, tc := range []struct {
		name   string
		gate   string
		mutate func(t *testing.T, db *gorm.DB)
	}{
		{"G-S3 使用者停用", "G-S3", func(t *testing.T, db *gorm.DB) {
			db.Model(&model.User{}).Where("id = ?", 1).Update("active", false)
		}},
		{"G-S4 憑證世代被推進", "G-S4", func(t *testing.T, db *gorm.DB) {
			db.Model(&model.User{}).Where("id = ?", 1).Update("credential_epoch", 9)
		}},
	} {
		t.Run("解封前被拒者零解密："+tc.name, func(t *testing.T) {
			h, db, codec := gateCountingFixture(t)
			seedEncrypted(t, db, codec)
			token, err := h.ConnectTokens.IssueConnectToken(context.Background(), gateGrant(1, 1, 0))
			if err != nil {
				t.Fatalf("issue: %v", err)
			}
			// seed 期間的加密不計入：自兌換開始重新計數
			atomic.StoreInt64(&codec.decrypts, 0)
			tc.mutate(t, db)

			status, resp := gateRedeemSSH(h, token, "80", "24")
			if status == http.StatusOK || status == http.StatusSwitchingProtocols {
				t.Fatalf("%s 應拒絕: status=%d resp=%v", tc.gate, status, resp)
			}
			if got := atomic.LoadInt64(&codec.decrypts); got != 0 {
				t.Fatalf("%s 在解封之前就拒絕，SHALL NOT 產生任何明文憑證，實得 DecryptFor %d 次",
					tc.gate, got)
			}
		})
	}

	t.Run("G-S5 尺寸解析失敗亦不得解封", func(t *testing.T) {
		h, db, codec := gateCountingFixture(t)
		seedEncrypted(t, db, codec)
		token, err := h.ConnectTokens.IssueConnectToken(context.Background(), gateGrant(1, 1, 0))
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		atomic.StoreInt64(&codec.decrypts, 0)
		status, _ := gateRedeemSSH(h, token, "abc", "24")
		if status != http.StatusBadRequest {
			t.Fatalf("尺寸解析失敗應 400，實得 %d", status)
		}
		if got := atomic.LoadInt64(&codec.decrypts); got != 0 {
			t.Fatalf("解析失敗發生在解封之前，不得產生明文憑證，實得 %d 次", got)
		}
	})

	t.Run("簽發側全程零解封（簽發只解析 username）", func(t *testing.T) {
		h, db, codec := gateCountingFixture(t)
		seedEncrypted(t, db, codec)
		atomic.StoreInt64(&codec.decrypts, 0)
		status, resp, _ := gateIssueRequest(h, 1, model.RoleUser, 1, 0, "")
		if status != http.StatusOK {
			t.Fatalf("簽發應成功: status=%d resp=%v", status, resp)
		}
		if got := atomic.LoadInt64(&codec.decrypts); got != 0 {
			t.Fatalf("簽發端點 SHALL NOT 解封任何憑證（只解析 username），實得 DecryptFor %d 次", got)
		}
	})
}

// gateGrant 造一張兌換用 grant
func gateGrant(userID, assetID, accountID uint) proxy.ConnectGrant {
	return proxy.ConnectGrant{UserID: userID, AssetID: assetID, AccountID: accountID}
}

// ---------------------------------------------------------------------------
// 組 4：副作用順序（審計標記 vs 後續拒絕）
// ---------------------------------------------------------------------------

// TestAuditSideEffectOrdering 副作用順序：閘 A 產生的審計標記在閘 B 拒絕時
// **必須已經寫入**——「先寫審計再拒」與「先拒再寫審計」的拒絕碼相同、語義不同，
// 只驗碼看不出差別
func TestAuditSideEffectOrdering(t *testing.T) {
	h, db, policies := setupPolicyGateTest(t)
	seedGateFixture(t, db)
	setGroupPolicy(t, db, 1, model.AccessPolicyApproval)
	gateSeedAccount(t, db, 1, "root", true)

	// 傳輸閘（G-I13，位於政策閘 G-I12 之後）攔截：RDP 資產＋warn 段位
	if err := db.Create(&model.Asset{Name: "rdp1", Protocol: "rdp", Host: "h", Port: 3389, CreatedBy: 2}).Error; err != nil {
		t.Fatalf("seed rdp: %v", err)
	}
	if err := db.Model(&model.Asset{}).Where("id = ?", 2).
		Update("access_policy", model.AccessPolicyApproval).Error; err != nil {
		t.Fatalf("set policy: %v", err)
	}
	if _, err := policies.Update(policy.PolicyTransportRDPLevel, policy.TransportLevelWarn, "admin"); err != nil {
		t.Fatalf("transport warn: %v", err)
	}
	h.TransmissionConsent = policy.NewTransmissionConsentService(db,
		policy.NewTransmissionPolicyService(policies, nil))

	// admin：G-I12 豁免放行並寫下審計標記 → G-I13 傳輸閘攔截（428）
	status, resp, keys := gateIssueRequest(h, 2, model.RoleAdmin, 2, 0, "")
	if status != http.StatusPreconditionRequired {
		t.Fatalf("應由傳輸閘攔截（428）: status=%d resp=%v", status, resp)
	}
	details, _ := keys["audit_details"].(map[string]string)
	if details["policy_exemption"] != "admin" {
		t.Fatalf("政策閘的 admin 豁免標記必須在後續閘拒絕之前就已寫入（副作用順序）: keys=%v", keys)
	}

	// 反向：政策閘自己攔截時，不得留下豁免標記（避免上面的斷言是無條件成立）
	_, _, userKeys := gateIssueRequest(h, 1, model.RoleUser, 2, 0, "")
	userDetails, _ := userKeys["audit_details"].(map[string]string)
	if userDetails["policy_exemption"] != "" {
		t.Fatalf("非 admin 被政策閘攔截時不應有豁免標記: keys=%v", userKeys)
	}
}
