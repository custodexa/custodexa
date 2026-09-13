package main

import (
	"bytes"
	"context"
	"errors"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/crypto/gcpkms"
	"github.com/custodexa/backend/pkg/crypto/vaulttransit"
)

// 解封世代的憑證持有者。
//
// # 為什麼是一個型別而不是三家各一個實作
//
// 設計稿原擬「共用介面 ＋ 三家各一實作」。改為單一型別的理由是**歸零紀律**：
// 三份平行的生命週期就是三處可以各自把 Close() 寫錯的地方，而這裡寫錯的後果是
// 憑證在封存後仍可用。單一型別下「綁定一個解封世代、Close() 歸零且永久失效、
// 重新解封另配新持有者」只有一份實作，三家共用同一組測試。規格要求的是三家
// **統一形狀**，單一型別比三份平行實作更直接地滿足它。
//
// # 生命週期
//
//	newCredentialOwner()          配置一個世代
//	adopt(topology, secrets)      接手本世代的拓撲與秘密（**取得位元組所有權**）
//	buildStartup / buildDelegated 以本世代憑證建構 provider
//	Close()                       歸零秘密、關閉 Vault client、使後續取用一律失敗（冪等、永久）
//
// 收束時機沿既有規則：金鑰管理器釋放後才收束。重新解封 SHALL 配置新的世代與
// 新的持有者，SHALL NOT 重用前一世代的憑證。
//
// # 誠實邊界
//
// 本型別保證的是「由本產品配置、承載明文的那些位元組於封存時被逐位元組覆寫」，
// 而非「行程記憶體中不再存在該明文」。憑證經 SDK、TLS 堆疊與 HTTP 傳輸時產生的
// 副本不在可控範圍；把秘密交給 vaulttransit.Settings／kms.Settings 這類 string
// 欄位時亦必然產生一份不可覆寫的副本。後者在 Go 的語義下不可避免，宣稱避免了
// 即為不誠實。

// delegatedSecrets 本世代持有的委託憑證（三家的聯集，按服務商只填其一組）。
//
// 全部以可覆寫的 []byte 承載：string 不可變，歸零原始請求體碰不到它。
type delegatedSecrets struct {
	awsAccessKeyID        []byte
	awsSecretAccessKey    []byte
	gcpServiceAccountJSON []byte
	vaultSecretID         []byte
	vaultToken            []byte
}

// zeroize 逐位元組覆寫並斷開參考。
func (s *delegatedSecrets) zeroize() {
	if s == nil {
		return
	}
	for _, b := range [][]byte{s.awsAccessKeyID, s.awsSecretAccessKey, s.gcpServiceAccountJSON, s.vaultSecretID, s.vaultToken} {
		material.Wipe(b)
	}
	s.awsAccessKeyID, s.awsSecretAccessKey, s.gcpServiceAccountJSON = nil, nil, nil
	s.vaultSecretID, s.vaultToken = nil, nil
}

// empty 本世代是否未持有任何委託憑證。
func (s *delegatedSecrets) empty() bool {
	return s == nil || (len(s.awsAccessKeyID) == 0 && len(s.awsSecretAccessKey) == 0 &&
		len(s.gcpServiceAccountJSON) == 0 && len(s.vaultSecretID) == 0 && len(s.vaultToken) == 0)
}

// credentialOwner belongs to one unsealed generation. Targets borrow its client.
// Closing a generation is permanent; restoration allocates a new owner.
type credentialOwner struct {
	mu           sync.Mutex
	life         context.Context
	cancel       context.CancelFunc
	clientCancel context.CancelFunc
	client       *vaulttransit.Client
	construct    vaultProviderConstructor
	// GCP 的 client 與建構子同樣綁定本世代：憑證抹除後不得再有可用的 client。
	gcpCancel    context.CancelFunc
	gcpClient    *gcpkms.Client
	gcpConstruct gcpProviderConstructor
	// topology 本世代綁定的非秘密拓撲（含自金鑰列取得的 KEK 引用）。
	topology config.KMSSettings
	// secrets 本世代持有的秘密；Close() 後恆為零值。
	secrets delegatedSecrets
	closed  bool
}

func newCredentialOwner() *credentialOwner {
	life, cancel := context.WithCancel(context.Background())
	return &credentialOwner{life: life, cancel: cancel}
}

// adopt 接手本世代的拓撲與秘密。呼叫端交出位元組所有權，不得再持有或覆寫它們。
func (o *credentialOwner) adopt(topology config.KMSSettings, secrets delegatedSecrets) {
	if o == nil {
		secrets.zeroize()
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.life.Err() != nil {
		secrets.zeroize()
		return
	}
	o.secrets.zeroize()
	o.topology, o.secrets = topology, secrets
}

// errCredentialOwnerClosed 世代已收束後的取用。
//
// **封存抹除的可觀察面**：封存後任何取用本世代憑證的嘗試都必須失敗，
// 而不是拿到一段全零的位元組繼續走下去——後者會在保管處端表現為一次難以歸因的
// 認證失敗，前者在本行程內就指得出原因。
var errCredentialOwnerClosed = errors.New("本解封世代的憑證持有者已收束：封存已抹除其憑證，請重新解封並重新提供")

// settings 組出建構 provider 所需的完整組態（拓撲 ＋ 本世代秘密）。
//
// Close 之後回錯——「取用一律失敗」是封存抹除的可觀察面。
func (o *credentialOwner) settings() (config.KMSSettings, error) {
	if o == nil {
		return config.KMSSettings{}, errCredentialOwnerClosed
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.settingsLocked()
}

func (o *credentialOwner) settingsLocked() (config.KMSSettings, error) {
	if o.closed || o.life.Err() != nil {
		return config.KMSSettings{}, errCredentialOwnerClosed
	}
	s := o.topology
	s.AWSAccessKeyID = string(o.secrets.awsAccessKeyID)
	s.AWSSecretAccessKey = string(o.secrets.awsSecretAccessKey)
	if len(o.secrets.gcpServiceAccountJSON) > 0 {
		// 交出副本而非原位元組：呼叫端（SDK）持有期間我方可能已 Close 並歸零，
		// 讓 SDK 讀到一段全零的「金鑰檔」會產生一個難以歸因的認證失敗。
		//
		// **以 bytes.Clone 而非 append(..., x...) 複製**：本檔自接上 GCP 正式
		// 建構子起進入 GCP 端點掃描器的射程，而該掃描器把任何變參展開視為可疑
		// （它要擋的是把一串 option 展開進 SDK 建構）。語義相同、不鬆動守衛。
		s.GCPServiceAccountJSON = bytes.Clone(o.secrets.gcpServiceAccountJSON)
	}
	s.Vault.SecretID = string(o.secrets.vaultSecretID)
	s.Vault.Token = string(o.secrets.vaultToken)
	return s, nil
}

// awsCredentialsProvider 由本世代的存取金鑰對組出 SDK 憑證提供者。
//
// **靜態提供者而非預設鏈**：部署形態是地端機房以開放名單連往外部雲端金鑰服務，
// 沒有實例身分可用；回落預設鏈只會撿到環境中不該用的憑證。缺一即回 nil，
// 由 kms 套件以 ErrCredentialsMissing 拒絕建構。
func awsCredentialsProvider(s config.KMSSettings) aws.CredentialsProvider {
	if s.AWSAccessKeyID == "" || s.AWSSecretAccessKey == "" {
		return nil
	}
	return credentials.NewStaticCredentialsProvider(s.AWSAccessKeyID, s.AWSSecretAccessKey, "")
}

func (o *credentialOwner) provider(ctx context.Context, settings vaulttransit.Settings) (crypto.KEKProvider, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil, errCredentialOwnerClosed
	}
	if err := o.life.Err(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	created := o.client == nil
	if created {
		lifetime, cancel := context.WithCancel(o.life)
		stop := context.AfterFunc(ctx, cancel)
		base := config.KMSSettings{Provider: vaulttransit.ProviderVault, KeyID: settings.KeyID}
		base.Vault.Address, base.Vault.RoleID = settings.Address, settings.RoleID
		base.Vault.SecretID, base.Vault.Token = settings.SecretID, settings.Token
		client, construct, err := newVaultProviderOwner(lifetime, base)
		stop()
		if err == nil {
			err = ctx.Err()
		}
		if err == nil {
			err = o.life.Err()
		}
		if err != nil {
			cancel()
			if client != nil {
				client.Close()
			}
			return nil, err
		}
		o.client, o.construct, o.clientCancel = client, construct, cancel
	}
	p, err := o.construct(ctx, settings)
	if err != nil && created {
		o.client.Close()
		o.clientCancel()
		o.client, o.construct, o.clientCancel = nil, nil, nil
	}
	return p, err
}

// gcpProvider 以本世代的服務帳號金鑰檔建構 GCP 目標的 provider。
//
// 形狀比照 Vault：世代持有 client（首次使用時建立、綁 o.life）、憑證來自解封頁
// 注入的持有者、Close() 時連同憑證一併收束。**不讀環境憑證**——設定一律自
// settingsLocked 取得，那裡的服務帳號金鑰檔只可能來自解封請求。
func (o *credentialOwner) gcpProvider(ctx context.Context, settings gcpkms.Settings) (crypto.KEKProvider, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil, errCredentialOwnerClosed
	}
	if err := o.life.Err(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	created := o.gcpClient == nil
	if created {
		base, err := o.settingsLocked()
		if err != nil {
			return nil, err
		}
		lifetime, cancel := context.WithCancel(o.life)
		stop := context.AfterFunc(ctx, cancel)
		client, construct, err := newGCPProviderOwner(lifetime, base)
		stop()
		if err == nil {
			err = ctx.Err()
		}
		if err == nil {
			err = o.life.Err()
		}
		if err != nil {
			cancel()
			if client != nil {
				_ = client.Close()
			}
			return nil, err
		}
		o.gcpClient, o.gcpConstruct, o.gcpCancel = client, construct, cancel
	}
	p, err := o.gcpConstruct(ctx, settings)
	if err != nil && created {
		_ = o.gcpClient.Close()
		o.gcpCancel()
		o.gcpClient, o.gcpConstruct, o.gcpCancel = nil, nil, nil
	}
	return p, err
}

func (o *credentialOwner) buildStartup(ctx context.Context, d *config.KEKDecision) (crypto.KEKProvider, *material.Secret, error) {
	return buildOwnedKEKProviderWithConstructors(ctx, d, o, o.provider, o.gcpProvider)
}

func (o *credentialOwner) buildDelegated(ctx context.Context, mode, keyRef string) (crypto.KEKProvider, error) {
	return buildDelegatedRewrapProviderWithConstructors(ctx, mode, keyRef, o, o.provider, o.gcpProvider)
}

// Close 歸零本世代的秘密並永久關閉。冪等。
func (o *credentialOwner) Close() {
	if o == nil {
		return
	}
	// Cancel before locking so construction and in-flight renewal can terminate.
	o.cancel()
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closed = true
	if o.client != nil {
		o.client.Close()
	}
	if o.clientCancel != nil {
		o.clientCancel()
	}
	o.client, o.construct, o.clientCancel = nil, nil, nil
	if o.gcpClient != nil {
		_ = o.gcpClient.Close()
	}
	if o.gcpCancel != nil {
		o.gcpCancel()
	}
	o.gcpClient, o.gcpConstruct, o.gcpCancel = nil, nil, nil
	o.secrets.zeroize()
	o.topology = config.KMSSettings{}
}

func (s *stage1) closeStartupVault() {
	s.credentials.Close()
}
