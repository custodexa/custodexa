package keyvault

import "github.com/custodexa/backend/pkg/crypto"

// 資料層 AAD 綁定身分的單一事實源。
//
// **AAD 綁 `table|column`，不綁主鍵**——故每個登記欄位的 CipherRef 是**常數**，
// 呼叫端於 insert 之前即可完成加密，**不需兩階段寫入**。這正是不綁 pk 相對於
// 「綁 pk」方案的核心工程紅利。
//
// 本檔與 envelopeMigrationTargets 必須逐項對應：登記表是 DEK 輪替重加密、
// legacy pending 判定、退役 DEK 銷毀前引用掃描與 AAD 遷移的共同來源；
// 若某欄位有 CipherRef 卻未登記（或反之），AAD 遷移就會漏掉該欄而使
// 「殘餘為 0」的把關失真。守衛：TestCipherRefsMatchMigrationTargets。
var (
	// assets
	RefAssetsSftpPassword = crypto.CipherRef{Table: "assets", Column: "sftp_password_enc"}
	// assets 的 password_enc／private_key_enc 自資產多帳號階段 2 起
	// **凍結不再寫入**（密文只落 asset_accounts），此處僅供遷移登記對應與
	// 潛在的歷史讀取路徑
	RefAssetsPassword   = crypto.CipherRef{Table: "assets", Column: "password_enc"}
	RefAssetsPrivateKey = crypto.CipherRef{Table: "assets", Column: "private_key_enc"}

	// asset_accounts（憑證本體的現行落點）
	RefAccountPassword   = crypto.CipherRef{Table: "asset_accounts", Column: "password_enc"}
	RefAccountPrivateKey = crypto.CipherRef{Table: "asset_accounts", Column: "private_key_enc"}

	// change_secret_candidates：未驗證的候選憑證。
	// 與 asset_accounts 的兩欄刻意分立——候選是短命的「可能已在遠端生效」副本，
	// 與帳號現行憑證是不同的信任面，共用 ref 會使兩者的 AAD 綁定無從區分
	RefChangeSecretCandidatePassword   = crypto.CipherRef{Table: "change_secret_candidates", Column: "password_enc"}
	RefChangeSecretCandidatePrivateKey = crypto.CipherRef{Table: "change_secret_candidates", Column: "private_key_enc"}

	// users
	RefUserTOTPSecret = crypto.CipherRef{Table: "users", Column: "totp_secret_enc"}

	// export_signing_keys
	RefExportSigningPrivateKey = crypto.CipherRef{Table: "export_signing_keys", Column: "private_key_enc"}

	// checkpoint_signing_keys（audit-checkpoint-chain）：檢查點鏈的 Ed25519
	// 私鑰。與匯出簽章鑰刻意分立——共用會使任一鑰的輪替／洩漏綁死兩個信任面
	RefCheckpointSigningPrivateKey = crypto.CipherRef{Table: "checkpoint_signing_keys", Column: "private_key_enc"}

	// notification_channels
	RefChannelSecret = crypto.CipherRef{Table: "notification_channels", Column: "secret"}
	RefChannelURL    = crypto.CipherRef{Table: "notification_channels", Column: "url"}

	// oidc_providers
	RefOIDCClientSecret = crypto.CipherRef{Table: "oidc_providers", Column: "client_secret_enc"}

	// ldap_directories
	RefLDAPBindPassword = crypto.CipherRef{Table: "ldap_directories", Column: "bind_password_enc"}

	// clipboard_events：RDP/VNC 剪貼簿
	// 留存內容。與憑證類欄位不同，這是**被監控者產生的原始材料本體**——
	// 落庫即密文（明文欄已於同一次改動移除），列表與匯出只回事實投影，
	// 內容僅經單筆調閱端點（逐筆留痕）與證據包（匯出留痕）解密取得
	RefClipboardContent = crypto.CipherRef{Table: "clipboard_events", Column: "content_enc"}
)

// allCipherRefs 供守衛測試逐項比對登記表
var allCipherRefs = []crypto.CipherRef{
	RefAssetsPassword, RefAssetsPrivateKey, RefAssetsSftpPassword,
	RefAccountPassword, RefAccountPrivateKey,
	RefChangeSecretCandidatePassword, RefChangeSecretCandidatePrivateKey,
	RefUserTOTPSecret, RefExportSigningPrivateKey, RefCheckpointSigningPrivateKey,
	RefChannelSecret, RefChannelURL,
	RefOIDCClientSecret,
	RefLDAPBindPassword,
	RefClipboardContent,
}
