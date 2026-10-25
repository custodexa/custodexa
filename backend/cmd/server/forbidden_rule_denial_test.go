package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 規則拒絕的文案分類：決定該碼的文案要驗什麼。
//   - classOperator：文案原本指出操作者所需的身分，已改寫，須等於新文案且不含權限鍵與角色詞。
//   - classNone：沒有身分字眼，原文保留，並套同一組不含權限鍵與角色詞的斷言。
//   - classTarget、classHelp：描述目標屬性或給求助指引，原文逐字保留，不做角色詞掃描。
const (
	classOperator = "operator"
	classNone     = "none"
	classTarget   = "target"
	classHelp     = "help"
)

type ruleDenialCase struct {
	code   apierror.ErrCode
	status int
	class  string
	zh     string
	en     string
	ja     string
}

// ruleDenialCases 規則拒絕子案例的期望文案：保留碼取基底原文，改寫碼取新文案。
// 這 32 碼都沒有以 HTTP 觸發：寫出點分散在各 handler 與服務層，各自需要不同的資料夾具與狀態，
// 而本守衛要驗的是文案與回應形狀，不是各處的判定條件，所以改在寫出函式層級斷言：
// 經 apierror.Write 實際產生回應，核對本文鍵、碼、錯誤文字，並讀三語 locale 逐字比對。
var ruleDenialCases = []ruleDenialCase{
	{"AUTH_AGENT_FORBIDDEN_ROUTE", 403, classNone, "自動化主體不可使用此端點", "Agents cannot access this endpoint", "エージェントはこのエンドポイントを利用できません"},
	{"AUTH_ASSET_CONNECT_DENIED", 403, classHelp, "您沒有連線此資產的權限，請聯絡管理員", "You do not have permission to connect to this asset; contact an administrator", "この資産へ接続する権限がありません。管理者にお問い合わせください"},
	{"AUTH_EXPORT_JOB_REQUESTER_ONLY", 403, classTarget, "匯出產物僅限申請者本人下載", "Export artifacts can only be downloaded by the requester", "エクスポート成果物は申請者本人のみダウンロードできます"},
	{"AUTH_LDAP_TRANSPORT_REJECTED", 403, classHelp, "LDAP 登入被傳輸安全政策拒絕：目錄連線未達加密要求，請管理員於身分管理的目錄設定頁改用 ldaps://", "LDAP login rejected by the transport security policy: the directory connection does not meet encryption requirements. Ask an administrator to switch the directory to ldaps:// on the directory settings page under Identity Management", "LDAP ログインが伝送セキュリティポリシーにより拒否されました：ディレクトリ接続が暗号化要件を満たしていません。管理者に ID 管理のディレクトリ設定ページで ldaps:// に変更するよう依頼してください"},
	{"AUTH_MONITOR_REVOKED", 403, classNone, "監看連線已因憑證撤銷而中止，請重新登入", "Monitoring session ended because your credentials were revoked. Please sign in again.", "認証情報が失効したため監視接続を終了しました。再度ログインしてください。"},
	{"AUTH_OIDC_ADMISSION_DENIED", 403, classHelp, "您的帳號不符合此登入方式的准入條件，請聯絡管理員", "Your account does not meet the admission requirements for this sign-in method. Please contact an administrator", "お使いのアカウントはこのログイン方法の受け入れ条件を満たしていません。管理者にお問い合わせください"},
	{"AUTH_PROTECTED_ACCOUNT_OPERATION", 403, classOperator, "這個帳號受保護，你無法執行此操作", "This account is protected. You cannot perform this operation", "このアカウントは保護されています。この操作は実行できません"},
	{"AUTH_PROTECTED_ROLE_ASSIGNMENT", 403, classOperator, "這個指派涉及受保護的角色，你無法執行此操作", "This assignment involves a protected role. You cannot perform this operation", "この割り当ては保護されたロールを含むため、実行できません"},
	{"AUTH_REQUEST_ITEM_MISMATCH", 403, classNone, "存取申請項目不符", "Access request item mismatch", "アクセス申請項目が一致しません"},
	{"AUTH_SOURCE_NOT_ALLOWED", 403, classHelp, "目前的來源位址不在允許範圍內，請聯絡管理員", "Your current source address is outside the allowed range. Contact an administrator.", "現在の送信元アドレスは許可範囲に含まれていません。管理者にお問い合わせください"},
	{"AUTH_TAG_FILTER_PRIVILEGED_ONLY", 400, classOperator, "你的帳號不能使用標籤篩選", "Your account cannot use tag filtering", "お使いのアカウントではタグ絞り込みを利用できません"},
	{"AUTH_USER_INACTIVE", 403, classNone, "使用者帳號未啟用", "User account is not activated", "ユーザーアカウントが有効化されていません"},
	{"RULE_ACCESS_APPROVAL_REQUIRED", 403, classNone, "本資產的存取政策要求申請核准後連線", "The access policy for this asset requires an approved request before connecting", "この資産のアクセスポリシーでは、接続前に申請の承認が必要です"},
	{"RULE_ACCESS_REASON_REQUIRED", 403, classNone, "本資產的存取政策要求填寫事由後連線", "The access policy for this asset requires a stated reason before connecting", "この資産のアクセスポリシーでは、接続前に理由の入力が必要です"},
	{"RULE_ACCESS_REQUEST_NOT_ELIGIBLE_APPROVER", 403, classTarget, "申請資產不在您的審核範圍內", "The requested asset is outside your approver scope", "申請されたアセットはあなたの承認範囲外です"},
	{"RULE_ACCESS_REQUEST_REQUESTER_EXEMPT", 403, classNone, "此角色不需或不得提出連線申請", "This role does not need to, or may not, submit connection requests", "このロールは接続申請を行う必要がない、または行えません"},
	{"RULE_ACCESS_REQUEST_SELF_APPROVAL", 403, classNone, "不得核准或拒絕自己的申請", "You cannot approve or reject your own request", "自分の申請を承認または却下することはできません"},
	{"RULE_ACCESS_TICKET_NOT_REVOKE_ELIGIBLE", 403, classOperator, "你沒有撤銷這筆臨時授權的資格", "You are not eligible to revoke this temporary grant", "この一時権限を取り消す資格がありません"},
	{"RULE_ACCOUNT_SCOPE_WIDEN_RESTRICTED", 403, classOperator, "非規則建立者只能縮小帳號範圍，不能擴大", "You can only narrow the account scope of this rule; widening it is not allowed", "ルール作成者以外はアカウント範囲を狭めることのみ可能で、広げることはできません"},
	{"RULE_AGENT_SELF_CREATE_DISABLED", 403, classNone, "未開放自助建立自動化帳號", "Self-service agent creation is disabled", "エージェントのセルフサービス作成は無効です"},
	{"RULE_AGENT_SELF_CREATE_LIMIT", 403, classNone, "名下自動化帳號已達自助建立上限", "Your agents have reached the self-service creation limit", "所有するエージェント数が作成上限に達しています"},
	{"RULE_ALERT_BATCH_SELF_TRIGGERED", 403, classNone, "自己連線觸發的告警不納入批次，請逐筆審閱", "Alerts triggered by your own sessions are not included in a batch; review them one at a time", "自分の接続で発生したアラートは一括処理の対象外です。1 件ずつレビューしてください"},
	{"RULE_APPROVER_SCOPE_NOT_APPROVER_ROLE", 400, classTarget, "目標使用者不具 approver 角色", "The target user does not have the approver role", "対象ユーザーは approver ロールを持っていません"},
	{"RULE_ASSET_DISABLED", 403, classNone, "資產已停用，無法連線", "The asset is disabled and cannot be connected to", "この資産は無効化されているため接続できません"},
	{"RULE_AUTHORIZATION_SELF_SUBJECT", 403, classTarget, "不得對自己、自己所屬的群組或自己擁有的 agent 建立或調整授權規則", "You cannot create or modify authorization rules for yourself, a group you belong to, or an agent you own", "自分自身、所属するグループ、または所有する agent を対象とする権限付与ルールは作成・変更できません"},
	{"RULE_BREAK_GLASS_DISABLED", 403, classNone, "破窗緊急連線未開放", "Break-glass emergency access is not enabled", "緊急接続（ブレークグラス）は有効ではありません"},
	{"RULE_BREAK_GLASS_NOT_ELIGIBLE", 403, classTarget, "無破窗資格（需持有該資產的常設連線授權）", "Not eligible for break-glass access (a standing connection grant for this asset is required)", "緊急接続の資格がありません（当該アセットの常設接続権限が必要です）"},
	{"RULE_BREAK_GLASS_SELF_REVIEW", 403, classNone, "不得補審自己的破窗連線", "You cannot review your own break-glass session", "自分の緊急接続を事後レビューすることはできません"},
	{"RULE_RECORDING_UNAVAILABLE", 403, classHelp, "錄影儲存異常，暫停新連線，請聯絡管理員", "Recording storage is unhealthy; new connections are suspended. Please contact an administrator", "録画ストレージに異常があるため新規接続を停止しています。管理者に連絡してください"},
	{"RULE_SESSION_RECORD_FAILED", 403, classNone, "會話記錄建立失敗，連線已中止", "Could not create the session record; the connection was aborted", "セッション記録の作成に失敗したため、接続を中止しました"},
	{"RULE_TRANSFER_DENIED", 403, classNone, "資料傳輸已被安全政策禁止（{action}，來源：{reason}）", "This data transfer is blocked by security policy ({action}, source: {reason})", "このデータ転送はセキュリティポリシーにより禁止されています（{action}、出所：{reason}）"},
	{"RULE_USER_LAST_ADMIN_DELETE", 400, classTarget, "不能刪除最後一個管理員帳號", "Cannot delete the last administrator account", "最後の管理者アカウントは削除できません"},
}

func readRuleDenialLocale(t *testing.T, lang string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(shapeLocaleDir(t), lang+".json"))
	require.NoError(t, err, lang)
	var doc struct {
		APIError map[string]any `json:"apiError"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc), lang)
	out := map[string]string{}
	for k, v := range doc.APIError {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

// sampleRuleDenialParams 為帶參數的碼取每個列舉參數的第一個合法值，讓回應能實際產生。
func sampleRuleDenialParams(t *testing.T, d apierror.Descriptor) map[string]any {
	t.Helper()
	if len(d.Params) == 0 {
		return nil
	}
	params := map[string]any{}
	for _, p := range d.Params {
		switch p.Kind {
		case apierror.ParamEnum:
			keys := make([]string, 0, len(p.ZhLabels))
			for k := range p.ZhLabels {
				keys = append(keys, k)
			}
			require.NotEmpty(t, keys, p.Key)
			params[p.Key] = keys[0]
		case apierror.ParamInt:
			params[p.Key] = 1
		default:
			params[p.Key] = "x"
		}
	}
	return params
}

func testRuleDenialSubcases(t *testing.T) {
	roleNames := shapeRoleNames(t)
	require.GreaterOrEqual(t, len(roleNames), 9, "三語譯名集合不得為空殼")
	var catalogKeys []string
	for _, d := range authz.Catalog() {
		catalogKeys = append(catalogKeys, string(d.Key))
	}
	require.NotEmpty(t, catalogKeys)
	loc := map[string]map[string]string{}
	for _, lang := range []string{"zh-TW", "en-US", "ja-JP"} {
		loc[lang] = readRuleDenialLocale(t, lang)
	}
	require.Len(t, ruleDenialCases, 32, "子案例須涵蓋 32 碼")

	assertNoOperatorIdentity := func(t *testing.T, label, text string) {
		t.Helper()
		lower := strings.ToLower(text)
		for _, k := range catalogKeys {
			assert.NotContains(t, lower, strings.ToLower(k), "%s：不得含權限鍵", label)
		}
		for _, w := range []string{"admin", "auditor", "approver"} {
			assert.NotContains(t, lower, w, "%s：不得含角色詞", label)
		}
		for _, n := range roleNames {
			assert.NotContains(t, text, n, "%s：不得含角色譯名", label)
		}
	}

	seen := map[apierror.ErrCode]bool{}
	for _, c := range ruleDenialCases {
		c := c
		require.False(t, seen[c.code], "重複的子案例 %s", c.code)
		seen[c.code] = true
		t.Run("規則拒絕/"+string(c.code), func(t *testing.T) {
			d, ok := apierror.DescriptorOf(c.code)
			require.True(t, ok, "碼須已登記")
			assert.False(t, d.AuditOnly, "回應碼不得為僅審計碼")
			assert.Equal(t, c.zh, d.ZhFallback, "繁中 fallback")
			for lang, want := range map[string]string{"zh-TW": c.zh, "en-US": c.en, "ja-JP": c.ja} {
				assert.Equal(t, want, loc[lang][string(c.code)], "%s 譯文", lang)
			}

			// 經寫出函式實際產生回應。
			gin.SetMode(gin.TestMode)
			w := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(w)
			ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)
			params := sampleRuleDenialParams(t, d)
			apierror.Write(ctx, c.status, apierror.ErrorResponse{Code: c.code, Params: params})
			assert.Equal(t, c.status, w.Code, "狀態")
			var body map[string]any
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body), w.Body.String())
			assert.Equal(t, string(c.code), body["code"], "碼")
			msg, _ := body["error"].(string)
			require.NotEmpty(t, msg, "error 文字")
			if len(params) == 0 {
				assert.Equal(t, c.zh, msg, "回應 error 即 fallback 原文")
			}
			// 不經本函式改動的 metadata 欄：本文鍵只可能是 code、error、params 類，不得帶權限或角色欄。
			for k := range body {
				assert.NotContains(t, []string{"required_permission", "required_role", "role"}, k, "本文不得帶權限或角色欄")
			}

			switch c.class {
			case classOperator, classNone:
				assertNoOperatorIdentity(t, "回應原文", w.Body.String())
				assertNoOperatorIdentity(t, "zh-TW 譯文", c.zh)
				assertNoOperatorIdentity(t, "en-US 譯文", c.en)
				assertNoOperatorIdentity(t, "ja-JP 譯文", c.ja)
			case classTarget, classHelp:
				// 目標屬性與求助指引：只驗逐字等於基底原文（上方的 fallback 與三語相等斷言），不掃角色詞。
			default:
				t.Fatalf("未知分類 %q", c.class)
			}
		})
	}
}
