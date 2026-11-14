package main

import (
	"context"
	"errors"
	"testing"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 改密計畫的執行授權重驗（範圍）：以 API token 建立計畫時，除了計畫頁的目標可見範圍，另以背景執行前重驗所用的
// 執行授權判定檢查最新目標的執行範圍。正式組合下兩者同取執行能力的範圍，可見範圍先擋下範圍外目標，執行範圍那一層
// 單獨驗不到；這裡把可見範圍放寬為全部（「看得到也管得到目標」），其餘元件與判定器沿用正式實作，
// 證明執行範圍的判定本身會拒絕。

// widenedViewScope 計畫頁的目標可見範圍放寬為全部，其餘判定沿用正式實作。
type widenedViewScope struct{ *authz.ChangeSecretScope }

func (widenedViewScope) ViewScope(context.Context, *gorm.DB, uint, string) (asset.ChangeSecretAssetScope, error) {
	return asset.ChangeSecretAssetScope{}, nil
}

// planRequestContext 與正式請求鏈相同的 context：請求憑證種類、請求主體、審計用的操作者鍵。
func planRequestContext(t *testing.T, db *gorm.DB, who cmpIdentity, kind model.RequestCredential, filter []uint) context.Context {
	t.Helper()
	facts := authz.TokenFacts{SubjectKind: model.KindHuman}
	if kind == model.RequestCredentialAPIToken {
		facts.AuthMethod = "api_token"
		facts.RoleFilter = authz.NewRoleFilter(filter)
	}
	p, err := authz.ResolveUserOn(db, who.userID, facts)
	if err != nil {
		t.Fatalf("解析請求主體：%v", err)
	}
	ctx := authz.ContextWithPrincipal(model.WithRequestCredential(context.Background(), kind), p)
	ctx = context.WithValue(ctx, "userID", who.userID)     //nolint:staticcheck // 沿用既有審計 context 慣例
	ctx = context.WithValue(ctx, "username", who.username) //nolint:staticcheck // 沿用既有審計 context 慣例
	return ctx
}

// TestAPITokenPlanRunScopeRecheckedForVisibleTarget token 持有執行能力但只在節點範圍內，目標可見卻在執行範圍外：
// 建立以執行授權的範圍拒絕被拒、不寫入；同一 token 對範圍內目標照常建立；同一請求以人類工作階段送出照常建立。
func TestAPITokenPlanRunScopeRecheckedForVisibleTarget(t *testing.T) {
	apiTokenBaselineGate(t)
	e := newBaselineEnv(t)
	ag1 := e.object("assetGroup.1").(uint)
	node := e.apiTokenNodePair(ag1)
	e.apiTokenRetemplate()
	inAsset := e.object("asset.ssh").(uint)
	outAsset := e.object("asset.approval").(uint)

	eval := newScopeEvaluatorOn(asset.NewScopeTopologyReader())
	mgmt := newCredentialManagementAdapter(authz.NewResolver(e.db)).withScope(eval, e.db)
	svc := asset.NewChangeSecretPlanService(e.db).WithAuthorizer(mgmt).WithAuditSink(audit.NewTxSink()).
		WithScope(widenedViewScope{authz.NewChangeSecretScope(eval)}, authz.NewCredentialScopeReader(eval, e.db))
	disabled := false
	req := func(name string, assetID uint) *asset.ChangeSecretPlanRequest {
		return &asset.ChangeSecretPlanRequest{Name: name, AssetIDs: []uint{assetID}, Accounts: []string{"baseline-root"},
			Cron: "0 3 * * *", Enabled: &disabled}
	}
	tokenCtx := planRequestContext(t, e.db, node.tokenSelf, model.RequestCredentialAPIToken, node.grantedRole)

	before := e.apiTokenCount("change_secret_plans", "")
	_, err := svc.Create(tokenCtx, req("cmp-plan-out-of-run-scope", outAsset))
	var runErr *asset.PlanRunAuthorizationError
	if !errors.As(err, &runErr) {
		t.Fatalf("應以執行授權拒絕，得到 %v", err)
	}
	var denied *authz.ErrScopeDenied
	if !errors.As(runErr.Err, &denied) {
		t.Errorf("拒絕原因應是執行範圍（範圍拒絕），得到 %T %v", runErr.Err, runErr.Err)
	}
	var capErr *asset.CapabilityDeniedError
	if errors.As(runErr.Err, &capErr) {
		t.Errorf("token 持有執行能力，拒絕原因不應是缺能力：%v", capErr)
	}
	if n := e.apiTokenCount("change_secret_plans", ""); n != before {
		t.Errorf("被拒卻寫入了計畫：%d→%d", before, n)
	}
	e.apiTokenRuleRestore()

	if _, err := svc.Create(tokenCtx, req("cmp-plan-in-run-scope", inAsset)); err != nil {
		t.Errorf("執行範圍內的目標應照常建立：%v", err)
	}
	e.apiTokenRuleRestore()

	humanCtx := planRequestContext(t, e.db, node.humanSelf, model.RequestCredentialHumanSession, nil)
	if _, err := svc.Create(humanCtx, req("cmp-plan-human", outAsset)); err != nil {
		t.Errorf("人類工作階段的保存不做執行授權重驗（到期執行前才重驗），應照常建立：%v", err)
	}
	e.apiTokenRuleRestore()
}

// TestAPITokenScheduledPlanRunRowsNotAttributed 排程日後執行所產生的稽核列不帶 token 標示：token 建立計畫的那次請求，
// 其落地列帶標示；之後排程入口以背景脈絡執行（所屬帳號的角色已被收回，執行前重驗即停止），停止的留痕列不帶標示，
// 操作者為計畫授權脈絡上的帳號。
func TestAPITokenScheduledPlanRunRowsNotAttributed(t *testing.T) {
	apiTokenBaselineGate(t)
	e := newBaselineEnv(t)
	super := seedAPITokenPairs(e)[0]
	sshAsset := e.object("asset.ssh").(uint)

	before := e.maxAuditID()
	code, body := e.apiTokenRuleCall(super.token, "POST", "/api/v1/change-secret-plans", map[string]any{
		"name": "cmp-scheduled-plan", "asset_ids": []uint{sshAsset}, "accounts": []string{"baseline-root"},
		"cron": "0 3 * * *", "enabled": true})
	if !is2xx(code) {
		t.Fatalf("token 建立計畫應成功，得到 %d %v", code, body)
	}
	created := e.auditRowsAfter(before)
	if len(created) == 0 {
		t.Fatal("建立計畫應留下稽核列")
	}
	for _, r := range created {
		if r.APITokenID == nil || *r.APITokenID != super.tokenID {
			t.Errorf("建立計畫的請求列應帶 token 標示：%s", describeAuditRows([]model.AuditLog{r}))
		}
	}
	var plan model.ChangeSecretPlan
	if err := e.db.Where("name = ?", "cmp-scheduled-plan").First(&plan).Error; err != nil {
		t.Fatalf("讀取計畫：%v", err)
	}
	if err := e.db.Where("user_id = ?", super.tokenSelf.userID).Delete(&model.UserRole{}).Error; err != nil {
		t.Fatalf("收回所屬帳號的角色：%v", err)
	}

	eval := newScopeEvaluatorOn(asset.NewScopeTopologyReader())
	runner := asset.NewChangeSecretRunner(e.db, nil, nil, nil, nil).
		WithManagementAuthorizer(newCredentialManagementAdapter(authz.NewResolver(e.db)).withScope(eval, e.db)).
		WithAuditSink(audit.NewTxSink())
	before = e.maxAuditID()
	runner.RunPlan(&plan)
	awaitBackground(t)
	rows := e.auditRowsAfter(before)
	if !auditRowsHave(rows, `"authorization_stop"`) {
		t.Fatalf("排程執行應以重驗失敗停止並留痕：%s", describeAuditRows(rows))
	}
	for _, r := range rows {
		if r.APITokenID != nil || r.APITokenName != nil {
			t.Errorf("排程執行產生的列不應帶 token 標示：%s", describeAuditRows([]model.AuditLog{r}))
		}
		if r.UserID != super.tokenSelf.userID {
			t.Errorf("排程執行的列操作者應為計畫授權脈絡上的帳號：%s", describeAuditRows([]model.AuditLog{r}))
		}
	}
	e.apiTokenRuleRestore()
}
