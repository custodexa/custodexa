package main

import (
	"errors"
	"fmt"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/modules/asset"
)

// 編譯期只證明型別有方法；注入與否由 require 在啟動時證明。
var _ api.RotationMemberProjection = (*asset.CredentialRotationService)(nil)

// scopedOutputWiring 範圍化輸出投影的注入狀態；正式組裝由 collectScopedOutputWiring 自 handler 取得。
type scopedOutputWiring struct {
	accountCredentialScope bool // 帳號 handler 的憑證投影來源
	accountRowProjector    bool // 憑證 handler 的帳號列投影器
	rotationProjection     bool // 憑證 handler 的輪替成員投影已注入
	rotationOutputScope    bool // 輪替成員投影的輸出判定已注入
	changeSecretOutput     bool // 改密 handler 的輸出判定
	candidatePlanScope     bool // 候選服務的計畫範圍判定
}

func collectScopedOutputWiring(accounts *api.AssetAccountHandler, creds *api.CredentialHandler,
	changeSecret *api.ChangeSecretHandler) scopedOutputWiring {
	return scopedOutputWiring{
		accountCredentialScope: accounts.AccountRowProjectorWired(),
		accountRowProjector:    creds.AccountRowProjectorWired(),
		rotationProjection:     creds.RotationProjectionInjected(),
		rotationOutputScope:    creds.RotationProjectionWired(),
		changeSecretOutput:     changeSecret.CredentialOutputScopeWired(),
		candidatePlanScope:     changeSecret.CandidateScopeWired(),
	}
}

// require 任一項不成立回錯誤並指出是哪一項；組裝根據此拒絕啟動。
func (w scopedOutputWiring) require() error {
	checks := []struct {
		ok   bool
		name string
	}{
		{w.accountCredentialScope, "帳號 handler 的憑證投影來源未注入"},
		{w.accountRowProjector, "憑證 handler 的帳號列投影器未注入"},
		{w.rotationProjection, "憑證 handler 的輪替成員投影未注入"},
		{w.rotationOutputScope, "輪替成員投影的輸出判定未注入"},
		{w.changeSecretOutput, "改密 handler 的輸出判定未注入"},
		{w.candidatePlanScope, "候選服務的計畫範圍判定未注入"},
	}
	var errs []error
	for _, c := range checks {
		if !c.ok {
			errs = append(errs, errors.New(c.name))
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("範圍化輸出投影未完整注入，拒絕啟動: %w", errors.Join(errs...))
}
