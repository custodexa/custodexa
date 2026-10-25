package main

import (
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
)

// TestAuthorizationScopeStartupGate 組裝期閘：授權規則寫入的範圍判定、撤銷的範圍判定與交易內審計
// 任一未注入，自檢回錯誤（stage2 據此拒絕啟動）；全部注入後通過。
func TestAuthorizationScopeStartupGate(t *testing.T) {
	db := newSAEnv(t).db
	scope := authz.NewAuthorizationWriteScope(authz.NewAuthorizationScopeEvaluator(authz.ProductCatalogue(), asset.NewScopeTopologyReader()))

	t.Run("write_scope_missing_refuses", func(t *testing.T) {
		err := requireAuthorizationWriteScope(authz.NewAssetAuthorizationService(db))
		require.Error(t, err)
		require.True(t, errors.Is(err, authz.ErrAuthorizationScopeMissing))
	})
	t.Run("write_scope_injected_passes", func(t *testing.T) {
		svc := authz.NewAssetAuthorizationService(db)
		svc.SetWriteScope(scope)
		require.NoError(t, requireAuthorizationWriteScope(svc))
	})
	t.Run("revoke_wiring_missing_refuses", func(t *testing.T) {
		svc := authz.NewAccessRequestService(db, nil, nil, nil, nil)
		err := requireAccessRequestRevokeWiring(svc)
		require.Error(t, err)
		require.True(t, errors.Is(err, authz.ErrRevokeWiringIncomplete))
	})
	t.Run("revoke_scope_only_refuses", func(t *testing.T) {
		svc := authz.NewAccessRequestService(db, nil, nil, nil, nil)
		svc.SetRevokeScope(scope)
		require.Error(t, requireAccessRequestRevokeWiring(svc))
	})
	t.Run("revoke_sink_only_refuses", func(t *testing.T) {
		svc := authz.NewAccessRequestService(db, nil, nil, nil, nil)
		svc.SetAuditTxSink(audit.NewTxSink())
		require.Error(t, requireAccessRequestRevokeWiring(svc))
	})
	t.Run("revoke_typed_nil_sink_refuses", func(t *testing.T) {
		svc := authz.NewAccessRequestService(db, nil, nil, nil, nil)
		svc.SetRevokeScope(scope)
		var typedNil *nilSink
		svc.SetAuditTxSink(typedNil)
		require.Error(t, requireAccessRequestRevokeWiring(svc))
	})
	t.Run("revoke_both_injected_passes", func(t *testing.T) {
		svc := authz.NewAccessRequestService(db, nil, nil, nil, nil)
		svc.SetRevokeScope(scope)
		svc.SetAuditTxSink(audit.NewTxSink())
		require.NoError(t, requireAccessRequestRevokeWiring(svc))
	})

	// stage2 的組裝順序：先注入、再自檢、自檢失敗即 fail（啟動不成立）
	t.Run("stage2_calls_gate_and_fails", func(t *testing.T) {
		src, err := os.ReadFile("stage2.go")
		require.NoError(t, err)
		text := string(src)
		for _, c := range []struct{ inject, check, step string }{
			{"authorizationService.SetWriteScope(", "requireAuthorizationWriteScope(authorizationService)", "authorizationWriteScope"},
			{"accessRequestService.SetAuditTxSink(", "requireAccessRequestRevokeWiring(accessRequestService)", "accessRequestRevokeWiring"},
		} {
			in, ck := strings.Index(text, c.inject), strings.Index(text, c.check)
			require.True(t, in >= 0 && ck > in, "%s 須在注入之後呼叫", c.check)
			require.Regexp(t, regexp.MustCompile(regexp.QuoteMeta(c.check)+`; err != nil \{\s*return fail\("`+c.step+`", err\)`), text)
		}
	})
}

// nilSink 供具型別 nil 的注入案例。
type nilSink struct{}

func (*nilSink) WriteInTx(_ *gorm.DB, _ port.AuditEvent) error { return nil }
