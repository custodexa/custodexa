package asset

import (
	"context"
	"errors"
	"github.com/custodexa/backend/internal/modules/audit"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/require"
)

type materialLifecycleExecutor struct {
	rotate func(context.Context) error
	verify func(context.Context) error
}

func (e materialLifecycleExecutor) Rotate(ctx context.Context, _ rotationTarget, _, _ []byte) error {
	return e.rotate(ctx)
}
func (e materialLifecycleExecutor) Verify(ctx context.Context, _ rotationTarget, _ []byte) error {
	return e.verify(ctx)
}

func TestRotationMemberMaterialLifecycle(t *testing.T) {
	t.Run("key_restore_failure_return", testMemberKeyRollback)
	for _, mode := range []string{"success", "deliver_failure", "verify_failure_retry", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f := setupRotationFixture(t)
			credID, accounts := f.sharedOn(t, "owned-rotation", "ops", "old-fixture", "10.9.8.7")
			rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
			require.NoError(t, err)
			trace := &materialTrace{BytesColumnCodec: f.assets.bytesCrypto}
			f.assets.bytesCrypto = trace
			f.assets.resolver.crypto = trace
			f.candidates.bytesCrypto = trace
			ctx, cancel := context.WithCancel(adminCtx())
			defer cancel()
			f.rotations.executors = func(string) rotationExecutor {
				return materialLifecycleExecutor{
					rotate: func(ctx context.Context) error {
						trace.live(t)
						if mode == "cancel" {
							cancel()
							return ctx.Err()
						}
						if mode == "deliver_failure" {
							return errors.New("injected delivery failure")
						}
						return nil
					},
					verify: func(context.Context) error {
						trace.live(t)
						if mode == "verify_failure_retry" {
							return errors.New("injected verify failure")
						}
						return nil
					},
				}
			}
			_ = f.rotations.Run(ctx, rot.ID)
			trace.zero(t)
			if mode == "verify_failure_retry" {
				member := f.memberFor(t, rot.ID, accounts[0])
				require.Equal(t, model.CredentialMemberChangedUnverified, member.State)
				trace.buffers = nil
				mode = "success"
				require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, member.ID))
				trace.zero(t)
				require.Equal(t, model.CredentialMemberApplied, f.memberFor(t, rot.ID, accounts[0]).State)
			}
			if mode == "success" {
				require.Equal(t, model.CredentialMemberApplied, f.memberFor(t, rot.ID, accounts[0]).State)
			}
		})
	}
}

func testMemberKeyRollback(t *testing.T) {
	f := setupChangeSecretFixture(t, "root", "fixture-password")
	require.NoError(t, f.db.AutoMigrate(&model.CredentialRotation{}, &model.CredentialRotationMember{}))
	old, oldLine := testKeyPair(t, "old-fixture")
	original := oldLine + "\n"
	f.server.seedAuthorizedKeys(original)
	require.NoError(t, f.assets.UpdatePrivateKey(f.assetID, f.accountID, f.username, old))
	f.server.mu.Lock()
	f.server.authorizedKeys = func() string { return original }
	f.server.mu.Unlock()
	var account model.AssetAccount
	require.NoError(t, f.db.First(&account, f.accountID).Error)
	require.NoError(t, f.db.Model(&model.Credential{}).Where("id = ?", account.CredentialID).Update("secret_type", model.ChangeSecretTypeSSHKey).Error)
	rotations := NewCredentialRotationService(f.db, f.assets, f.candidates, f.hostKeys, f.assets.crypto, audit.NewTxSink(), &fakePermissionChecker{defaultAllow: true})
	rot, err := rotations.Start(adminCtx(), account.CredentialID, StartRotationRequest{})
	require.NoError(t, err)
	trace := &materialTrace{BytesColumnCodec: f.assets.bytesCrypto}
	f.assets.bytesCrypto = trace
	f.assets.resolver.crypto = trace
	f.candidates.bytesCrypto = trace
	require.NoError(t, rotations.Run(adminCtx(), rot.ID))
	trace.zero(t)
	require.Equal(t, keyMaterial(oldLine), keyMaterial(strings.TrimSpace(readAuthorizedKeysFile(t, f.server))))
	var member model.CredentialRotationMember
	require.NoError(t, f.db.Where("rotation_id = ?", rot.ID).First(&member).Error)
	require.Contains(t, []string{model.CredentialMemberRetryWait, model.CredentialMemberTerminalFailed}, member.State)
}

func TestCandidateSecretZeroize(t *testing.T) {
	for _, mode := range []string{"success", "second_field_failure", "empty"} {
		t.Run(mode, func(t *testing.T) {
			codec := &trackedMaterialCodec{}
			svc := &ChangeSecretCandidateService{bytesCrypto: codec}
			cand := &model.ChangeSecretCandidate{PasswordEnc: "password-fixture", PrivateKeyEnc: "key-fixture"}
			if mode == "second_field_failure" {
				codec.failAt = 2
			}
			if mode == "empty" {
				cand.PasswordEnc = ""
				cand.PrivateKeyEnc = ""
			}
			out, err := svc.Secret(context.Background(), cand)
			if mode == "second_field_failure" {
				require.ErrorContains(t, err, "injected decrypt failure")
				require.Nil(t, out.Password)
				require.Nil(t, out.PrivateKey)
			} else {
				require.NoError(t, err)
				if mode == "success" {
					require.NoError(t, out.Password.Borrow(func(raw []byte) error { require.Equal(t, []byte("password-fixture"), raw); return nil }))
				}
				out.Destroy()
			}
			for _, raw := range codec.buffers {
				require.Equal(t, make([]byte, len(raw)), raw)
			}
		})
	}
}

func TestCandidatePromotionMaterialLifecycle(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "retry_promote", true: "promote_failure"}[fail], func(t *testing.T) {
			f := setupChangeSecretFixture(t, "root", "fixture-password")
			cand, err := f.candidates.Create(context.Background(), CandidateInput{AssetID: f.assetID, AccountID: f.accountID, AccountUsername: f.username, SecretType: model.ChangeSecretTypePassword, Password: "fixture-password"})
			require.NoError(t, err)
			trace := &materialTrace{BytesColumnCodec: f.assets.bytesCrypto}
			f.candidates.bytesCrypto = trace
			f.assets.bytesCrypto = trace
			if fail {
				cand.AccountID += 1000
			}
			promoted := f.retry.RetryOne(cand)
			require.Equal(t, !fail, promoted)
			require.Equal(t, 2, trace.calls, "verification and commit decrypt independently")
			require.Len(t, trace.buffers, 2)
			require.NotSame(t, &trace.buffers[0][0], &trace.buffers[1][0])
			trace.zero(t)
		})
	}
	t.Run("split_transfer_commit", func(t *testing.T) {
		f := setupRotationFixture(t)
		credID, accounts := f.sharedOn(t, "owned-split", "ops", "old-fixture", "10.9.8.6")
		rot, err := f.rotations.StartSplit(adminCtx(), credID, StartRotationRequest{})
		require.NoError(t, err)
		trace := &materialTrace{BytesColumnCodec: f.assets.bytesCrypto}
		f.assets.bytesCrypto = trace
		f.assets.resolver.crypto = trace
		f.candidates.bytesCrypto = trace
		require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
		trace.zero(t)
		require.Equal(t, model.CredentialMemberApplied, f.memberFor(t, rot.ID, accounts[0]).State)
		require.NotEqual(t, credID, f.binding(t, accounts[0]).CredentialID)
	})
}
