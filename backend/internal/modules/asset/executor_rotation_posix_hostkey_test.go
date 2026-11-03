package asset

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/custodexa/backend/internal/model"
)

// 代改撥號時主機金鑰不符：沿用既有的主機金鑰原因碼，且專用帳號的憑證在認證前就被擋下、一個位元組都沒送出。
func TestRotateDelegatedHostKeyMismatchSendsNoExecutorCredential(t *testing.T) {
	cases := []struct {
		name   string
		cause  error
		reason string
	}{
		{"金鑰與綁定不符", ErrHostKeyChanged, model.ChangeSecretReasonHostKeyMismatch},
		{"主機身分變更", ErrHostIdentityChanged, model.ChangeSecretReasonHostIdentityChanged},
		{"主機金鑰查核失敗", ErrHostKeyCheckFailed, model.ChangeSecretReasonHostKeyCheckFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newExecSSHServer(t)
			srv.addAccount(delegExecutorUser, delegExecutorSecret, fakeSudoNopasswd)
			srv.addAccount(delegTargetUser, delegServerOldPW, fakeSudoNone)
			rt := directRotationTarget(t, srv, delegTargetUser, false)
			rt.hostKeyCB = func(string, net.Addr, ssh.PublicKey) error { return fmt.Errorf("握手拒絕: %w", tc.cause) }

			login := rotationLogin{username: delegExecutorUser, password: []byte(delegExecutorSecret)}
			_, err := posixSSHExecutor{}.RotateDelegated(context.Background(), rt, login, []byte("new-pw"))
			var rejected *remoteRejectedError
			require.ErrorAs(t, err, &rejected)
			assert.Equal(t, tc.reason, rejected.reason)
			assert.Empty(t, srv.authAttempts(), "主機金鑰不符：專用帳號憑證不得送出（認證嘗試 0）")
			assert.Empty(t, srv.execSessions(), "不得開任何 session")
			assert.Zero(t, srv.attemptsAs(delegTargetUser, ""), "不得以目標帳號登入")
		})
	}
}
