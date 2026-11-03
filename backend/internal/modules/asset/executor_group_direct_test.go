package asset

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// directRecorder 記下每台成員派送時的 directCommand 旗標。
type directRecorder struct {
	*secretRecorder
	mu     sync.Mutex
	direct map[string]bool
}

func (d *directRecorder) Rotate(ctx context.Context, t rotationTarget, old, next []byte) error {
	d.mu.Lock()
	d.direct[t.asset.Host] = t.directCommand
	d.mu.Unlock()
	return d.secretRecorder.Rotate(ctx, t, old, next)
}

// 整組輪替的成員派送：只有專用帳號掛載的成員走不經殼層的提權指令（directCommand），
// 同一筆共用憑證下的登入帳號成員維持原本的自改指令。
func TestGroupRotationDirectCommandOnlyForExecutorMembers(t *testing.T) {
	f := setupBatchFixture(t)
	credID, mounts := f.sharedOn(t, "混合共用", "cx-exec", "exec-old", "10.9.8.1", "10.9.8.2")
	require.Len(t, mounts, 2)
	markExecutor(t, mounts[0])
	rec := &directRecorder{secretRecorder: newSecretRecorder(), direct: map[string]bool{}}
	f.useExecutor(rec.secretRecorder)
	f.rotations.executors = func(string) rotationExecutor { return rec }

	rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
	require.NoError(t, err)
	require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))

	require.Len(t, rec.direct, 2, "兩台成員都派送過")
	assert.True(t, rec.direct["10.9.8.1"], "專用帳號成員：不經殼層的提權指令")
	assert.False(t, rec.direct["10.9.8.2"], "登入帳號成員：自改指令不變")
	assert.Equal(t, model.AccountPurposeExecutor, f.bindingOf(t, mounts[0]).Purpose)
	assert.Equal(t, model.AccountPurposeLogin, f.bindingOf(t, mounts[1]).Purpose)
}
