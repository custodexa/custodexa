//go:build latency

package kms

import (
	"bytes"
	"context"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/custodexa/backend/pkg/crypto"
	"os/exec"
	"runtime"
	"sort"
	"testing"
	"time"
)

// Discover an existing enabled symmetric key; never create or mutate keys.
func TestAWSUnwrapLatency(t *testing.T) {
	const endpoint = "http://127.0.0.1:4566"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := localstackClient(t, endpoint)
	pages := awskms.NewListKeysPaginator(client, &awskms.ListKeysInput{})
	var arn string
	for pages.HasMorePages() && arn == "" {
		page, err := pages.NextPage(ctx)
		if err != nil {
			t.Fatal("fixture ListKeys failed")
		}
		for _, key := range page.Keys {
			out, err := client.DescribeKey(ctx, &awskms.DescribeKeyInput{KeyId: key.KeyId})
			if err != nil || out.KeyMetadata == nil {
				continue
			}
			m := out.KeyMetadata
			if m.KeyState == types.KeyStateEnabled && m.KeySpec == types.KeySpecSymmetricDefault && m.KeyUsage == types.KeyUsageTypeEncryptDecrypt && m.Arn != nil {
				arn = *m.Arn
				break
			}
		}
	}
	if arn == "" {
		t.Fatal("prerequisite missing: existing enabled symmetric fixture key")
	}
	p, err := New(ctx, Settings{Provider: ProviderAWS, KeyID: arn, Region: localstackRegion, Endpoint: endpoint})
	if err != nil {
		t.Fatal("provider preflight failed")
	}
	t.Logf("LATENCY_FIXTURE endpoint=%s key_ref=%s", endpoint, arn)
	measureUnwrapLatency(t, "aws-localstack", p)
}

func TestLocalUnwrapLatency(t *testing.T) {
	key := bytes.Repeat([]byte{19}, 32)
	defer clear(key)
	p, err := crypto.NewEnvKEKProvider(key)
	if err != nil {
		t.Fatal("local provider construction failed")
	}
	measureUnwrapLatency(t, "local-env", p)
}

// Timing includes the real driver call, but excludes checks and buffer clearing.
func measureUnwrapLatency(t *testing.T, label string, p crypto.KEKProvider) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	plain := bytes.Repeat([]byte{37}, 32)
	defer clear(plain)
	aad := crypto.DEKAAD("data", 1)
	wrapped, err := p.Wrap(ctx, plain, aad)
	if err != nil {
		t.Fatal("sample wrap failed")
	}
	samples := make([]int64, 0, 100)
	load, err := exec.Command("uptime").Output()
	if err != nil {
		t.Fatal("host load unavailable")
	}
	t.Logf("LATENCY_HOST_LOAD provider=%s %s", label, bytes.TrimSpace(load))
	t.Logf("LATENCY_START provider=%s time=%s go=%s os=%s arch=%s cpus=%d", label, time.Now().Format(time.RFC3339Nano), runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
	for i := 0; i < 105; i++ {
		start := time.Now()
		got, err := p.Unwrap(ctx, wrapped, aad)
		elapsed := time.Since(start).Nanoseconds()
		valid := bytes.Equal(got, plain)
		clear(got)
		if err != nil || !valid {
			t.Fatalf("unwrap failed at sample %d", i)
		}
		if i >= 5 {
			samples = append(samples, elapsed)
		}
	}
	t.Logf("LATENCY_RAW_NS provider=%s samples=%v", label, samples)
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	t.Logf("LATENCY_RESULT provider=%s warmup=5 n=100 p50_ms=%.6f p95_ms=%.6f max_ms=%.6f end=%s", label, float64(samples[49])/1e6, float64(samples[94])/1e6, float64(samples[99])/1e6, time.Now().Format(time.RFC3339Nano))
}
