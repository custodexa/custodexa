package gcpkms

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"hash/crc32"
	"sync"
	"testing"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const fixtureKey = "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/source"
const fixtureOtherKey = "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/target"

type fakeCall struct {
	method  string
	request proto.Message
}

// A queued fault either returns an error or replaces one response, including nil.
// The hook runs without the fake's mutex so cancellation can be injected safely.
type fakeFault struct {
	err      error
	response proto.Message
	replace  bool
	hook     func(context.Context)
}

type fakeKey struct {
	meta *kmspb.CryptoKey
	aead cipher.AEAD
}

// fakeClient binds ciphertext to independently generated keys and raw AAD.
// Its nonce-plus-AES-GCM bytes are test data, not a Cloud KMS wire format.
// Captured requests are cloned and exist only within the test's lifetime.
type fakeClient struct {
	mu     sync.Mutex
	keys   map[string]fakeKey
	calls  []fakeCall
	faults map[string][]fakeFault
}

var _ API = (*fakeClient)(nil)

func newFakeClient(t *testing.T) *fakeClient {
	t.Helper()
	f := &fakeClient{keys: make(map[string]fakeKey), faults: make(map[string][]fakeFault)}
	for _, name := range []string{fixtureKey, fixtureOtherKey} {
		material := make([]byte, 32)
		if _, err := rand.Read(material); err != nil {
			t.Fatal("fixture entropy unavailable")
		}
		block, err := aes.NewCipher(material)
		clear(material)
		if err != nil {
			t.Fatal("fixture cipher unavailable")
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal("fixture AEAD unavailable")
		}
		f.keys[name] = fakeKey{aead: aead, meta: &kmspb.CryptoKey{
			Name: name, Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
			Primary: &kmspb.CryptoKeyVersion{Name: name + "/cryptoKeyVersions/1", State: kmspb.CryptoKeyVersion_ENABLED, Algorithm: kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION},
		}}
	}
	return f
}

func fakeCRC(value []byte) *wrapperspb.Int64Value {
	return wrapperspb.Int64(int64(crc32.Checksum(value, crc32.MakeTable(crc32.Castagnoli))))
}

func fakeCRCValid(value []byte, sum *wrapperspb.Int64Value) bool {
	return sum != nil && sum.Value == fakeCRC(value).Value
}

func (f *fakeClient) inject(method string, fault fakeFault) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.faults[method] = append(f.faults[method], fault)
}

func (f *fakeClient) snapshot() []fakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]fakeCall, len(f.calls))
	for i, call := range f.calls {
		out[i] = fakeCall{call.method, proto.Clone(call.request)}
	}
	return out
}

func (f *fakeClient) begin(ctx context.Context, method string, request proto.Message) (fakeFault, error) {
	if err := ctx.Err(); err != nil {
		return fakeFault{}, err
	}
	if !request.ProtoReflect().IsValid() {
		return fakeFault{}, status.Error(codes.InvalidArgument, "request required")
	}
	f.mu.Lock()
	f.calls = append(f.calls, fakeCall{method, proto.Clone(request)})
	var fault fakeFault
	if queue := f.faults[method]; len(queue) > 0 {
		fault, f.faults[method] = queue[0], queue[1:]
	}
	f.mu.Unlock()
	if fault.hook != nil {
		fault.hook(ctx)
	}
	if err := ctx.Err(); err != nil {
		return fakeFault{}, err
	}
	return fault, fault.err
}

func (f *fakeClient) GetCryptoKey(ctx context.Context, in *kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	fault, err := f.begin(ctx, "metadata", in)
	if err != nil {
		return nil, err
	}
	if fault.replace {
		out, _ := proto.Clone(fault.response).(*kmspb.CryptoKey)
		return out, nil
	}
	k, ok := f.keys[in.Name]
	if !ok {
		return nil, status.Error(codes.NotFound, "key unavailable")
	}
	return proto.Clone(k.meta).(*kmspb.CryptoKey), nil
}

func (f *fakeClient) Encrypt(ctx context.Context, in *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
	fault, err := f.begin(ctx, "encrypt", in)
	if err != nil {
		return nil, err
	}
	if fault.replace {
		out, _ := proto.Clone(fault.response).(*kmspb.EncryptResponse)
		return out, nil
	}
	k, ok := f.keys[in.Name]
	if !ok {
		return nil, status.Error(codes.NotFound, "key unavailable")
	}
	// This fake intentionally requires the integrity fields the provider must send.
	if !fakeCRCValid(in.Plaintext, in.PlaintextCrc32C) || !fakeCRCValid(in.AdditionalAuthenticatedData, in.AdditionalAuthenticatedDataCrc32C) {
		return nil, status.Error(codes.InvalidArgument, "request checksum rejected")
	}
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.New("fixture entropy unavailable")
	}
	blob := k.aead.Seal(nonce, nonce, in.Plaintext, in.AdditionalAuthenticatedData)
	return &kmspb.EncryptResponse{Name: k.meta.Primary.Name, Ciphertext: blob, CiphertextCrc32C: fakeCRC(blob), VerifiedPlaintextCrc32C: true, VerifiedAdditionalAuthenticatedDataCrc32C: true}, nil
}

func (f *fakeClient) Decrypt(ctx context.Context, in *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
	fault, err := f.begin(ctx, "decrypt", in)
	if err != nil {
		return nil, err
	}
	if fault.replace {
		out, _ := proto.Clone(fault.response).(*kmspb.DecryptResponse)
		return out, nil
	}
	k, ok := f.keys[in.Name]
	if !ok {
		return nil, status.Error(codes.NotFound, "key unavailable")
	}
	if !fakeCRCValid(in.Ciphertext, in.CiphertextCrc32C) || !fakeCRCValid(in.AdditionalAuthenticatedData, in.AdditionalAuthenticatedDataCrc32C) {
		return nil, status.Error(codes.InvalidArgument, "request checksum rejected")
	}
	if len(in.Ciphertext) < k.aead.NonceSize()+k.aead.Overhead() {
		return nil, status.Error(codes.InvalidArgument, "ciphertext rejected")
	}
	plain, err := k.aead.Open(nil, in.Ciphertext[:k.aead.NonceSize()], in.Ciphertext[k.aead.NonceSize():], in.AdditionalAuthenticatedData)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "ciphertext binding rejected")
	}
	return &kmspb.DecryptResponse{Plaintext: plain, PlaintextCrc32C: fakeCRC(plain)}, nil
}

func fakeEncryptRequest(name string, plain, aad []byte) *kmspb.EncryptRequest {
	return &kmspb.EncryptRequest{Name: name, Plaintext: plain, AdditionalAuthenticatedData: aad, PlaintextCrc32C: fakeCRC(plain), AdditionalAuthenticatedDataCrc32C: fakeCRC(aad)}
}

func fakeDecryptRequest(name string, blob, aad []byte) *kmspb.DecryptRequest {
	return &kmspb.DecryptRequest{Name: name, Ciphertext: blob, AdditionalAuthenticatedData: aad, CiphertextCrc32C: fakeCRC(blob), AdditionalAuthenticatedDataCrc32C: fakeCRC(aad)}
}

// Exercise the fake's sequence recorder, not a provider or a database transaction.
func fakeMove(ctx context.Context, client API, wrapped, aad []byte) (*kmspb.EncryptResponse, error) {
	plain, err := client.Decrypt(ctx, fakeDecryptRequest(fixtureKey, wrapped, aad))
	if err != nil {
		return nil, err
	}
	defer clear(plain.Plaintext)
	return client.Encrypt(ctx, fakeEncryptRequest(fixtureOtherKey, plain.Plaintext, aad))
}

func TestGCPFakeClientContract(t *testing.T) {
	ctx := context.Background()
	plain, aad := bytes.Repeat([]byte{7}, 32), []byte("custodexa|wrapped-dek|v1|4:data|1:3")
	seed := func(t *testing.T, f *fakeClient) *kmspb.EncryptResponse {
		t.Helper()
		out, err := f.Encrypt(ctx, fakeEncryptRequest(fixtureKey, plain, aad))
		if err != nil {
			t.Fatal("valid encryption rejected")
		}
		return out
	}
	t.Run("metadata-roundtrip-and-capture", func(t *testing.T) {
		f := newFakeClient(t)
		meta, err := f.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: fixtureKey})
		if err != nil || meta.Name != fixtureKey || meta.Primary.State != kmspb.CryptoKeyVersion_ENABLED {
			t.Fatal("metadata mismatch")
		}
		wrapped := seed(t, f)
		if wrapped.Name != fixtureKey+"/cryptoKeyVersions/1" || bytes.Contains(wrapped.Ciphertext, plain) || !fakeCRCValid(wrapped.Ciphertext, wrapped.CiphertextCrc32C) || !wrapped.VerifiedPlaintextCrc32C || !wrapped.VerifiedAdditionalAuthenticatedDataCrc32C {
			t.Fatal("encryption response mismatch")
		}
		request := fakeDecryptRequest(fixtureKey, wrapped.Ciphertext, bytes.Clone(aad))
		got, err := f.Decrypt(ctx, request)
		if err != nil || !bytes.Equal(got.Plaintext, plain) || !fakeCRCValid(got.Plaintext, got.PlaintextCrc32C) {
			t.Fatal("roundtrip mismatch")
		}
		clear(request.AdditionalAuthenticatedData)
		calls := f.snapshot()
		enc := calls[1].request.(*kmspb.EncryptRequest)
		dec := calls[2].request.(*kmspb.DecryptRequest)
		if calls[0].method != "metadata" || calls[1].method != "encrypt" || calls[2].method != "decrypt" || enc.Name != fixtureKey || dec.Name != fixtureKey || !bytes.Equal(enc.AdditionalAuthenticatedData, aad) || !bytes.Equal(dec.AdditionalAuthenticatedData, aad) || !fakeCRCValid(enc.Plaintext, enc.PlaintextCrc32C) || !fakeCRCValid(dec.Ciphertext, dec.CiphertextCrc32C) || !fakeCRCValid(enc.AdditionalAuthenticatedData, enc.AdditionalAuthenticatedDataCrc32C) || !fakeCRCValid(dec.AdditionalAuthenticatedData, dec.AdditionalAuthenticatedDataCrc32C) {
			t.Fatal("request snapshot mismatch")
		}
	})
	for _, problem := range []string{"wrong-key", "wrong-aad", "ciphertext", "encrypt-crc", "decrypt-crc", "aad-crc", "missing-crc"} {
		t.Run(problem, func(t *testing.T) {
			f := newFakeClient(t)
			wrapped := seed(t, f)
			request := fakeDecryptRequest(fixtureKey, bytes.Clone(wrapped.Ciphertext), bytes.Clone(aad))
			switch problem {
			case "wrong-key":
				request.Name = fixtureOtherKey
			case "wrong-aad":
				request.AdditionalAuthenticatedData[0] ^= 1
				request.AdditionalAuthenticatedDataCrc32C = fakeCRC(request.AdditionalAuthenticatedData)
			case "ciphertext":
				request.Ciphertext[0] ^= 1
				request.CiphertextCrc32C = fakeCRC(request.Ciphertext)
			case "decrypt-crc":
				request.CiphertextCrc32C.Value ^= 1
			case "aad-crc":
				request.AdditionalAuthenticatedDataCrc32C.Value ^= 1
			case "missing-crc":
				request.CiphertextCrc32C = nil
			case "encrypt-crc":
				bad := fakeEncryptRequest(fixtureKey, plain, aad)
				bad.PlaintextCrc32C.Value ^= 1
				if out, err := f.Encrypt(ctx, bad); status.Code(err) != codes.InvalidArgument || out != nil {
					t.Fatal("bad encrypt checksum accepted")
				}
			}
			if problem != "encrypt-crc" {
				if out, err := f.Decrypt(ctx, request); status.Code(err) != codes.InvalidArgument || out != nil {
					t.Fatal("invalid decryption accepted")
				}
			}
			if out, err := f.Decrypt(ctx, fakeDecryptRequest(fixtureKey, wrapped.Ciphertext, aad)); err != nil || !bytes.Equal(out.Plaintext, plain) {
				t.Fatal("valid control rejected")
			}
		})
	}
	t.Run("malformed-response-injection", func(t *testing.T) {
		f := newFakeClient(t)
		wrapped := seed(t, f)
		for _, method := range []string{"metadata", "encrypt", "decrypt"} {
			for _, response := range []proto.Message{nil, &kmspb.CryptoKey{}, &kmspb.EncryptResponse{}, &kmspb.DecryptResponse{Plaintext: []byte{1}, PlaintextCrc32C: wrapperspb.Int64(-1)}} {
				if response != nil && ((method == "metadata" && response.ProtoReflect().Descriptor().Name() != "CryptoKey") || (method == "encrypt" && response.ProtoReflect().Descriptor().Name() != "EncryptResponse") || (method == "decrypt" && response.ProtoReflect().Descriptor().Name() != "DecryptResponse")) {
					continue
				}
				f.inject(method, fakeFault{replace: true, response: response})
				var out proto.Message
				var err error
				switch method {
				case "metadata":
					out, err = f.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: fixtureKey})
				case "encrypt":
					out, err = f.Encrypt(ctx, fakeEncryptRequest(fixtureKey, plain, aad))
				case "decrypt":
					out, err = f.Decrypt(ctx, fakeDecryptRequest(fixtureKey, wrapped.Ciphertext, aad))
				}
				if err != nil || (response == nil && out.ProtoReflect().IsValid()) || (response != nil && !proto.Equal(out, response)) {
					t.Fatal("response fault was not delivered")
				}
			}
		}
		seed(t, f)
		if out, err := f.Decrypt(ctx, fakeDecryptRequest(fixtureKey, wrapped.Ciphertext, aad)); err != nil || !bytes.Equal(out.Plaintext, plain) {
			t.Fatal("fault queue did not recover")
		}
	})
	for _, problem := range []string{"none", "source-failure", "target-failure", "cancel-before", "cancel-during"} {
		t.Run("sequence-"+problem, func(t *testing.T) {
			f := newFakeClient(t)
			wrapped := seed(t, f)
			bounded, cancel := context.WithCancel(ctx)
			defer cancel()
			wantCode, wantCalls := codes.OK, 2
			switch problem {
			case "source-failure":
				f.inject("decrypt", fakeFault{err: status.Error(codes.PermissionDenied, "source denied")})
				wantCode, wantCalls = codes.PermissionDenied, 1
			case "target-failure":
				f.inject("encrypt", fakeFault{err: status.Error(codes.Unavailable, "target unavailable")})
				wantCode = codes.Unavailable
			case "cancel-before":
				cancel()
				wantCode, wantCalls = codes.Canceled, 0
			case "cancel-during":
				f.inject("decrypt", fakeFault{hook: func(context.Context) { cancel() }})
				wantCode, wantCalls = codes.Canceled, 1
			}
			out, err := fakeMove(bounded, f, wrapped.Ciphertext, aad)
			gotCode := status.Code(err)
			if errors.Is(err, context.Canceled) {
				gotCode = codes.Canceled
			}
			calls := f.snapshot()[1:]
			if gotCode != wantCode || len(calls) != wantCalls || (err != nil && out != nil) {
				t.Fatal("sequence outcome mismatch")
			}
			if len(calls) > 0 && (calls[0].method != "decrypt" || calls[0].request.(*kmspb.DecryptRequest).Name != fixtureKey) {
				t.Fatal("source call mismatch")
			}
			if len(calls) > 1 && (calls[1].method != "encrypt" || calls[1].request.(*kmspb.EncryptRequest).Name != fixtureOtherKey) {
				t.Fatal("target call mismatch")
			}
			if err == nil {
				got, err := f.Decrypt(ctx, fakeDecryptRequest(fixtureOtherKey, out.Ciphertext, aad))
				if err != nil || !bytes.Equal(got.Plaintext, plain) {
					t.Fatal("target roundtrip mismatch")
				}
			}
		})
	}
}
