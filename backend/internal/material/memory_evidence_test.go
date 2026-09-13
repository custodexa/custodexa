package material

import (
	"bytes"
	"crypto/rand"
	"os"
	"runtime"
	"strings"
	"testing"
	"unsafe"
)

func TestControlledMaterialMemoryEvidence(t *testing.T) {
	raw := make([]byte, 64)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal("fixture entropy unavailable")
	}
	owner := Adopt(raw)
	// Deliberately retain a distinct immutable copy in this test process only.
	copyString := strings.Clone(string(raw))
	owner.Destroy()
	if !bytes.Equal(raw, make([]byte, len(raw))) {
		t.Fatal("original allocation not zero")
	}
	mem, err := os.Open("/proc/self/mem")
	if err != nil {
		t.Fatal("isolated self memory reader unavailable")
	}
	defer mem.Close()
	observed := make([]byte, len(raw))
	defer Wipe(observed)
	if _, err = mem.ReadAt(observed, int64(uintptr(unsafe.Pointer(unsafe.SliceData(raw))))); err != nil {
		t.Fatal("original address read failed")
	}
	if !bytes.Equal(observed, make([]byte, len(raw))) {
		t.Fatal("original address not zero")
	}
	if _, err = mem.ReadAt(observed, int64(uintptr(unsafe.Pointer(unsafe.StringData(copyString))))); err != nil {
		t.Fatal("distinct copy address read failed")
	}
	if !bytes.Equal(observed, []byte(copyString)) || bytes.Equal(observed, raw) {
		t.Fatal("distinct retained copy not observed")
	}
	runtime.KeepAlive(raw)
	runtime.KeepAlive(copyString)
	t.Logf("EVIDENCE memory-evidence process=isolated_go_test toolchain=%s os=%s arch=%s original_reference=zero original_address=zero distinct_retained_string=present whole_heap=unverified dump_saved=false", runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
