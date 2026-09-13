package gcpkms

import (
	"errors"
	"strings"
)

const ProviderGCP = "gcp"

// MaxKeyIDBytes bounds references to the existing persisted identity column.
const MaxKeyIDBytes = 255

var ErrKeyRef = errors.New("GCP CryptoKey reference invalid")
var ErrProjectScope = errors.New("GCP key is outside the deployment project")

// KeyResource preserves the deployment's spelling without guessing project aliases.
type KeyResource struct {
	Project  string
	Location string
	KeyRing  string
	Key      string
}

func resourceSegment(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range []byte(value) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// ParseKeyResource accepts only a complete CryptoKey, never a version or URL.
// Segment checks are a conservative input policy, not proof of a remote key's existence.
func ParseKeyResource(value string) (KeyResource, error) {
	if len(value) > MaxKeyIDBytes {
		return KeyResource{}, ErrKeyRef
	}
	parts := strings.Split(value, "/")
	if len(parts) != 8 || parts[0] != "projects" || parts[2] != "locations" || parts[4] != "keyRings" || parts[6] != "cryptoKeys" {
		return KeyResource{}, ErrKeyRef
	}
	for _, i := range []int{1, 3, 5, 7} {
		if !resourceSegment(parts[i]) {
			return KeyResource{}, ErrKeyRef
		}
	}
	return KeyResource{Project: parts[1], Location: parts[3], KeyRing: parts[5], Key: parts[7]}, nil
}

// ProjectScope is derived exclusively from a deployment CryptoKey reference.
type ProjectScope struct{ project string }

func (s ProjectScope) Project() string { return s.project }

func ResolveProjectScope(deploymentKey string) (ProjectScope, error) {
	resource, err := ParseKeyResource(deploymentKey)
	if err != nil {
		return ProjectScope{}, err
	}
	return ProjectScope{project: resource.Project}, nil
}

func (s ProjectScope) ResolveKey(target string) (string, error) {
	resource, err := ParseKeyResource(target)
	if err != nil {
		return "", err
	}
	if s.project == "" || resource.Project != s.project {
		return "", ErrProjectScope
	}
	return target, nil
}

// ValidateVersionParent binds an EncryptResponse version to its exact CryptoKey.
func ValidateVersionParent(keyID, versionName string) error {
	if _, err := ParseKeyResource(keyID); err != nil {
		return err
	}
	prefix := keyID + "/cryptoKeyVersions/"
	if !strings.HasPrefix(versionName, prefix) {
		return ErrKeyRef
	}
	id := strings.TrimPrefix(versionName, prefix)
	if id == "" || id[0] == '0' {
		return ErrKeyRef
	}
	for _, c := range []byte(id) {
		if c < '0' || c > '9' {
			return ErrKeyRef
		}
	}
	return nil
}

// Settings contains no region, endpoint, or credential injection surface.
type Settings struct {
	KeyID string
	Scope ProjectScope
	// ServiceAccountJSON 服務帳號金鑰檔內容（**正式路徑必填**）。
	//
	// 自委託憑證改由解封頁提供起，認證一律以此內容顯式建構 token source，
	// **SHALL NOT 回落環境自動發現（ADC）**——地端機房以開放名單連往外部雲端
	// 金鑰服務時沒有工作負載身分可用，而「環境中恰有可用的 ADC」在這個部署形態
	// 下代表撿到了不該用的憑證，不是可用的退路。
	//
	// 本欄由該解封世代的記憶體憑證持有者供給；產品不建立私有 credential store、
	// 不將其持久化。缺席即拒絕建構。
	ServiceAccountJSON []byte
}
