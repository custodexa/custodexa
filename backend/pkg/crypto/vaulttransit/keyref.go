package vaulttransit

import (
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

const ProviderVault = "vault"

// MaxKeyIDBytes matches the persisted key-reference column capacity.
const MaxKeyIDBytes = 255

var (
	ErrInvalidReference = errors.New("Vault key reference is invalid")
	ErrInvalidAddress   = errors.New("Vault address must be a valid HTTPS origin")
	ErrOutsideScope     = errors.New("Vault key reference is outside the deployment scope")
)

// ASCII predicates avoid package-level parser state and initialization ordering.
func asciiAlphanumeric(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func validKeyName(name string) bool {
	if name == "" {
		return false
	}
	for i := range name {
		if !asciiAlphanumeric(name[i]) && name[i] != '_' && name[i] != '-' {
			return false
		}
	}
	return true
}

func validDNSLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 || !asciiAlphanumeric(label[0]) || !asciiAlphanumeric(label[len(label)-1]) {
		return false
	}
	for i := range label {
		if !asciiAlphanumeric(label[i]) && label[i] != '-' {
			return false
		}
	}
	return true
}

// CanonicalOrigin excludes path, credentials, query, fragments, and HTTP.
func CanonicalOrigin(address string) (string, error) {
	u, err := url.Parse(address)
	if err != nil || u == nil || strings.ToLower(u.Scheme) != "https" || u.Opaque != "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(address, "#") ||
		u.RawPath != "" || (u.Path != "" && u.Path != "/") {
		return "", ErrInvalidAddress
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.HasSuffix(u.Host, ":") {
		return "", ErrInvalidAddress
	}
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	} else {
		if len(host) > 253 {
			return "", ErrInvalidAddress
		}
		for _, label := range strings.Split(host, ".") {
			if !validDNSLabel(label) {
				return "", ErrInvalidAddress
			}
		}
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", ErrInvalidAddress
		}
		if n == 443 {
			port = ""
		} else {
			port = strconv.Itoa(n)
		}
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return "https://" + host, nil
}

// CanonicalKeyID encodes an origin and a fixed-mount Transit key without versions.
func CanonicalKeyID(address, name string) (string, error) {
	origin, err := CanonicalOrigin(address)
	if err != nil {
		return "", err
	}
	if !validKeyName(name) {
		return "", ErrInvalidReference
	}
	id := "vault:" + base64.RawURLEncoding.EncodeToString([]byte(origin)) + ":transit:" + name
	if len(id) > MaxKeyIDBytes {
		return "", ErrInvalidReference
	}
	return id, nil
}

// ParseKeyID accepts only canonical references and never checks key ownership.
func ParseKeyID(id string) (origin, name string, err error) {
	if len(id) > MaxKeyIDBytes {
		return "", "", ErrInvalidReference
	}
	parts := strings.Split(id, ":")
	if len(parts) != 4 || parts[0] != ProviderVault || parts[2] != "transit" {
		return "", "", ErrInvalidReference
	}
	raw, decodeErr := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if decodeErr != nil {
		return "", "", ErrInvalidReference
	}
	canonical, makeErr := CanonicalKeyID(string(raw), parts[3])
	if makeErr != nil || canonical != id {
		return "", "", ErrInvalidReference
	}
	return string(raw), parts[3], nil
}

// Scope is derived only from deployment configuration, never a request.
type Scope struct{ origin string }

func (s Scope) Origin() string { return s.origin }

// ResolveScope validates the deployment key and its declared origin without I/O.
func ResolveScope(address, deploymentKey string) (Scope, string, error) {
	origin, err := CanonicalOrigin(address)
	if err != nil {
		return Scope{}, "", err
	}
	id := deploymentKey
	if !strings.HasPrefix(id, "vault:") {
		id, err = CanonicalKeyID(origin, deploymentKey)
		if err != nil {
			return Scope{}, "", err
		}
	}
	scope := Scope{origin: origin}
	if _, err := scope.ResolveKey(id); err != nil {
		return Scope{}, "", err
	}
	return scope, id, nil
}

// ResolveKey rejects zero scopes and cross-origin references before client creation.
func (s Scope) ResolveKey(id string) (string, error) {
	origin, _, err := ParseKeyID(id)
	if err != nil {
		return "", err
	}
	if s.origin == "" || s.origin != origin {
		return "", ErrOutsideScope
	}
	return id, nil
}

// Settings separates deployment credentials from the canonical target reference.
type Settings struct {
	Address string
	// RoleID／SecretID AppRole 登入路徑。RoleID 為非秘密（取自拓撲設定），
	// SecretID 為秘密（取自該解封世代的記憶體憑證持有者）。
	RoleID   string
	SecretID string
	// Token 直接提供的權杖路徑，**與 RoleID／SecretID 互斥**。
	//
	// 等同跳過 AppRole 登入；其餘生命週期與登入路徑相同（依回傳租期續期、
	// 失效即 fail-close、封存時隨世代抹除）。**失效後不自行以角色識別補位**——
	// 沒有可重試的登入，恢復一律經重新解封提供新的權杖或角色密鑰。
	//
	// 長壽命權杖非建議做法：其暴露窗等於權杖壽命，而本產品無法為它做輪替。
	Token string
	KeyID string
	Scope Scope
}

// UsesToken 是否走直接權杖路徑。
func (s Settings) UsesToken() bool { return s.Token != "" }
