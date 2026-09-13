package gcpkms

import (
	"strings"
	"testing"
)

func TestGCPKeyRef(t *testing.T) {
	for _, key := range []string{fixtureKey, strings.Replace(fixtureKey, "test-project", "123456789", 1)} {
		r, err := ParseKeyResource(key)
		if err != nil || "projects/"+r.Project+"/locations/"+r.Location+"/keyRings/"+r.KeyRing+"/cryptoKeys/"+r.Key != key {
			t.Fatal("resource roundtrip failed")
		}
	}
	for _, bad := range []string{"", "key", fixtureKey + "/cryptoKeyVersions/1", "https://cloudkms.googleapis.com/" + fixtureKey, fixtureKey + "/", " " + fixtureKey, strings.Replace(fixtureKey, "test-ring", "..", 1), strings.Replace(fixtureKey, "test-ring", "ring%2fother", 1), strings.Replace(fixtureKey, "test-project", "", 1), fixtureKey + "?x=1", fixtureKey + "#x", fixtureKey + "\\x"} {
		if _, err := ParseKeyResource(bad); err == nil || strings.Contains(err.Error(), fixtureKey) {
			t.Fatal("invalid reference accepted or reflected")
		}
	}
	boundary := fixtureKey + strings.Repeat("x", MaxKeyIDBytes-len(fixtureKey))
	if _, err := ParseKeyResource(boundary); err != nil {
		t.Fatal("column boundary refused")
	}
	if _, err := ParseKeyResource(boundary + "x"); err == nil {
		t.Fatal("column overflow accepted")
	}
	t.Run("version-parent", func(t *testing.T) {
		if err := ValidateVersionParent(fixtureKey, fixtureKey+"/cryptoKeyVersions/23"); err != nil {
			t.Fatal("valid version refused")
		}
		for _, bad := range []string{fixtureOtherKey + "/cryptoKeyVersions/1", fixtureKey, fixtureKey + "/cryptoKeyVersions/", fixtureKey + "/cryptoKeyVersions/0", fixtureKey + "/cryptoKeyVersions/01", fixtureKey + "/cryptoKeyVersions/latest", fixtureKey + "/cryptoKeyVersions/1/extra"} {
			if ValidateVersionParent(fixtureKey, bad) == nil {
				t.Fatal("invalid version parent accepted")
			}
		}
	})
}

func TestGCPProjectScope(t *testing.T) {
	scope, err := ResolveProjectScope(fixtureKey)
	if err != nil || scope.Project() != "test-project" {
		t.Fatal("deployment scope mismatch")
	}
	for _, key := range []string{fixtureKey, fixtureOtherKey, strings.Replace(fixtureKey, "global/keyRings/test-ring", "us-central1/keyRings/another", 1)} {
		if got, err := scope.ResolveKey(key); err != nil || got != key {
			t.Fatal("in-project reference refused")
		}
	}
	for _, bad := range []string{strings.Replace(fixtureKey, "test-project", "foreign-project", 1), strings.Replace(fixtureKey, "test-project", "123456789", 1), fixtureKey + "/cryptoKeyVersions/1"} {
		if _, err := scope.ResolveKey(bad); err == nil {
			t.Fatal("untrusted reference accepted")
		}
	}
	if _, err := (ProjectScope{}).ResolveKey(fixtureKey); err == nil {
		t.Fatal("undeclared scope accepted")
	}
	if _, err := ResolveProjectScope("alias"); err == nil {
		t.Fatal("invalid deployment anchor accepted")
	}
}
