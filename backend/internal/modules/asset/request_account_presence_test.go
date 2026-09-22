package asset

import (
	"github.com/custodexa/backend/internal/model"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"testing"
)

func TestRequestAccountPresence(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.AutoMigrate(&model.AssetAccount{}, &model.Credential{}); err != nil {
		t.Fatal(err)
	}
	c := model.Credential{Username: "actual", Scope: model.CredentialScopeDedicated, SecretType: "password", ProtocolFamily: model.ProtocolFamilySSH}
	if err = db.Create(&c).Error; err != nil {
		t.Fatal(err)
	}
	mount := model.AssetAccount{AssetID: 7, CredentialID: c.ID, Username: "stale-mirror"}
	if err = db.Create(&mount).Error; err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		id   uint
		name string
		want bool
	}{{7, "actual", true}, {7, "stale-mirror", false}, {8, "actual", false}} {
		got, err := RequestAccountPresent(db, tc.id, tc.name)
		if err != nil || got != tc.want {
			t.Fatal(tc, got, err)
		}
	}
	db.Delete(&mount)
	if got, err := RequestAccountPresent(db, 7, "actual"); err != nil || got {
		t.Fatal(got, err)
	}
}
