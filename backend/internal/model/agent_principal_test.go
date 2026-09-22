package model

import (
	"encoding/json"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestUserPrincipalKind(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { sqlDB.Close() })
	if err = db.AutoMigrate(&User{}); err != nil {
		t.Fatal(err)
	}
	u := User{Username: "default-human", Password: "!"}
	if err = db.Create(&u).Error; err != nil {
		t.Fatal(err)
	}
	if u.Kind != KindHuman {
		t.Fatalf("zero-value kind persisted as %q", u.Kind)
	}
	var stored User
	if err = db.First(&stored, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.Kind != KindHuman {
		t.Fatalf("default kind=%q", stored.Kind)
	}
}
func TestAgentTokenModel(t *testing.T) {
	sch, err := schema.Parse(&AgentToken{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	f := sch.LookUpField("ExpiresAt")
	if !f.NotNull || f.FieldType != reflect.TypeOf(time.Time{}) {
		t.Fatal("expires_at must be required non-pointer time.Time")
	}
	b, err := json.Marshal(AgentToken{TokenHash: "secret-digest"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "token_hash") || strings.Contains(string(b), "secret-digest") {
		t.Fatalf("hash leaked: %s", b)
	}
}
func TestSessionModelAgentLinksNullable(t *testing.T) {
	sch, err := schema.Parse(&Session{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"AgentTokenID", "AccessRequestID"} {
		f := sch.LookUpField(name)
		if f.NotNull || f.FieldType != reflect.TypeOf((*uint)(nil)) {
			t.Fatalf("%s must be nullable", name)
		}
	}
}
