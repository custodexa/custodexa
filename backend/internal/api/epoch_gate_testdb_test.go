package api

import (
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// installEpochGateDB 為「只用 mock、原本完全不需要 DB」的路由測試裝一個最小的
// database.DB，並建出 token 所宣稱的使用者列。
//
// 需要它的原因：AuthMiddleware 的憑證世代閘現查
// users.credential_epoch，且 **DB 未注入時一律拒**（原本回 nil
// 放行，等於整套撤銷機制可被一條漏接的組裝路徑靜默關掉）。
//
// 這些 fixture 先前之所以會過，靠的是同一個 test binary 內其他測試遺留在
// database.DB 的值——換句話說它們的「真 AuthMiddleware」宣稱本來就只成立一半，
// 且對測試執行順序敏感。此處顯式建立並於結束後還原，順序相依性一併消除。
func installEpochGateDB(t *testing.T, userIDs ...uint) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}); err != nil {
		t.Fatalf("migrate users: %v", err)
	}
	for i, id := range userIDs {
		u := &model.User{Username: "gate-user-" + itoaTest(i), Password: "x", Active: true}
		u.ID = id
		if err := db.Create(u).Error; err != nil {
			t.Fatalf("seed user %d: %v", id, err)
		}
	}
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })
	return db
}

// itoaTest 小整數轉字串（測試用；避免為單一格式化引入 strconv）
func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	var buf []byte
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}
