package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/notifycat"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 檢查點驗證端點的角色指派維度（role-assignment-integrity task 4.1）。
//
// 竄改一律以**原生 SQL 直寫**製造：威脅模型明載對手能直寫資料庫，
// 經 ORM 造出來的差異只證明得了守衛擋得住自己。
// 本檔測的是「識別換算成名字之後，稽核讀到的東西是不是對的」——
// 對帳本身的正確性由 audit 模組的測試承擔，這裡不重測。

// roleStateFailureRecorder 把失效事件真的寫成一列，
// 使 last_event 的投影測到的是「從資料庫讀回來的事件」而非記憶體物件
type roleStateFailureRecorder struct{ db *gorm.DB }

func (r *roleStateFailureRecorder) ReportWithCounts(mechanism, causeCode string,
	params map[string]string, _ map[string]int) {
	blob, _ := json.Marshal(params)
	r.db.Create(&model.AuditFailureEvent{
		Mechanism: mechanism, CauseCode: causeCode, CauseParams: string(blob),
		Cause: "角色指派與檢查點快照不符", StartedAt: time.Now(),
	})
}

// NotifyOngoing 本測試的對帳器路徑不會呼叫（僅為滿足共用出口介面）
func (r *roleStateFailureRecorder) NotifyOngoing(notifycat.Event, map[string]string) {}

func (r *roleStateFailureRecorder) Resolve(mechanism string) {
	now := time.Now()
	r.db.Model(&model.AuditFailureEvent{}).
		Where("mechanism = ? AND ended_at IS NULL", mechanism).
		Update("ended_at", now)
}

// roleStateAPIFixture 一條真的鏈＋對帳器＋只掛驗證端點的引擎
type roleStateAPIFixture struct {
	db   *gorm.DB
	seal *audit.CheckpointService
	r    *gin.Engine
}

func setupRoleStateAPIFixture(t *testing.T) *roleStateAPIFixture {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	// `:memory:` 配連線池＝每條連線各自一個空庫（本專案踩過），故收斂為單連線
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.AuditLog{},
		&model.AuditCheckpoint{}, &model.AuditCheckpointTrim{},
		&model.IntegrityBaseline{}, &model.AuditFailureEvent{}, &model.UserRole{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.Create(&model.IntegrityBaseline{
		ID: 1, BaselineAt: time.Now().Add(-time.Hour), MaxLogID: 0}).Error; err != nil {
		t.Fatalf("baseline: %v", err)
	}
	for id, name := range map[uint]string{1: "admin", 7: "zhangsan"} {
		u := &model.User{Username: name, Password: "x", Active: true}
		u.ID = id
		if err := db.Create(u).Error; err != nil {
			t.Fatalf("user: %v", err)
		}
	}
	for id, name := range map[uint]string{1: model.RoleAdmin, 3: model.RoleAuditor} {
		if err := db.Create(&model.Role{ID: id, Name: name}).Error; err != nil {
			t.Fatalf("role: %v", err)
		}
	}

	signer := newFakeCheckpointSigner(t)
	seal := audit.NewCheckpointService(db, signer, nil, nil)
	rec := audit.NewRoleStateReconciler(db, &roleStateFailureRecorder{db: db})
	seal.SetRoleStateReconciler(rec)
	if err := seal.EnsureGenesis(); err != nil {
		t.Fatalf("genesis: %v", err)
	}
	verifier := audit.NewCheckpointVerifier(db, seal, audit.NewCheckpointPurger(db, signer), nil, nil)
	verifier.SetRoleStateReconciler(rec)

	h := &AuditCheckpointHandler{verifier: verifier, signing: signer}
	// 名稱換算與事件查詢都走真的模組服務（下沉後接入層不再自持 DB）
	// 單例必須帶真的政策服務：nil 政策會讓同套件後續走到 Report 的測試踩 nil deref，
	// 且單例跨測試存活，故測完還原（backlog 78 的根因）
	failures := audit.InitAuditFailure(db, policy.NewSecurityPolicyService(db))
	t.Cleanup(audit.ResetAuditFailureSingleton)
	h.SetRoleStateNames(identity.NewUserService(db, nil), failures)
	r := gin.New()
	r.GET("/verify", h.Verify)
	return &roleStateAPIFixture{db: db, seal: seal, r: r}
}

// roleStateOf 打一次驗證端點並取回角色指派維度
func (f *roleStateAPIFixture) roleStateOf(t *testing.T) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	f.r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/verify", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("狀態碼 = %d, body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Data struct {
			Chain map[string]any `json:"chain"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析: %v", err)
	}
	rs, ok := resp.Data.Chain["role_state"].(map[string]any)
	if !ok {
		t.Fatalf("回應缺 role_state：稽核看不到這一列即等於機制不存在。chain=%v", resp.Data.Chain)
	}
	return rs
}

// TestCheckpointVerifyRoleStateNotCovered 首個含快照的檢查點之前＝尚未涵蓋
func TestCheckpointVerifyRoleStateNotCovered(t *testing.T) {
	f := setupRoleStateAPIFixture(t)
	// 清掉 genesis 的快照欄，模擬升級後尚未封出任何含快照的檢查點
	if err := f.db.Exec(`UPDATE audit_checkpoints SET role_state_snapshot = NULL`).Error; err != nil {
		t.Fatalf("清快照欄: %v", err)
	}

	rs := f.roleStateOf(t)
	if rs["covered"] != false {
		t.Errorf("covered = %v, want false", rs["covered"])
	}
	if rs["state"] != audit.RoleStateNotCovered {
		t.Errorf("state = %v, want %s", rs["state"], audit.RoleStateNotCovered)
	}
	if _, ok := rs["since_seq"]; ok {
		t.Errorf("尚未涵蓋卻回了 since_seq = %v：起算點不存在時不得給一個數字", rs["since_seq"])
	}
	if rs["last_event"] != nil {
		t.Errorf("尚未涵蓋不得附事件，got %v", rs["last_event"])
	}
}

// TestCheckpointVerifyRoleStateMatch 合法狀態＝相符，且指出涵蓋至哪個檢查點
func TestCheckpointVerifyRoleStateMatch(t *testing.T) {
	f := setupRoleStateAPIFixture(t)
	rs := f.roleStateOf(t)
	if rs["state"] != audit.RoleStateMatch {
		t.Fatalf("state = %v, want %s", rs["state"], audit.RoleStateMatch)
	}
	if rs["covered"] != true {
		t.Errorf("covered = %v, want true", rs["covered"])
	}
	if rs["since_seq"] != float64(1) {
		t.Errorf("since_seq = %v, want 1（genesis 即基準）", rs["since_seq"])
	}
	if rs["missing"] != nil || rs["extra"] != nil {
		t.Errorf("相符卻有差集: missing=%v extra=%v", rs["missing"], rs["extra"])
	}
	if rs["last_event"] != nil {
		t.Errorf("相符不得附事件，got %v", rs["last_event"])
	}
}

// TestCheckpointVerifyRoleStateMismatchNamesAndEvent 直寫提權後：
// 差集以帳號名與角色名呈現，並附最近一筆失效事件供連結
func TestCheckpointVerifyRoleStateMismatchNamesAndEvent(t *testing.T) {
	f := setupRoleStateAPIFixture(t)
	// 直寫提權：zhangsan(7) 掛上 admin(1)，無任何審計列
	if err := f.db.Exec(`INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)`, 7, 1).Error; err != nil {
		t.Fatalf("直寫提權: %v", err)
	}

	rs := f.roleStateOf(t)
	if rs["state"] != audit.RoleStateMismatch {
		t.Fatalf("state = %v, want %s", rs["state"], audit.RoleStateMismatch)
	}
	if rs["since_seq"] != float64(1) {
		t.Errorf("since_seq = %v, want 1", rs["since_seq"])
	}
	extra, _ := rs["extra"].([]any)
	if len(extra) != 1 {
		t.Fatalf("extra 筆數 = %d, want 1（%v）", len(extra), rs["extra"])
	}
	row, _ := extra[0].(map[string]any)
	if row["username"] != "zhangsan" || row["role_name"] != model.RoleAdmin {
		t.Errorf("差集名稱 = %v/%v, want zhangsan/%s（只有識別的差集稽核讀不出結論）",
			row["username"], row["role_name"], model.RoleAdmin)
	}
	if row["user_id"] != float64(7) || row["role_id"] != float64(1) {
		t.Errorf("差集識別 = %v/%v, want 7/1（改名之後只有識別對得回事件）",
			row["user_id"], row["role_id"])
	}
	ev, ok := rs["last_event"].(map[string]any)
	if !ok {
		t.Fatalf("不符卻無 last_event：稽核無從連到事件。role_state=%v", rs)
	}
	if ev["cause_code"] != model.CauseRoleStateMismatch {
		t.Errorf("last_event.cause_code = %v, want %s", ev["cause_code"], model.CauseRoleStateMismatch)
	}
	if ev["mechanism"] != model.MechanismRoleStateIntegrity {
		t.Errorf("last_event.mechanism = %v, want %s", ev["mechanism"], model.MechanismRoleStateIntegrity)
	}
	if _, has := ev["cause_params"]; has {
		t.Errorf("last_event 帶了 cause_params：鑑識細節不出站")
	}
}

// TestCheckpointVerifyRoleStateMissingAfterDirectDelete 直寫移除＝差集落在 missing 側
func TestCheckpointVerifyRoleStateMissingAfterDirectDelete(t *testing.T) {
	f := setupRoleStateAPIFixture(t)
	// 合法指派（同交易留痕），再以直寫刪除
	if err := f.db.Transaction(func(tx *gorm.DB) error {
		return model.AssignUserRole(tx, 7, 3, model.RoleOriginAPI)
	}); err != nil {
		t.Fatalf("合法指派: %v", err)
	}
	if err := f.db.Exec(`DELETE FROM user_roles WHERE user_id = ? AND role_id = ?`, 7, 3).Error; err != nil {
		t.Fatalf("直寫移除: %v", err)
	}

	rs := f.roleStateOf(t)
	if rs["state"] != audit.RoleStateMismatch {
		t.Fatalf("state = %v, want %s", rs["state"], audit.RoleStateMismatch)
	}
	missing, _ := rs["missing"].([]any)
	if len(missing) != 1 {
		t.Fatalf("missing 筆數 = %d, want 1（%v）", len(missing), rs["missing"])
	}
	row, _ := missing[0].(map[string]any)
	if row["username"] != "zhangsan" || row["role_name"] != model.RoleAuditor {
		t.Errorf("差集名稱 = %v/%v, want zhangsan/%s", row["username"], row["role_name"], model.RoleAuditor)
	}
}

// TestCheckpointVerifyRoleStateWithoutNameLookup 未注入換算面時仍出識別與狀態。
//
// **不得整段隱藏**：驗證頁少一列會被讀成「沒有這個機制」，
// 而它其實正在運作，只是名字補不上
func TestCheckpointVerifyRoleStateWithoutNameLookup(t *testing.T) {
	f := setupRoleStateAPIFixture(t)
	if err := f.db.Exec(`INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)`, 7, 1).Error; err != nil {
		t.Fatalf("直寫提權: %v", err)
	}
	report := &audit.RoleStateReport{Covered: true, State: audit.RoleStateMismatch, SinceSeq: 1,
		Extra: []audit.RolePair{{UserID: 7, RoleID: 1}}}

	view := projectRoleState(report, nil)
	if view == nil || view.State != audit.RoleStateMismatch || len(view.Extra) != 1 {
		t.Fatalf("未注入換算面就沒有結果: %+v", view)
	}
	if view.Extra[0].UserID != 7 || view.Extra[0].RoleID != 1 {
		t.Errorf("識別遺失: %+v", view.Extra[0])
	}
	if view.Extra[0].Username != "" || view.Extra[0].RoleName != "" {
		t.Errorf("未注入換算面卻有名稱: %+v（不得以識別冒充名稱）", view.Extra[0])
	}
}
