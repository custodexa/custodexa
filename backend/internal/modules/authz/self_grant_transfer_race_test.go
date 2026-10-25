package authz

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"gorm.io/gorm"
)

// 擁有者轉移與申請決定、多票核准的交錯（安全審查 B-02、B-04）。
//
// B-02：自核判定原本只在交易外做一次；擁有者轉移可以插在判定與寫票之間。
// 修法是交易內先鎖申請人（agent）的使用者列（與擁有者轉移同鎖序）再重判。
// B-04：新擁有者先前對該 agent 投下、仍有效的核准票，轉移守衛原本看不到；
// 修法是轉移守衛納入票，且最後計票只算與申請人獨立的票。
//
// 突變自檢：
// - 把 approveRequestItems／RejectItem 交易內的 selfDecisionBlockedLocked 拿掉，
//   「轉移插在判定與交易之間」兩案轉紅；
// - 把 CheckOwnerTransfer 的核准票查詢拿掉，「待審票擋轉移」「已核准票擋轉移」轉紅；
// - 把 independentVoteCount 改回直接 Count，「現任擁有者的舊票不計入門檻」轉紅。

// afterFirstOwnerRead 在第一次「查申請人擁有者」的 count 查詢完成後執行一次 fn：
// 確定性地把另一個操作排在守衛讀值之後。
func afterFirstOwnerRead(t *testing.T, db *gorm.DB, name string, fn func()) *bool {
	t.Helper()
	fired := false
	err := db.Callback().Query().After("gorm:query").Register(name, func(q *gorm.DB) {
		sql := q.Statement.SQL.String()
		if fired || !strings.Contains(sql, "count(*)") || !strings.Contains(sql, "owner_user_id =") {
			return
		}
		fired = true
		fn()
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Callback().Query().Remove(name) })
	return &fired
}

// raceEnv 在 ownAgentEnv 上補齊擁有者轉移守衛解析新擁有者主體所需的角色表。
func raceEnv(t *testing.T) (*AccessRequestService, *gorm.DB) {
	t.Helper()
	svc, db := ownAgentEnv(t)
	if err := db.AutoMigrate(&model.Role{}, &model.RolePermission{}, &model.UserGroupMember{},
		&model.UserGroupRole{}, &model.RoleBindingNode{}); err != nil {
		t.Fatal(err)
	}
	return svc, db
}

// transferGuarded 走真守衛的擁有者轉移（與 UserService.guardOwnerTransfer 同序：鎖 agent 列後判定）。
func transferGuarded(db *gorm.DB, agentID, newOwner uint) error {
	return db.Transaction(func(tx *gorm.DB) error {
		if err := lockUserRows(tx, []uint{agentID}); err != nil {
			return err
		}
		if err := (SelfGrantGuard{}).CheckOwnerTransfer(tx, agentID, newOwner); err != nil {
			return err
		}
		return tx.Model(&model.User{}).Where("id = ?", agentID).Update("owner_user_id", newOwner).Error
	})
}

func ticketsFor(t *testing.T, db *gorm.DB, agentID uint) int64 {
	t.Helper()
	var n int64
	if err := db.Model(&model.AssetAuthorization{}).Where("user_id = ? AND source = ?", agentID, model.AuthorizationSourceTicket).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

func requestStatus(t *testing.T, db *gorm.DB, id uint) model.AccessRequestStatus {
	t.Helper()
	var row model.AccessRequest
	if err := db.First(&row, id).Error; err != nil {
		t.Fatal(err)
	}
	return row.Status
}

func TestApprovalOwnerTransferInterleavings(t *testing.T) {
	// agent 7 屬 owner 2；user 5 具資格且非擁有者。
	t.Run("轉移插在核准的交易外判定與交易之間：交易內重判拒絕，零票零票證", func(t *testing.T) {
		svc, db := raceEnv(t)
		req := submitByAgent(t, svc)
		fired := afterFirstOwnerRead(t, db, "race-approve", func() {
			if err := transferGuarded(db, 7, 5); err != nil {
				t.Errorf("此刻尚無 5 的票或票證，轉移應成功: %v", err)
			}
		})
		_, err := svc.Approve(5, false, req.ID, DecideInput{})
		if !*fired {
			t.Fatal("夾具：交錯未發生")
		}
		if !errors.Is(err, ErrSelfApproval) {
			t.Fatalf("轉移後成為擁有者的核准應回 ErrSelfApproval，實得 %v", err)
		}
		if v := countVotes(t, db, req.ID); v != 0 {
			t.Fatalf("被拒不得留票: votes=%d", v)
		}
		if n := ticketsFor(t, db, 7); n != 0 {
			t.Fatalf("被拒不得發票證: tickets=%d", n)
		}
		if s := requestStatus(t, db, req.ID); s != model.AccessRequestPending {
			t.Fatalf("單應維持待審: %s", s)
		}
	})

	t.Run("轉移插在拒絕的交易外判定與交易之間：交易內重判拒絕，單維持待審", func(t *testing.T) {
		svc, db := raceEnv(t)
		req := submitByAgent(t, svc)
		fired := afterFirstOwnerRead(t, db, "race-reject", func() {
			if err := transferGuarded(db, 7, 5); err != nil {
				t.Errorf("轉移應成功: %v", err)
			}
		})
		_, err := svc.RejectItem(5, false, req.ID, 0, "no")
		if !*fired {
			t.Fatal("夾具：交錯未發生")
		}
		if !errors.Is(err, ErrSelfApproval) {
			t.Fatalf("應回 ErrSelfApproval，實得 %v", err)
		}
		if s := requestStatus(t, db, req.ID); s != model.AccessRequestPending {
			t.Fatalf("單應維持待審: %s", s)
		}
	})

	t.Run("核准先提交再轉移：票證由 5 核發，轉給 5 被守衛拒絕", func(t *testing.T) {
		svc, db := raceEnv(t)
		req := submitByAgent(t, svc)
		if _, err := svc.Approve(5, false, req.ID, DecideInput{}); err != nil {
			t.Fatalf("非擁有者核准應成功: %v", err)
		}
		if n := ticketsFor(t, db, 7); n != 1 {
			t.Fatalf("tickets=%d", n)
		}
		if err := transferGuarded(db, 7, 5); !errors.Is(err, ErrAgentOwnerTransferSelfGrant) {
			t.Fatalf("有效票證的核發者不得成為擁有者: %v", err)
		}
	})
}

func TestQuorumVoteThenOwnerTransfer(t *testing.T) {
	setup := func(t *testing.T) (*AccessRequestService, *gorm.DB, *model.AccessRequest) {
		t.Helper()
		svc, db := raceEnv(t)
		if _, err := svc.policies.Update(policy.PolicyAccessRequestMinApprovals, "2", "admin"); err != nil {
			t.Fatal(err)
		}
		return svc, db, submitByAgent(t, svc)
	}

	t.Run("待審票擋轉移：5 投第一票後，把 agent 轉給 5 被拒", func(t *testing.T) {
		svc, db, req := setup(t)
		if _, err := svc.Approve(5, false, req.ID, DecideInput{}); err != nil {
			t.Fatalf("第一票: %v", err)
		}
		if s := requestStatus(t, db, req.ID); s != model.AccessRequestPending {
			t.Fatalf("門檻 2 時一票應仍待審: %s", s)
		}
		if err := transferGuarded(db, 7, 5); !errors.Is(err, ErrAgentOwnerTransferSelfGrant) {
			t.Fatalf("對該 agent 持待審票者不得成為擁有者: %v", err)
		}
		// 票作廢（單被拒）後同一轉移成功
		if _, err := svc.RejectItem(3, true, req.ID, 0, "closed"); err != nil {
			t.Fatalf("拒絕: %v", err)
		}
		if err := transferGuarded(db, 7, 5); err != nil {
			t.Fatalf("票已無效後轉移應成功: %v", err)
		}
	})

	t.Run("現任擁有者的舊票不計入門檻：繞過守衛改擁有者後，最後一票不足額", func(t *testing.T) {
		svc, db, req := setup(t)
		if _, err := svc.Approve(5, false, req.ID, DecideInput{}); err != nil {
			t.Fatalf("第一票: %v", err)
		}
		// 不經守衛直接改擁有者：模擬守衛以外的路徑，計票必須自己守住獨立性
		if err := db.Model(&model.User{}).Where("id = ?", 7).Update("owner_user_id", 5).Error; err != nil {
			t.Fatal(err)
		}
		got, err := svc.Approve(2, false, req.ID, DecideInput{})
		if err != nil {
			t.Fatalf("前擁有者 2 已非擁有者，投票應成功: %v", err)
		}
		if got.Status != model.AccessRequestPending {
			t.Fatalf("5 已是擁有者，其舊票不得計入；兩票中只有一票獨立，單應仍待審: %s", got.Status)
		}
		if n := ticketsFor(t, db, 7); n != 0 {
			t.Fatalf("不足額不得發票證: tickets=%d", n)
		}
		if v := countVotes(t, db, req.ID); v != 2 {
			t.Fatalf("票列保留供稽核: votes=%d", v)
		}
	})

	t.Run("已核准票擋轉移：票證由最後一票核發，先前投票者仍不得成為擁有者；票證到期後可", func(t *testing.T) {
		svc, db, req := setup(t)
		if _, err := svc.Approve(5, false, req.ID, DecideInput{}); err != nil {
			t.Fatalf("第一票: %v", err)
		}
		got, err := svc.Approve(3, true, req.ID, DecideInput{})
		if err != nil || got.Status != model.AccessRequestApproved {
			t.Fatalf("第二票應核准: err=%v status=%s", err, got.Status)
		}
		var ticket model.AssetAuthorization
		if err := db.Where("user_id = ? AND source = ?", 7, model.AuthorizationSourceTicket).First(&ticket).Error; err != nil {
			t.Fatal(err)
		}
		if ticket.GrantedBy != 3 {
			t.Fatalf("夾具：票證應記最後一票 3: %d", ticket.GrantedBy)
		}
		if err := transferGuarded(db, 7, 5); !errors.Is(err, ErrAgentOwnerTransferSelfGrant) {
			t.Fatalf("5 的核准票仍支撐有效票證，轉移應被拒: %v", err)
		}
		past := time.Now().Add(-time.Second)
		if err := db.Model(&model.AssetAuthorization{}).Where("id = ?", ticket.ID).Update("date_expired", past).Error; err != nil {
			t.Fatal(err)
		}
		if err := transferGuarded(db, 7, 5); err != nil {
			t.Fatalf("票證到期後轉移應成功: %v", err)
		}
	})
}
