package asset

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/sshmaterial"
)

const e2eSudoers = "root ALL=(ALL) ALL\nalice ALL=(ALL) ALL\n%wheel ALL=(ALL) ALL\n"

func e2eFinding(res *invScanResult, name string) *invFindingResult {
	for i := range res.Findings {
		if res.Findings[i].Username == name {
			return &res.Findings[i]
		}
	}
	return nil
}

func e2eCoverage(res *invScanResult, check string) *invCoverageItem {
	for i := range res.Coverage {
		if res.Coverage[i].Check == check {
			return &res.Coverage[i]
		}
	}
	return nil
}

// root 身分讀得到 sudoers：完成，各項檢查範圍皆為已檢查。
func TestInventoryE2ERoot(t *testing.T) {
	tg := newInvTarget(t, "pw")
	tg.setStandard("0\n", stdPasswd+"alice:x:1001:1001:Linux User:/home/alice:/bin/sh\n", stdGroup,
		sudoFrames(true, strp(e2eSudoers), "ok"))
	res, ie := runCollect(t, tg, "root", "")
	if ie != nil {
		t.Fatalf("盤點失敗：%v", ie)
	}
	if res.Status != model.HostAccountScanSucceeded {
		t.Fatalf("status=%s coverage=%+v", res.Status, res.Coverage)
	}
	for _, c := range res.Coverage {
		if c.State != invStateChecked {
			t.Fatalf("root 身分應全部已檢查，%s=%s/%s", c.Check, c.State, c.Reason)
		}
	}
	a := e2eFinding(res, "alice")
	if a == nil || !a.Privileged || !strings.Contains(strings.Join(a.Reasons, ","), model.PrivReasonSudoersUser) {
		t.Fatalf("alice 應因 sudoers 直接授權為特權：%+v", a)
	}
	if a.Incomplete {
		t.Fatalf("完整檢查下不應標 incomplete")
	}
}

// 非 root 身分讀不到 sudoers：部分完成，逐項標無法讀取，帳號標 incomplete。
func TestInventoryE2ENonRoot(t *testing.T) {
	tg := newInvTarget(t, "pw")
	tg.setStandard("1000\n", stdPasswd, stdGroup, sudoFrames(true, strp("!unreadable"), "ok", [2]string{"90-x", "!unreadable"}))
	res, ie := runCollect(t, tg, "ops", "")
	if ie != nil {
		t.Fatalf("盤點失敗：%v", ie)
	}
	if res.Status != model.HostAccountScanPartial {
		t.Fatalf("應為部分完成，got %s", res.Status)
	}
	m := e2eCoverage(res, invCheckSudoMain)
	if m == nil || m.State != invStateUnreadable {
		t.Fatalf("主規則檔應標無法讀取：%+v", m)
	}
	incomplete := 0
	for _, f := range res.Findings {
		if f.Incomplete {
			incomplete++
		}
	}
	if incomplete == 0 {
		t.Fatalf("讀不到 sudoers 時至少一個帳號應標 incomplete")
	}
}

// 登入失敗：只有一次交握，出現的帳號名恰為該帳號，密碼與公鑰嘗試各至多一次。
func TestInventoryE2ELoginFailedSingleHandshake(t *testing.T) {
	tg := newInvTarget(t, "right-password")
	tg.setStandard("0\n", stdPasswd, stdGroup, sudoFrames(false, nil, "absent"))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, ie := collectInventory(ctx, 1, tg.addr(), "ops", sshmaterial.CopyPassword([]byte("wrong")), nil, tg.hostKeyCallback(), "")
	if ie == nil || ie.Reason != model.InventoryLoginFailed {
		t.Fatalf("應以登入失敗結束，got %v", ie)
	}
	tg.mu.Lock()
	defer tg.mu.Unlock()
	if tg.handshakes != 1 {
		t.Fatalf("交握次數 %d，應為 1", tg.handshakes)
	}
	if len(tg.users) != 1 || !tg.users["ops"] {
		t.Fatalf("出現的帳號名集合應恰為 ops：%v", tg.users)
	}
	if tg.pwCalls > 1 || tg.pkCalls > 1 {
		t.Fatalf("認證嘗試過多：password=%d publickey=%d", tg.pwCalls, tg.pkCalls)
	}
	if len(tg.commands) != 0 {
		t.Fatalf("登入失敗後不應執行任何指令：%q", tg.commands)
	}
}

// 逾時：遠端停滯超過期限，以逾時原因碼結束，不寫部分結果。
func TestInventoryE2ETimeout(t *testing.T) {
	tg := newInvTarget(t, "pw")
	tg.setStandard("0\n", stdPasswd, stdGroup, sudoFrames(false, nil, "absent"))
	tg.stall = 3 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	start := time.Now()
	res, ie := collectInventory(ctx, 1, tg.addr(), "root", sshmaterial.CopyPassword([]byte("pw")), nil, tg.hostKeyCallback(), "")
	if ie == nil || ie.Reason != model.InventoryTimeout {
		t.Fatalf("應以逾時結束，got res=%v err=%v", res, ie)
	}
	if res != nil {
		t.Fatalf("逾時不應回部分結果")
	}
	if time.Since(start) > 2500*time.Millisecond {
		t.Fatalf("逾時沒有及時返回：%v", time.Since(start))
	}
}
