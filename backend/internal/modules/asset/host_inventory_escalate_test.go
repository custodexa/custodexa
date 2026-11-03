package asset

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/sshmaterial"
)

type tarEnt struct {
	name string
	typ  byte
	body string
	link string
}

func buildTar(t *testing.T, ents ...tarEnt) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for _, e := range ents {
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: 0o440, Linkname: e.link}
		if e.typ == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if e.typ == tar.TypeDir {
			h.Mode = 0o750
		}
		require.NoError(t, w.WriteHeader(h))
		if e.typ == tar.TypeReg {
			_, err := w.Write([]byte(e.body))
			require.NoError(t, err)
		}
	}
	require.NoError(t, w.Close())
	return b.Bytes()
}

const adminRule = "ops ALL=(ALL) ALL\n#includedir /etc/sudoers.d\n"

func regE(name, body string) tarEnt { return tarEnt{name: name, typ: tar.TypeReg, body: body} }
func dirE(name string) tarEnt       { return tarEnt{name: name, typ: tar.TypeDir} }

// runEsc 以專用帳號身分對靶機跑一次盤點；password 為 nil＝金鑰型（不提供密碼副本），否則為密碼型。
func runEsc(t *testing.T, tg *invTarget, uid string, sudo string, password []byte) (*invScanResult, *inventoryError) {
	t.Helper()
	tg.setStandard(uid, stdPasswd, stdGroup, sudo)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	esc := password
	if esc == nil {
		esc = []byte{}
	}
	return collectInventoryWith(ctx, 1, tg.addr(), "ops", sshmaterial.CopyPassword([]byte("pw")), nil, tg.hostKeyCallback(), "", esc)
}

func TestInventoryEscalatedReadConstant(t *testing.T) {
	unreadable := sudoFrames(true, strp("!unreadable"), "unreadable")
	archive := string(buildTar(t, regE("sudoers", adminRule), dirE("sudoers.d")))
	var runs [][]string
	for _, v := range []string{"ops", "svc-admin"} {
		tg := newInvTarget(t, "pw")
		tg.setCmd(inventoryEscalatedCmdNoPassword, invResponse{Out: archive})
		tg.setStandard("1000\n", stdPasswd, stdGroup, unreadable)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		_, ie := collectInventoryWith(ctx, 1, tg.addr(), v, sshmaterial.CopyPassword([]byte("pw")), nil, tg.hostKeyCallback(), "root,wheel", []byte{})
		cancel()
		require.Nil(t, ie)
		runs = append(runs, tg.recorded())
	}
	require.Len(t, runs[0], 5)
	assert.Equal(t, runs[0], runs[1], "兩組帳號名下送出的指令逐位元組相同")
	for _, c := range runs[0] {
		assert.NotContains(t, c, "sh -c 'env", "提權讀取不經 sh -c")
	}
	assert.Equal(t, inventoryEscalatedCmdNoPassword, runs[0][4])
	assert.NotContains(t, inventoryEscalatedCmdNoPassword, "sh -c")
	assert.NotContains(t, inventoryEscalatedCmdPassword, "sh -c")

	t.Run("金鑰型所有 stdin 不含密碼", func(t *testing.T) {
		tg := newInvTarget(t, "pw")
		tg.setCmd(inventoryEscalatedCmdNoPassword, invResponse{Err: "sudo: a password is required\n", Exit: 1})
		_, ie := runEsc(t, tg, "1000\n", unreadable, nil)
		require.Nil(t, ie)
		for _, in := range tg.stdins {
			assert.NotContains(t, in, "pw")
		}
		assert.Len(t, tg.stdinOf(inventoryEscalatedCmdPassword), 0, "金鑰型沒有第二段")
	})
	t.Run("密碼型第一段 stdin 為空、第二段恰為密碼一列", func(t *testing.T) {
		tg := newInvTarget(t, "pw")
		tg.setCmd(inventoryEscalatedCmdNoPassword, invResponse{Err: "sudo: a password is required\n", Exit: 1})
		tg.setCmd(inventoryEscalatedCmdPassword, invResponse{Out: archive})
		res, ie := runEsc(t, tg, "1000\n", unreadable, []byte("sekret-pw"))
		require.Nil(t, ie)
		assert.Equal(t, []string{""}, tg.stdinOf(inventoryEscalatedCmdNoPassword))
		assert.Equal(t, []string{"sekret-pw\n"}, tg.stdinOf(inventoryEscalatedCmdPassword))
		assert.Equal(t, invEscalationUsed, res.Escalation)
	})
	t.Run("預設帳號與 uid 0 不提權", func(t *testing.T) {
		tg := newInvTarget(t, "pw")
		_, ie := runCollect(t, tg, "ops", "")
		_ = ie
		tg2 := newInvTarget(t, "pw")
		res, ie2 := runEsc(t, tg2, "0\n", unreadable, []byte{})
		require.Nil(t, ie2)
		assert.Equal(t, invEscalationNotNeeded, res.Escalation)
		for _, r := range [][]string{tg.recorded(), tg2.recorded()} {
			for _, c := range r {
				assert.False(t, reSudoCommandWord.MatchString(c), c)
			}
		}
		assert.Len(t, tg2.recorded(), 4)
	})
}

func TestInventoryEscalatedReadParse(t *testing.T) {
	t.Run("正常兩檔", func(t *testing.T) {
		a, err := parseEscalatedArchive(buildTar(t, regE("sudoers", adminRule), dirE("sudoers.d"), regE("sudoers.d/a", "x\n"), regE("sudoers.d/b", "y\n")))
		require.NoError(t, err)
		assert.True(t, a.HasMain)
		assert.Len(t, a.Files, 2)
		assert.Zero(t, a.Unparsable)
	})
	t.Run("符號連結計入無法解析", func(t *testing.T) {
		a, err := parseEscalatedArchive(buildTar(t, regE("sudoers", adminRule), dirE("sudoers.d"),
			tarEnt{name: "sudoers.d/link", typ: tar.TypeSymlink, link: "/etc/shadow"}))
		require.NoError(t, err)
		assert.Equal(t, 1, a.Unparsable)
		assert.Empty(t, a.Files)
	})
	t.Run("更深的路徑略過", func(t *testing.T) {
		a, err := parseEscalatedArchive(buildTar(t, regE("sudoers", adminRule), dirE("sudoers.d"), dirE("sudoers.d/a"), regE("sudoers.d/a/b", "z\n")))
		require.NoError(t, err)
		assert.Empty(t, a.Files)
		assert.Zero(t, a.Unparsable)
	})
	t.Run("串流超過 4 MiB", func(t *testing.T) {
		tg := newInvTarget(t, "pw")
		tg.setCmd(inventoryEscalatedCmdNoPassword, invResponse{Out: strings.Repeat("A", inventoryMaxEscalatedBytes+1)})
		_, ie := runEsc(t, tg, "1000\n", sudoFrames(true, strp("!unreadable"), "unreadable"), nil)
		require.NotNil(t, ie)
		assert.Equal(t, model.InventoryOutputLimit, ie.Reason)
	})
	t.Run("截斷標頭", func(t *testing.T) {
		full := buildTar(t, regE("sudoers", adminRule), dirE("sudoers.d"))
		tg := newInvTarget(t, "pw")
		tg.setCmd(inventoryEscalatedCmdNoPassword, invResponse{Out: string(full[:300])})
		_, ie := runEsc(t, tg, "1000\n", sudoFrames(true, strp("!unreadable"), "unreadable"), nil)
		require.NotNil(t, ie)
		assert.Equal(t, model.InventoryOutputMalformed, ie.Reason)
	})
	t.Run("檔內容含 @@END 與換行不影響後續檔", func(t *testing.T) {
		a, err := parseEscalatedArchive(buildTar(t, regE("sudoers", adminRule), dirE("sudoers.d"),
			regE("sudoers.d/a", "@@END\nF 6161 ok\n"), regE("sudoers.d/b", "ok\n")))
		require.NoError(t, err)
		require.Len(t, a.Files, 2)
		assert.Equal(t, "b", a.Files[1].Name)
	})
}

func TestInventoryEscalatedReadCoverage(t *testing.T) {
	unreadable := sudoFrames(true, strp("!unreadable"), "unreadable")
	run := func(t *testing.T, s4 string, out []byte, exit uint32) (*invScanResult, *inventoryError) {
		t.Helper()
		tg := newInvTarget(t, "pw")
		tg.setCmd(inventoryEscalatedCmdNoPassword, invResponse{Out: string(out), Exit: exit})
		return runEsc(t, tg, "1000\n", s4, nil)
	}
	t.Run("提權讀取成功", func(t *testing.T) {
		res, ie := run(t, unreadable, buildTar(t, regE("sudoers", adminRule), dirE("sudoers.d")), 0)
		require.Nil(t, ie)
		for _, c := range []string{invCheckSudoMain, invCheckSudoDir, invCheckUnresolved} {
			it := coverageOf(res, c)
			assert.Equal(t, invStateChecked, it.State, c)
			assert.Equal(t, invReasonViaEscalation, it.Reason, c)
		}
		assert.Equal(t, model.HostAccountScanSucceeded, res.Status)
		var ops *invFindingResult
		for i := range res.Findings {
			if res.Findings[i].Username == "ops" {
				ops = &res.Findings[i]
			}
		}
		require.NotNil(t, ops)
		assert.True(t, ops.Privileged, "sudoers 規則授權的帳號為特權")
	})
	t.Run("提權讀取被拒", func(t *testing.T) {
		res, ie := run(t, sudoFrames(true, strp("!unreadable"), "unreadable"), nil, 1)
		require.Nil(t, ie)
		assert.Equal(t, invEscalationDenied, res.Escalation)
		assert.Equal(t, invReasonEscalationDenied, coverageOf(res, invCheckSudoMain).Reason)
		assert.Equal(t, invReasonEscalationDenied, coverageOf(res, invCheckSudoDir).Reason)
		assert.Equal(t, model.HostAccountScanPartial, res.Status)
		for _, f := range res.Findings {
			assert.True(t, f.Incomplete, f.Username)
		}
	})
	t.Run("未提權讀取為 absent 的項目被拒時維持不存在", func(t *testing.T) {
		res, ie := run(t, sudoFrames(true, strp("!unreadable"), "absent"), nil, 1)
		require.Nil(t, ie)
		assert.Equal(t, invStateAbsent, coverageOf(res, invCheckSudoDir).State)
		assert.Equal(t, invReasonEscalationDenied, coverageOf(res, invCheckSudoMain).Reason)
	})
	for _, exit := range []uint32{2, 1} {
		t.Run(fmt.Sprintf("封存只含 sudoers、退出碼 %d、目錄 absent", exit), func(t *testing.T) {
			res, ie := run(t, sudoFrames(true, strp("!unreadable"), "absent"), buildTar(t, regE("sudoers", adminRule)), exit)
			require.Nil(t, ie)
			main := coverageOf(res, invCheckSudoMain)
			assert.Equal(t, invStateChecked, main.State)
			assert.Equal(t, invReasonViaEscalation, main.Reason)
			assert.Equal(t, invStateAbsent, coverageOf(res, invCheckSudoDir).State)
			for _, it := range res.Coverage {
				assert.NotEqual(t, invReasonEscalationDenied, it.Reason)
			}
		})
	}
	t.Run("退出 0 但沒有 sudoers 一般檔", func(t *testing.T) {
		_, ie := run(t, unreadable, buildTar(t, dirE("sudoers.d")), 0)
		require.NotNil(t, ie)
		assert.Equal(t, model.InventoryOutputMalformed, ie.Reason)
	})
	t.Run("退出碼非零的完整性核對", func(t *testing.T) {
		okDir := sudoFrames(true, strp("!unreadable"), "ok", [2]string{"a", "!unreadable"}, [2]string{"b", "!unreadable"})
		res, ie := run(t, okDir, buildTar(t, regE("sudoers", adminRule), dirE("sudoers.d"), regE("sudoers.d/a", "x\n")), 2)
		require.Nil(t, ie)
		dir := coverageOf(res, invCheckSudoDir)
		assert.Equal(t, invStatePartial, dir.State)
		assert.Equal(t, invReasonViaEscalation, dir.Reason)
		assert.Equal(t, 1, dir.Count)
		assert.Equal(t, model.HostAccountScanPartial, res.Status)
		for _, f := range res.Findings {
			assert.True(t, f.Incomplete)
		}

		res, ie = run(t, unreadable, buildTar(t, regE("sudoers", adminRule), dirE("sudoers.d")), 2)
		require.Nil(t, ie)
		dir = coverageOf(res, invCheckSudoDir)
		assert.Equal(t, invStatePartial, dir.State, "未提權讀取的目錄讀不到、退出非零：不是已檢查")
		assert.Equal(t, invReasonViaEscalation, dir.Reason)

		res, ie = run(t, sudoFrames(true, strp("!unreadable"), "ok", [2]string{"a", "x\n"}), buildTar(t, regE("sudoers", adminRule)), 2)
		require.Nil(t, ie)
		dir = coverageOf(res, invCheckSudoDir)
		assert.Equal(t, invStateUnreadable, dir.State, "目錄存在但封存沒有：無法讀取，不是不存在")
		assert.Equal(t, invReasonViaEscalation, dir.Reason)
	})
	t.Run("退出 0 的對照組照封存記已檢查", func(t *testing.T) {
		okDir := sudoFrames(true, strp("!unreadable"), "ok", [2]string{"a", "!unreadable"}, [2]string{"b", "!unreadable"})
		res, ie := run(t, okDir, buildTar(t, regE("sudoers", "#includedir /etc/sudoers.d\n"), dirE("sudoers.d"), regE("sudoers.d/a", "x\n"), regE("sudoers.d/b", "y\n")), 0)
		require.Nil(t, ie)
		dir := coverageOf(res, invCheckSudoDir)
		assert.Equal(t, invStateChecked, dir.State)
		assert.Equal(t, invReasonViaEscalation, dir.Reason)
		assert.Equal(t, 2, dir.Count)
	})
	t.Run("真 tar 產生的封存", func(t *testing.T) {
		if _, err := exec.LookPath("tar"); err != nil {
			t.Skip("測試環境沒有 tar；由實機實跑補證")
		}
		d := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(d, "sudoers"), []byte(adminRule), 0o440))
		cmd := exec.Command("tar", "-cf", "-", "-C", d, "sudoers", "sudoers.d")
		out, _ := cmd.Output() // sudoers.d 不存在：非零退出但封存仍合法
		res, ie := run(t, sudoFrames(true, strp("!unreadable"), "absent"), out, 2)
		require.Nil(t, ie)
		assert.Equal(t, invReasonViaEscalation, coverageOf(res, invCheckSudoMain).Reason)
		assert.Equal(t, invStateAbsent, coverageOf(res, invCheckSudoDir).State)
	})
}
