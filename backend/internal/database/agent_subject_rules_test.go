package database

import (
	"fmt"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/testgate"
	"regexp"
	"testing"
	"time"
)

func TestAgentSubjectRuleSeedPatterns(t *testing.T) {
	for _, r := range builtinAlertRules {
		if r.SubjectKind != model.KindAgent {
			continue
		}
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			t.Fatal(err)
		}
		examples := []string{"ssh host", "  scp file host:dest", "sftp host", "nc host 22", "socat TCP:host:22 -", "Enter-PSSession host", "Invoke-Command host", "psexec host", "sudo ssh host", "sudo -u ops ssh host", "cd /tmp; ssh host", "true && nc host 22", "x | ssh host", "$(ssh host)", "true || ssh host", "/usr/bin/ssh host", "FOO=bar ssh host", "\"ssh\" host", "pwd\nssh host", "env ncat host 22", "sudo cat x; sftp host", "ssh", "(nc host 22)", "ssh;id", "$'ssh' host", "\\ssh host", "\"\"ssh host", "X=ssh; $X host"}
		negatives := []string{"pwd", "cat ~/.ssh/id_rsa", "sudo cat /root/.ssh/id_rsa", "ls .ssh", "grep sshd /etc/passwd", "echo myssh", "cat scp.log"}
		if r.Name == "Agent 敏感路徑讀取阻斷" {
			examples = []string{"cat ~/.ssh/config", "cat authorized_keys", "cat /etc/shadow", "head id_rsa"}
			negatives = []string{"pwd", "ssh host"}
		}
		for _, cmd := range examples {
			if !re.MatchString(cmd) {
				t.Fatal(r.Name, cmd)
			}
		}
		for _, cmd := range negatives {
			if re.MatchString(cmd) {
				t.Fatal("must not match", r.Name, cmd)
			}
		}
		if r.Action != "block" || r.Direction != model.DirectionInput {
			t.Fatal(r)
		}
	}
}
func TestAgentSubjectRulesPostgres(t *testing.T) {
	db := freshSchema(t, testgate.Value(t, testgate.EnvPGDSN), fmt.Sprintf("w33_rules_%d", time.Now().UnixNano()))
	for _, m := range migrations {
		if err := m.Up(db); err != nil {
			t.Fatal(m.Version, err)
		}
	}
	assertBuiltinAlertRules(t, db)
	if err := applyAgentSubjectRules(db); err != nil {
		t.Fatal(err)
	}
	assertBuiltinAlertRules(t, db)
	if err := db.Model(&model.AlertRule{}).Where("subject_kind=?", model.KindAgent).Updates(map[string]any{"enabled": false, "pattern": "operator-edited"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := applyAgentSubjectRules(db); err != nil {
		t.Fatal(err)
	}
	var rows []model.AlertRule
	db.Where("subject_kind=?", model.KindAgent).Find(&rows)
	if len(rows) != 2 {
		t.Fatal(rows)
	}
	for _, r := range rows {
		if r.Enabled || r.Pattern != "operator-edited" {
			t.Fatal("seed overwrote operator edit", r)
		}
	}
}
