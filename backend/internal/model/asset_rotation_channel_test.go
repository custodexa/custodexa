package model

import "testing"

var rotationTestProtocols = []ProtocolType{
	ProtocolSSH, ProtocolRDP, ProtocolVNC, ProtocolMySQL,
	ProtocolPostgres, ProtocolRedis, ProtocolMSSQL, ProtocolK8s,
}

// 五通道（含未設定）× 八協定的相容性表：每一格都寫死，新增通道或協定時表格必須跟著改。
func TestRotationChannelCompatibilityTable(t *testing.T) {
	want := map[string]map[ProtocolType]bool{
		"": {ProtocolSSH: true, ProtocolRDP: true, ProtocolVNC: true, ProtocolMySQL: true,
			ProtocolPostgres: true, ProtocolRedis: true, ProtocolMSSQL: true, ProtocolK8s: true},
		RotationChannelNone: {ProtocolSSH: true, ProtocolRDP: true, ProtocolVNC: true, ProtocolMySQL: true,
			ProtocolPostgres: true, ProtocolRedis: true, ProtocolMSSQL: true, ProtocolK8s: true},
		RotationChannelPosixSSH:     {ProtocolSSH: true},
		RotationChannelWindowsWinRM: {ProtocolSSH: true, ProtocolRDP: true},
		RotationChannelWindowsSSH:   {ProtocolSSH: true, ProtocolRDP: true},
		RotationChannelDBNative:     {ProtocolMySQL: true, ProtocolPostgres: true, ProtocolMSSQL: true},
	}
	for channel, row := range want {
		for _, p := range rotationTestProtocols {
			if got := RotationChannelCompatibleWith(p, channel); got != row[p] {
				t.Errorf("RotationChannelCompatibleWith(%q, %q) = %v, want %v", p, channel, got, row[p])
			}
		}
	}
	if RotationChannelCompatibleWith(ProtocolMySQL, "db") {
		t.Error("值域外的通道不得相容任何協定")
	}
}

func TestRotationChannelValueDomain(t *testing.T) {
	if !IsRotationChannel(RotationChannelDBNative) {
		t.Fatal("db_native 必須在值域內")
	}
	if len(RotationChannelDBNative) > 16 {
		t.Fatal("通道值超過欄寬 16")
	}
	if IsRotationChannel("db_native ") {
		t.Fatal("值域外字串不得放行")
	}
}

// 推導不納入 db_native：未設定的資料庫資產一律推成 none。
func TestRotationChannelEffectiveNoDBInference(t *testing.T) {
	for _, p := range rotationTestProtocols {
		a := &Asset{Protocol: p}
		want := RotationChannelNone
		if p == ProtocolSSH {
			want = RotationChannelPosixSSH
		}
		if got := a.EffectiveRotationChannel(); got != want {
			t.Errorf("EffectiveRotationChannel(%s, 未設定) = %q, want %q", p, got, want)
		}
	}
	for _, p := range []ProtocolType{ProtocolMySQL, ProtocolPostgres, ProtocolMSSQL} {
		if got := (&Asset{Protocol: p}).EffectiveRotationChannel(); got != RotationChannelNone {
			t.Errorf("空值 %s 資產推導為 %q，必須是 none", p, got)
		}
		if got := (&Asset{Protocol: p, RotationChannel: RotationChannelDBNative}).EffectiveRotationChannel(); got != RotationChannelDBNative {
			t.Errorf("顯式 db_native 的 %s 資產推導為 %q", p, got)
		}
	}
}

func TestRotationChannelSupportsSSHKey(t *testing.T) {
	want := map[string]bool{
		"": false, RotationChannelNone: false, RotationChannelPosixSSH: true,
		RotationChannelWindowsWinRM: false, RotationChannelWindowsSSH: false, RotationChannelDBNative: false,
	}
	for ch, w := range want {
		if got := RotationChannelSupportsSSHKey(ch); got != w {
			t.Errorf("RotationChannelSupportsSSHKey(%q) = %v, want %v", ch, got, w)
		}
	}
}

func TestRotationChannelHostKeyTransport(t *testing.T) {
	cases := []struct {
		channel, transport string
		hasKey             bool
	}{
		{RotationChannelPosixSSH, HostKeyTransportSSH, true},
		{RotationChannelWindowsSSH, HostKeyTransportSSH, true},
		{RotationChannelWindowsWinRM, HostKeyTransportWinRM, false},
		{RotationChannelDBNative, HostKeyTransportDB, false},
		{RotationChannelNone, HostKeyTransportSSH, true},
		{"", HostKeyTransportSSH, true},
		{"unknown_channel", HostKeyTransportSSH, true},
	}
	for _, c := range cases {
		got := HostKeyTransportForChannel(c.channel)
		if got != c.transport {
			t.Errorf("HostKeyTransportForChannel(%q) = %q, want %q", c.channel, got, c.transport)
		}
		if HostKeyTransportHasHostKey(got) != c.hasKey {
			t.Errorf("HostKeyTransportHasHostKey(%q) = %v, want %v", got, !c.hasKey, c.hasKey)
		}
	}
	for _, tr := range []string{HostKeyTransportSSH, HostKeyTransportWinRM, HostKeyTransportDB} {
		if !IsHostKeyTransport(tr) {
			t.Errorf("IsHostKeyTransport(%q) 應為真", tr)
		}
	}
	for tr, want := range map[string]bool{HostKeyTransportWinRM: true, HostKeyTransportDB: true,
		HostKeyTransportSSH: false, "": false, "rdp": false} {
		if HostKeyTransportIsKeyless(tr) != want {
			t.Errorf("HostKeyTransportIsKeyless(%q) 應為 %v（空值與值域外須落在 fail-closed 側）", tr, want)
		}
	}
	for _, tr := range []string{"", "SSH", "rdp", "db_native"} {
		if IsHostKeyTransport(tr) {
			t.Errorf("IsHostKeyTransport(%q) 應為假", tr)
		}
		if HostKeyTransportHasHostKey(tr) {
			t.Errorf("HostKeyTransportHasHostKey(%q) 應為假", tr)
		}
	}
}

// 資料庫自改的傳輸風險：四協定 × 五個 TLS 檔位（含值域外）× 兩通道，每格寫死。
func TestDBRotationTransportRisk(t *testing.T) {
	tlsModes := []string{"", "disable", "require", "verify-ca", "verify-full", "prefer"}
	encrypted := map[string]bool{"require": true, "verify-ca": true, "verify-full": true}
	dbProtocols := map[ProtocolType]bool{ProtocolMySQL: true, ProtocolPostgres: true, ProtocolMSSQL: true, ProtocolRedis: false}
	for p, supported := range dbProtocols {
		for _, mode := range tlsModes {
			for _, channel := range []string{RotationChannelDBNative, RotationChannelNone} {
				want := ""
				if supported && channel == RotationChannelDBNative && !encrypted[mode] {
					want = RiskDBRotationUnencrypted
				}
				if got := DBRotationTransportRisk(string(p), channel, mode); got != want {
					t.Errorf("DBRotationTransportRisk(%q, %q, %q) = %q, want %q", p, channel, mode, got, want)
				}
			}
		}
	}
	if got := DBRotationTransportRisk(string(ProtocolMySQL), RotationChannelDBNative, "disable"); got != "db_rotation_unencrypted" {
		t.Errorf("風險鍵字面須為 db_rotation_unencrypted, got %q", got)
	}
	if got := DBRotationTransportRisk(string(ProtocolMySQL), "", ""); got != "" {
		t.Errorf("未設定通道（推導為 none）不得標資料庫改密風險, got %q", got)
	}
}
