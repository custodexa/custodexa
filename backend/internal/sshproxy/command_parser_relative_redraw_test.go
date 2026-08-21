package sshproxy

// 純相對重繪的全螢幕程式不得產生假指令（charter backlog #18）。
//
// 語料為**實錄**：session-266（`less -X /etc/services`——GNU less 停用 alternate
// screen，`LESS=-X` 是常見的使用者設定）該會話 WS 客戶端的送出/收到交錯序列。
//
// **這一格是 `vtscreen.Redrawn()` 判準的偽陰性面**：`less -X` 整份輸出流的
// CUP／VPA／ED 2·3／DECSTBM 次數是 **0**——它只用 `\r` ＋ `ESC[K` 逐行重畫，
// 一次絕對定位都不送。Redrawn 因此不觸發，而該輪的原點與提示符都被 pager 的
// 狀態列佔走（`/etc/services`），三條剝除規則同時落空。
// 修法前（`4d56d74`..`db2eecc`）此處入庫的是
// `ssh-test-server:~$ echo done-BASHGNULESS_NOALT`——一條使用者從未送出的字串。
//
// 兩個方向的斷言都要有：
//   (a) 任何含提示符的拼接結果一筆都不得入庫（防捏造）；
//   (b) 使用者確實送出的四條指令必須全部入庫（防以漏記換不捏造）。

import (
	"strings"
	"testing"
	"time"
)

// relativeRedrawPagerOps 為 session-266 的實錄事件序。
var relativeRedrawPagerOps = []fullScreenOp{
	{dir: "out", data: "Welcome to OpenSSH Server\r\n\u001b[?2004hssh-test-server:~$ "},
	{dir: "in", data: "echo sync-BASHGNULESS_NOALT\r"},
	{dir: "out", data: "echo sync-BASHGNULESS_NOALT\r\n\u001b[?2004l\rsync-BASHGNULESS_NOALT\r\n\u001b[?2004hssh-test-server:~$ "},
	{dir: "in", data: "less -X /etc/services\r"},
	{dir: "out", data: "less -X /etc/services\r\n\u001b[?2004l\r\u001b[?1h\u001b=\r# Network services, Internet style\r\n#\r\n# Updated from https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml .\r\n#\r\n# New ports will be added on request if they have been officially assigned\r\n# by IANA and used in the real-world or are needed by a debian package.\r\n# If you need a huge list of used numbers please install the nmap package.\r\n\r\ntcpmux          1/tcp                           # TCP port service multiplexer\r\necho            7/tcp\r\necho            7/udp\r\ndiscard         9/tcp           sink null\r\ndiscard         9/udp           sink null\r\nsystat          11/tcp          users\r\ndaytime         13/tcp\r\ndaytime         13/udp\r\nnetstat         15/tcp\r\nqotd            17/tcp          quote\r\nchargen         19/tcp          ttytst source\r\nchargen         19/udp          ttytst source\r\nftp-data        20/tcp\r\nftp             21/tcp\r\nfsp             21/udp          fspd\r\nssh             22/tcp                          # SSH Remote Login Protocol\r\ntelnet          23/tcp\r\nsmtp            25/tcp          mail\r\ntime            37/tcp          timserver\r\ntime            37/udp          timserver\r\nwhois           43/tcp          nicname\r\n\u001b[7m/etc/services\u001b[27m\u001b[K"},
	{dir: "in", data: " "},
	{dir: "out", data: "\r\u001b[Ktacacs          49/tcp                          # Login Host Protocol (TACACS)\r\ntacacs          49/udp\r\ndomain          53/tcp                          # Domain Name Server\r\ndomain          53/udp\r\nbootps          67/udp\r\nbootpc          68/udp\r\ntftp            69/udp\r\ngopher          70/tcp                          # Internet Gopher\r\nfinger          79/tcp\r\nhttp            80/tcp          www             # WorldWideWeb HTTP\r\nkerberos        88/tcp          kerberos5 krb5 kerberos-sec     # Kerberos v5\r\nkerberos        88/udp          kerberos5 krb5 kerberos-sec     # Kerberos v5\r\niso-tsap        102/tcp         tsap            # part of ISODE\r\nacr-nema        104/tcp         dicom           # Digital Imag. & Comm. 300\r\npop3            110/tcp         pop-3           # POP version 3\r\nsunrpc          111/tcp         portmapper      # RPC 4.0 portmapper\r\nsunrpc          111/udp         portmapper\r\nauth            113/tcp         authentication tap ident\r\nnntp            119/tcp         readnews untp   # USENET News Transfer Protocol\r\nntp             123/udp                         # Network Time Protocol\r\nepmap           135/tcp         loc-srv         # DCE endpoint resolution\r\nnetbios-ns      137/udp                         # NETBIOS Name Service\r\nnetbios-dgm     138/udp                         # NETBIOS Datagram Service\r\nnetbios-ssn     139/tcp                         # NETBIOS session service\r\nimap2           143/tcp         imap            # Interim Mail Access P 2 and 4\r\nsnmp            161/tcp                         # Simple Net Mgmt Protocol\r\nsnmp            161/udp\r\nsnmp-trap       162/tcp         snmptrap        # Traps for SNMP\r\nsnmp-trap       162/udp         snmptrap\r\n:\u001b[K"},
	{dir: "in", data: " "},
	{dir: "out", data: "\r\u001b[Kcmip-man        163/tcp                         # ISO mgmt over IP (CMOT)\r\ncmip-man        163/udp\r\ncmip-agent      164/tcp\r\ncmip-agent      164/udp\r\nmailq           174/tcp                 # Mailer transport queue for Zmailer\r\nxdmcp           177/udp                 # X Display Manager Control Protocol\r\nbgp             179/tcp                         # Border Gateway Protocol\r\nsmux            199/tcp                         # SNMP Unix Multiplexer\r\nqmtp            209/tcp                         # Quick Mail Transfer Protocol\r\nz3950           210/tcp         wais            # NISO Z39.50 database\r\nipx             213/udp                         # IPX [RFC1234]\r\nptp-event       319/udp\r\nptp-general     320/udp\r\npawserv         345/tcp                         # Perf Analysis Workbench\r\nzserv           346/tcp                         # Zebra server\r\nrpc2portmap     369/tcp\r\nrpc2portmap     369/udp                         # Coda portmapper\r\ncodaauth2       370/tcp\r\ncodaauth2       370/udp                         # Coda authentication server\r\nclearcase       371/udp         Clearcase\r\nldap            389/tcp                 # Lightweight Directory Access Protocol\r\nldap            389/udp\r\nsvrloc          427/tcp                         # Server Location\r\nsvrloc          427/udp\r\nhttps           443/tcp                         # http protocol over TLS/SSL\r\nhttps           443/udp                         # HTTP/3\r\nsnpp            444/tcp                         # Simple Network Paging Protocol\r\nmicrosoft-ds    445/tcp                         # Microsoft Naked CIFS\r\nkpasswd         464/tcp\r\n:\u001b[K"},
	{dir: "in", data: "q"},
	{dir: "out", data: "\r\u001b[K\u001b[?1l\u001b>\u001b[?2004hssh-test-server:~$ "},
	{dir: "in", data: "echo done-BASHGNULESS_NOALT\r"},
	{dir: "out", data: "echo done-BASHGNULESS_NOALT\r\n\u001b[?2004l\rdone-BASHGNULESS_NOALT\r\n\u001b[?2004hssh-test-server:~$ "},
	{dir: "in", data: "exit\r"},
	{dir: "out", data: "exit\r\n\u001b[?2004l\rlogout\r\n"},
}

func TestCommandParserRelativeRedrawPagerDoesNotFabricate(t *testing.T) {
	got := replayFullScreenOps(relativeRedrawPagerOps)

	// (a) 防捏造：提示符不得出現在任何一筆指令文字裡。
	for _, cmd := range got {
		if strings.Contains(cmd, "ssh-test-server:~$") {
			t.Errorf("入庫了使用者從未送出的拼接字串（提示符＋指令）：%q\n全部結算：%q", cmd, got)
		}
	}

	// (b) 防漏記：使用者確實送出的四條指令必須全部在。
	want := []string{
		"echo sync-BASHGNULESS_NOALT",
		"less -X /etc/services",
		"echo done-BASHGNULESS_NOALT",
		"exit",
	}
	for _, w := range want {
		found := false
		for _, cmd := range got {
			if cmd == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("真實送出的指令漏記：%q 不在結算結果中\n全部結算：%q", w, got)
		}
	}
}

// TestCommandParserRelativeRedrawWithoutAnchorIsNotEmitted 釘死判準的另一半：
// 跨列且無任何錨時**不得發出**，並留下可告警的降級訊號。
//
// 上一支測試（實錄語料）走的是「已學提示符把指令救回來」那條路；本支走的是
// 「連已學提示符都對不上」的終態——pager 只用 `\r` ＋ `ESC[K` 逐行重畫，
// Redrawn 不觸發，而重繪把內容推到第 1 列以後，
// 「最後一個非空白行 == 使用者在編輯的那一行」這個恆等式斷裂。
// 舊實作在此把螢幕殘留當成指令發出去（即 backlog #8／#18 的捏造形態）。
func TestCommandParserRelativeRedrawWithoutAnchorIsNotEmitted(t *testing.T) {
	var got []string
	p := NewCommandParser(func(cmd string, _ time.Time) {
		got = append(got, cmd)
	}, "ssh")

	// pager 停在螢幕上：原點與提示符都被它的狀態列佔走（實測 busybox less 取到 `/etc/services`）
	p.WriteOutput([]byte("\x1b[7m/etc/services\x1b[27m\x1b[K"))

	// 翻頁鍵沒有 Enter，故當輪從這裡開到下一個 Enter 才結算；
	// 其間整段重繪只用 `\r` ＋ `ESC[K`，一次絕對定位都沒有。
	p.WriteInput([]byte(" "))
	p.WriteOutput([]byte("\r\x1b[Ktacacs 49/tcp\r\ndomain 53/tcp\r\nbootps 67/udp\r\n:\x1b[K"))
	p.WriteInput([]byte("q\r"))
	p.WriteOutput([]byte("\r\x1b[Kbye-from-pager\r\n"))
	p.Flush()

	if len(got) != 0 {
		t.Errorf("跨列且無錨時仍發出指令（即捏造）：%q", got)
	}
	if !p.unanchored {
		t.Error("降級未留下可觀測訊號：unanchored 仍為 false（降級必須可告警，非僅可搜尋）")
	}
}
