package dbconsole

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

// ErrInvalidCACert 自訂 CA 無法解析
var ErrInvalidCACert = errors.New("dbconsole: 自訂 CA 憑證無法解析為 PEM")

// ErrUnknownTLSMode TLS 檔位不在五檔之內
var ErrUnknownTLSMode = errors.New("dbconsole: 未知的 TLS 檔位")

// tlsSettings 五檔映射後的結果。
//
// 三個 driver 的設定形狀互不相同（pgx 收 *tls.Config、mysql 要先註冊具名
// TLS 設定、mssql 收 Encrypt 與 TrustServerCertificate 兩個旗標），故先在此
// 收斂成一組**語義**，各方言再自行翻譯。中間隔這一層的理由是：五檔的語義
// 只該有一個定義點，否則 verify-ca 在某一個方言上悄悄降級成 require
// 而畫面上的傳輸風險徽章照樣顯示已加密。
type tlsSettings struct {
	// enabled 是否加密
	enabled bool
	// verifyCert 是否驗證伺服器憑證鏈
	verifyCert bool
	// verifyHostname 是否核對憑證的主機名（verify-full 才為真）
	verifyHostname bool
	// rootCAs 自訂 CA 池（nil＝系統根憑證）。**記憶體池，不落暫存檔**
	rootCAs *x509.CertPool
}

// resolveTLS 把五檔字面值映射成語義。
//
// 空字串（沿 driver 預設）刻意**不**等同 disable：既有資產在命令列路徑上
// 是「用 client 的預設」，把它在主控台上硬解成停用會讓同一台資產在兩條路徑上
// 有不同的傳輸安全，而使用者沒有做過任何改變。
func resolveTLS(mode, caPEM string) (tlsSettings, error) {
	var s tlsSettings
	switch mode {
	case TLSModeDefault:
		// driver 預設：不由我方施加任何強制。各方言的預設不同，
		// 這一檔的語義就是「維持該 driver 的既有行為」
		return tlsSettings{}, nil
	case TLSModeDisable:
		return tlsSettings{enabled: false}, nil
	case TLSModeRequire:
		s = tlsSettings{enabled: true}
	case TLSModeVerifyCA:
		s = tlsSettings{enabled: true, verifyCert: true}
	case TLSModeVerifyFull:
		s = tlsSettings{enabled: true, verifyCert: true, verifyHostname: true}
	default:
		return tlsSettings{}, fmt.Errorf("%w: %q", ErrUnknownTLSMode, mode)
	}

	if caPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(caPEM)) {
			return tlsSettings{}, ErrInvalidCACert
		}
		s.rootCAs = pool
	}
	return s, nil
}

// isDefaultMode 該檔位是否為「沿 driver 預設」（無任何 TLS 設定要施加）
func (s tlsSettings) isDefaultMode(mode string) bool { return mode == TLSModeDefault }

// stdConfig 產出 `crypto/tls` 設定。serverName 供主機名核對使用。
//
// require 檔位設 `InsecureSkipVerify`：那正是它的語義（加密但不驗憑證），
// 不是疏漏。verify-ca 則保留驗證鏈但不核對主機名——`crypto/tls` 沒有這個組合的
// 直接旗標，故以 InsecureSkipVerify＋自訂 VerifyPeerCertificate 實作
func (s tlsSettings) stdConfig(serverName string) *tls.Config {
	if !s.enabled {
		return nil
	}
	if !s.verifyCert {
		// 加密不驗證：明確標示語義，不是忘了驗
		return &tls.Config{InsecureSkipVerify: true, ServerName: serverName}
	}
	if s.verifyHostname {
		return &tls.Config{ServerName: serverName, RootCAs: s.rootCAs}
	}
	return &tls.Config{
		ServerName:         serverName,
		RootCAs:            s.rootCAs,
		InsecureSkipVerify: true,
		// 驗證鏈但不核對主機名：標準庫沒有這個檔位，故自行走一次鏈驗證。
		// **DNSName 留空**才是「不核對主機名」；把 serverName 填進去就變回 verify-full
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyChainWithoutHostname(rawCerts, s.rootCAs)
		},
	}
}

func verifyChainWithoutHostname(rawCerts [][]byte, roots *x509.CertPool) error {
	if len(rawCerts) == 0 {
		return errors.New("dbconsole: 目標端未提供憑證")
	}
	certs := make([]*x509.Certificate, 0, len(rawCerts))
	for _, raw := range rawCerts {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("dbconsole: 解析目標端憑證失敗: %w", err)
		}
		certs = append(certs, cert)
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter})
	return err
}
