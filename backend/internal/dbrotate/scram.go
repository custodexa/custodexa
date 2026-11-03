package dbrotate

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
)

// SCRAM-SHA-256 verifier 的參數（與 PostgreSQL 預設相同）。
const (
	scramIterations = 4096
	scramSaltLen    = 16
	scramKeyLen     = sha256.Size
)

// SCRAMVerifier 以隨機鹽算出 PostgreSQL 的 SCRAM-SHA-256 verifier：
// `SCRAM-SHA-256$4096:<salt>$<StoredKey>:<ServerKey>`（三段皆標準 base64）。
//
// 呼叫端保證密碼為 ASCII（CheckPreconditions），SASLprep 對它是恆等。
// 不改動 password。
func SCRAMVerifier(password []byte) (string, error) {
	salt := make([]byte, scramSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("dbrotate: 產生 SCRAM 鹽失敗")
	}
	return scramVerifierWithSalt(password, salt, scramIterations)
}

func scramVerifierWithSalt(password, salt []byte, iterations int) (string, error) {
	_, storedKey, serverKey, err := scramKeys(password, salt, iterations)
	if err != nil {
		return "", err
	}
	enc := base64.StdEncoding
	return "SCRAM-SHA-256$" + strconv.Itoa(iterations) + ":" + enc.EncodeToString(salt) + "$" +
		enc.EncodeToString(storedKey) + ":" + enc.EncodeToString(serverKey), nil
}

// scramKeys RFC 5802／7677 的金鑰推導：SaltedPassword＝PBKDF2(HMAC-SHA-256)，
// ClientKey＝HMAC(SaltedPassword, "Client Key")，StoredKey＝SHA-256(ClientKey)，
// ServerKey＝HMAC(SaltedPassword, "Server Key")。
func scramKeys(password, salt []byte, iterations int) (clientKey, storedKey, serverKey []byte, err error) {
	salted, err := pbkdf2.Key(sha256.New, string(password), salt, iterations, scramKeyLen)
	if err != nil {
		// 不帶原始錯誤：標準庫的訊息不含密碼，但本套件一律只回類別
		return nil, nil, nil, fmt.Errorf("dbrotate: 計算 SCRAM verifier 失敗")
	}
	defer clear(salted)
	clientKey = hmacSHA256(salted, []byte("Client Key"))
	sum := sha256.Sum256(clientKey)
	storedKey = sum[:]
	serverKey = hmacSHA256(salted, []byte("Server Key"))
	return clientKey, storedKey, serverKey, nil
}

func hmacSHA256(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}
