package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/material"
)

// 解封流程的第一段：管理員帳號與密碼驗證。
//
// # 為什麼要有這一段
//
// 改前的委託解封只需一個 Bearer 權杖即可觸發還原，`ui` 模式甚至只靠「知道
// 材料」承擔授權。自本版起三種模式一律先過帳密——解封頁要在這之後才呈現任何
// 秘密輸入欄，而秘密是雲端保管處的憑證，交給錯的人的代價遠高於一次還原。
//
// # 邊界（寫進營運文件的已知取捨）
//
// 已封存狀態下**只驗帳密、不驗動態驗證碼**：種子受資料金鑰保護，封存時解不開。
// 這使本端點的攻擊面比正常登入弱一級，緩解為既有的退避與鎖定、來源網段限制、
// 回應不可區分與逐次留痕。**SHALL NOT 把解封頁描述為具備雙因子保護。**

// MaxSealAuthorizeBodyBytes 授權請求體上限。
//
// 只收帳號與密碼兩個欄位，4 KiB 遠超實際所需；上限的用途是使單次驗證成本有界。
const MaxSealAuthorizeBodyBytes = 4 << 10

// sealAuthorizePayload 授權請求的精確鍵集。
//
// 密碼以可覆寫的 []byte 承載並於處理結束時歸零（誠實邊界同
// SealUnsealPayload.Zeroize：`encoding/json` 的內部緩衝與 bcrypt 的內部副本
// 不在可控範圍）。
type sealAuthorizePayload struct {
	Username string
	Password []byte
}

func (p *sealAuthorizePayload) Zeroize() {
	if p == nil {
		return
	}
	zeroBytes(p.Password)
	p.Password = nil
	p.Username = ""
}

// decodeSealAuthorize 解析授權請求體：精確鍵集 `{username, password}`。
//
// 嚴格性沿解封材料的同一組理由：未知鍵、重複鍵、尾隨內容一律拒絕。
func decodeSealAuthorize(body []byte) (*sealAuthorizePayload, error) {
	if len(body) == 0 || len(body) > MaxSealAuthorizeBodyBytes {
		return nil, ErrSealPayloadMalformed
	}
	p := &sealAuthorizePayload{}
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := decodeAuthorizeObject(dec, p); err != nil {
		p.Zeroize()
		return nil, ErrSealPayloadMalformed
	}
	var trailing json.RawMessage
	err := dec.Decode(&trailing)
	zeroBytes(trailing)
	if !errorIsEOF(err) {
		p.Zeroize()
		return nil, ErrSealPayloadMalformed
	}
	if p.Username == "" || len(p.Password) == 0 {
		p.Zeroize()
		return nil, ErrSealPayloadMalformed
	}
	return p, nil
}

func errorIsEOF(err error) bool { return err == io.EOF }

func decodeAuthorizeObject(dec *json.Decoder, p *sealAuthorizePayload) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return ErrSealPayloadMalformed
	}
	seen := map[string]bool{}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyTok.(string)
		if !ok || seen[key] {
			return ErrSealPayloadMalformed
		}
		seen[key] = true
		switch key {
		case "username":
			if err := decodePlainString(dec, &p.Username); err != nil {
				return err
			}
		case "password":
			if err := decodeSecretBytes(dec, &p.Password); err != nil {
				return err
			}
		default:
			return ErrSealPayloadMalformed
		}
	}
	tok, err = dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '}' {
		return ErrSealPayloadMalformed
	}
	return nil
}

// SealCredentialVerifier 驗證管理員帳密並回傳其使用者識別。
//
// 以 func 注入而非介面：本 handler 只需要這一件事，宣告介面會把 identity 的
// 型別拉進 internal/api。實作為 identity.VerifySealAdminCredential。
type SealCredentialVerifier func(username string, password []byte) (uint, error)

// SetSealAuthorization 注入授權脈絡表與帳密驗證器。
//
// 未注入時 `/seal/authorize` 一律回拒——缺驗證器不得退化為「免驗證」。
func (h *SealHandler) SetSealAuthorization(grants *SealGrantStore, verify SealCredentialVerifier) {
	h.grants = grants
	h.verifyCredential = verify
}

// Authorize 驗證管理員帳密並簽發解封授權脈絡。
//
// **不做任何材料判斷、不觸及狀態機**：本端點的產物只是「這個人是管理員」這個
// 事實的短效憑據，解封本身仍走 `/seal/unseal` 的既有臨界區。
func (h *SealHandler) Authorize(c *gin.Context) {
	if h.unsealRelocated {
		apierror.Respond(c, http.StatusForbidden, apierror.CodeSealSourceNotAllowed, nil)
		return
	}
	if !h.sourceAllowed(c) {
		apierror.Respond(c, http.StatusForbidden, apierror.CodeSealSourceNotAllowed, nil)
		return
	}
	if h.grants == nil || h.verifyCredential == nil {
		// 未接線即拒：缺驗證器不得退化為免驗證。
		h.logAuthorizeAttempt(false)
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeSealAuthorizeRejected, nil)
		return
	}

	// 退避與冷卻先於讀取請求體：被擋下的嘗試不驗證、不計入失敗計數、
	// 不刷新到期時間（否則持續送請求即可把窗口無限往後推）。
	key := h.sourceKey(c)
	now := time.Now()
	if until, active := h.authorizeCooldownUntil(now); active {
		_ = until
		apierror.Respond(c, http.StatusTooManyRequests, apierror.CodeSealCooldownActive, nil)
		return
	}
	if allowed, _ := h.authorizeLimiter().AllowSource(key, now); !allowed {
		apierror.Respond(c, http.StatusTooManyRequests, apierror.CodeSealBackoffActive, nil)
		return
	}

	body := make([]byte, MaxSealAuthorizeBodyBytes+1)
	defer material.Wipe(body)
	n, err := io.ReadFull(c.Request.Body, body)
	body = body[:n]
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		err = nil
	}
	var payload *sealAuthorizePayload
	if err == nil {
		payload, err = decodeSealAuthorize(body)
	}
	if err != nil {
		h.recordAuthorizeFailure(key, now)
		h.logAuthorizeAttempt(false)
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeSealAuthorizeRejected, nil)
		return
	}
	defer payload.Zeroize()

	userID, verr := h.verifyCredential(payload.Username, payload.Password)
	if verr != nil {
		h.recordAuthorizeFailure(key, now)
		h.logAuthorizeAttempt(false)
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeSealAuthorizeRejected, nil)
		return
	}

	token, expires, ierr := h.grants.Issue(userID, payload.Username)
	if ierr != nil {
		// CSPRNG 失敗：拒絕簽發而非以可預測值頂替。
		h.logAuthorizeAttempt(false)
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeSealAuthorizeRejected, nil)
		return
	}
	h.authorizeLimiter().RecordSuccess(key)
	h.logAuthorizeAttempt(true)

	out := gin.H{"grant": token, "expires_at": expires.UTC().Format(time.RFC3339)}
	if view, ok := h.topologyView(); ok {
		out["topology_digest"] = view.Digest
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, out)
}

// logAuthorizeAttempt 封存期留痕。
//
// 審計服務於段 2 才存在，封存期的留痕由行程日誌承擔（欄位有界：只記結果，
// 不記帳號、不記來源明細，避免把可枚舉的資訊寫進一份會被轉送的日誌）。
func (h *SealHandler) logAuthorizeAttempt(ok bool) {
	log.Printf("[SealAudit] unseal authorization attempt accepted=%t", ok)
}

// grantFromRequest 取出請求攜帶的解封授權脈絡。
//
// 標頭形態為 `Authorization: SealGrant <grant>`。**與 Bearer 分開的 scheme**：
// 兩者的授權語義完全不同（一個是業務工作階段，一個只證明剛通過帳密驗證），
// 共用 scheme 會讓「把登入權杖拿來解封」與「把解封脈絡拿去打業務端點」這兩件
// 錯事在程式碼裡看起來都像對的。
func (h *SealHandler) grantFromRequest(c *gin.Context) (string, SealGrant, error) {
	raw := c.GetHeader("Authorization")
	const scheme = "SealGrant "
	if len(raw) <= len(scheme) || raw[:len(scheme)] != scheme {
		return "", SealGrant{}, ErrSealGrantInvalid
	}
	token := raw[len(scheme):]
	if h.grants == nil {
		return "", SealGrant{}, ErrSealGrantInvalid
	}
	g, err := h.grants.Verify(token)
	if err != nil {
		return "", SealGrant{}, err
	}
	return token, g, nil
}
