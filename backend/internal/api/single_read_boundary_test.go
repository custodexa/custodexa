package api

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 單筆讀取的識別邊界：識別的格式與數值範圍只由輸入決定，不因資源是否存在、是否可見而有不同回應。

// singleReadMalformedIDs 不是 32 位元無號整數的識別：非數字、負數、超出 32 位元、超出 64 位元與更長的整數。
var singleReadMalformedIDs = []string{"abc", "-1", "4294967296", "18446744073709551616", "99999999999999999999999"}

// singleReadMissingRaw 不存在的識別（各測試的資料都遠小於此值）。
const singleReadMissingRaw = "999999"

// assertIDBoundaries 以 get(原始識別字串) 驗證一個主體在一條單筆路由上的識別邊界：
// 32 位元上限（合法、查無）與不存在同一回應；前導零與同值的識別同一回應（可讀者 200、看不到者同不存在）；
// 不合法的識別回 400 且彼此相同；zeroMalformed 為真時 0 歸入不合法，否則與不存在同一回應。
func assertIDBoundaries(t *testing.T, get func(raw string) (int, []byte), readableID, hiddenID uint, zeroMalformed bool) {
	t.Helper()
	missCode, missBody := get(singleReadMissingRaw)
	require.Equal(t, http.StatusNotFound, missCode, "前提：不存在的識別回 404：%s", missBody)

	code, body := get("4294967295")
	assert.Equal(t, missCode, code, "32 位元上限的識別與不存在同狀態碼")
	assert.Equal(t, string(missBody), string(body), "32 位元上限的識別與不存在同本文")

	readCode, readBody := get(fmt.Sprint(readableID))
	require.Equal(t, http.StatusOK, readCode, "前提：識別 %d 可讀：%s", readableID, readBody)
	for _, raw := range []string{"0" + fmt.Sprint(readableID), "000" + fmt.Sprint(readableID)} {
		code, body := get(raw)
		assert.Equal(t, readCode, code, "%q：前導零與同值的可讀識別同狀態碼", raw)
		assert.Equal(t, string(readBody), string(body), "%q：前導零與同值的可讀識別同本文", raw)
	}

	hidCode, hidBody := get(fmt.Sprint(hiddenID))
	require.Equal(t, missCode, hidCode, "前提：識別 %d 看不到，與不存在同狀態碼：%s", hiddenID, hidBody)
	require.Equal(t, string(missBody), string(hidBody), "前提：識別 %d 看不到，與不存在同本文", hiddenID)
	code, body = get("0" + fmt.Sprint(hiddenID))
	assert.Equal(t, missCode, code, "前導零的看不到識別與不存在同狀態碼")
	assert.Equal(t, string(missBody), string(body), "前導零的看不到識別與不存在同本文")

	malformed := append([]string{}, singleReadMalformedIDs...)
	if zeroMalformed {
		malformed = append(malformed, "0")
	} else {
		code, body := get("0")
		assert.Equal(t, missCode, code, "識別 0 與不存在同狀態碼")
		assert.Equal(t, string(missBody), string(body), "識別 0 與不存在同本文")
	}
	firstCode, firstBody := get(malformed[0])
	assert.Equal(t, http.StatusBadRequest, firstCode, "%q：不合法的識別回 400：%s", malformed[0], firstBody)
	for _, raw := range malformed[1:] {
		code, body := get(raw)
		assert.Equal(t, firstCode, code, "%q：不合法的識別彼此同狀態碼", raw)
		assert.Equal(t, string(firstBody), string(body), "%q：不合法的識別彼此同本文", raw)
	}
}
