package asset

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tarFiles 依序寫入多個一般檔（名稱 → 大小）。
func tarFiles(t *testing.T, files [][2]any) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range files {
		name, size := f[0].(string), f[1].(int)
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o440, Size: int64(size)}))
		_, err := tw.Write(bytes.Repeat([]byte("x"), size))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	return buf.Bytes()
}

func tarBytes(t *testing.T, bodySize int, withMain bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	name := "other"
	if withMain {
		name = "sudoers"
	}
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o440, Size: int64(bodySize)}))
	_, err := tw.Write(bytes.Repeat([]byte("x"), bodySize))
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	return buf.Bytes()
}

func TestExecutorCheckStreamArchive(t *testing.T) {
	run := func(data []byte) (escalatedStreamResult, []byte, error) {
		var res escalatedStreamResult
		budget := int64(inventoryMaxEscalatedBytes)
		out, err := streamEscalatedArchive(&res)(bytes.NewReader(data), &budget)
		return res, out, err
	}
	t.Run("大封存只計數與判定、不回傳任何內容", func(t *testing.T) {
		// 不屬規則檔的大成員不計入規則內容上限，只計入總量
		data := tarFiles(t, [][2]any{{"sudoers", 10}, {"other", 3 << 20}})
		res, out, err := run(data)
		require.NoError(t, err)
		assert.Nil(t, out, "不得保留輸出內容")
		assert.True(t, res.HasMain)
		assert.Equal(t, int64(len(data)), res.Bytes)
	})
	t.Run("規則內容超過盤點的解出上限", func(t *testing.T) {
		_, _, err := run(tarFiles(t, [][2]any{{"sudoers", 10}, {"sudoers.d/big", inventoryMaxSudoBytes}}))
		var ie *inventoryError
		require.True(t, errors.As(err, &ie))
		assert.Equal(t, inventoryReasonOutputLimit, ie.Reason)
		assert.Equal(t, "sudo_bytes", ie.Detail)
	})
	t.Run("規則檔數超過盤點的上限", func(t *testing.T) {
		files := [][2]any{{"sudoers", 10}}
		for i := 0; i <= inventoryMaxSudoFiles; i++ {
			files = append(files, [2]any{fmt.Sprintf("sudoers.d/r%03d", i), 1})
		}
		_, _, err := run(tarFiles(t, files))
		var ie *inventoryError
		require.True(t, errors.As(err, &ie))
		assert.Equal(t, inventoryReasonOutputLimit, ie.Reason)
		assert.Equal(t, "files", ie.Detail)
	})
	t.Run("規則檔數剛好在上限內", func(t *testing.T) {
		files := [][2]any{{"sudoers", 10}}
		for i := 0; i < inventoryMaxSudoFiles; i++ {
			files = append(files, [2]any{fmt.Sprintf("sudoers.d/r%03d", i), 1})
		}
		res, _, err := run(tarFiles(t, files))
		require.NoError(t, err)
		assert.True(t, res.HasMain)
	})
	t.Run("沒有 sudoers 一般檔", func(t *testing.T) {
		res, _, err := run(tarBytes(t, 10, false))
		require.NoError(t, err)
		assert.False(t, res.HasMain)
	})
	t.Run("空輸出", func(t *testing.T) {
		res, _, err := run(nil)
		require.NoError(t, err)
		assert.Zero(t, res.Bytes)
	})
	t.Run("超過總量上限", func(t *testing.T) {
		_, _, err := run(tarBytes(t, inventoryMaxEscalatedBytes+1, true))
		var ie *inventoryError
		require.True(t, errors.As(err, &ie))
		assert.Equal(t, inventoryReasonOutputLimit, ie.Reason)
	})
	t.Run("截斷的封存", func(t *testing.T) {
		data := tarBytes(t, 2048, true)
		_, _, err := run(data[:700])
		var ie *inventoryError
		require.True(t, errors.As(err, &ie))
		assert.Equal(t, inventoryReasonOutputMalformed, ie.Reason)
	})
	t.Run("封存後的多餘輸出也計入上限", func(t *testing.T) {
		data := append(tarBytes(t, 10, true), bytes.Repeat([]byte{0}, inventoryMaxEscalatedBytes)...)
		_, _, err := run(data)
		require.Error(t, err)
	})
}
