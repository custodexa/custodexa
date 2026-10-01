package asset

// CSV 原文 → 一批待驗證的列（伺服端解析，見 design §1.1）。
//
// 檔案層規則：UTF-8（檔首 BOM 可有可無，有則剝除）、非 UTF-8 整份拒收不猜編碼；
// RFC 4180 嚴格引號；第 1 列為表頭，比對去空白、不分大小寫、容必填標記前綴 `*`；
// 秘密欄、未知欄、重複欄、缺必填欄整份拒收；全空列略過；列號取 CSV 記錄序號
// （表頭＝第 1 列，儲存格內換行不另計）。

import (
	"bytes"
	"encoding/csv"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/custodexa/backend/internal/apierror"
)

// importColumns 第一版的 13 欄（範本欄序）
var importColumns = []string{
	importFieldName, importFieldProtocol, importFieldHost, importFieldPort,
	importFieldCredentialID, importFieldTags, importFieldNodes, importFieldDescription,
	importFieldAccessPolicy, importFieldDBName, importFieldK8sNamespace,
	importFieldRDPSecurity, importFieldDBTLSMode,
}

// utf8BOM UTF-8 位元組順序標記（Excel 另存「CSV UTF-8」會帶）
const utf8BOM = "\xEF\xBB\xBF"

// normalizeHeaderCell 表頭儲存格 → 機器欄名：去 BOM 與前後空白、去必填標記 `*`、轉小寫
func normalizeHeaderCell(v string) string {
	v = strings.TrimSpace(strings.TrimPrefix(v, "\uFEFF"))
	v = strings.TrimSpace(strings.TrimLeft(v, "*"))
	return strings.ToLower(v)
}

func headerError(column, reason string) *ImportFileError {
	return &ImportFileError{Code: apierror.CodeAssetImportHeader,
		Params: map[string]any{"column": column},
		Meta:   map[string]any{"reason": reason}}
}

// ParseImportCSV 解析 CSV 原文。檔案層問題回 *ImportFileError
func ParseImportCSV(data []byte) (*ImportBatch, error) {
	data = bytes.TrimPrefix(data, []byte(utf8BOM))
	if !utf8.Valid(data) {
		return nil, &ImportFileError{Code: apierror.CodeAssetImportEncoding}
	}
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1
	r.LazyQuotes = false

	header, err := r.Read()
	if errors.Is(err, io.EOF) {
		return nil, &ImportFileError{Code: apierror.CodeAssetImportEmpty}
	}
	if err != nil {
		return nil, malformed(1)
	}
	columns, ferr := parseImportHeader(header)
	if ferr != nil {
		return nil, ferr
	}

	batch := &ImportBatch{Source: ImportSourceCSV}
	line := 1 // 表頭已佔第 1 列；全空記錄也佔一列。
	for {
		rec, rerr := r.Read()
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return nil, malformed(line + 1)
		}
		line++
		// encoding/csv 會跳過完全空白的實體行；Excel 的全空列會寫成逗號分隔的記錄。
		if blankRecord(rec) {
			continue
		}
		for i, c := range columns {
			if c == "" && i < len(rec) && strings.TrimSpace(rec[i]) != "" {
				// 表頭空白的欄下有資料：不知道該對到哪一欄，整份拒收而不是靜默丟值
				return nil, headerError("#"+strconv.Itoa(i+1), "unknown")
			}
		}
		if len(rec) > len(columns) && !blankRecord(rec[len(columns):]) {
			// 資料列比表頭多出有內容的格：對不上欄，整份拒收而不是靜默丟值
			return nil, &ImportFileError{Code: apierror.CodeAssetImportCSVMalformed,
				Params: map[string]any{"line": line}}
		}
		if len(batch.Rows) >= ImportMaxRows {
			return nil, &ImportFileError{Code: apierror.CodeAssetImportTooManyRows,
				Params: map[string]any{"max": ImportMaxRows}}
		}
		row, raw, perrs := csvRecordToRow(rec, columns, line)
		batch.Rows = append(batch.Rows, row)
		batch.raw = append(batch.raw, raw)
		batch.parseErrs = append(batch.parseErrs, perrs)
	}
	if len(batch.Rows) == 0 {
		return nil, &ImportFileError{Code: apierror.CodeAssetImportEmpty}
	}
	return batch, nil
}

// malformed 解析器錯誤 → CSV_MALFORMED（列號取最後成功讀取記錄之後一列）
func malformed(line int) *ImportFileError {
	return &ImportFileError{Code: apierror.CodeAssetImportCSVMalformed, Params: map[string]any{"line": line}}
}

// parseImportHeader 表頭 → 每一欄的機器欄名（空字串＝無名欄，其下資料須全空）。
// 秘密欄優先判定：只要出現就整份拒收，不再看其他表頭問題
func parseImportHeader(header []string) ([]string, error) {
	columns := make([]string, len(header))
	for i, cell := range header {
		columns[i] = normalizeHeaderCell(cell)
		if columns[i] != "" && IsImportSecretField(columns[i]) {
			return nil, &ImportFileError{Code: apierror.CodeAssetImportSecretField,
				Params: map[string]any{"column": strings.TrimSpace(strings.TrimPrefix(cell, "\uFEFF"))}}
		}
	}
	known := make(map[string]bool, len(importColumns))
	for _, c := range importColumns {
		known[c] = true
	}
	seen := map[string]bool{}
	for i, c := range columns {
		if c == "" {
			continue
		}
		if !known[c] {
			return nil, headerError(strings.TrimSpace(strings.TrimPrefix(header[i], "\uFEFF")), "unknown")
		}
		if seen[c] {
			return nil, headerError(c, "duplicate")
		}
		seen[c] = true
	}
	for _, c := range []string{importFieldName, importFieldProtocol, importFieldHost} {
		if !seen[c] {
			return nil, headerError(c, "missing")
		}
	}
	return columns, nil
}

func blankRecord(rec []string) bool {
	for _, v := range rec {
		if strings.TrimSpace(v) != "" {
			return false
		}
	}
	return true
}

// csvRecordToRow 一筆記錄 → 列。所有儲存格先去前後空白；埠與憑證編號無法轉型時
// 值為 null、原文放 raw，並帶該欄的列錯誤
func csvRecordToRow(rec, columns []string, line int) (ImportRow, map[string]string, []ImportFieldError) {
	row := ImportRow{Line: &line}
	raw := map[string]string{}
	errs := []ImportFieldError{}
	for i, col := range columns {
		if i >= len(rec) || col == "" {
			continue
		}
		v := strings.TrimSpace(rec[i])
		switch col {
		case importFieldName:
			row.Name = v
		case importFieldProtocol:
			row.Protocol = v
		case importFieldHost:
			row.Host = v
		case importFieldPort:
			if v == "" {
				continue
			}
			n, err := strconv.Atoi(v)
			if err != nil {
				raw[col] = v
				errs = append(errs, fieldErr(col, apierror.CodeAssetImportPort))
				continue
			}
			row.Port = &n
		case importFieldCredentialID:
			if v == "" {
				continue
			}
			n, err := strconv.ParseInt(strings.TrimPrefix(v, "#"), 10, 64)
			if err != nil {
				raw[col] = v
				errs = append(errs, fieldErr(col, apierror.CodeAssetImportFieldFormat))
				continue
			}
			row.CredentialID = &n
		case importFieldTags:
			row.Tags = v
		case importFieldNodes:
			for _, p := range strings.Split(v, ";") {
				if p = strings.TrimSpace(p); p != "" {
					row.NodePaths = append(row.NodePaths, p)
				}
			}
		case importFieldDescription:
			row.Description = v
		case importFieldAccessPolicy:
			row.AccessPolicy = v
		case importFieldDBName:
			row.DBName = v
		case importFieldK8sNamespace:
			row.K8sNamespace = v
		case importFieldRDPSecurity:
			row.RDPSecurity = v
		case importFieldDBTLSMode:
			row.DBTLSMode = v
		}
	}
	return row, raw, errs
}
