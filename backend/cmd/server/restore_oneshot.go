package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"gorm.io/gorm"
)

// 一次性子命令：管理腳本以
// `docker compose run --rm --no-deps -T backend ./custodexa <子命令>` 呼叫，
// 不經 HTTP、不新增路由，腳本因此不必自己重寫 SQL 與 CSPRNG。
//
//	permission-meta                       唯讀：印出備份摘要用的 authz.* 鍵值行
//	permission-restore --op-id X --input-digest Y --expect-digest Z
//	                                      原狀態核對（authz digest）→ 參照／最後本地超管檢查 →
//	                                      恢復交易（換新世代）；同一操作已提交過則跳過核對與換世代
//
// 子命令只連資料庫：不跑 migration、不取單實例鎖、不開監聽、不解封。
// 輸出為 key=value 行，只含計數、摘要、具型別 ID 與世代指紋，不含秘密或個資。
// 結束碼：0 成功；1 其他失敗；2 用法錯誤；3 完整性檢查拒絕（未提交任何變更）；
// 4 另有未完成且操作識別不同的恢復紀錄（停下，不猜）；5 匯入後的權限狀態與備份摘要不符。
const (
	oneShotOK       = 0
	oneShotFail     = 1
	oneShotUsage    = 2
	oneShotRefused  = 3
	oneShotConflict = 4
	oneShotMismatch = 5
)

// runOneShot 判斷 args 是否為一次性子命令；是則執行並回傳結束碼。
// 不是（含沒有參數）回 handled=false，由正常伺服器啟動流程接手。
func runOneShot(args []string) (code int, handled bool) {
	if len(args) == 0 {
		return 0, false
	}
	switch args[0] {
	case "permission-meta", "permission-restore":
	default:
		return 0, false
	}
	cfg := config.Load()
	if err := database.InitDatabase(cfg); err != nil {
		log.Printf("資料庫連線失敗: %v", err)
		return oneShotFail, true
	}
	defer database.Close()
	return runOneShotWith(database.DB, args, os.Stdout), true
}

// runOneShotWith 以已連線的資料庫執行子命令（測試入口）。
func runOneShotWith(db *gorm.DB, args []string, out io.Writer) int {
	switch args[0] {
	case "permission-meta":
		return permissionMeta(db, out)
	case "permission-restore":
		ra, ok := parseRestoreArgs(args[1:])
		if !ok {
			fmt.Fprintln(out, "usage=permission-restore --op-id <id> --input-digest <sha256> --expect-digest <hex>")
			return oneShotUsage
		}
		return permissionRestoreOnce(db, ra, out)
	}
	return oneShotUsage
}

type restoreArgs struct{ opID, inputDigest, expectDigest string }

func parseRestoreArgs(args []string) (restoreArgs, bool) {
	var ra restoreArgs
	if len(args)%2 != 0 {
		return ra, false
	}
	for i := 0; i+1 < len(args); i += 2 {
		switch args[i] {
		case "--op-id":
			ra.opID = args[i+1]
		case "--input-digest":
			ra.inputDigest = args[i+1]
		case "--expect-digest":
			ra.expectDigest = args[i+1]
		default:
			return restoreArgs{}, false
		}
	}
	return ra, validRestoreToken(ra.opID) && validRestoreToken(ra.inputDigest) && validRestoreToken(ra.expectDigest)
}

// validRestoreToken 操作識別與輸入摘要只接受 [A-Za-z0-9._-]，長度 1 至 128。
func validRestoreToken(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

func hasPermissionModel(db *gorm.DB) bool {
	m := db.Migrator()
	return m.HasTable(&model.AuthzState{}) && m.HasColumn(&model.AuthzState{}, "RestoreGeneration")
}

// readPermissionSummary 在 tx 內讀權限狀態：回傳快照與其 digest。
func readPermissionSummary(tx *gorm.DB) (*audit.PermissionState, string, error) {
	audit.SetPermissionSources(authz.PermissionStateAuthzPart, identity.PermissionStateIdentityPart)
	st, err := audit.ReadPermissionState(context.Background(), tx)
	if err != nil {
		return nil, "", err
	}
	digest, err := st.Digest()
	if err != nil {
		return nil, "", err
	}
	return st, digest, nil
}

// permissionMeta 印出備份摘要用的權限狀態維度。權限模型遷移前的資料庫印 authz.model=legacy，
// 不查尚不存在的表。
func permissionMeta(db *gorm.DB, out io.Writer) int {
	if !hasPermissionModel(db) {
		fmt.Fprintln(out, "authz.model=legacy")
		return oneShotOK
	}
	var lines []string
	var refsFindings int
	err := db.Transaction(func(tx *gorm.DB) error {
		st, digest, err := readPermissionSummary(tx)
		if err != nil {
			return err
		}
		lines = append(lines,
			fmt.Sprintf("authz.model=%d", st.Meta.Model),
			fmt.Sprintf("authz.snapshot=%d", audit.PermissionSummaryVersion),
			"authz.catalog="+st.Meta.Catalog,
			"authz.digest="+digest,
			fmt.Sprintf("authz.version=%d", st.Meta.Version),
		)
		for _, name := range audit.PermissionSetNames() {
			lines = append(lines, fmt.Sprintf("authz.count.%s=%d", name, len(st.Sets[name])))
		}
		rep, err := authz.CheckRestoreIntegrity(tx, identity.CountLocalAdmins, identity.RestoreMappingRefChecks())
		if err != nil {
			return err
		}
		refsFindings = len(rep.Findings)
		return nil
	})
	if err != nil {
		fmt.Fprintf(out, "error=permission-meta\n")
		log.Printf("擷取權限狀態摘要失敗: %v", err)
		return oneShotFail
	}
	if refsFindings == 0 {
		lines = append(lines, "authz.refs=ok")
	} else {
		lines = append(lines, fmt.Sprintf("authz.refs=findings:%d", refsFindings))
	}
	fmt.Fprintln(out, strings.Join(lines, "\n"))
	return oneShotOK
}

// alreadyCommitted 同一個 (操作識別, 輸入摘要) 的恢復交易是否已提交（腳本落盤前中斷後的 resume）。
func alreadyCommitted(db *gorm.DB, ra restoreArgs) bool {
	var st model.AuthzState
	if err := db.Where("id = 1").Take(&st).Error; err != nil {
		return false
	}
	return st.RestoreOpID == ra.opID && st.RestoreInputDigest == ra.inputDigest && st.RestoreGeneration != ""
}

// permissionRestoreOnce 在匯入後先以原狀態核對權限 digest（此時不得已經 bump version
// 或清票證），再做參照與最後本地超管檢查，全部通過才在單一交易提交恢復（新世代）。
// 核對與檢查只讀、不修復；拒絕時不提交任何變更。同一個 (opID, inputDigest) 已提交過就原樣回報、
// 不重核對（資料已被該次恢復改過，digest 必然不同）也不重換世代。
func permissionRestoreOnce(db *gorm.DB, ra restoreArgs, out io.Writer) int {
	if !hasPermissionModel(db) {
		fmt.Fprintln(out, "restore.model=legacy")
		return oneShotOK
	}
	var rep *authz.RestoreIntegrityReport
	if !alreadyCommitted(db, ra) {
		if err := db.Transaction(func(tx *gorm.DB) error {
			// 最後本地超管沿日常不變式同一查詢（identity.CountLocalAdmins）與同一把系統級鎖：
			// 恢復時後端已停，此鎖只保證與任何殘留寫者的取鎖順序一致（system 先）
			if tx.Dialector.Name() == "postgres" {
				if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", identity.LocalAdminLockKey).Error; err != nil {
					return fmt.Errorf("取得本地管理員不變式互斥鎖失敗: %w", err)
				}
			}
			_, digest, err := readPermissionSummary(tx)
			if err != nil {
				return err
			}
			if digest != ra.expectDigest {
				fmt.Fprintf(out, "mismatch.expected=%s\nmismatch.actual=%s\n", ra.expectDigest, digest)
				return errOriginalStateMismatch
			}
			rep, err = authz.CheckRestoreIntegrity(tx, identity.CountLocalAdmins, identity.RestoreMappingRefChecks())
			return err
		}); err != nil {
			if errors.Is(err, errOriginalStateMismatch) {
				return oneShotMismatch
			}
			fmt.Fprintln(out, "error=integrity-check")
			log.Printf("還原前的權限核對無法完成: %v", err)
			return oneShotFail
		}
		if !rep.OK() {
			for _, f := range rep.Findings {
				fmt.Fprintf(out, "finding=%s:%s\n", f.Code, f.Detail)
			}
			fmt.Fprintf(out, "restore.local_super_admins=%d\n", rep.LocalSuperAdmins)
			return oneShotRefused
		}
	}
	gen, fresh, err := authz.CommitRestoreOnce(db, ra.opID, ra.inputDigest)
	if err != nil {
		if errors.Is(err, authz.ErrRestoreOpConflict) {
			fmt.Fprintln(out, "error=op-conflict")
			return oneShotConflict
		}
		fmt.Fprintln(out, "error=commit")
		log.Printf("提交恢復交易失敗: %v", err)
		return oneShotFail
	}
	fmt.Fprintf(out, "restore.generation_fp=%s\nrestore.fresh=%t\n", audit.PermissionGenerationFingerprint(gen), fresh)
	if rep != nil {
		fmt.Fprintf(out, "restore.local_super_admins=%d\n", rep.LocalSuperAdmins)
	}
	return oneShotOK
}

var errOriginalStateMismatch = errors.New("匯入後的權限狀態與備份摘要不符")
