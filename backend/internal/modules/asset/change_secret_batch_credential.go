package asset

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
)

// 批次改密與共用憑證的交會處：整批同一組模式建立的具名共用憑證，
// 以及每台各自隨機模式下對共用憑證成員的拆分路由。
//
// # 為什麼共用憑證的成員不能走單帳號路徑
//
// 單帳號路徑會在該掛載引用的憑證上追加一個新版本並把它設為現行版本。憑證是共用的
// 時候，那一版只有一台主機真的吃得下——其餘成員的主機仍是舊秘密，而憑證庫會顯示
// 一個沒有任何一台以外的機器就位的「現行版本」。改一員就得改整組，不然就別在原憑證上改。

// jobFromBatch 把批次翻成執行設定；整批同一組模式在此產生那一組密碼，
// 並為本批次建立一筆具名共用憑證與其密文版本。
//
// 明文密碼只活在回傳值裡：批次列不存它，憑證版本與各目標的候選列各以信封加密持有。
func (r *ChangeSecretRunner) jobFromBatch(batch *model.ChangeSecretBatch,
	assetIDs []uint) (rotationJob, error) {

	job := rotationJob{
		batchID:    batch.ID,
		source:     batchSource(batch),
		scope:      model.AccountScope{batch.Username},
		secretType: model.ChangeSecretTypePassword,
		targetKind: model.PlanTargetAccount,
		policy: PasswordPolicy{
			Length:           batch.PasswordLength,
			IncludeSymbol:    batch.PasswordIncludeSymbol,
			ExcludeAmbiguous: batch.PasswordExcludeAmbiguous,
		},
	}
	if job.policy.Length == 0 {
		job.policy.Length = model.PasswordLengthDefault
	}
	if batch.PasswordMode != model.BatchPasswordShared {
		return job, nil
	}
	password, err := GeneratePassword(job.policy)
	if err != nil {
		return job, err
	}
	job.fixedPassword = password
	cred, version, err := r.createBatchSharedCredential(batch, assetIDs, password)
	if err != nil {
		return job, err
	}
	job.sharedCredentialID = cred.ID
	job.sharedVersionID = version.ID
	if cred.Name != nil {
		job.sharedCredentialName = *cred.Name
	}
	batch.SharedCredentialID = cred.ID
	return job, nil
}

// createBatchSharedCredential 為整批同一組模式建立具名共用憑證與其密文版本。
//
// **一筆憑證而非把同一組密文複製到多筆專用憑證**：同一組密碼在多台生效這件事必須
// 在憑證庫與報告上看得見，複製出去之後系統就再也回答不了「這組秘密被哪些主機使用」。
// 憑證於此刻零掛載，成功的目標逐台改綁進來；一台都沒成功時由批次收尾回收它。
func (r *ChangeSecretRunner) createBatchSharedCredential(batch *model.ChangeSecretBatch,
	assetIDs []uint, password string) (*model.Credential, *model.CredentialSecretVersion, error) {

	name := strings.TrimSpace(batch.SharedCredentialName)
	if name == "" {
		return nil, nil, ErrBatchCredentialNameRequired
	}
	enc, err := r.candidates.crypto.EncryptFor(context.Background(),
		keyvault.RefCredentialVersionPassword, password)
	if err != nil {
		return nil, nil, fmt.Errorf("加密批次共用密碼失敗: %w", err)
	}
	cred := &model.Credential{
		Name:           &name,
		Scope:          model.CredentialScopeShared,
		Username:       batch.Username,
		SecretType:     model.ChangeSecretTypePassword,
		AuthMethod:     AuthMethodSQL,
		ProtocolFamily: r.batchProtocolFamily(assetIDs),
	}
	var version *model.CredentialSecretVersion
	err = r.db.Transaction(func(tx *gorm.DB) error {
		if serr := assertSharedNameFree(tx, name, 0); serr != nil {
			return serr
		}
		if cerr := tx.Create(cred).Error; cerr != nil {
			return credentialUniqueViolation(cerr, "建立批次共用憑證失敗")
		}
		v, verr := appendCredentialVersion(tx, cred.ID, model.ChangeSecretTypePassword,
			enc, "", model.CredentialVersionReasonRotation)
		if verr != nil {
			return verr
		}
		if serr := setCredentialCurrentVersion(tx, cred.ID, v.ID); serr != nil {
			return serr
		}
		version = v
		return writeCredentialAudit(r.candidates.auditTx, tx, credentialAudit{
			CredentialID: cred.ID,
			Operation:    model.AccountOpCreate,
			Scope:        cred.Scope,
			Fields:       []string{"password"},
		}, batch.RequestedBy, batch.RequestedByName)
	})
	if err != nil {
		return nil, nil, err
	}
	return cred, version, nil
}

// batchProtocolFamily 由目標資產推導本批次共用憑證的協定族。
//
// 取第一台解析得到的資產：批次以帳號名為軸，同名帳號跨族的情形罕見，
// 而族別只影響憑證庫的過濾與掛載檢核，取不到時退為 ssh（既有帳號的多數）。
func (r *ChangeSecretRunner) batchProtocolFamily(assetIDs []uint) string {
	for _, id := range assetIDs {
		asset, err := r.assetService.GetByID(id)
		if err != nil {
			continue
		}
		if family := model.ProtocolFamilyForAsset(asset); family != "" {
			return family
		}
	}
	return model.ProtocolFamilySSH
}

// remainingAssetIDs 扣掉已由別條路徑處理的資產。
func remainingAssetIDs(assetIDs []uint, routed map[uint]bool) []uint {
	if len(routed) == 0 {
		return assetIDs
	}
	out := make([]uint, 0, len(assetIDs))
	for _, id := range assetIDs {
		if !routed[id] {
			out = append(out, id)
		}
	}
	return out
}

// skipOutOfSyncBindings 憑證的上一輪改密尚未收斂時，本批次不碰它的掛載。
//
// 回傳略過記錄與被擋下的資產集合（呼叫端據此把它們排除在其後的全部路徑之外）。
//
// **判準沿用發起新一輪的那一個**（assertCredentialConverged），不另立第二套：
// 未收斂的憑證上還掛著一個待生效版本與一批未就位的成員，此刻再改一次那些主機的
// 密碼，補跑就再也對不回那一輪的秘密，而該掛載的就位版本會停在誰都沒宣告過的狀態。
// 兩種密碼模式同受此限——整批同一組模式會把目標改綁到新憑證，同樣是動遠端。
//
// 略過而非失敗：這些主機一個位元都沒被觸碰，收斂之後重跑批次即可。
func (r *ChangeSecretRunner) skipOutOfSyncBindings(job rotationJob,
	assetIDs []uint) ([]model.ChangeSecretRecord, map[uint]bool) {

	blocked := map[uint]bool{}
	if len(assetIDs) == 0 {
		return nil, blocked
	}
	names := explicitAccountNames(job.scope)
	if len(names) == 0 {
		return nil, blocked
	}
	var accounts []model.AssetAccount
	if err := r.db.Where("asset_id IN ? AND username IN ?", assetIDs, names).
		Order("asset_id asc, id asc").Find(&accounts).Error; err != nil {
		log.Printf("[ChangeSecret] 查詢批次目標掛載失敗 batch=%d err=%v", job.batchID, err)
		return nil, blocked
	}
	credIDs := make([]uint, 0, len(accounts))
	for i := range accounts {
		credIDs = append(credIDs, accounts[i].CredentialID)
	}
	creds, err := credentialsByID(r.db, credIDs)
	if err != nil {
		log.Printf("[ChangeSecret] 查詢批次目標憑證失敗 batch=%d err=%v", job.batchID, err)
		return nil, blocked
	}
	var stale []model.AssetAccount
	for i := range accounts {
		cred := creds[accounts[i].CredentialID]
		if cred == nil {
			continue
		}
		if errors.Is(assertCredentialConverged(r.db, cred), ErrCredentialOutOfSync) {
			stale = append(stale, accounts[i])
			blocked[accounts[i].AssetID] = true
		}
	}
	if len(stale) == 0 {
		return nil, blocked
	}
	log.Printf("[ChangeSecret] 批次略過未收斂憑證的掛載 batch=%d 目標數=%d", job.batchID, len(stale))
	return r.skipRecords(job, stale, model.ChangeSecretReasonSharedCredentialTargetRequired), blocked
}

// runSharedMembersSplit 把掛在共用憑證上的批次目標改走拆分輪替。
//
// 回傳本路徑產生的改密記錄，以及已被本路徑接手的資產集合（呼叫端據此把它們
// 排除在逐帳號路徑之外，同一台不會被兩條路徑各改一次）。
//
// 整批同一組模式不走這裡：那個模式的目標一律改綁到本批次新建的共用憑證，
// 原憑證的其餘成員不受影響（它們的主機沒被觸碰，就位版本仍然有效）。
func (r *ChangeSecretRunner) runSharedMembersSplit(job rotationJob,
	assetIDs []uint) ([]model.ChangeSecretRecord, map[uint]bool) {

	routed := map[uint]bool{}
	if job.sharedCredentialID != 0 || len(assetIDs) == 0 {
		return nil, routed
	}
	names := explicitAccountNames(job.scope)
	if len(names) == 0 {
		return nil, routed
	}
	var accounts []model.AssetAccount
	if err := r.db.Where("asset_id IN ? AND username IN ?", assetIDs, names).
		Order("asset_id asc, id asc").Find(&accounts).Error; err != nil {
		log.Printf("[ChangeSecret] 查詢批次目標掛載失敗 batch=%d err=%v", job.batchID, err)
		return nil, routed
	}
	snapshots, err := accountsCredentialSnapshots(r.db, accounts)
	if err != nil {
		log.Printf("[ChangeSecret] 查詢批次目標憑證失敗 batch=%d err=%v", job.batchID, err)
		return nil, routed
	}

	// 依憑證分組：同一筆共用憑證的多個目標要在同一次拆分裡處理，
	// 逐台各發一次拆分會讓原憑證的收尾判定在中途被觸發
	order := make([]uint, 0, len(accounts))
	groups := map[uint][]model.AssetAccount{}
	for i := range accounts {
		snap := snapshots[accounts[i].ID]
		if !snap.Shared {
			continue
		}
		if _, ok := groups[snap.CredentialID]; !ok {
			order = append(order, snap.CredentialID)
		}
		groups[snap.CredentialID] = append(groups[snap.CredentialID], accounts[i])
		routed[accounts[i].AssetID] = true
	}

	var records []model.ChangeSecretRecord
	for _, credentialID := range order {
		records = append(records, r.splitOneCredential(job, credentialID, groups[credentialID])...)
	}
	r.alertFailures(job, records)
	return records, routed
}

// splitOneCredential 對單一共用憑證的選中成員發起拆分並推進。
//
// 輪替引擎未接線或起始交易失敗時，逐台記一筆略過並帶原因碼——**不退回單帳號路徑**：
// 那條路徑會污染共用憑證，而略過只是這一輪沒改到。
func (r *ChangeSecretRunner) splitOneCredential(job rotationJob, credentialID uint,
	bindings []model.AssetAccount) []model.ChangeSecretRecord {

	if r.rotations == nil {
		log.Printf("[ChangeSecret] 輪替引擎未接線，共用憑證成員略過 batch=%d credential=%d",
			job.batchID, credentialID)
		return r.skipRecords(job, bindings, model.ChangeSecretReasonSharedCredentialTargetRequired)
	}
	accountIDs := make([]uint, 0, len(bindings))
	for i := range bindings {
		accountIDs = append(accountIDs, bindings[i].ID)
	}
	ctx := context.Background()
	rot, err := r.rotations.StartSplitFor(ctx, credentialID, accountIDs,
		StartRotationRequest{Policy: job.policy})
	if err != nil {
		log.Printf("[ChangeSecret] 拆分輪替啟動失敗 batch=%d credential=%d err=%v",
			job.batchID, credentialID, err)
		return r.skipRecords(job, bindings, splitStartReason(err))
	}
	records, err := r.rotations.RunFor(ctx, rot.ID, RotationRecordOrigin{BatchID: job.batchID})
	if err != nil {
		log.Printf("[ChangeSecret] 拆分輪替推進失敗 batch=%d rotation=%d err=%v",
			job.batchID, rot.ID, err)
	}
	return records
}

// splitStartReason 起始交易失敗的原因碼（只回機器碼，不反射任何錯誤原文）。
func splitStartReason(err error) string {
	switch {
	case errors.Is(err, ErrCandidateExists):
		return model.ChangeSecretReasonCandidatePending
	case errors.Is(err, ErrCredentialRotationActive), errors.Is(err, ErrCredentialOutOfSync):
		return model.ChangeSecretReasonSharedCredentialTargetRequired
	default:
		return model.ChangeSecretReasonSharedCredentialTargetRequired
	}
}

// skipRecords 為一組未被觸碰的目標各記一筆略過。
func (r *ChangeSecretRunner) skipRecords(job rotationJob, bindings []model.AssetAccount,
	reason string) []model.ChangeSecretRecord {

	out := make([]model.ChangeSecretRecord, 0, len(bindings))
	for i := range bindings {
		out = append(out, r.save(model.ChangeSecretRecord{
			PlanID: job.planID, BatchID: job.batchID, AssetID: bindings[i].AssetID,
			AccountID: bindings[i].ID, AccountUsername: bindings[i].Username,
			CredentialID:   bindings[i].CredentialID,
			CredentialName: credentialNameSnapshot(r.db, bindings[i].CredentialID),
			SecretType:     job.secretType,
			Status:         model.ChangeSecretSkipped, Error: reason,
			ExecutedAt: time.Now(),
		}))
	}
	return out
}

// settleBatchSharedCredential 批次建立的共用憑證於掛載少於 2 且已無待驗證候選時轉為專用。
//
// **兩個觸發點**：批次結束時，以及每一次候選轉正之後。只在批次結束評估不夠——
// 最後一筆候選由重試轉正時，會留下一筆只有一個掛載的具名共用憑證，
// 而那正是這條規則要消除的狀態（一個人的「共用」不是共用）。
//
// 收尾規則與拆分輪替共用同一份實作（settleSourceCredential），不另寫第二套判定。
func settleBatchSharedCredential(db *gorm.DB, credentialID uint) {
	if credentialID == 0 {
		return
	}
	err := db.Transaction(func(tx *gorm.DB) error {
		cred, err := lockCredentialRow(tx, credentialID)
		if err != nil {
			if errors.Is(err, ErrCredentialNotFound) {
				return nil
			}
			return err
		}
		pending, err := credentialPendingCandidates(tx, cred.ID)
		if err != nil {
			return err
		}
		// 仍有待驗證候選：那幾台可能稍後轉正並掛進來，此刻解散會讓實際共用
		// 同一組密碼的主機沒有一台被標示
		if pending > 0 {
			return nil
		}
		return settleSourceCredential(tx, cred)
	})
	if err != nil {
		log.Printf("[ChangeSecret] 批次共用憑證收尾失敗 credential=%d err=%v", credentialID, err)
	}
}
