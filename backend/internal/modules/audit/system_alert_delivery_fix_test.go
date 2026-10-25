package audit

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// brokenCodec 明文直通，但信封格式且以 enc:broken 開頭的密文解不開（模擬 KEK 變更後解不開的舊密文）。
type brokenCodec struct{}

func (brokenCodec) EncryptFor(_ context.Context, _ crypto.CipherRef, plaintext string) (string, error) {
	return plaintext, nil
}

func (brokenCodec) DecryptFor(_ context.Context, _ crypto.CipherRef, ciphertext string) (string, error) {
	if strings.HasPrefix(ciphertext, "enc:broken") {
		return "", errors.New("信封解密失敗：AAD 不符")
	}
	return ciphertext, nil
}

func seedRawChannel(t *testing.T, db *gorm.DB, name, rawURL, rawSecret string) model.NotificationChannel {
	t.Helper()
	ch := model.NotificationChannel{Name: name, Type: "webhook", URL: rawURL, Secret: rawSecret,
		Enabled: true, Language: "zh-TW", MinSeverity: "low"}
	if err := db.Create(&ch).Error; err != nil {
		t.Fatal(err)
	}
	return ch
}

func outboxOf(t *testing.T, db *gorm.DB, channelID uint) model.SystemAlertOutbox {
	t.Helper()
	var rows []model.SystemAlertOutbox
	if err := db.Where("source_channel_id = ?", channelID).Find(&rows).Error; err != nil || len(rows) != 1 {
		t.Fatalf("通道 %d 應恰有一筆投遞列: %d %v", channelID, len(rows), err)
	}
	return rows[0]
}

// 缺陷一：一個解不開的通道不得擋下會產生系統告警的業務操作；告警照常落地，壞通道留下看得到的失敗紀錄。
func TestSystemAlertUnreadableChannel(t *testing.T) {
	t.Run("壞通道不擋業務操作、告警列仍寫入、壞通道有可見的放棄紀錄", func(t *testing.T) {
		db := setupSystemAlertDB(t)
		stub := newStubReceiver(t, 0)
		good := seedRawChannel(t, db, "good", stub.srv.URL, "")
		bad := seedRawChannel(t, db, "bad", "enc:broken:url", "enc:broken:secret")
		codec := &brokenCodec{}
		sink := NewSystemAlertSink(codec)

		var receipt port.SystemAlertReceipt
		var business int64
		if err := db.Transaction(func(tx *gorm.DB) error {
			// 業務寫入（以一筆審計列代表）與告警同交易。
			if err := tx.Create(&model.AuditLog{Action: "update", Resource: "role", Status: "success"}).Error; err != nil {
				return err
			}
			var err error
			receipt, err = port.RaiseInTx(sink, tx, validGrantEvent())
			return err
		}); err != nil {
			t.Fatalf("壞通道擋下了業務操作: %v", err)
		}
		db.Model(&model.AuditLog{}).Count(&business)
		if business != 1 || systemAlertRowCount(t, db, "command_alerts") != 1 || systemAlertRowCount(t, db, "system_alert_details") != 1 {
			t.Fatalf("業務寫入 %d、告警列 %d、明細 %d", business, systemAlertRowCount(t, db, "command_alerts"), systemAlertRowCount(t, db, "system_alert_details"))
		}
		if receipt.Destinations != 1 || receipt.Unreadable != 1 {
			t.Fatalf("回執應為 1 個可投遞目的地加 1 個解不開的通道: %+v", receipt)
		}

		// 好通道照常排入；壞通道留下一筆立即放棄、帶原因、不含任何密文殘值的紀錄。
		g := outboxOf(t, db, good.ID)
		if g.State != model.SystemAlertOutboxPending {
			t.Fatalf("好通道應為待投遞: %+v", g)
		}
		b := outboxOf(t, db, bad.ID)
		if b.State != model.SystemAlertOutboxAbandoned || b.Attempts != 0 || b.LastError == "" ||
			b.URLEnc != "" || b.SecretEnc != "" || b.DestName != "bad" {
			t.Fatalf("壞通道的放棄紀錄不符: %+v", b)
		}
		if strings.Contains(b.LastError, "broken:") {
			t.Fatalf("失敗原因不得帶出密文殘值: %q", b.LastError)
		}

		// 明細 API 看得到：該目的地狀態為放棄。
		view, err := NewSystemAlertCatalogService(db, NewTxSink()).Detail(receipt.AlertID)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]string{}
		for _, d := range view.Deliveries {
			seen[d.DestName] = d.State
		}
		if seen["bad"] != model.SystemAlertOutboxAbandoned || seen["good"] != model.SystemAlertOutboxPending {
			t.Fatalf("明細投遞狀態不符: %v", seen)
		}

		// 投遞程序只送好通道，不碰放棄列。
		w := NewSystemAlertOutboxWorker(db, codec)
		w.tee = func(model.CommandAlert) {}
		w.RunOnce()
		if stub.count() != 1 {
			t.Fatalf("好通道應收到 1 則: %d", stub.count())
		}
		if after := outboxOf(t, db, bad.ID); after.State != model.SystemAlertOutboxAbandoned || after.Attempts != 0 {
			t.Fatalf("放棄列不應被投遞程序認領: %+v", after)
		}
	})

	t.Run("沒有好通道時只有放棄紀錄，告警列仍存在", func(t *testing.T) {
		db := setupSystemAlertDB(t)
		bad := seedRawChannel(t, db, "bad", "enc:broken:url", "")
		var receipt port.SystemAlertReceipt
		if err := db.Transaction(func(tx *gorm.DB) error {
			var err error
			receipt, err = port.RaiseInTx(NewSystemAlertSink(&brokenCodec{}), tx, validGrantEvent())
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if receipt.Destinations != 0 || receipt.Unreadable != 1 || systemAlertRowCount(t, db, "command_alerts") != 1 {
			t.Fatalf("回執 %+v、告警 %d", receipt, systemAlertRowCount(t, db, "command_alerts"))
		}
		if b := outboxOf(t, db, bad.ID); b.State != model.SystemAlertOutboxAbandoned {
			t.Fatalf("應有放棄紀錄: %+v", b)
		}
	})

	t.Run("解不開的通道仍可修復與刪除", func(t *testing.T) {
		db := setupSystemAlertDB(t)
		codec := &brokenCodec{}
		svc := newChannelSvc(t, db, codec)
		stub := newStubReceiver(t, 0)
		fixme := seedRawChannel(t, db, "fixme", "enc:broken:url", "enc:broken:secret")
		gone := seedRawChannel(t, db, "gone", "enc:broken:url", "")

		// 修復＝重新給網址並清掉解不開的密鑰（任一欄解不開，該通道就不作為額外投遞目的地）。
		if _, err := svc.Update(fixme.ID, &NotificationChannelRequest{Name: "fixme", URL: stub.srv.URL + "/hook/ABCDEFGHIJKL",
			ClearSecret: true, ActorID: 5, ActorName: "sec-admin"}); err != nil {
			t.Fatalf("修復解不開的通道被擋: %v", err)
		}
		if err := svc.Delete(gone.ID, channelActor); err != nil {
			t.Fatalf("刪除解不開的通道被擋: %v", err)
		}
		var n int64
		db.Model(&model.NotificationChannel{}).Where("id = ?", gone.ID).Count(&n)
		if n != 0 {
			t.Fatal("通道列應已刪除")
		}
		// 兩個變更各留一筆審計與一筆告警；審計不得帶出密文殘值。
		var audits []model.AuditLog
		if err := db.Find(&audits).Error; err != nil || len(audits) != 2 {
			t.Fatalf("審計列 %d: %v", len(audits), err)
		}
		for _, a := range audits {
			if strings.Contains(a.Details, "broken:") {
				t.Fatalf("審計帶出密文殘值: %s", a.Details)
			}
		}
		if systemAlertRowCount(t, db, "command_alerts") != 2 {
			t.Fatalf("告警列 %d", systemAlertRowCount(t, db, "command_alerts"))
		}
		// 修復後的網址成為可投遞目的地：第二筆告警（刪除）送到它。
		NewSystemAlertOutboxWorker(db, codec).RunOnce()
		if stub.count() == 0 {
			t.Fatal("修復後的通道應收到之後的告警")
		}
	})

	t.Run("只有密鑰解不開時改網址，審計與告警仍記得到前後網址", unreadableSecretKeepsURLChange)
}

// 只有密鑰解不開時，網址仍各自解：改網址的審計與告警記得到前後網址。
func unreadableSecretKeepsURLChange(t *testing.T) {
	db := setupSystemAlertDB(t)
	codec := &brokenCodec{}
	svc := newChannelSvc(t, db, codec)
	half := seedRawChannel(t, db, "half", "https://old.example.test/hook/AAAABBBBCCCC", "enc:broken:secret")

	if _, err := svc.Update(half.ID, &NotificationChannelRequest{Name: "half", URL: "https://new.example.test/hook/DDDDEEEEFFFF",
		ActorID: 5, ActorName: "sec-admin"}); err != nil {
		t.Fatalf("改網址被擋: %v", err)
	}
	var audits []model.AuditLog
	if err := db.Find(&audits).Error; err != nil || len(audits) != 1 {
		t.Fatalf("審計列 %d: %v", len(audits), err)
	}
	var details struct {
		URLBefore string `json:"url_before"`
		URLAfter  string `json:"url_after"`
		Changes   []struct {
			Field string `json:"field"`
		} `json:"changes"`
	}
	if err := json.Unmarshal([]byte(audits[0].Details), &details); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(details.URLBefore, "old.example.test") || !strings.Contains(details.URLAfter, "new.example.test") {
		t.Fatalf("審計應記得到遮罩後的前後網址: %s", audits[0].Details)
	}
	if len(details.Changes) != 1 || details.Changes[0].Field != "url" {
		t.Fatalf("變更欄位應只有 url: %s", audits[0].Details)
	}
	if strings.Contains(audits[0].Details, "broken:") || strings.Contains(audits[0].Details, "AAAABBBBCCCC") {
		t.Fatalf("審計帶出密文殘值或完整網址: %s", audits[0].Details)
	}
	// 有欄位變動即產生告警，參數帶遮罩後的前後網址。
	var detail model.SystemAlertDetail
	if err := db.First(&detail).Error; err != nil {
		t.Fatalf("應產生通道變更告警: %v", err)
	}
	if !strings.Contains(detail.Params, "old.example.test") || !strings.Contains(detail.Params, "new.example.test") {
		t.Fatalf("告警參數應帶前後網址: %s", detail.Params)
	}
	// 密鑰解不開的一側不作為額外目的地（不以空密鑰送出未簽章通知）；啟用中的本通道留放棄紀錄。
	var rows []model.SystemAlertOutbox
	if err := db.Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].State != model.SystemAlertOutboxAbandoned || rows[0].URLEnc != "" {
		t.Fatalf("投遞列應只有本通道的一筆放棄紀錄: %+v", rows)
	}
}

var deliveryKeyRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// 缺陷二：投遞識別不得在還原後與還原前重複。
func TestSystemAlertDeliveryKey(t *testing.T) {
	t.Run("每列帶隨機識別且互不相同", func(t *testing.T) {
		db, sink := outboxTestSetup(t,
			model.NotificationChannel{Name: "a", Type: "webhook", URL: "https://a.example.test/h", Enabled: true, Language: "zh-TW", MinSeverity: "low"},
			model.NotificationChannel{Name: "b", Type: "webhook", URL: "https://b.example.test/h", Enabled: true, Language: "zh-TW", MinSeverity: "low"})
		raiseEvent(t, db, sink, port.SystemAlertManagementRoleGranted, validGrantEvent().Params)
		rows := outboxRows(t, db)
		if len(rows) != 2 || !deliveryKeyRe.MatchString(rows[0].DeliveryKey) || !deliveryKeyRe.MatchString(rows[1].DeliveryKey) || rows[0].DeliveryKey == rows[1].DeliveryKey {
			t.Fatalf("識別不符: %q %q", rows[0].DeliveryKey, rows[1].DeliveryKey)
		}
	})

	t.Run("還原後重用的列編號不會產生相同識別", func(t *testing.T) {
		db, sink := outboxTestSetup(t,
			model.NotificationChannel{Name: "a", Type: "webhook", URL: "https://a.example.test/h", Enabled: true, Language: "zh-TW", MinSeverity: "low"})
		raiseEvent(t, db, sink, port.SystemAlertManagementRoleGranted, validGrantEvent().Params) // 備份內的列
		raiseEvent(t, db, sink, port.SystemAlertManagementRoleGranted, validGrantEvent().Params) // 備份之後、還原前發出的列
		before := outboxRows(t, db)
		if len(before) != 2 {
			t.Fatalf("列數 %d", len(before))
		}
		lost := before[1]
		// 模擬還原到只含第一列的備份：第二列消失、序列退回。
		if err := db.Delete(&model.SystemAlertOutbox{}, lost.ID).Error; err != nil {
			t.Fatal(err)
		}
		db.Exec(`UPDATE sqlite_sequence SET seq = ? WHERE name = 'system_alert_outbox'`, before[0].ID)
		raiseEvent(t, db, sink, port.SystemAlertManagementRoleGranted, validGrantEvent().Params) // 還原後的新告警
		after := outboxRows(t, db)
		if len(after) != 2 || after[1].ID != lost.ID {
			t.Fatalf("測試前提：還原後的新列應重用編號 %d: %+v", lost.ID, after)
		}
		if after[1].DeliveryKey == lost.DeliveryKey {
			t.Fatalf("還原後的新列與還原前發出的列識別相同: %q", lost.DeliveryKey)
		}
		if after[0].DeliveryKey != before[0].DeliveryKey {
			t.Fatal("備份內的列識別不得改變")
		}
	})

	t.Run("payload 的 delivery_id 為該列識別且重送不變", func(t *testing.T) {
		stub := newStubReceiver(t, 1)
		db, sink := outboxTestSetup(t, model.NotificationChannel{Name: "c", Type: "webhook", URL: stub.srv.URL,
			Enabled: true, Language: "zh-TW", MinSeverity: "low"})
		raiseEvent(t, db, sink, port.SystemAlertManagementRoleGranted, validGrantEvent().Params)
		w := fastWorker(db)
		w.RunOnce()
		time.Sleep(10 * time.Millisecond)
		w.RunOnce()
		if stub.count() != 1 {
			t.Fatalf("重送後應收到 1 則成功: %d", stub.count())
		}
		var got struct {
			DeliveryID string `json:"delivery_id"`
		}
		if err := json.Unmarshal(stub.body(0), &got); err != nil {
			t.Fatalf("delivery_id 應為字串: %v", err)
		}
		row := outboxRows(t, db)[0]
		if got.DeliveryID != row.DeliveryKey || row.Attempts != 2 {
			t.Fatalf("delivery_id=%q key=%q attempts=%d", got.DeliveryID, row.DeliveryKey, row.Attempts)
		}
	})
}
