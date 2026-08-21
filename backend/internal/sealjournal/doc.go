// Package sealjournal 實作封印期（B 模式）的定長環狀 journal 與 at-least-once 回灌。
//
// # 存在理由
//
// B 模式解封端點不要求 JWT，其嘗試必須留痕；而封印期段 2 尚未執行，
// AuditLogService 與 HMAC 蓋章鏈都還不存在。既有的檔案 fallback 受
// FEATURE_AUDIT_FALLBACK_TO_FILE 控制且可被關閉，無法承擔此職。
// 本套件是「全操作審計」紅線在封印期的唯一承載，因此：
//
//   - 不受任何 feature flag 控制、不可關閉；
//   - 建立失敗即回錯，呼叫端據此 SHALL NOT 開放解封端點監聽；
//   - 落點沿用既有 AUDIT_LOG_PATH 所在目錄、另立固定檔名，不新增 env 鍵。
//
// # 呼叫端契約（本套件無法自行保證的部分）
//
//  1. 材料驗證 SHALL 於 WriteReceived 成功回傳「之後」才開始。
//     WriteReceived 回傳時已完成 `寫資料槽 → fdatasync → 推進 header → fdatasync`；
//     若在此之前就驗證，崩潰後可能沒有可辨識的 received，
//     不變式「任何被驗證的嘗試必有 durable 個別紀錄」當場破。
//  2. WriteReceived 失敗 SHALL 回滾 CAS 至 sourceState、拒絕該次、不驗證材料。
//  3. 未取得獨佔的嘗試只走 RecordRejected（不寫 critical 環、不觸發 fsync）。
//  4. outcome=success SHALL 於 publish 之前寫入並成功回傳；
//     WriteOutcome 或 WritePublished 失敗即 SHALL 丟棄服務圖、清除已解封的 KEK、
//     回 sourceState，SHALL NOT 回覆解封成功（不得 publish-then-write）。
//  5. Replay 的 Sink 實作 MUST 走既有審計寫入路徑（同一序列化入口），
//     MUST NOT 另開直寫 DB；並 MUST 把 ReplayEvent.IdempotencyUUID 與
//     AggregateRow.DeterministicID 設為 DB 唯一鍵。
//  6. CAS 勝出前 SHALL 先取得 Admit 資格，並於 received 落地與否對應
//     Ticket.Release(true/false)。
//
// # 內容白名單
//
// 進入 journal 的只有：格式版本、boot ID、全域序號、事件種類、長度、時間、
// 來源摘要（十六進位，經 validateSourceDigest 強制）、結果碼、CRC32C。
// 請求體 SHALL NOT 入 journal；KEK 材料或其片段、認證憑證或其衍生值亦然。
// 由於唯一的自由字串欄位只接受十六進位摘要，原始材料在建構上無法寫入。
//
// # 誠實邊界
//
//   - 定長環會被依序洪水繞回，屆時已驗證過的個別紀錄仍會消失；
//     本套件選擇「記錄被覆蓋的序號範圍」，不選環滿鎖死、不選外部儲存依賴。
//   - rejected 合批與「總數永不可否認」互斥：崩潰最多遺失一個有明確上限的未 flush
//     時窗；Status 同時提供 observed／durable／overwritten 三類計數。
//   - CRC32C 只防 torn write，不防本機竄改、不提供不可否認性。
//   - 首次建立途中失敗會留下不完整檔案，下次啟動即落入 (i) 而 fail-close；
//     這是刻意的——自動清理等於提供一條把歷史歸零的合法途徑。
//     人工處置（離線檢視、備份留存、確認後決定是否以新檔重新起算並記錄該決定）
//     屬 runbook 範疇。
package sealjournal
