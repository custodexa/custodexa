# key-management Specification

## Purpose
本規範定義落庫敏感資料的信封加密（KEK/DEK 分層）、金鑰清冊與換鑰治理、KEK 切換狀態機與軟刪除退役，以及金鑰清冊儀表板之顯示、指紋與可觀測性。
## Requirements
### Requirement: KEK/DEK 信封加密分層
系統 SHALL 以信封加密保護落庫敏感資料：資料由 DEK（AES-256-GCM）加密，DEK 由 KEK 包裹後存於金鑰表（含用途、版本、狀態；每用途同時僅一把 active，retired 鑰 SHALL 永久保留供舊資料解密）。KEK SHALL 經 `KEKProvider` 介面取得。落庫密文 SHALL 一律為帶自描述方案前綴之信封格式並含 AAD 綁定（見「信封密文的 AAD 列綁定」）；無前綴或方案未知之值 SHALL fail-close 回可辨識格式錯，系統 SHALL NOT 具備任何 legacy 單鑰解密路徑。KEK 明文與 DEK 明文 SHALL NOT 落庫、SHALL NOT 經 API 回傳、SHALL NOT 寫入日誌。

自 KEK provider 模組化起本 requirement 擴充如下：`KEKProvider` SHALL 支援多種 KEK 來源模式，且模式差異 SHALL 完全封裝於該介面之下——金鑰表版本鏈、信封密文格式、輪替、重包、清理與退役狀態機在各模式下 SHALL 具相同語義。DEK 明文於啟動時解出後常駐行程記憶體，運行期一般加解密 SHALL NOT 觸發 KEK 操作（KEK 僅於啟動、重包與清理時被使用）；委託型 provider 之外部服務短暫不可達 SHALL NOT 影響既有連線與既有密文之加解密。

#### Scenario: 新資料以信封格式加密
- **WHEN** 建立帶密碼的資產
- **THEN** 落庫密文帶自描述方案前綴，以 active data DEK 加密並綁定 AAD，讀取時正確解密

#### Scenario: 換 KEK 不動資料本體
- **WHEN** KEK 重包完成（僅重寫金鑰表的 wrapped_key）
- **THEN** 所有既有資料密文位元不變且仍可正確解密

#### Scenario: 非終態格式密文 fail-close
- **WHEN** 讀取一筆無前綴或方案未知的密文值（不論其來源）
- **THEN** 解密 MUST 失敗並回可辨識格式錯，MUST NOT 靜默回退任何其他解密路徑、MUST NOT 回傳明文

#### Scenario: 運行期不依賴 KEK 可達性
- **WHEN** 系統已完成啟動，其後委託型 KEK 服務（現行為 KMS）不可達
- **THEN** 既有連線、審計寫入與既有密文之加解密完全正常；僅重包與清理等 KEK 操作被拒並回明確錯誤

### Requirement: 換鑰精靈（無自動輪換）
系統 SHALL 提供 admin 專屬換鑰操作且 SHALL NOT 自動輪換任何金鑰：(1) DEK 輪替——生成新版本、批次重加密該用途全部資料（audit_integrity 用途 SHALL NOT 重算歷史章，僅新章改用新鑰）、舊代轉 retired；進度可查、可中斷續跑。(2) KEK 重包——生成新 KEK（SHALL 僅一次性顯示，不落庫不落日誌）、以新舊 KEK 雙包裹並存落庫、引導更新 env 後重啟、新 KEK 開機驗證成功後將舊包裹列**軟退役**（保留列與 `wrapped_key` 材料至顯式清理，SHALL NOT 硬刪——見「退役資料軟刪除與顯式清理」）。所有換鑰操作 SHALL 入審計（操作者、鑰用途、版本變化）。

自 KEK provider 模組化起，上段 (2) 的「伺服端生成新 KEK 並一次性顯示」語義**已被下列明文流向反轉取代**（原文保留供追溯）：KEK 重包的新 KEK 材料 SHALL 由管理員於請求中提供，伺服端 SHALL NOT 生成、SHALL NOT 回傳任何 KEK 明文、SHALL NOT 落庫、SHALL NOT 寫入日誌，且該請求內容 SHALL NOT 進入審計紀錄的請求內容欄位（`audit_logs.request_body`；措辭與「新 KEK 明文暴露面收斂」一致，避免實作者只擋其他欄位）。重包回應 SHALL 僅含新 KEK 指紋（非機密）與重包列數。請求 SHALL 包含二次輸入（paste-back）與保存確認旗標，兩者 SHALL 由伺服端校驗——二次輸入不符或未確認保存時 SHALL 拒絕（400）且 SHALL NOT 對金鑰表產生任何寫入；此校驗 SHALL NOT 僅實作於前端。**兩欄位之證明力 SHALL 明確區分**：二次輸入之比對為伺服端唯一可獨立驗證的機械不變式（證明呼叫端當下持有並能完整重述該材料），SHALL 為受理之前置條件；保存確認旗標 SHALL NOT 被視為具授權力或安全不變式——伺服端無從驗證材料是否已離線保存，該欄位僅為使用者意圖聲明，系統 SHALL NOT 以其宣稱材料已安全保存。**重包請求體 SHALL 為互斥的變體結構**：本地目標攜帶新 KEK 材料與其二次輸入，委託目標攜帶目標金鑰引用，由顯式的目標種類欄位判別；混合或與所宣告種類不符之請求體 SHALL fail-close 拒絕，SHALL NOT 以欄位優先序擇一處理（否則可繞過本地目標之格式驗證與二次輸入，或使 KEK 明文被送入本應僅接受引用的委託路徑）。委託型目標（KMS／HSM）之重包 SHALL 以目標金鑰引用取代 KEK 材料，並於受理前完成目標金鑰之連通性與權限預檢。其餘語義（雙包裹並存、切換後退役、全操作入審計）不變。

#### Scenario: DEK 輪替後新舊資料皆可讀
- **WHEN** admin 執行 data DEK 輪替完成
- **THEN** 全部資料已重加密為新版本前綴且可讀，舊代 DEK 轉 retired，操作入審計

#### Scenario: KEK 重包中途未換 env 不鎖死
- **WHEN** KEK 重包完成但管理員未更新 env 即重啟
- **THEN** 服務以舊 KEK 正常啟動（舊包裹列仍在），清冊顯示「重包未完成」

#### Scenario: 蓋章鑰輪替不動歷史
- **WHEN** admin 對 audit_integrity 用途執行輪替
- **THEN** 新審計列以新版本蓋章，歷史列的 HMAC 與 key_version 不變且驗證仍通過

#### Scenario: 重包回應不含 KEK 明文
- **WHEN** admin 提交含新 KEK 材料的重包請求且重包成功
- **THEN** 回應僅含新 KEK 指紋與重包列數，任一欄位 MUST NOT 含 KEK 明文；伺服端日誌與審計紀錄的請求內容欄位（`audit_logs.request_body`）亦不含該材料

#### Scenario: 未通過保存確認即拒絕
- **WHEN** 重包請求的二次輸入與新 KEK 不符，或未帶保存確認旗標
- **THEN** 請求被拒（400＋機器碼），金鑰表 MUST 零寫入（不產生任何 pending 過渡列）

### Requirement: 金鑰清冊儀表板
系統 SHALL 提供 admin 專屬金鑰清冊：列出 DEK 各版本與蓋章鑰各版本（自 v1 起）之用途、版本、狀態、年齡、上次輪替時間，以及 env 側金鑰（JWT_SECRET、KEK、匯出簽章鑰）之指紋。DEK／蓋章鑰版本鏈 SHALL 僅呈現以**現行 KEK 包裹且未退役、非待切換**的列（退役之舊 KEK 包裹列與待切換 pending 列 SHALL NOT 混入版本鏈，另以退役史／待切換狀態呈現）。env 側三鑰 SHALL 一致呈現指紋：`JWT_SECRET` 與 KEK SHALL 顯示其材料的 SHA-256 前 8 bytes 摘要指紋、Ed25519 匯出簽章鑰 SHALL 顯示其**公鑰指紋**（對原始公鑰位元組取 SHA-256 前 8 bytes，公鑰來源與 `/api/v1/audit-export/public-key` 端點一致）。三鑰指紋 SHALL 由同一 fingerprint 演算法產生（`hex(SHA-256(material)[:8])`）。指紋為單向摘要、僅供人眼辨識，SHALL NOT 用於反推金鑰、SHALL NOT 作授權或業務唯一性判斷依據（KEK 指紋於重包時作碰撞保守拒絕之用不在此限，見「KEK 切換狀態機」）。env 側金鑰 SHALL 標示管理方（`JWT_SECRET`／KEK 為部署方管理、Ed25519 匯出簽章鑰為系統管理）並附輪替 runbook 指引。env 側金鑰 SHALL 僅呈現指紋與管理方，**SHALL NOT 呈現「年齡」或「上次輪替時間」**——環境變數不帶輪替紀錄，該值技術上無從得知，呈現任何數字即為捏造；指紋本身已隱含「該鑰是否存在」（未設定者無指紋可算）。清冊 SHALL NOT 顯示任何金鑰明文、私鑰或 wrapped 值（Ed25519 公鑰非機密，不在此限）。清冊 SHALL NOT 含任何 legacy 遷移狀態欄位。金鑰管理頁 SHALL 承載 cryptoperiod 提醒政策鍵 `key_cryptoperiod_reminder_days` 的設定區（沿安全政策機制與本頁 PCI 子集偏離摘要／套用本頁建議值）。cryptoperiod 提醒政策 >0 且金鑰超齡時 SHALL 於清冊顯示提醒（僅提醒，SHALL NOT 觸發任何動作或外送通知）。

#### Scenario: 清冊誠實區分可管與不可管
- **WHEN** admin 開啟金鑰清冊
- **THEN** DB 側鑰顯示版本鏈與輪替入口，env 側鑰標管理方（部署方／系統）無輪替按鈕、附 runbook

#### Scenario: env 三鑰皆顯示指紋
- **WHEN** admin 開啟金鑰清冊，`JWT_SECRET`（已達長度下限）與 KEK 已設定、Ed25519 匯出簽章鑰已生成
- **THEN** 三鑰各自顯示指紋（`JWT_SECRET`／KEK 為 secret 摘要指紋、Ed25519 為公鑰指紋），無任一鑰的指紋欄留空為「—」

#### Scenario: 版本鏈不含退役/待切換 KEK 包裹列
- **WHEN** 金鑰清冊呈現 DEK／蓋章鑰版本鏈，且存在已退役舊 KEK 包裹列或待切換 pending 列
- **THEN** 版本鏈僅列現行 KEK 包裹的未退役非 pending 列，退役列另於「KEK 退役史」呈現、pending 另於待切換狀態呈現

#### Scenario: 全新安裝清冊無出生即退役列
- **WHEN** 全新安裝完成首次啟動後 admin 開啟金鑰清冊
- **THEN** 版本鏈僅含 active 鑰（data v1、audit_integrity v1），MUST NOT 含任何 retired 列或 v0 快照列

#### Scenario: JWT 指紋可於部署外自行核對
- **WHEN** admin 以 `echo -n <JWT_SECRET> | sha256sum` 取前 16 hex 字元
- **THEN** 其值等於金鑰清冊顯示的 `JWT_SECRET` 指紋（裸 SHA-256 前 8 bytes，未 keyed）

#### Scenario: 指紋不外洩金鑰材料
- **WHEN** 清冊回傳 env 側金鑰資訊
- **THEN** 僅含指紋（單向摘要）與 Ed25519 公鑰，SHALL NOT 含任何對稱金鑰明文、私鑰或 wrapped 值

#### Scenario: 提醒鍵同頁設定即時反映
- **WHEN** admin 於金鑰管理頁將提醒天數自 0 改為 365 並儲存，且某 active 鑰年齡達 400 天
- **THEN** 儲存入審計，清冊顯示該鑰超齡提醒，無需切換頁面

#### Scenario: 超齡提醒
- **WHEN** 提醒政策設 365 且某 active 鑰年齡達 400 天
- **THEN** 清冊顯示該鑰超齡提醒，系統行為無任何其他變化

自 KEK provider 模組化起本 requirement 擴充如下（原文所述 env 三鑰之指紋語義維持為本地模式的規範，不廢止）：KEK 項 SHALL 另呈現其**執行期 provider 模式**（`env`／`ui`／`kms`／`hsm`）與**金鑰引用**。指紋欄的語義依模式分岔——本地模式（`env`／`ui`）SHALL 維持 `hex(SHA-256(material)[:8])` 材料指紋；**委託模式（`kms`／`hsm`）無本地材料，SHALL 以外部金鑰引用（正規化後的雲端金鑰 ARN；`hsm` 之引用形式待其 provider 交付時定案）取代材料指紋呈現，此情形 SHALL NOT 視為違反「無任一鑰的指紋欄留空」**（原 Scenario 之前提為本地模式，委託模式下該欄以金鑰引用滿足「可供人眼辨識與外部對照」之目的）。外部金鑰引用非機密，SHALL 完整呈現以供稽核對照外部主控台。provider 欄 SHALL 由執行期 provider 物件導出，SHALL NOT 重新讀取環境變數。`ui` 模式 SHALL 另呈現封印狀態（`sealed`／`unsealing`／`unsealed`／`sealed-faulted`）。上述新增呈現 SHALL NOT 洩漏任何金鑰材料。

#### Scenario: 委託模式以金鑰引用取代材料指紋
- **WHEN** 以 `kms` 模式運行並檢視金鑰清冊的 KEK 項（`hsm` 之呈現契約相同，但其 provider 未交付故此情境目前不可達）
- **THEN** 該項顯示 provider 模式與外部金鑰引用（非機密、完整呈現），指紋欄不因無材料而留空為「—」，且回應不含任何金鑰材料

#### Scenario: provider 欄不得重讀環境變數
- **WHEN** 清冊組出 KEK 項的 provider 欄
- **THEN** 其值 MUST 取自執行期 provider 物件之**模式存取器**；守衛 MUST 確認該處未讀取 `KEK_PROVIDER` 環境變數（重讀將使部署宣告與執行期實況同源而失去互證價值），且 MUST NOT 由金鑰引用之 provider 維度推導（該維度不區分兩種本地模式）

### Requirement: JWT_SECRET 長度下限
`JWT_SECRET` 為 HS256 認證信任根，系統啟動時 SHALL 要求其長度達下限（≥32 **bytes**，對齊 HS256 之 256-bit 密碼學下限）；不足時 SHALL fail-close 拒絕啟動並輸出含排查指引的明確錯誤，SHALL NOT 以弱 secret 帶病啟動。`JWT_SECRET` SHOULD 由 CSPRNG 生成——長度檢查為符合 key-size 下限、降低常見弱值風險的務實手段，系統 SHALL NOT 宣稱可由單一值驗證其熵（低熵長字串仍可被猜測）。開發用預設值與範本 SHALL 亦滿足此下限。

#### Scenario: 過短 JWT_SECRET 拒絕啟動
- **WHEN** `JWT_SECRET` 長度不足 32 bytes
- **THEN** 系統拒絕啟動並輸出明確錯誤（要求 ≥32 bytes、建議隨機生成），不進入服務狀態

#### Scenario: 合規 JWT_SECRET 正常啟動
- **WHEN** `JWT_SECRET` 長度 ≥32 bytes
- **THEN** 系統正常啟動，金鑰清冊顯示其指紋

### Requirement: 匯出簽章公鑰之清冊取用
系統 SHALL 於金鑰清冊提供 Ed25519 匯出簽章鑰之**公鑰**取用入口，供管理員交付外部驗證者（QSA）離線驗簽：SHALL 提供複製公鑰（base64）與下載公鑰檔案兩種操作。取用之公鑰 SHALL 與 `GET /api/v1/audit-export/public-key` 端點回傳者同源（`ExportSigningService` 的 canonical 公鑰），SHALL NOT 使用未經一致性保證的其他來源。下載檔案 SHALL 為 canonical JSON（`{"algorithm":"Ed25519","public_key":"<base64>"}`）。私鑰 SHALL NOT 經此入口或清冊以任何形式外洩。此入口 SHALL 限 admin。

#### Scenario: 複製與下載公鑰
- **WHEN** admin 於金鑰清冊 Ed25519 列點「複製公鑰」或「下載公鑰檔案」
- **THEN** 取得該鑰之 base64 公鑰（複製至剪貼簿或下載為 canonical JSON 檔），內容與 `/audit-export/public-key` 端點一致

#### Scenario: 私鑰不外洩
- **WHEN** 管理員經清冊取用匯出簽章公鑰
- **THEN** 僅公鑰可取，私鑰維持信封加密落庫、SHALL NOT 出現於清冊回應或下載內容

### Requirement: KEK 失效明確報錯
開機時 KEK 無法解包任何 active wrapped_key（指紋不符或解包失敗）時，系統 SHALL 拒絕啟動並輸出含排查指引的明確錯誤；SHALL NOT 靜默退回任何其他解密路徑帶病運行。

自 KEK provider 模組化起補充判準與範圍：金鑰表一致性的**權威判準 SHALL 為「現行代表列實際解包成功」**，`kek_id` 相等 SHALL 僅作為篩選條件、SHALL NOT 被任何路徑當作一致性的充分條件（委託型 provider 的 `kek_id` 為外部金鑰引用，不可由材料重算）。委託型 KEK 服務於啟動時不可達或無權限時，系統 SHALL 拒絕啟動並輸出可辨識的明確錯誤，SHALL NOT 降級啟動、SHALL NOT 以本地材料替代。

#### Scenario: 錯誤 KEK 拒絕啟動
- **WHEN** env 中 KEK 被改為與金鑰表 kek_id 不符的值後啟動
- **THEN** 啟動失敗，錯誤訊息指出 KEK 不符並提示檢查方向

#### Scenario: 指紋相符但材料不符仍拒絕啟動
- **WHEN** 現行代表列的 `kek_id` 與 provider 引用相等，但實際解包失敗
- **THEN** 系統 MUST 拒絕啟動（不得因引用相等而放行）

#### Scenario: 委託服務不可達拒絕啟動
- **WHEN** `KEK_PROVIDER` 為委託型（現行為 `kms`），且啟動時該服務不可達或無 Decrypt 權限
- **THEN** 系統 MUST 拒絕啟動並輸出可辨識錯誤，MUST NOT 降級為本地材料或其他 provider

### Requirement: 放棄未切換的 KEK 重包
系統 SHALL 提供管理員經 UI 放棄尚未切換的 KEK 重包：將以新 KEK 包裹的過渡列**軟退役**（標記退役時間與 `reason=abandoned`、無 replacement 指紋，`wrapped_key` 材料 SHALL 保留至顯式清理）並清除待切換狀態，回到重包前狀態，服務續以現行 KEK 運行。放棄操作 SHALL NOT 硬刪除任何金鑰列——金鑰材料之銷毀 SHALL 僅發生於使用者顯式清理操作（見「退役資料軟刪除與顯式清理」）；金鑰操作不可逆，誤刪的代價遠高於多留一份待清理的材料，安全性由「顯式清理」那一步承擔。放棄 SHALL 僅作用於 `kek_id` 不等於現行 KEK 指紋的過渡列，**SHALL NOT** 動到以現行 KEK 包裹的任何活躍或退休金鑰列（服務運行所依）。放棄 SHALL 限 admin，且僅在重包待切換時可用（否則回 409）；操作 SHALL 經審計記錄。此能力確保管理員在遺失一次性新 KEK 或決定不切換時，能自 UI 自助脫離「待切換」鎖定狀態，無需直接異動資料庫。

上述「只軟退役外來列、不動現行 KEK 列」的安全不變式，SHALL 在單一 backend 實例假設下成立——與 KEK 重包及啟動收尾相同，KEK 變動操作以 process-local 鎖序列化。切換機制為改 env 重啟（舊實例先停才起新實例），部署 SHALL NOT 於切換期間並存不同 KEK 的多個 backend 實例；多實例支援（需 DB 層跨實例互斥）不在此範圍。

#### Scenario: 待切換時放棄成功回復
- **WHEN** KEK 重包待切換（`rewrap_pending` 為真），管理員於金鑰管理頁點「放棄本次切換」並確認
- **THEN** 系統將以新 KEK 包裹的過渡列軟退役（`reason=abandoned`、材料保留）、清除待切換狀態，清冊 `rewrap_pending` 轉為否、橫幅消失、輪替與重包按鈕恢復可用；服務續以現行 KEK 運行，既有資料照常解密

#### Scenario: 放棄只退役外來列不動現行 KEK 列
- **WHEN** 執行放棄，`data_keys` 表同時含現行 KEK 指紋列與新 KEK 指紋（未切換）列
- **THEN** 僅新 KEK 指紋列被軟退役且其列與 `wrapped_key` 材料 MUST 仍在（MUST NOT 被硬刪）；所有現行 KEK 指紋的活躍/退休列完整保留

#### Scenario: 非待切換時拒絕放棄
- **WHEN** 無待切換重包（`rewrap_pending` 為否）時呼叫放棄端點
- **THEN** 回 409（無待切換重包），不退役亦不刪除任何列

### Requirement: KEK 切換狀態機與軟刪除退役
KEK 切換 SHALL 以明確持久化狀態欄位（非 wall-clock 時間推導）管理，且 **SHALL NOT 因切換收尾失敗而拒絕啟動**（堡壘機為生產運維唯一通道，可用性優先）。金鑰列 SHALL 具五種合法**欄位形狀**之一（形狀集合已隨「退役資料軟刪除與顯式清理」的引入而擴充，本段原先的「retired 即清空 wrapped_key」語義已被其取代）：live（非 pending、未退役、有 wrapped_key）、pending（待切換、未退役、有 wrapped_key）、retired-switched（切換退役，記錄 replacement 指紋與 reason=switched）、retired-abandoned（放棄重包退役，無 replacement、reason=abandoned）——後兩者的 wrapped_key **保留至顯式清理**，材料尚存或已清理皆合法；purged-placeholder（顯式清理後的退役 DEK 版本現行列：wrapped_key 空、status=retired，載入時跳過解包以保版本鏈不斷號）。啟動時 SHALL 驗證每列屬合法形狀，非法形狀 SHALL fail-close（資料損毀）。金鑰列相對現行 KEK 的**角色**（現行代表／待退役 predecessor／退役 backlog／待切換／退役歷史）SHALL 由欄位形狀與 `kek_id` 是否等於現行 KEK 推導，**SHALL NOT 將正常切換後的 live 舊列（`kek_id<>env`）誤判為非法**。所有 pending 列 SHALL 僅屬單一 KEK 指紋（單一重包 campaign）。

- **金鑰完整性與 bootstrap 閘門**：啟動時僅在金鑰表**完全為空**時才允許 bootstrap 補鑄；bootstrap SHALL 僅鑄造各必要用途之 v1 active 鑰，SHALL NOT 快照任何 legacy 派生鑰為 v0——此適用於**全部**初始化路徑（env 模式首啟與 `ui` 模式初始化解封同）。金鑰表非空時，每個既有金鑰用途版本 SHALL 恰有一列以現行 KEK 包裹且未退役（現行代表列）；系統 SHALL 對現行代表列形成的金鑰鏈驗證完整性——`Status ∈ {active, retired}`、每必要用途恰一 active、data 與 audit_integrity 版本皆自 1 至 max 連續；**金鑰表存在任何 version 0 之列 SHALL 判為發佈前過渡格式並拒絕啟動（錯誤訊息指明須重建資料庫）**——v0 列既不構成斷號也不缺 active，若不顯式拒絕會被放行且其鑰被載入，使「系統無 v0 鑰」不變式被推翻。若某用途版本無現行代表列、缺必要用途、缺 active、多 active、版本斷號或形狀非法，SHALL 判為金鑰表損毀／KEK 不符並拒絕啟動（不待讀到信封密文才失敗），SHALL NOT 補鑄。系統 SHALL 僅以現行代表列解密，退役列與空 wrapped_key SHALL NOT 被任何解密路徑當作可用金鑰、SHALL NOT 以非現行 KEK 包裹列解密。
- **切換收尾（原子、best-effort）**：啟動時若某待切換 pending 列的 KEK 指紋等於現行 KEK，SHALL 於**單一資料庫交易**內將該 pending 列轉為現行、並將同用途版本的舊現行列軟刪除退役（記錄退役時間、replacement 指紋與 reason=switched，保留 kek_id；**wrapped_key 材料保留至顯式清理**——見「退役資料軟刪除與顯式清理」）。此交易為 best-effort：失敗時系統 SHALL 仍以現行 KEK 正常啟動、僅記日誌，並於後續啟動整筆重試（冪等，SHALL NOT 覆寫既有退役時間）。日誌與審計 SHALL 僅於交易提交且實際退役列數大於零後產生。
- **退役列保護與 pending 身分**：退役列 SHALL 永久保留、SHALL NOT 參與現行金鑰解析、SHALL NOT 被 KEK 重包或放棄重包誤退役或誤刪。重包與放棄操作 SHALL 僅作用於明確標記為待切換 pending（`KEKPending` 為真且未退役）的列，依持久化狀態而非時間推導。`AbandonRewrap` 執行前 SHALL 以資料庫重新確認所有 pending 列均為 foreign（`kek_id<>` 現行 KEK），SHALL NOT 退役或刪除任何 `kek_id==` 現行 KEK 的 pending 列（切換完成待轉正、正供解密），SHALL NOT 僅憑記憶體旗標判定。
- **重包守衛**：KEK 重包時，若已存在待切換 pending 列 SHALL 拒絕（要求先完成切換或明確放棄重包，SHALL NOT 靜默清除既有 pending 而使已交付的新 KEK 失效）；若存在前次切換未成功退役的舊列（退役 backlog）SHALL 拒絕開始新重包並提示先重啟收斂；此二拒絕 SHALL NOT 阻塞服務啟動、SHALL 以明確錯誤（HTTP 409）回應並含恢復指引。前端於重包衝突（409）SHALL 刷新清冊並引導管理員恢復（放棄後重做或先完成切換），SHALL NOT 僅記 console 錯誤。KEK 重包 SHALL 拒絕使用曾出現於金鑰表（含退役列）的 KEK 指紋（指紋碰撞之保守拒絕）。
- **可觀測性**：退役收尾成功後 SHALL 輸出含切換前後 KEK 指紋的日誌，並 SHALL（best-effort）補記一筆以既有審計 UI 可渲染格式承載前後指紋與退役列數的 `key_management` 審計事件（審計失敗 SHALL NOT 阻塞啟動）。切換證據 SHALL 以退役列本身承載（含 replacement 指紋）。金鑰清冊 SHALL 呈現 KEK 退役史（退役 KEK 指紋、replacement 指紋、退役時間），退役史查詢 SHALL NOT 選取 wrapped_key 本值（材料存量以 SQL 端衍生布林呈現）。指紋為單向摘要，SHALL NOT 洩漏金鑰明文。未發生切換的啟動 SHALL NOT 產生退役、切換日誌或審計事件。

#### Scenario: 切換以原子交易軟刪除退役收尾
- **WHEN** 管理員完成 KEK 重包並更新 `ENCRYPTION_KEY` 重啟，待切換 pending 列指紋等於現行 KEK
- **THEN** 於單一交易內 pending 列轉為現行、舊現行列軟刪除退役（記錄退役時間、replacement 指紋與 reason=switched，保留 kek_id 與 wrapped_key 材料——材料銷毀僅發生於顯式清理）；提交後輸出「KEK 切換完成 `<舊指紋>` → `<新指紋>`」日誌；金鑰清冊呈現該筆退役史；（best-effort）審計新增一筆含前後指紋與退役列數的事件

#### Scenario: 收尾交易失敗不阻塞啟動且重試
- **WHEN** 退役收尾交易或審計寫入失敗
- **THEN** 系統仍以現行 KEK 正常啟動並受理請求，僅記日誌警告；於後續啟動整筆重試（冪等、不覆寫退役時間），切換證據不遺失

#### Scenario: 待切換與退役 backlog 精確區分不誤動
- **WHEN** 前次切換的舊列軟退役失敗而殘留（退役 backlog），管理員之後執行放棄重包
- **THEN** 放棄僅軟退役明確標記為待切換 pending 的列，退役 backlog 舊列完整保留（其列與材料 MUST 不被動到）

#### Scenario: 有既存 pending 時拒絕新重包
- **WHEN** 已存在待切換 pending 列，管理員再次觸發 KEK 重包
- **THEN** 系統拒絕並要求先完成切換或放棄重包，既有 pending 列不被清除、已交付的新 KEK 不失效

#### Scenario: 金鑰用途版本缺現行代表列時拒絕啟動
- **WHEN** 資料表非空，但某既有用途版本無以現行 KEK 包裹且未退役的代表列
- **THEN** 系統判為金鑰表損毀／KEK 不符並拒絕啟動，SHALL NOT 誤判為空表而鑄造新金鑰

#### Scenario: 金鑰鏈斷號或多 active 拒絕啟動
- **WHEN** 現行代表列形成的金鑰鏈出現版本斷號（data 或 audit_integrity 自 v1 起不連續）、同用途多個 active 或非法 Status
- **THEN** 系統於啟動時判為金鑰表損毀並拒絕啟動，不待讀取密文才失敗

#### Scenario: 全新安裝 bootstrap 不鑄 v0
- **WHEN** 金鑰表完全為空的全新安裝首次啟動（含 `ui` 模式之初始化解封路徑）
- **THEN** bootstrap 僅鑄造 data v1 與 audit_integrity v1（皆 active），MUST NOT 產生任何 v0 或 retired 列

#### Scenario: v0 殘列拒絕啟動
- **WHEN** 金鑰表存在任何用途之 version 0 列（例：`audit_integrity` v0，發佈前過渡格式資料庫）
- **THEN** 系統 MUST 拒絕啟動且錯誤訊息指明「資料庫含發佈前過渡格式，請重建」，MUST NOT 載入該 v0 鑰

#### Scenario: 放棄重包不動切換完成待轉正的 env pending
- **WHEN** 切換完成後 pending 列 kek_id 等於現行 KEK（待轉正、正供解密），管理員誤觸放棄重包
- **THEN** 系統以 DB 確認該 pending 為現行 KEK（非 foreign）而拒絕放棄，不退役亦不刪除該供解密的列

#### Scenario: 多次切換退役史 from→to 正確
- **WHEN** 歷經 A→B→C 多次 KEK 切換後檢視 KEK 退役史
- **THEN** 每筆退役列自帶其 replacement 指紋（A 的為 B、B 的為 C），退役史正確呈現各段 from→to，不誤配為 A→C

#### Scenario: 無切換不留痕
- **WHEN** backend 以未變更的 `ENCRYPTION_KEY` 正常重啟（無待切換 pending、無退役 backlog）
- **THEN** 不執行退役、不輸出切換日誌、不寫入切換審計事件

### Requirement: env 側金鑰清冊顯示字串隨語言呈現
金鑰清冊「部署層金鑰（env）」區塊的名稱與說明 SHALL 隨當前介面語言呈現。後端 SHALL 為每個 env 鑰項附穩定機器碼（`name_code`/`note_code`）並保留 zh 顯示字串作為 wire fallback；前端 SHALL 以機器碼查譯（`keyEnvName.<code>`/`keyEnvNote.<code>`），當前語言命中才譯，否則降級後端 zh 字串。技術識別字（如 `ENCRYPTION_KEY`、`JWT_SECRET` 的名稱）SHALL NOT 翻譯，直接顯示。

#### Scenario: 非中文語言顯示對應譯文
- **WHEN** 介面語言為 en-US 或 ja-JP，檢視金鑰清冊 env 區塊
- **THEN** 各 env 鑰的說明與描述型名稱（如 Ed25519 匯出簽章鑰）以該語言呈現，非中文

#### Scenario: 缺譯降級後端 zh
- **WHEN** 某機器碼在當前語言無對應翻譯
- **THEN** 顯示後端提供的 zh 字串（wire fallback），不顯示空字串或裸機器碼

#### Scenario: 技術識別字不翻譯
- **WHEN** 檢視 `ENCRYPTION_KEY`/`JWT_SECRET` 的名稱欄
- **THEN** 各語言皆顯示原技術識別字，不譯

### Requirement: 新 KEK 明文暴露面收斂
Rewrap 回應中的新 KEK 明文 SHALL 不進入任何 HTTP 快取層；前端 SHALL 於明文不再需要顯示的當下自元件狀態清除（承諾範圍為元件狀態層，不承諾 JS 執行環境的記憶體抹除）。

#### Scenario: Rewrap 回應禁止快取
- **WHEN** 客戶端呼叫 KEK 重包端點且成功取得含新 KEK 明文的回應
- **THEN** 回應標頭 MUST 含 `Cache-Control: no-store` 與 `Pragma: no-cache`

#### Scenario: 關閉事件當下清除明文
- **WHEN** 重包結果對話框關閉事件觸發、成功放棄重包、或金鑰管理元件卸載
- **THEN** 前端持有新 KEK 明文的元件狀態 MUST 於該事件處理完成當下被置空——測試斷言 MUST 打在關閉事件完成後的元件狀態，不得以「重新開啟對話框看不到舊值」為通過依據（該行為由既有開窗重設既已滿足，屬零改動即綠的假驗證）

自 KEK provider 模組化起，明文流向反轉（新 KEK 改由管理員於請求中提供，伺服端不生成不回傳），本 requirement 隨之擴充（原文與其 Scenario 保留供追溯）：上段所述「回應中的新 KEK 明文」在反轉後**不再存在**，故第一個 Scenario 的 WHEN 前提自此不可達；其 THEN 所要求的 `Cache-Control: no-store` 與 `Pragma: no-cache` 標頭 SHALL 於重包端點**繼續存在**（保護對象自「回應洩漏」轉為「請求／回應對的快取與重放」）。反轉後 SHALL 另行滿足：請求中的 KEK 明文 SHALL NOT 出現於審計紀錄的請求內容欄位、SHALL NOT 寫入日誌、SHALL NOT 落庫；前端於明文不再需要顯示的當下自元件狀態清除之承諾（含承諾範圍限於元件狀態層）維持不變，並延伸涵蓋**輸入與二次輸入（paste-back）欄位**。

#### Scenario: 請求中的 KEK 明文不入審計紀錄
- **WHEN** 管理員提交含新 KEK 明文的重包請求
- **THEN** 該次操作的審計紀錄之請求內容欄位 MUST NOT 含 KEK 明文或其片段——斷言 MUST 打在實際捕獲欄位（`audit_logs.request_body`）的實值上，MUST NOT 僅斷言其他欄位

#### Scenario: 重包端點維持不可快取
- **WHEN** 客戶端呼叫 KEK 重包端點（反轉後回應已不含明文）
- **THEN** 回應標頭 MUST 仍含 `Cache-Control: no-store` 與 `Pragma: no-cache`

#### Scenario: 輸入與二次輸入欄位一併清除
- **WHEN** 重包對話框關閉事件觸發、重包成功、或金鑰管理元件卸載
- **THEN** 前端持有新 KEK 明文的輸入欄與 paste-back 欄之元件狀態 MUST 於該事件處理完成當下一併被置空

### Requirement: 換鑰操作跨實例互斥與收尾語義守衛
`data_keys` 的全部五個寫入路徑（KEK 重包、放棄重包、啟動退役收尾、data DEK 輪替、audit DEK 輪替）SHALL 以資料庫層 try 語義互斥鎖跨實例序列化，一切狀態判定 SHALL 於鎖內交易重讀；收尾 SHALL 以語義不變式守衛保證任何操作順序下 `data_keys` 不可能失去現行 KEK 的 live 代表列。

#### Scenario: 並發換鑰操作恰一成功
- **WHEN** 兩個並發請求同時進入重包（或放棄）流程，且雙方皆尚未建立 pending 狀態（測試以同步屏障保證同時性）
- **THEN** 恰一方成功，另一方 MUST 取鎖失敗回 409 且附機器可辨識錯誤碼——該 409 MUST 可與既有的「已有待切換 pending」409 區分

#### Scenario: 判定以鎖內重讀為準
- **WHEN** 任一寫入路徑取得互斥鎖
- **THEN** pending 存在性、backlog、campaign 歸屬等判定 MUST 以鎖內交易重讀的資料為準，行程內記憶體狀態 MUST NOT 作為跨實例安全判定的權威

#### Scenario: promote 列數守衛
- **WHEN** 啟動收尾的 promote 步驟實際影響列數與鎖內重讀所得的預期 clone 數不符（含 clones 已被放棄退役）
- **THEN** 整筆交易 MUST rollback，不進入退役步驟，既有金鑰列原封不動

#### Scenario: 退役不失代表列守衛
- **WHEN** 退役步驟將使任一 (purpose, version) slot 失去現行 KEK 的 live 代表列
- **THEN** 整筆交易 MUST rollback，該狀態記入 backlog 走 degraded 流程

#### Scenario: DEK 輪替納入跨實例判定
- **WHEN** 另一實例已建立 pending campaign（以 DB 鎖內現查為準），本實例執行 data 或 audit DEK 輪替
- **THEN** 輪替 MUST 被拒絕（409），不得依賴行程內 pending 旗標放行

#### Scenario: 無 advisory lock 環境的等價 try 語義
- **WHEN** 執行環境無 advisory lock 能力（sqlite 測試環境）
- **THEN** 系統 MUST 以行程層級共用的 try 互斥（非阻塞、取不到即回 409）提供同等語義，使單行程多 service 實例的互斥測試可驗證；白名單外的未知 dialect MUST 直接拒絕（不得靜默退化為行程內鎖）

#### Scenario: stale 實例輪替 fail-close
- **WHEN** 本實例 in-memory active 版本與 DB 鎖內重讀不符，或本實例 KEK 已無 live 代表列（另一實例已完成輪替或 KEK 切換）
- **THEN** DEK 輪替 MUST 被拒絕（409＋重啟指引），MUST NOT 鑄出以已退役 KEK 包裹的新版本或以過期基準續作

#### Scenario: bootstrap 空表競態 fail-close
- **WHEN** 空庫多實例同時啟動，bootstrap 鎖內重讀發現用途金鑰已由另一實例建立
- **THEN** 本實例 MUST fail-close 拒絕啟動（重啟後重新載入即收斂），MUST NOT 以不同 KEK 再鑄同版本金鑰（腦裂）

### Requirement: 退役收斂降級與持續告警
KEK 退役收尾失敗（retire backlog 存在）時系統 SHALL 進入 degraded 狀態：服務與連線功能完全不受影響；清冊標示與後端 log 為無條件訊號；告警政策啟用且通道可用時持續對外告警至收斂；重啟不得將未收斂的 backlog 假記為恢復。

#### Scenario: 偵測時點不誤報
- **WHEN** 正常換鑰流程進行中（pending clones 存在、收尾尚未執行）
- **THEN** 系統 MUST NOT 判定 degraded；degraded 判定僅發生於開機收尾流程完成後與週期評估時

#### Scenario: backlog 出現即上報
- **WHEN** 啟動收尾失敗或啟動時偵測到既存 retire backlog，且告警初始化已完成
- **THEN** 系統 MUST 經機制失效事件族上報並於通知通道可用時投遞；上報 MUST 發生於告警與通知服務就緒之後（啟動時序不得使事件靜默丟失）

#### Scenario: 無通道時的無條件訊號
- **WHEN** 告警政策關閉或無可用通知通道
- **THEN** 金鑰清冊 degraded 標示與後端 log MUST 仍然記錄——外送依組態，本地訊號無條件

#### Scenario: backlog 長存週期重發
- **WHEN** retire backlog 跨週期評估持續存在
- **THEN** 系統 MUST 由獨立週期評估重發提醒（不受機制失效事件「進行中即去重」語義抑制）

#### Scenario: 重啟不假恢復
- **WHEN** 系統重啟且 retire backlog 仍存在
- **THEN** 該機制的未結束事件 MUST NOT 被啟動回填無條件標記為已恢復；恢復 MUST 以謂詞重評估為準

#### Scenario: 收斂後恢復配對
- **WHEN** retire backlog 歸零
- **THEN** 系統 MUST 發出恢復通知與先前告警配對，且不再重發

#### Scenario: degraded 不降服務
- **WHEN** retire backlog 存在期間
- **THEN** 連線建立、審計寫入、既有密文之加解密 MUST 完全正常（測試 MUST 含 Encrypt/Decrypt 與清冊查詢的具體斷言）；新重包維持既有 409 拒絕

### Requirement: 退役資料軟刪除與顯式清理
金鑰列的材料銷毀 SHALL 僅發生於使用者顯式清理操作：放棄重包 SHALL 軟退役（不硬刪除）、退役 SHALL 保留包裹材料；清理後指紋與退役軌跡 SHALL 永久保留。

**保護類別（宣告式，可擴充）**：每個金鑰用途 SHALL 於程式中登記一個銷毀保護類別，宣告「該材料被什麼引用、銷毀的後果是什麼」；清理路徑 SHALL 僅經單一前置入口取用該類別判定，不得於他處各自推導。類別 SHALL 支援未來新增的保護型態（含「不論引用數一律不可銷毀」的宣告）。

**稽核軌跡保護（不可清理）**：仍被審計紀錄引用的蓋章鑰版本 SHALL 永不可清理，不論管理員如何操作。審計紀錄的完整性驗章依賴當時的 `audit_integrity` DEK 版本——銷毀該材料等同令歷史審計紀錄永久無法驗章，稽核軌跡即失去證明力。此為稽核需求（PCI DSS 10.3 稽核紀錄防竄改／10.5 保留期內可讀），不是實作上的保守取捨，任何未來的「強制清理」「清理全部」選項均 SHALL NOT 得繞過本限制。

**未登記用途的保底行為**：遇到未登記保護類別的用途，系統 SHALL 保守保留該列並逐項回報，且 SHALL NOT 中止整個清理操作——把「一列未知」升級為「清理功能整組不可用」會使釋出後的管理員撞牆且無自救手段（只能等新版程式），而少清一列本身零風險。回報 SHALL 說明這是程式層面的定義缺漏、需更新版本才能處理，不得讓管理員誤以為是自己的操作問題。登記完備性由開發期守衛測試把關，使該保底不被常態依賴。

#### Scenario: 放棄重包軟退役
- **WHEN** 使用者放棄尚未切換的 KEK 重包
- **THEN** foreign pending clones MUST 被標記退役（reason=abandoned）而非刪除，`WrappedKey` 材料保留至顯式清理；重試重包 MUST NOT 因軟退役舊列佔用唯一索引而失敗（partial index 排除退役列；指紋碰撞守衛另行保守拒絕重複指紋）

#### Scenario: 退役保留材料
- **WHEN** 啟動收尾退役舊 KEK 列
- **THEN** 僅變更狀態欄位（reason=switched），`WrappedKey` MUST NOT 被清空——最後手段回退（依 runbook 手動復原退役列）在清理前於資料層始終可行

#### Scenario: 退役 KEK 開機得定向回退指引
- **WHEN** 以已退役且材料尚未清理的 KEK 作為 env 開機
- **THEN** 系統 MUST 維持 fail-close 拒絕啟動，且錯誤訊息 MUST 指明「此 KEK 已退役、材料尚存、確要回退依 runbook 手動復原／誤設請改回現行 KEK」，不得只回籠統 mismatch；材料已清理者回歸籠統 mismatch

#### Scenario: 顯式清理為唯一銷毀點
- **WHEN** admin 於金鑰清冊執行「清理退役資料」並確認
- **THEN** 退役列的 `WrappedKey` MUST 被清空且產生審計記錄（含清理列數與各 kek_id／版本指紋）；列本身、指紋、退役軌跡（from→to、時間戳）MUST 永久保留

#### Scenario: 清理前置全收斂閘
- **WHEN** 存在 pending campaign 或 retire backlog 時嘗試清理
- **THEN** 清理 MUST 被拒絕（409），UI 按鈕 MUST 依清冊狀態禁用

#### Scenario: 退役 DEK 版本引用掃描閘
- **WHEN** 清理範圍含退役 DEK 版本（`Status=retired`）
- **THEN** 系統 MUST 先掃描全部信封加密欄位確認無該版本存量密文引用；仍有引用的版本 MUST 拒清並逐項回報「版本與引用筆數」，僅零引用版本可清

#### Scenario: 引用掃描遇不可歸屬殘值保守拒清
- **WHEN** 引用掃描期間發現無法歸屬任何版本之非終態格式值（哨兵所定義之不可能態殘值）
- **THEN** 該次清理 MUST 保守拒絕並逐項回報殘值位置，MUST NOT 將其計為零引用而放行銷毀——與啟動哨兵共用同一判定口徑

#### Scenario: 稽核蓋章鑰不可清理（稽核需求）
- **WHEN** 清理範圍含 `audit_integrity` 用途的退役版本，且仍有審計紀錄以該版本蓋章（`audit_logs.key_version` 命中）
- **THEN** 該版本 MUST 拒清並以 `reason=audit_referenced` 回報引用筆數；系統 MUST NOT 提供任何繞過此閘的介面或參數。理由 SHALL 於使用者可見處說明為「保留歷史審計紀錄的驗章能力」，而非泛稱「仍被引用」

#### Scenario: 未登記用途保守跳過但不阻斷
- **WHEN** 清理範圍含未登記保護類別的用途
- **THEN** 該列 MUST 被保守保留（材料不得銷毀）並以 `reason=unregistered_purpose`／`protection_class=unregistered` 逐項回報，其餘可清列 MUST 照常清理；整個清理操作 MUST NOT 因此失敗

#### Scenario: 清理前置逐 slot 自證
- **WHEN** 清理範圍含 KEK 退役列（材料尚存的舊 KEK 包裹副本）
- **THEN** 系統 MUST 於同一交易內逐 slot 確認「存在現行 KEK 的 live 材料列」，缺失即整筆中止不銷毀——退役副本為該版本唯一材料時銷毀＝永久不可解

#### Scenario: 清理透明度（事前清單與事後標示）
- **WHEN** admin 開啟清理確認對話框，或清理完成後檢視清冊
- **THEN** 確認文案 MUST 列明銷毀候選（退役且材料尚存的 DEK 版本、退役 KEK 包裹列數）與「先重啟所有後端實例」提醒；清冊 MUST 以衍生欄位（`material_purged`／`material_rows`）標示已清理態，且該衍生 MUST NOT 取用 `wrapped_key` 本值入服務記憶體

#### Scenario: 收斂狀態不可讀時不得假健康
- **WHEN** 清冊端點讀取 finalize_pending 或 retire_backlog 失敗
- **THEN** 回應 MUST 標示 `converge_state_error`，UI MUST 呈現未知態警示並保守禁用清理按鈕，MUST NOT 以 0 呈現為健康

### Requirement: 金鑰管理錯誤訊息的機器碼化
金鑰管理端點回傳給使用者的錯誤 SHALL 一律以機器碼表達並由前端查譯，SHALL NOT 直接回傳後端 Go error 的中文訊息（全域 i18n 規範）。

#### Scenario: 使用者可見的 409 全走機器碼
- **WHEN** 金鑰管理端點因前置狀態衝突回 409（鎖忙、未收斂、狀態過期、重包待切換、已有 pending、退役 backlog、無待切換重包）
- **THEN** 回應 MUST 帶機器碼並於三語 `apiError` 段有譯文（`ZhFallback` 與 zh-TW 譯文逐字一致）；MUST NOT 以裸訊息回傳。守衛：AST 掃該 handler，任一 `StatusConflict` 走裸訊息即測試失敗

### Requirement: 強 KEK 生成指引
部署範本 SHALL 提供 CSPRNG 生成 KEK 的具體指令，降低弱 KEK 風險。指令 SHALL 為**有序集合**而非單一指令，且 SHALL 涵蓋每一種被接受的輸入形態各至少一條；集合中的每一條 SHALL 經守衛實跑驗證其產出必然通過伺服端驗證（SHALL NOT 為「通常會通過」的機率性指令）。範本 SHALL NOT 保留任何已不成立的形態警告。

#### Scenario: .env.example 含生成指令
- **WHEN** 檢視 `.env.example` 的 `ENCRYPTION_KEY` 段
- **THEN** MUST 含全行註解形式的 CSPRNG 生成指令集合（涵蓋原字元、十六進位、base64 三形態），且不觸發行內註解守衛

#### Scenario: 指令產出必然合格
- **WHEN** 反覆執行範本所列的任一條生成指令
- **THEN** 其產出 MUST 每次皆通過伺服端材料驗證

### Requirement: KEK 來源模式與顯式判定
系統 SHALL 以顯式環境變數 `KEK_PROVIDER` 宣告 KEK 來源模式，其值 SHALL 為白名單之一：`env`（本地 env 材料）、`ui`（管理員經介面注入、僅存記憶體）、`kms`（雲端金鑰服務委託）、`hsm`（硬體安全模組委託）；未設定時 SHALL 預設為 `env`（向後相容路徑；**部署範本之出貨預設值為 `ui`**，見 deployment-configuration 的「KEK 出貨預設模式」）。系統 SHALL NOT 以任何組態的存在或留空隱式推斷模式——本地 KEK 鑰留空 SHALL NOT 被解讀為「意圖使用 `ui`」，而 SHALL 視為缺少必要組態並 fail-close。

**交付狀態的誠實界定（SHALL 明載）**：白名單列出四值，但**可實際運作的模式為 `env`、`ui`、`kms` 三者**。`hsm` 目前僅交付**介面與組態層**——`KEKProvider` 介面的委託形狀、組態鍵的逐鍵齊備檢查、PIN 與 PIN 檔恰一有值之判定、以及非 HSM 建置變體下的拒絕——**其 provider 實作未交付**，故以 `KEK_PROVIDER=hsm` 啟動 SHALL 拒絕啟動並輸出「尚未交付」之可辨識錯誤，SHALL NOT 回落至其他 provider、SHALL NOT 靜默降級。系統與其文件 SHALL NOT 宣稱具備硬體安全模組保護能力。此界定的原因是外部條件未定（廠商與其 PKCS#11 行為、金鑰生命週期規則尚未確認），非實作遺漏；完整交付的時機與範圍待前述外部條件確認後另行規劃。

**值正規化**：`KEK_PROVIDER` SHALL 於比對前 trim 前後空白；trim 後為空字串者 SHALL 等同未設；比對 SHALL 大小寫敏感（`ENV` 等大小寫不符之值 SHALL 判為白名單外並拒絕啟動，SHALL NOT 做大小寫寬容）。

組態矛盾 SHALL 一律 fail-close 拒絕啟動並輸出可辨識的明確錯誤：宣告 `ui`／`kms`／`hsm` 而本地 KEK 材料鍵仍有值（防假 in-memory）、宣告 `env` 而無本地材料、`KEK_PROVIDER` 為白名單外之值、委託模式之必要組態不齊（錯誤 SHALL **逐鍵**列出缺少或衝突之組態鍵，SHALL NOT 以單一布林「齊／不齊」籠統回報）、宣告 `hsm` 而執行檔未含 HSM 能力。「本地材料鍵有值」之判定 SHALL 直接取**唯一**材料鍵 `ENCRYPTION_KEY` 之值並判定其 trim 後是否非空——系統 SHALL NOT 具備第二把 KEK 材料鍵、SHALL NOT 具備任何鍵名回落或別名，故亦不存在「以空字串遮蔽另一把鑰」之情境（設為空字串與未設在此判定上等價，皆為「無本地材料」）。出廠預設值 SHALL 視為有值（不得成為隱式豁免）；全為空白字元之值 SHALL 視為無值（防以空白字串充當合法長度材料）。

**判定分兩段**：純組態判定（正規化、白名單、矛盾格、材料格式、委託組態齊備、建置能力）SHALL 於連接資料庫之前完成，此段任一 fail-close 路徑 SHALL NOT 產生任何資料庫寫入；資料庫相關之閘（金鑰表一致性）必然發生於 schema 遷移與初始資料建立之後，該段 SHALL 保證**金鑰表**未被寫入，SHALL NOT 宣稱資料庫整體未被寫入。

**`env` 模式的材料格式驗證**：`env` 模式啟動時 SHALL 對本地 KEK 材料施以與新 KEK 相同的伺服端格式驗證（輸入編碼之解碼、字元集、非出廠預設值）；不合格 SHALL 拒絕啟動，SHALL NOT 僅以部署範本註解作為唯一防線。此驗證之編碼與字元集適用範圍依「KEK 材料的輸入編碼」要求：三種形態皆可，字元集政策僅適用於原字元形態。**未宣告 `KEK_PROVIDER` 之相容路徑維持不施加格式政策**，僅套用輸入編碼之解碼——既有部署升級後行為完全不變。

#### Scenario: 未設 KEK_PROVIDER 且有本地鑰
- **WHEN** 部署僅設 `ENCRYPTION_KEY` 而未設 `KEK_PROVIDER`
- **THEN** 系統以 `env` 模式啟動，無須額外組態

#### Scenario: 未設 KEK_PROVIDER 且無本地鑰
- **WHEN** 未設 `KEK_PROVIDER`，且本地 KEK 材料鍵不存在或為空
- **THEN** 系統 MUST 拒絕啟動（缺少 KEK 材料），MUST NOT 推斷為 `ui` 模式

#### Scenario: ui 模式下本地鑰有值即拒絕
- **WHEN** `KEK_PROVIDER=ui` 且本地 KEK 材料鍵仍有值（含出廠預設值）
- **THEN** 系統 MUST 拒絕啟動並指出組態矛盾（宣告不落地卻於環境留存材料）

#### Scenario: 委託模式組態不齊逐項列缺
- **WHEN** `KEK_PROVIDER=kms` 但金鑰識別或區域等必要鍵缺少
- **THEN** 系統 MUST 拒絕啟動，錯誤 MUST 逐項列出缺少的組態鍵，而非籠統報錯

#### Scenario: 白名單外的值不猜
- **WHEN** `KEK_PROVIDER` 設為白名單外的值（含大小寫不符，如 `ENV`）
- **THEN** 系統 MUST 拒絕啟動，MUST NOT 回落為預設模式

#### Scenario: KEK 材料鍵唯一，別名不被消費
- **WHEN** 環境中設有 `ENCRYPTION_KEY` 以外、名稱近似 KEK 材料的任何鍵（含已廢止之舊鍵名）
- **THEN** 該鍵 MUST 完全不參與 KEK 材料判定——僅設該鍵而未設 `ENCRYPTION_KEY` MUST 判為「無本地材料」；`ui`／委託模式下該鍵有值 MUST NOT 被判為「本地材料仍有值」

#### Scenario: 空字串與純空白等同未設
- **WHEN** `KEK_PROVIDER` 設為空字串或僅含空白字元
- **THEN** 判定 MUST 等同未設（走向後相容路徑），MUST NOT 因「已設定但不在白名單」而拒絕，亦 MUST NOT 使白名單檢查被靜默繞過

#### Scenario: 全空白材料不得視為合法 KEK
- **WHEN** 本地 KEK 材料鍵設為恰好符合長度下限的全空白字元
- **THEN** 系統 MUST 判為無效材料並拒絕啟動，MUST NOT 因位元組長度符合而放行

#### Scenario: 委託組態缺項逐鍵回報且不猜優先序
- **WHEN** `KEK_PROVIDER=hsm` 且 PIN 與 PIN 檔兩個組態鍵同時有值（或同時無值）
- **THEN** 系統 MUST 拒絕啟動並逐鍵指出衝突或缺項，MUST NOT 以任一方為優先而靜默採用

#### Scenario: env 模式接受十六進位與 base64 材料
- **WHEN** `KEK_PROVIDER=env` 且 `ENCRYPTION_KEY` 為 64 個十六進位字元或解碼後恰 32 位元組的 base64
- **THEN** 系統 MUST 正常啟動，其 KEK 為解碼後的 32 位元組

### Requirement: KEK 材料鍵三職拆解
`ENCRYPTION_KEY` 原同時承擔三項職責——KEK 材料、legacy 無前綴密文之解密鑰、服務建構期之預設 Codec 參數。後兩職已隨過渡機制拆除而消滅：系統 SHALL NOT 具備 legacy 解密鑰概念——`LEGACY_ENCRYPTION_KEY` SHALL NOT 被讀取（與 `AUDIT_INTEGRITY_KEY` 同處置：完全不消費，部署範本與文件一併移除；殘留於環境中的該鍵為無效死值，SHALL NOT 影響啟動判定）；服務建構期 SHALL NOT 讀取任何環境金鑰材料——需要加解密的服務 SHALL 於建構時注入 `Codec` 實作，SHALL NOT 以環境材料建立會被事後覆寫的預設 Codec。KEK 材料由**單一鍵** `ENCRYPTION_KEY` 承載：系統 SHALL NOT 具備第二把材料鍵、別名或任何鍵名回落窗（該雙鍵窗已隨名稱收斂整組移除；產品未發佈、無存量站點，不需相容窗）。

**讀取語義（三值，不可退化為兩值）**：全部金鑰類環境變數 SHALL 以「未設／設為空字串／設為有效值」三種互相區分的語義讀取，SHALL NOT 對其套用任何預設值注入——否則委託／`ui` 模式下「本地鑰有值」恆為真而永不可啟動，且公開已知的出廠預設材料會被靜默注入為 KEK。

**出廠預設值注入之廢除**：KEK 材料鍵 SHALL NOT 具備出廠預設值；未設定時系統 SHALL fail-close 拒絕啟動，SHALL NOT 以公開已知的預設材料靜默啟動（與認證信任根之既有處置一致）。

**預設密鑰守衛之模式感知**：檢查「是否仍使用出廠預設密鑰」的啟動守衛 SHALL 依 KEK 來源模式判定——`env` 模式下「KEK 材料等於出廠預設值」SHALL 仍判為違規（合規紅線不放寬）；非 `env` 模式下「本地 KEK 材料鍵未設」SHALL 判為**合法組態**、SHALL NOT 列為違規。此守衛 SHALL NOT 以整體放寬取代模式感知。

#### Scenario: KEK 材料取自 ENCRYPTION_KEY
- **WHEN** 部署設 `ENCRYPTION_KEY` 為合格材料
- **THEN** KEK 材料取自該值正常啟動；系統 MUST NOT 將該值用於任何 legacy 解密路徑（該路徑不存在）

#### Scenario: 廢止鍵不被消費
- **WHEN** 環境中 `LEGACY_ENCRYPTION_KEY` 或 `AUDIT_INTEGRITY_KEY` 仍設有值（不論模式）
- **THEN** 系統 MUST 完全忽略其值正常啟動——不讀取、不參與任何判定、不出現於任何解密或蓋章路徑

#### Scenario: 顯式清空即無材料
- **WHEN** `ENCRYPTION_KEY` 顯式設為空字串或全空白
- **THEN** 系統 MUST 判為「無本地材料」——`env` 模式（含未宣告之向後相容路徑）MUST 拒絕啟動，MUST NOT 以任何預設值注入補位；`ui`／委託模式 MUST 判為合法組態

#### Scenario: 非 env 模式未設 KEK 鑰不算違規
- **WHEN** 以 `ui`／`kms`／`hsm` 模式於生產設定啟動，本地 KEK 材料鍵未設
- **THEN** 預設密鑰守衛 MUST 判為合法並允許啟動，MUST NOT 因「未設或非預期值」而阻擋

#### Scenario: env 模式仍擋出廠預設值
- **WHEN** 以 `env` 模式於生產設定啟動且 KEK 材料為出廠預設值
- **THEN** 系統 MUST 拒絕啟動（合規紅線維持）

#### Scenario: 服務建構不依賴環境金鑰
- **WHEN** 以無本地 KEK 材料的模式啟動
- **THEN** 所有需要加解密的服務 MUST 能完成建構（其 Codec 由注入取得），MUST NOT 因缺少環境金鑰材料而建構失敗

### Requirement: KEKProvider 介面與金鑰引用抽象
`KEKProvider` 介面 SHALL 以金鑰引用（KeyRef：provider 名稱＋金鑰識別）表達 KEK，使外部生成、本地僅持引用的模式成為一等公民；介面方法 SHALL 帶 `context`，並 SHALL 提供重加密（ReEncrypt）能力以支援委託服務的原生重包原語（預設實作為解包後重新包裹）。金鑰識別的語義 SHALL 依模式分岔：本地模式為材料指紋（可由材料重算），委託模式為外部金鑰引用（不可由材料重算）。

金鑰表的 KEK 識別欄位 SHALL 具足以容納外部金鑰引用的長度。包裹後材料 SHALL 自描述其格式；**格式標示與金鑰引用之 provider 名稱 SHALL 屬不同名字空間**——本地模式（`env`／`ui`）SHALL 共用單一「本地」格式標示，SHALL NOT 依材料來源再作區分（否則同一材料在兩模式下寫出的列格式不同，同鑰互換即不再等價）。wrapped_key 前綴 SHALL 恆為強制語義：寫入端 SHALL 一律寫出帶前綴形式、讀取端 SHALL 拒絕無前綴值並於**解包前**回可辨識格式錯，SHALL NOT 落入籠統的驗證失敗路徑；系統 SHALL NOT 具備任何接受無前綴 wrapped 值的相容窗，亦 SHALL NOT 存在控制該行為的持久化標記或階段狀態。

**包裹層 AAD 之判別子**：格式的版本段 SHALL 承載「該包裹值是否帶 AAD」之判別子（`1`＝無 AAD、`2`＝帶 AAD）。寫入端（本地與委託皆同）SHALL 一律產出帶 AAD 形式（判別子 `2`），且系統 SHALL NOT 具備任何產出判別子 `1` 之寫出或就地改寫能力（含前綴遷移之字串包裝工具）；**全部 provider（本地與委託）之包裹與解包路徑 SHALL 於建構上拒絕空 AAD**——原「本地 provider 接受 nil AAD＝不綁定」之 per-provider 差異為相容窗時代產物，隨相容窗一同廢止。讀取端 SHALL 拒收判別子 `1` 並於解包前回可辨識格式錯——判別子 `1` 之合法產出路徑已不存在，接受它等同永久接受任何無 AAD 之舊包裹材料（含備份）被貼入金鑰槽。

**金鑰引用不含執行期組態模式**：金鑰引用之 provider 維度 SHALL 僅表達「該引用以何種途徑解讀」（本地／雲端金鑰服務／硬體模組三類），**本地之兩種執行期模式（環境變數填鑰與介面填鑰）SHALL 同映射為「本地」**。金鑰引用之相等性 SHALL 僅由該維度與金鑰識別決定，**SHALL NOT 含執行期組態模式**——否則「同一材料於兩種本地模式下金鑰引用相同」在結構上不可能成立，同鑰互換免遷移即失去依據。執行期組態模式 SHALL 由 provider 物件之獨立存取器提供（供清冊呈現與稽核對照），SHALL NOT 進入金鑰引用、SHALL NOT 落入金鑰表之 KEK 識別欄。

**外部金鑰引用之正規化**：委託模式下同一把金鑰可能有多種等價表示形式；系統 SHALL 於啟動時將組態所給之引用解析為**單一正規形式**後才作為金鑰表之 KEK 識別值，使等價的組態寫法變更 SHALL NOT 導致代表列篩選落空而拒絕啟動。解析失敗 SHALL fail-close，SHALL NOT 以原值猜測。既有非正規形式之列 SHALL 由一次性識別欄改寫遷移收斂（純識別欄改寫，SHALL NOT 需要重包，材料與資料密文不動）。

#### Scenario: 無前綴 wrapped 值拒收
- **WHEN** 金鑰載入時遇到無前綴的 wrapped_key 值（不論其來源，含拆除前建立之資料庫）
- **THEN** 系統 MUST 於解包前回可辨識格式錯並 fail-close 拒絕啟動，錯誤訊息 MUST 指明「資料庫含發佈前過渡格式，請重建」，MUST NOT 嘗試以任何相容語義解包

#### Scenario: 判別子 1 拒收
- **WHEN** 金鑰載入時遇到判別子為 `1`（無 AAD 包裹）的 wrapped_key 值
- **THEN** 系統 MUST 於解包前回可辨識格式錯並 fail-close，MUST NOT 以空 AAD 或無 AAD 語義解包

#### Scenario: 外部金鑰引用可完整存放
- **WHEN** 以委託型 provider 重包，金鑰識別為雲端金鑰 ARN 或裝置金鑰標籤
- **THEN** 該識別完整存入金鑰表且唯一索引仍生效，未被截斷

#### Scenario: 金鑰引用不因執行期模式而不同
- **WHEN** 以相同 KEK 材料分別於環境變數填鑰與介面填鑰兩種模式下取得金鑰引用
- **THEN** 兩者 MUST 完全相同（provider 維度皆為「本地」）；執行期模式之差異 MUST 僅出現在清冊呈現，MUST NOT 出現在金鑰引用或金鑰表之 KEK 識別欄

#### Scenario: 本地與介面模式產出可互解
- **WHEN** 以相同 KEK 材料分別經 `env` 與 `ui` 模式包裹同一金鑰
- **THEN** 兩者的金鑰引用相同、格式標示相同，且**各自產出之包裹值可由對方解包**——此為同鑰互換免遷移之基礎。驗收 MUST NOT 要求兩者輸出位元相同（帶隨機初始向量之認證加密使該條件物理上不可滿足，寫成驗收條件只會逼出被刪改的假綠測試）

#### Scenario: 等價的委託金鑰引用寫法不影響開機
- **WHEN** 委託模式下將組態中的金鑰引用自一種等價形式改為另一種（無語義變更）
- **THEN** 系統 MUST 正常啟動（引用經正規化後比對），MUST NOT 因字面不符而判為無代表列

### Requirement: 信封密文的 AAD 列綁定
信封加密 SHALL 導入額外驗證資料（AAD）綁定：DEK 之包裹 SHALL 綁定其用途與版本；資料密文 SHALL 綁定其邏輯位置（登記之表名與欄名）——**SHALL NOT 綁定自增主鍵**（見下方「綁定維度之取捨」）。**AAD SHALL 僅由不可變維度組成，SHALL NOT 含任何可因組態變更或識別正規化而改變之值**（KEK 引用即屬此類，SHALL NOT 納入——包裹材料本已只能由當初包裹它的金鑰解開，將該金鑰的識別再寫入 AAD 為冗餘，卻會使識別正規化改寫必然破壞解包）。密文格式 SHALL 自描述其 AAD 方案。

**AAD 綁定恆為強制**：寫入端 SHALL 在**建構上不具備寫出無 AAD 密文之能力**（無 AAD 之寫入方法不存在於介面，SHALL NOT 以執行期政策判斷決定寫出何種格式）；讀取端 SHALL 無條件要求 AAD 綁定——非帶 AAD 方案之密文值 SHALL fail-close 回可辨識格式錯。系統 SHALL NOT 具備寬鬆（permissive）讀取模式、SHALL NOT 存在控制嚴格與否的持久化標記、行程內旗標或任何切換入口，亦 SHALL NOT 提供任何正向或反向的存量遷移操作面。

**啟動哨兵（提示層，非把關）**：啟動時系統 SHALL 以廉價計數（SQL 前綴下界）掃描全部登記欄位；發現任何非帶 AAD 方案之值 SHALL 記警告日誌並沿既有失效事件告警族開列——該告警之 cause SHALL 為單一「不可能態」值（表示程式缺陷或繞過 API 之資料庫直寫），SHALL NOT 沿用任何描述遷移進度或模式狀態之舊 cause 值，SHALL NOT 附任何遷移指引、SHALL NOT 阻塞啟動、SHALL NOT 構成自動改寫路徑。計數失敗 SHALL 記「狀態未知」，SHALL NOT 以零頂替。（金鑰層之過渡格式——無前綴或判別子 `1` 之 wrapped_key、v0 金鑰列——不歸哨兵，SHALL 依各自條款於載入時 fail-close。）

**完備性依賴（SHALL 明載）**：以用途與版本作為 DEK 包裹之判別維度，其完備性依賴既有的兩項不變式——金鑰表「用途、版本、KEK 識別」三欄唯一索引，以及重包時拒絕任何曾出現過之 KEK 識別的守衛；二者共同保證同一把 KEK 下每個用途版本至多一列帶材料。放寬其中任一項 SHALL 視為同時削弱 AAD 之綁定強度，SHALL 有守衛測試使該依賴不致靜默失效。

**綁定維度之取捨（SHALL 明載）**：AAD SHALL 由 canonical 編碼之 `ct|表名|欄名` 組成（用途與版本由 DEK 包裹層承載、方案版本由密文前綴承載），編碼 SHALL 以長度前綴或逸出避免維度間串接碰撞，SHALL NOT 裸串接。**SHALL NOT 納入自增主鍵**：綁定主鍵所防之「同表同欄跨列搬移」以資料庫寫入權為前提，而該權限已列於信任邊界之外，且持該權限者另有等價手段（改寫同列之非加密欄、刪列後以同主鍵重建）；反之綁定主鍵會迫使所有建立路徑改為「先插入取得主鍵、再回寫密文」之兩階段寫入，並使密文無法於還原至不同主鍵環境時解開、於主鍵可重用之資料庫（如 sqlite）打折、破壞既有「密文原樣複製」之跨 change 契約。此取捨與「KEK 引用不納入 AAD」同源——不為已聲明在信任邊界外之威脅付出結構代價。

系統 SHALL NOT 宣稱 AAD 提供超出「跨表、跨欄搬移密文失效」之保護：**同表同欄之跨列搬移 SHALL 明載為可解密**（屬信任邊界內，且非惡意之列錯位為 fail-visible——搬錯之密碼登入即敗、TOTP 驗證即敗、簽章鑰驗章即敗），刪除整列、以綁定一致之另一份密文替換亦不在防護範圍。資料庫完整性仍屬信任邊界。表名或欄名變更 SHALL 由同版遷移重寫對應密文（新欄位之資料自建立起即以其自身欄位身分綁定，SHALL NOT 產生任何需事後補綁的狀態）。

#### Scenario: 跨表或跨欄搬移密文失效
- **WHEN** 具資料庫寫入權者將某表某欄的帶 AAD 密文複製至另一表或另一欄
- **THEN** 該處解密 MUST 失敗，MUST NOT 回傳明文

#### Scenario: 同表同欄跨列搬移為明載之信任邊界
- **WHEN** 具資料庫寫入權者將同表同欄某列的帶 AAD 密文複製至另一列
- **THEN** 該列解密 MUST 成功（AAD 不綁主鍵），此為明載之信任邊界而非缺陷；系統 MUST NOT 於文件或介面宣稱可防禦此情形

#### Scenario: 無 AAD 密文 fail-close
- **WHEN** 讀取一筆非帶 AAD 方案的信封密文值（不論其來源）
- **THEN** 解密 MUST 失敗並回可辨識格式錯，MUST NOT 以任何寬鬆語義解密

#### Scenario: 哨兵偵測不可能態
- **WHEN** 啟動時掃描發現某登記欄位存在非帶 AAD 方案之值
- **THEN** 系統 MUST 記警告並開列失效事件告警，MUST 正常完成啟動，MUST NOT 自動改寫該值、MUST NOT 提供遷移入口

#### Scenario: 新增登記欄位不產生狀態事件
- **WHEN** 後續版本新增一個信封加密欄位並入冊
- **THEN** 該欄位之資料自建立起即以其自身欄位身分綁定 AAD，系統 MUST NOT 因此要求任何遷移、標記更新或模式操作

### Requirement: 介面填鑰模式之封印狀態機
`ui` 模式下系統 SHALL 以封印狀態機管理可用性，狀態集合 SHALL 為四態：**封印**（未持有材料）、**解封中**（已取得解封獨佔；材料驗證與初始化皆在其臨界區內進行）、**已解封**（初始化完成且服務已發佈）、**封印且故障**（材料正確但後續初始化失敗）。啟動時 SHALL 進入封印狀態且 SHALL NOT 讀取金鑰材料。封印狀態 SHALL NOT 被持久化——行程重啟 SHALL 重新封印。`env` 與委託模式於啟動完成後 SHALL 恆為已解封，使狀態查詢在各模式下形狀一致。

**兩段啟動**：`ui` 模式的啟動 SHALL 分為兩段——第一段建立封印閘、健康檢查、封印狀態查詢與解封端點、封印期留痕寫入器並開放監聽；第二段（金鑰管理器載入、依賴金鑰之服務建構、完整路由樹）SHALL 延後至解封成功後執行。第二段之失敗 SHALL NOT 終止行程，SHALL 回傳可辨識機器碼並使狀態轉為「封印且故障」，且 SHALL 允許再次解封重試；非 `ui` 模式維持啟動期致命錯之既有語義。第一段 SHALL NOT 建構任何第二段服務——封印期對非白名單路由之 503 SHALL 由「服務不存在」而非「服務已存在但被攔阻」達成。

**服務圖之組裝 SHALL 完成於發佈之前**：對外可服務所需的**全部**構件（含路由樹本身）SHALL 於狀態發佈之前組裝完畢，發佈後之步驟 SHALL 僅為單次原子換手。若組裝之任一部分留待發佈之後執行，其失敗將使系統停留於「狀態已解封、但對外仍全面拒絕服務」且**無出邊可重試**的死狀態——已解封狀態依設計僅由行程結束離開，故該失敗不可自癒。發佈後之換手 SHALL NOT 具備失敗分支。

**解封的原子性與單一飛行**：進入「解封中」SHALL 以比較並設定（CAS）方式獨佔，其**來源態集合 SHALL 包含「封印」與「封印且故障」兩者**——自「封印且故障」重試 SHALL 同樣經由「解封中」，SHALL NOT 直達已解封（否則故障後之並發重試可繞過獨佔）。**取得獨佔 SHALL 發生於任何材料驗證開始之前**：獨佔的臨界區 SHALL 涵蓋材料格式檢查、材料驗證（解包現行代表列，或初始化路徑之憑證驗證）、初始金鑰建立、第二段初始化與發佈之**全程**；未取得獨佔的請求 SHALL 在**任何驗證開始前**即被拒（衝突），SHALL NOT 有第二份驗證同時執行。「材料是否正確」SHALL 為「解封中」之內的一個步驟，SHALL NOT 為進入「解封中」的前置條件。已解封狀態下收到的解封請求 SHALL 被拒且 SHALL NOT 重跑初始化。

**世代與發佈的原子性**：狀態、世代序號與服務圖 SHALL 由**單一可原子更新的載體**承載，第二段之每一次終局寫入 SHALL 以「進入時的世代序號」為期望值一次性完成比對與更新——SHALL NOT 採「先比對世代、後寫入」之兩步形式（其間仍可被逾時切換而產生撕裂）。世代序號 SHALL 於**每次取得解封獨佔時遞增**（兩個來源態皆然）。柵欄 SHALL 涵蓋第二段的**全部終局副作用**——發佈、轉入「封印且故障」、失敗計數與冷卻更新——SHALL NOT 僅涵蓋發佈；否則逾時後之舊執行流仍可將一個已健康的服務標記為故障而使其全面拒絕服務。封印閘之判定與請求之服務取用 SHALL 讀取同一次載入結果——任何時點 SHALL NOT 存在「閘已放行但服務尚未就緒」之可觀察窗口。

**逾時後之收束（SHALL 具可觀察節點）**：逾時 SHALL 取消進行中之第二段；被取消者 SHALL NOT 於取消後啟動排程器、開始外送通知或建立新的外部連線，且 SHALL 釋放其已建構之資源。狀態載體 SHALL 具「有前代持有者待收束」之欄位，該欄位 SHALL 於第二段失敗或逾時之同一次原子更新中設定、於收束完成後以原子更新清除；**「無待收束之前代」SHALL 為取得解封獨佔的前置條件之一**——使「不得使兩份半初始化的服務圖同時持有資源」成為狀態轉移的結構性前置，而非僅為敘述性要求。因該前置為「等不到即拒絕、絕不放行」，同時至多存在一個待收束之前代。封印狀態查詢 SHALL 暴露該欄位；因此被拒之解封請求 SHALL 收到可與「解封進行中」「已解封」區分之專屬機器碼。逾時 SHALL NOT 計入材料失敗計數（材料為正確者），SHALL 另計並於達門檻時告警。

**第二段之逾時**（取消、資源釋放與不計入失敗計數之要求見上「逾時後之收束」，此處不重複）：第二段 SHALL 設逾時；逾時後狀態 SHALL **回到進入獨佔時所記之來源態**——自「封印」進入者回到「封印」，自「封印且故障」進入者 SHALL **保留「封印且故障」與其原故障機器碼**。逾時 SHALL NOT 被解讀為「先前的故障已排除」：逾時本身不新增故障資訊，因此亦 SHALL NOT 抹除既有的故障事實（若無條件降回「封印」，管理員會誤判系統僅是尚未解封）。**逾時後才完成的初始化 SHALL NOT 產生任何終局副作用**（由上述世代柵欄保證）。**逾時發生於初始化路徑時，初始金鑰可能已建立**：系統 SHALL 於封印狀態查詢與介面明示「初始化可能已完成，請以**第一次輸入的**材料重試，切勿改用新材料」——以新材料重試將永遠失敗，而第一把材料已成為部署主金鑰，未保存即等同資料永久不可解。無逾時將使初始化卡死時永久停留於「解封中」、所有解封請求被拒，恢復手段僅剩重啟——與「不需重啟即可恢復」之要求抵觸。封印狀態查詢 SHALL 暴露當前狀態、故障機器碼與**冷卻到期時間**。

**「封印且故障」下之再次嘗試**：材料驗證失敗時 SHALL 維持「封印且故障」（先前之初始化故障不因一次輸入錯誤而消失），該失敗 SHALL 併入與「封印」態相同的失敗計數與退避冷卻。

**初始化解封（空金鑰表）**：解封時金鑰表為空者 SHALL 走初始化路徑——所提供之材料即成為本部署之初始 KEK，並據以執行既有的初始金鑰建立流程；金鑰表非空者 SHALL 走一般解封路徑，其唯一成功條件為該材料能成功解包現行代表列。**初始化解封 SHALL 要求初始管理員憑證**（一般解封維持不要求登入憑證）——空金鑰表時任何材料皆「成功」，不存在「能解開既有代表列」這個授權證明，若不另行認證，則全新部署在管理員動手前的窗口內，任何可連線者皆得搶先將自己知悉的材料宣告為部署主金鑰，且合法管理員僅會見到「已解封」而無從察覺。此要求 SHALL NOT 造成與多因素認證之死鎖：初始管理員於第一段已建立、其密碼為雜湊而不受 KEK 保護、全新安裝必然尚未啟用多因素認證。初始化解封 SHALL NOT 豁免初始管理員之「首次登入強制改密」狀態——該狀態 SHALL 於解封後維持不變，SHALL NOT 因通過解封而被清除或視為已完成（解封是一次性部署動作、不是登入，二者不得互相代償）。該憑證驗證於第一段執行，SHALL 據實記載其**不套用既有帳號鎖定政策**（該政策於第二段才建構），其防爆破由解封退避承擔。初始化解封另 SHALL 要求與新 KEK 重包相同的二次輸入與保存確認（認證約束「誰有權宣告」、二次輸入約束「宣告內容是否正確」，兩者正交且皆為必要），並 SHALL 施以完整的材料格式驗證（一般解封 SHALL NOT 施以格式驗證，既有部署之 KEK 可能早於格式規則）。兩條路徑 SHALL 產生可區分的審計事件，初始化事件 SHALL 記錄其金鑰引用與所建立之金鑰版本。多實例同時初始化 SHALL 沿用既有跨實例互斥與鎖內重讀，恰一成功、其餘 fail-close。

**封印期路由與授權**：封印期間，除健康檢查、封印狀態查詢與解封端點外，系統 SHALL 對所有路由回應 503 並附機器碼（SHALL NOT 以 401 或 500 表達，狀態須可被外部監控正確辨識）。**一般解封**端點 SHALL NOT 要求既有登入憑證（多因素認證秘密本身受 KEK 保護，要求登入將形成死鎖）；該論證之適用範圍 SHALL 限於金鑰表非空之情形——唯有「能解開既有代表列」方構成真實的授權證明。初始化解封之授權要求另見上。

**抗鎖死**：連續失敗 SHALL 以指數退避與有時限冷卻抑制，冷卻 SHALL 於期滿後自動恢復可嘗試——系統 SHALL NOT 具備任何需重啟行程才能解除的終局鎖定狀態（**本要求之範圍為失敗計數與冷卻**——即攻擊者可觸發者；前代持有者之資源收束遲未完成屬行程級**故障**而非鎖定，SHALL 於封印狀態查詢明示並容許管理員重啟，二者 SHALL NOT 混為一談）。**冷卻期間抵達之嘗試 SHALL 被直接拒絕（不驗證、不取得獨佔），且 SHALL NOT 計入失敗計數、SHALL NOT 刷新或延長冷卻到期時間**；退避成長 SHALL 有明確上限。缺此二者則即使無終局鎖定態，持續送出的嘗試仍可使到期窗口永不出現，等價於可持續的服務阻斷。系統 SHALL NOT 宣稱退避本身即為完整防禦——可嘗試窗口必然出現，攻擊者仍可於窗口內搶先嘗試，故 SHALL 與來源網段限制搭配（解封端點不要求登入憑證，終局鎖定將使匿名請求者得以持續阻斷正當管理員解封）。退避 SHALL 分層為個別來源與全域兩級，全域門檻 SHALL 明顯高於個別來源。系統 SHALL 定義可信代理來源之組態；未設定可信代理時，個別來源之退避 SHALL 保守降級為全域退避，SHALL NOT 依賴可被請求標頭偽造的來源識別。系統 SHALL 提供解封端點繫結獨立監聽位址或限制來源網段之組態（是否啟用由部署方決定）；該組態一經**顯式設定**即 SHALL 具實效——**繫結失敗 SHALL fail-close 拒絕啟動**（SHALL NOT 僅記錄後續行，否則安全邊界靜默降級）、**獨立監聽位址上 SHALL 僅暴露封印相關端點**（SHALL NOT 於解封後轉為完整業務介面，否則管理網段的隔離意圖被反轉），且**來源網段限制 SHALL 涵蓋整個封印端點群**而非僅解封動作。**未設定可信代理時，來源判定 SHALL 僅採信傳輸層對端位址**，SHALL NOT 採用可由請求標頭影響之來源識別——否則網段白名單可被轉送標頭污染而繞過。可信代理組態本身若不合法，系統 SHALL 拒絕啟動，SHALL NOT 退回「信任全部代理」之預設而同時對外宣稱可信代理已設定。

**失敗回應之不可區分範圍（SHALL 精確界定）**：不可區分之對象為**材料類失敗**——格式錯誤、材料驗證失敗、初始化解封之憑證錯誤、二次輸入不符、保存確認未完成，五者 SHALL 共用同一狀態碼、同一機器碼與同一回應內容。憑證錯誤 SHALL 併入本類：若其可與材料錯誤區分，請求者即可探得「管理員憑證正確但金鑰材料不符」，該位元正是初始化窗口最不應洩漏者。**限速類回應（退避、冷卻）SHALL 可區分**並附到期資訊——正當管理員必須能分辨「正被限速」與「輸入錯誤」，此為抗鎖死要求的必要可觀測性；「不可區分」SHALL NOT 被擴張解讀為涵蓋限速回應。時間側通道不在承諾範圍（路徑長度天然不同），SHALL 據實記載。

**封印期留痕**：封印期間審計蓋章鑰不可用。系統 SHALL 於第一段建立獨立於金鑰管理器與資料庫的留痕紀錄，依「保證與其誠實邊界」所載之分層保證記錄解封嘗試（時間、來源、結果、失敗機器碼、單調序號與冪等識別）——**被驗證的嘗試具個別持久化紀錄、被拒絕者以合批計數承載**，系統 SHALL NOT 宣稱「記錄全部嘗試且逐筆不可遺失」（與合批之未同步時窗及環狀覆寫互斥）。留痕 SHALL NOT 記錄任何 KEK 材料或其片段。該留痕 SHALL NOT 受既有「審計失敗時是否落檔」之功能開關控制、SHALL NOT 可被關閉；留痕不可用（無法建立、路徑不可寫等）時 `ui` 模式 SHALL 拒絕開放監聽——無留痕能力即不得提供未經登入的端點。**留痕 SHALL 為兩筆式協定**：`received`（於**取得解封獨佔之後、任何材料驗證之前**寫入並同步至穩定儲存，含時間、來源、單調序號、冪等識別與嘗試種類）與 `outcome`（處理後寫入，以同一冪等識別關聯，含結果與失敗機器碼）。單一寫入 SHALL NOT 被要求同時承載處理結果——結果於 `received` 寫入時尚未產生。`received` 寫入失敗 SHALL 使該次嘗試回滾獨佔、被拒且不進行任何材料驗證；此順序 SHALL NOT 顛倒，否則會留下「已被驗證但無紀錄」的嘗試。不變式 SHALL 為「**任何被驗證的嘗試必有持久化的個別紀錄**」。

**崩潰恢復語義**：僅有 `received` 而無對應 `outcome` 者，SHALL 判為「結果未知」並於回灌時據實標示，SHALL NOT 推測為成功或失敗，SHALL NOT 靜默丟棄（「曾有人於此時嘗試解封」本身即為必須留存之事實）。`outcome` 之結果碼 SHALL 涵蓋成功、材料失敗、**初始化失敗**、逾時與**主動中止**五類。

**回灌 SHALL 經既有審計寫入路徑（同一序列化入口），SHALL NOT 另闢直接寫入**——留痕檔端雖已收斂為單一擁有者，資料庫與完整性鏈端若使回灌與解封後之正常審計各自進入，兩者會並行競爭鏈尾，而蓋章鏈依賴寫入順序。回灌 SHALL 僅視為另一個審計事件來源。

**回灌 SHALL 為 at-least-once**：事件識別於資料庫具唯一性；**SHALL 先提交資料庫交易、再持久化回灌進度**，反向順序 SHALL NOT 被採用（先推進進度再提交者，中止即永久遺失該批）。覆蓋 SHALL NOT 默默跨過尚未回灌之資料——SHALL 累加各類被覆蓋計數與序號範圍並於回灌時據實入審計。回灌另行合成之聚合列（計數差額、首末時間、遺失明細數）不具個別事件之冪等識別，SHALL 以**留痕檔身分與其涵蓋之起訖序號構成確定性識別**並納入資料庫唯一鍵，否則進度未落盤而重跑時該列會重複入審計。**成功事件 SHALL 於服務發佈之前寫入並持久化**——定序為「第二段完成 → 寫入成功事件並同步 → 成功後方得發佈 → 寫入發佈標記 → 送出回應」。該寫入失敗 SHALL 使系統丟棄已建構之服務圖、清除已解封之金鑰材料、回到來源態；**服務因此從未被發佈**，故 SHALL NOT 存在「已放行後需收回、已接受之請求需善後」之窗口。

**成功事件之語義與發佈標記**：成功事件所記錄者為「材料驗證通過且第二段完成」，**SHALL NOT 被解讀為服務已發佈**。發佈成功後 SHALL 另寫一筆帶同一世代之**發佈標記**。回灌時，具成功事件而**無**同世代發佈標記者 SHALL **據實標示為「已驗證通過但未確認發佈」**，SHALL NOT 標示為解封成功。成功事件已持久化而發佈未成功（世代已被逾時取代或行程中止）SHALL 比照寫入失敗之處置——回到來源態、清除金鑰材料、丟棄服務圖，且**SHALL NOT 因此鎖死**：後續解封照常受理並產生新世代，既有成功事件僅為歷史紀錄，SHALL NOT 構成任何前置條件。

**殘餘窗口之誠實界定**：發佈標記自身之寫入與發佈之間仍存在窗口——任兩個原子操作之間皆然，SHALL NOT 藉由再增加紀錄宣稱消除（新紀錄僅產生下一個窗口）。本規範之選擇為**使窗口可被辨識並據實標示**：凡無法判定者一律標為「結果未知」或「未確認發佈」，且任一情形 SHALL NOT 導致鎖死。系統 SHALL NOT 採「先發佈後寫入」之順序（已回應之操作不可撤銷，只能事後補記）。此定序亦使已解封狀態維持「僅由行程結束離開」之性質。

**留痕載體為定長預配置檔（永不成長）**：留痕 SHALL 於第一段以預配置方式建立為**固定大小**之檔案，含雙 header 槽（各具世代序號與檢查碼，取檢查碼有效且世代較大者）與兩個各自定長的環狀區——**關鍵事件環**（`received`／`outcome`）與**拒絕事件環**。建立失敗 SHALL 不開放監聽。因容量固定，系統 SHALL NOT 具備「容量耗盡」狀態，亦 SHALL NOT 需要輪替、聚合視窗或任何形式的准入配額（容量攻擊面於物理上不存在）。

**寫入定序**：`received` SHALL 寫於**取得解封獨佔之後、任何材料驗證之前**，並於持久化成功後方得進行驗證；其寫入失敗 SHALL 使該次嘗試回滾獨佔、被拒且不進行驗證。系統 SHALL NOT 於取得獨佔之前寫入任何 durable 計數——取得獨佔至寫入 `received` 之間的中止尚未驗證任何材料，SHALL NOT 被記為「結果未知」；**唯有「有 `received` 而無 `outcome`」方判定為結果未知**。未取得獨佔者 SHALL 僅記入拒絕事件環（原因碼含冷卻、退避、衝突），SHALL NOT 觸發逐筆持久化同步。

**寫入 `received` 之後、驗證完成之前的主動中止**（請求取消、未預期執行期錯誤）SHALL 回滾獨佔至來源態，**並補寫一筆結果為「主動中止」之 `outcome`**——該 `received` 已持久化，若不補則會落入「結果未知」而使一次明確的中止被永久記載為疑似中斷。**該補寫 SHALL 先於回滾**：SHALL 於中止結果持久化成功後方回到來源態，SHALL NOT 反序（反序會在已知為主動中止的情況下留下「結果未知」）。若該補寫失敗，系統 SHALL 觸發留痕輸出入故障處置（拒收新嘗試）**且仍回到來源態**（SHALL NOT 為記錄而滯留於解封中），該筆據實留為「結果未知」。此類中止 SHALL NOT 計入材料失敗計數。`outcome` 之結果碼 SHALL 因此涵蓋成功、材料失敗、初始化失敗、逾時與主動中止五類。

**取得獨佔後、寫入 `received` 之前的中止**（請求取消、未預期的執行期錯誤、寫入阻塞）SHALL 一律回滾獨佔至來源態：實作 SHALL 於取得獨佔後立即註冊延後回滾以涵蓋所有提前返回與未預期錯誤路徑，且 `received` 之寫入與同步 SHALL 具獨立逾時，逾時 SHALL 視同留痕輸出入故障並拒絕該次嘗試。此類中止 SHALL NOT 計入材料失敗計數（未觸及任何材料），亦 SHALL NOT 使系統滯留於解封中。

**崩潰一致性**：SHALL NOT 假設單一槽位之寫入為原子——SHALL 採「先寫並同步資料槽、再推進 header」之提交順序，header 以世代序號與檢查碼雙副本輪替。**header 之更新本身亦 SHALL 同步至穩定儲存**，且**材料驗證 SHALL 僅於該同步完成之後開始**；完整定序為「寫資料槽 → 同步 → 推進 header → 同步 → 方得驗證材料」。若驗證早於 header 落地，中止後可能不存在可辨識之 `received`，核心不變式即被破壞。每槽 SHALL 至少含格式版本、開機識別、全域序號、事件種類、長度、時間、來源摘要與檢查碼。

**單一寫入者**：留痕檔之**全部寫入 SHALL 收斂於單一擁有者**並由其序列化（個別事件、拒絕事件合批、回灌進度推進）；回灌 SHALL 經該擁有者更新進度，**SHALL NOT 自行寫入 header**。兩路獨立讀改寫 header SHALL NOT 被採用——較新世代可能挾帶較舊之進度或游標而使其回退或漏算。

**啟動恢復** SHALL 明確處理三種情形：**兩個 header 皆無效**、序號缺口、環繞過程中的斷裂覆寫；檢查碼不符者 SHALL 標為毀損並據實入審計。**「留痕檔不存在」與「留痕檔存在但兩個 header 皆無效」SHALL 嚴格分流，SHALL NOT 以 header 是否可解析合流判定**（合流會使損壞被當作首次而觸發重建，等同自側面繞過下述禁令）：前者 SHALL 建立檔案、預配置、寫入初始有效 header 並同步，**且 SHALL 同步其父目錄項**（否則中止後檔案本身可能不存在，下次啟動再度視為首次而使單調計數自零重起），任一步失敗 SHALL 不開放監聽；後者 SHALL fail-close：**不開放監聽、保留檔案原樣供人工檢視，SHALL NOT 截斷、SHALL NOT 自動重建或掃槽重置**。此外，**即使至少一個 header 有效**，若檔案非一般檔案、長度與預配置大小不符、固定佈局偏移不合、或無法完整讀寫，SHALL 一律比照 fail-close 處置（不開放監聽、不截斷、不補齊、不重建）——否則「header 恰好有效」即成為繞過前述禁令之側門——重建會重置單調計數器與回灌進度，等同抹除歷史，正是留痕所要防止者；後續處置 SHALL 為有紀錄的人工決定。關鍵事件環 SHALL 逐筆同步；拒絕事件 SHALL 以定長記憶體聚合器按固定頻率合批，SHALL NOT 逐筆寫入。

**保證與其誠實邊界**：拒絕事件之計數保證 SHALL 表述為「**截至最後一個已持久化世代之計數不可回退，中止最多遺失一個有明確上限的未同步時窗**」，SHALL NOT 宣稱逐筆不可否認（合批與逐筆不可否認互斥，屬物理取捨）。系統 SHALL 記錄觀察總數、已持久化總數、被覆蓋總數三類計數與**缺失序號範圍**。關鍵事件環在依序取得獨佔的持續攻擊下**亦會被覆蓋**，規格 SHALL 承認此點並**記錄被覆蓋之序號範圍**；「已驗證紀錄永不丟失」「不鎖死」「不引入外部儲存」三者 SHALL NOT 被同時宣稱，本系統選擇記錄覆蓋範圍。資源保護 SHALL 以**固定最小受理間隔**與輸入大小、驗證成本上限達成——該間隔 SHALL NOT 具備可耗盡、可扣減或需重置之語義。其正面契約 SHALL 為：**單一全域間隔**（非每來源——所保護者為全域之輸出入與驗證成本，每來源計量會使總量隨來源數倍增而失去界定）；**以單調時鐘度量**（SHALL NOT 使用牆鐘，避免校時即可繞過或延長）；**基準僅於取得獨佔且 `received` 成功落地後更新**（SHALL NOT 於請求抵達時更新——否則被間隔拒絕之請求亦會推遲下一次，可耗盡語義即由此回流）；**作用範圍為單一行程內全部處理執行緒**，SHALL NOT 跨實例協調；**不持久化，重啟即重置**（重啟可繞過一次，惟重啟需主機層權限，不屬未經登入之遠端攻擊面）。因基準延至 `received` 落地後方更新，取得獨佔者之寫入延遲會疊加於間隔之前，故**已具受理資格且僅等待當前 `received` 寫入完成**之請求，其阻塞 SHALL 具明確上界——**最小間隔與 `received` 寫入逾時之和**，該上界 SHALL 為可驗證之條件。此上界 SHALL NOT 被表述為「任何正當請求之最壞阻塞」：持續搶占、冷卻期間與等待前代收束皆可超過該值，三者各有其獨立之界定與誠實邊界。系統 SHALL NOT 宣稱上述手段能於未經登入之端點保證管理員可用性；防搶占 SHALL 由來源網段限制或本機控制台通道承擔。檢查碼僅能偵測寫入斷裂，SHALL NOT 被宣稱可防本機竄改或提供不可否認性。

**運行期間留痕失效（權限變更、落點不可寫等）時，解封端點 SHALL fail-close 拒收新嘗試**並於封印狀態查詢標示；僅於監聽前做一次可寫檢查 SHALL NOT 視為滿足本要求——否則服務開啟後仍存在零留痕的解封窗口。已解封之服務不受此拒收影響。**記錄欄位 SHALL 為白名單**，SHALL NOT 記錄請求內容本體、SHALL NOT 記錄任何 KEK 材料或其片段、**SHALL NOT 記錄任何認證憑證或其衍生值**。解封成功後系統 SHALL 將尚未回灌之留痕寫入審計紀錄，回灌 SHALL 冪等（重複回灌 SHALL NOT 產生重複審計列）、SHALL 具進度標記以支援重啟續灌、失敗時 SHALL 保留原留痕並經既有審計失效機制重試，SHALL NOT 刪除未確認回灌之條目。留痕於回灌前不受審計完整性鏈保護，該窗口之防竄改性弱於平時，SHALL 據實記載。

**失敗回應**：解封失敗之回應**內容** SHALL NOT 洩漏可用於區分失敗原因的細節；系統 SHALL NOT 宣稱其失敗路徑為等時（格式錯與材料錯之處理路徑長度天然不同），承諾範圍限於回應內容。

`ui` 模式下 KEK 遺失 SHALL 導致全部信封密文永久不可解，系統 SHALL NOT 提供任何託管、備份或救援機制，並 SHALL 於解封介面與清冊以不可略過的措辭陳述此事實。

#### Scenario: 封印期非白名單路由一律 503
- **WHEN** `ui` 模式啟動後尚未解封，請求任一業務路由
- **THEN** 回應 MUST 為 503＋機器碼；僅健康檢查、封印狀態查詢與解封端點可達

#### Scenario: 正確材料解封成功
- **WHEN** 管理員提供能解包現行代表列的 KEK 材料
- **THEN** 系統轉為解封狀態、全服務上線，並於審計留下解封記錄

#### Scenario: 全新安裝經初始化解封啟用
- **WHEN** 全新部署（金鑰表為空）以 `ui` 模式啟動，管理員於解封端點提供材料並通過二次輸入與保存確認
- **THEN** 該材料成為初始 KEK、初始金鑰建立完成、系統轉為已解封；審計事件 MUST 可與一般解封區分

#### Scenario: 初始化解封需初始管理員憑證
- **WHEN** 金鑰表為空，解封請求未帶或帶錯初始管理員憑證
- **THEN** 請求 MUST 被拒且 MUST NOT 建立任何金鑰；該拒絕 MUST 併入退避計數。一般解封（金鑰表非空）MUST NOT 因此被要求登入憑證

#### Scenario: 初始化解封缺二次輸入即拒絕
- **WHEN** 金鑰表為空，解封請求未帶二次輸入或未帶保存確認
- **THEN** 請求 MUST 被拒，MUST NOT 以該材料建立任何金鑰（避免打錯之字串被固化為部署主金鑰）

#### Scenario: 並發解封恰一執行驗證與初始化
- **WHEN** 兩個攜帶正確材料的解封請求並發抵達
- **THEN** 恰一方取得獨佔並執行「驗證＋初始化」全程、另一方 MUST 在**任何驗證開始前**被拒；MUST NOT 兩者皆執行材料驗證，更 MUST NOT 兩者皆執行金鑰管理器初始化

#### Scenario: 冷卻期間的嘗試不延長冷卻
- **WHEN** 系統處於冷卻期間，持續收到解封嘗試
- **THEN** 各次嘗試 MUST 被直接拒絕且 MUST NOT 刷新或延長冷卻到期時間；冷卻 MUST 於原到期時間屆滿後自動恢復可嘗試

#### Scenario: 留痕寫入失敗即拒收嘗試
- **WHEN** 運行期間留痕落點變為不可寫，其後收到解封嘗試
- **THEN** 該嘗試 MUST 被拒（不驗證、不取得獨佔），封印狀態 MUST 標示留痕失效；MUST NOT 出現任何未留痕即被處理的解封嘗試

#### Scenario: 自故障態重試逾時不清除故障事實
- **WHEN** 系統處於「封印且故障」，管理員重試且第二段逾時
- **THEN** 狀態 MUST 回到「封印且故障」並保留原故障機器碼；MUST NOT 被降為「封印」（否則先前真實的初始化失敗被抹除，管理員誤判系統僅是尚未解封）

#### Scenario: 待收束期間的解封請求得知在等什麼
- **WHEN** 前一次第二段逾時或失敗後其資源尚未收束完成，此時收到新的解封請求
- **THEN** 該請求 MUST 被拒且 MUST 收到可與「解封進行中」「已解封」區分之專屬機器碼；封印狀態查詢 MUST 暴露「有前代待收束」；MUST NOT 取得獨佔（不得使兩份半初始化服務圖並存）

#### Scenario: 未取得獨佔者不觸發逐筆同步
- **WHEN** 某次嘗試通過冷卻檢查但因已有持有者（或有前代待收束）而未取得獨佔
- **THEN** 該次 MUST 僅記入拒絕事件環（原因碼「衝突」）；MUST NOT 寫入關鍵事件環、MUST NOT 觸發逐筆持久化同步

#### Scenario: 首次啟動建立留痕檔並持久化目錄項
- **WHEN** `ui` 模式首次啟動且留痕檔不存在
- **THEN** 系統 MUST 建立檔案、預配置、寫入初始有效 header 並同步，**且同步其父目錄項**；任一步失敗 MUST 不開放監聽。此路徑 MUST 與「檔案存在但 header 無效」分流判定（以檔案是否存在為準）

#### Scenario: received 落地後的主動中止補寫中止結果
- **WHEN** `received` 已持久化之後、驗證完成之前發生請求取消或未預期執行期錯誤
- **THEN** 系統 MUST 回滾獨佔至來源態並**補寫結果為「主動中止」之 `outcome`**；該筆 MUST NOT 被留為「結果未知」，且 MUST NOT 計入材料失敗計數

#### Scenario: 有成功事件而無發佈標記時標為未確認發佈
- **WHEN** 成功事件已持久化，但發佈因世代被逾時取代或行程中止而未成功
- **THEN** 回灌 MUST 據實標示為「已驗證通過但未確認發佈」，MUST NOT 標示為解封成功；系統 MUST NOT 因此鎖死——後續解封 MUST 照常受理並產生新世代

#### Scenario: 中止結果須先持久化再回滾
- **WHEN** `received` 已落地後發生主動中止
- **THEN** 系統 MUST 先持久化「主動中止」結果、成功後方回到來源態；MUST NOT 反序（否則已知的主動中止會被留為「結果未知」）。該補寫失敗時 MUST 仍回到來源態並觸發留痕故障處置，MUST NOT 滯留於解封中

#### Scenario: 佈局不健全即使 header 有效仍拒絕開放監聽
- **WHEN** 留痕檔至少一個 header 有效，但其為非一般檔案、長度與預配置不符、或無法完整讀寫
- **THEN** 系統 MUST fail-close 不開放監聽，且 MUST NOT 截斷、補齊或重建

#### Scenario: 成功事件未持久化則服務從未發佈
- **WHEN** 第二段初始化完成但成功事件之寫入失敗
- **THEN** 系統 MUST 丟棄服務圖、清除已解封之金鑰材料並回到來源態；服務 MUST NOT 曾被發佈（MUST NOT 出現「已放行後收回」而需處置已接受請求的情形）

#### Scenario: 兩個 header 皆無效時拒絕開放監聽且不自動重建
- **WHEN** 啟動恢復發現留痕檔的兩個 header 皆無效
- **THEN** 系統 MUST fail-close 不開放監聽並保留檔案原樣；MUST NOT 自動重建或掃槽重置（重建會重置單調計數器與回灌進度＝抹除歷史）

#### Scenario: 材料驗證不得早於 header 落地
- **WHEN** 系統寫入 `received` 並推進 header
- **THEN** 材料驗證 MUST 僅於 header 之同步完成後開始；MUST NOT 於資料槽同步後、header 落地前即開始驗證（否則中止後可能無可辨識之 `received`）

#### Scenario: 取得獨佔後寫入 received 前的非中止性失敗仍回滾
- **WHEN** 取得獨佔後、寫入 `received` 之前發生請求取消、未預期執行期錯誤或寫入逾時
- **THEN** 系統 MUST 回滾獨佔至來源態且 MUST NOT 滯留於解封中；該次 MUST NOT 計入材料失敗計數

#### Scenario: 受理間隔不因被拒嘗試而後移
- **WHEN** 攻擊者於受理間隔內持續送出解封嘗試
- **THEN** 各次 MUST 被拒且 MUST NOT 更新間隔基準（基準僅於取得獨佔且 `received` 落地後更新）；正當管理員 MUST 能於原間隔屆滿時取得受理

#### Scenario: 取得獨佔至寫入 received 之間中止不記為結果未知
- **WHEN** 系統於取得解封獨佔之後、寫入 `received` 之前中止
- **THEN** 該次 MUST NOT 被判為「結果未知」（其時尚未驗證任何材料）；MUST NOT 因此要求於取得獨佔前寫入任何 durable 計數

#### Scenario: 留痕兩筆與結果未知
- **WHEN** 系統於寫入 `received` 之後、寫入 `outcome` 之前崩潰
- **THEN** 回灌時該筆 MUST 被標示為「結果未知」；MUST NOT 被推測為成功或失敗，MUST NOT 被靜默丟棄

#### Scenario: 初始化逾時後的重試指引
- **WHEN** 初始化路徑的第二段逾時，狀態回到封印
- **THEN** 封印狀態查詢與介面 MUST 明示「初始化可能已完成，請以第一次輸入的材料重試」；以新材料重試 MUST 失敗（既有金鑰表已由第一把材料建立）

#### Scenario: 已解封時再解封不重跑初始化
- **WHEN** 系統已解封，再次收到解封請求
- **THEN** 請求 MUST 被拒，MUST NOT 重新執行第二段初始化

#### Scenario: 解封後初始化失敗不終止行程
- **WHEN** 材料驗證通過但第二段初始化失敗（如金鑰表損毀）
- **THEN** 行程 MUST 存活、回傳可辨識機器碼、狀態轉為「封印且故障」，且 MUST 允許再次解封重試

#### Scenario: 故障態下材料失敗維持故障態
- **WHEN** 系統處於「封印且故障」，再次解封但材料驗證失敗
- **THEN** 狀態 MUST 維持「封印且故障」（先前故障不因輸入錯誤而被清除），該次失敗 MUST 併入與封印態相同的失敗計數與退避

#### Scenario: 故障態重試必經解封中
- **WHEN** 系統處於「封印且故障」，收到材料正確的重試且同時有另一重試併發抵達
- **THEN** 重試 MUST 經由「解封中」並受同一獨佔閘約束，恰一方執行初始化；MUST NOT 自故障態直達已解封

#### Scenario: 第二段逾時回來源態且不得遲發佈
- **WHEN** 第二段初始化逾時
- **THEN** 狀態 MUST 回到**進入獨佔時所記之來源態**（自「封印」進入者回「封印」；自「封印且故障」進入者保留該態與其故障機器碼）且允許再次嘗試；逾時後才完成的初始化 MUST NOT 產生任何終局副作用（MUST NOT 出現「已回來源態卻被發佈為已解封」）

#### Scenario: 錯誤材料不洩漏細節
- **WHEN** 提供的材料長度合法但無法解包，或格式不合法
- **THEN** 回應**內容** MUST 為同一種可辨識的失敗，MUST NOT 使呼叫端得以區分失敗原因

#### Scenario: 冷卻期滿自動恢復
- **WHEN** 連續失敗觸發冷卻後，冷卻時限屆滿
- **THEN** 系統 MUST 自動恢復接受解封嘗試，MUST NOT 要求重啟行程才能恢復

#### Scenario: 無可信代理時退避降級為全域
- **WHEN** 未設定可信代理來源
- **THEN** 個別來源退避 MUST 降級為全域退避，MUST NOT 以可由請求標頭控制的來源識別作為限速鍵

#### Scenario: 留痕不可關閉且不可用即不開服務
- **WHEN** 既有「審計失敗時落檔」功能開關被關閉，或封印期留痕路徑不可寫
- **THEN** 前者 MUST NOT 影響封印期留痕（被驗證的嘗試仍具個別持久化紀錄，被拒絕者仍計入合批計數——依「保證與其誠實邊界」所載分層保證，不主張逐筆不可遺失）；後者 MUST 使 `ui` 模式拒絕開放監聽

#### Scenario: 回灌冪等
- **WHEN** 解封成功後回灌留痕，且因重啟或重試而重複執行
- **THEN** 審計紀錄 MUST NOT 出現重複列；未成功回灌之條目 MUST 被保留並重試

#### Scenario: 重啟重新封印
- **WHEN** 已解封的 `ui` 模式服務重啟
- **THEN** 系統 MUST 回到封印狀態，MUST NOT 自任何持久化來源恢復解封

### Requirement: KEK 提供者切換路徑
系統 SHALL 支援下列 KEK 提供者切換路徑，且各路徑之前置條件 SHALL 明確：`env` 與 `ui` 之間以**相同材料**互換 SHALL 免遷移——僅需改變模式宣告與材料注入方式，金鑰引用一致即可上線，SHALL NOT 產生任何金鑰表寫入、SHALL NOT 觸發退役收尾。更換材料，或自 `env`／`ui` 切換至委託模式、委託模式之間切換、自委託模式切回本地模式，SHALL 一律經換鑰精靈重包完成。自委託模式將材料流回本地 SHALL 為需顯式確認的降級操作並入審計。

上線判準 SHALL 為「金鑰引用一致**且**現行代表列全數實際解包成功」，SHALL NOT 僅以引用（截斷摘要）相等為充分條件。免遷移切換 SHALL 於單一實例（或全部實例先停再起）下進行——切換期間若另一實例執行 DEK 輪替，其新版本僅存在於該行程記憶體，未重啟之實例將以舊版本續寫而後續無法互讀；此為既有的行程內金鑰版本快取限制（與多副本部署前置之金鑰寫入柵欄同一根因），本規範沿用既有單實例部署不變式，SHALL NOT 宣稱涵蓋多副本併發切換。

#### Scenario: 同鑰互換免遷移
- **WHEN** 以相同 KEK 材料自 `env` 切換為 `ui`（或反向）並重啟
- **THEN** 服務正常啟動（`ui` 模式為解封後），金鑰表 MUST 零寫入，MUST NOT 產生退役或切換日誌；上線 MUST 以代表列全數解包成功為準，MUST NOT 僅憑引用相等放行

#### Scenario: 切換至委託模式必經重包
- **WHEN** 自 `env`／`ui` 切換為 `kms`／`hsm`
- **THEN** 系統 MUST 要求先完成以目標金鑰為對象的重包；未重包即切換 MUST fail-close 拒絕啟動

### Requirement: 新 KEK 材料之弱鑰防線
系統 SHALL 於兩路降低弱 KEK 風險：部署範本 SHALL 提供 CSPRNG 生成指令（涵蓋 KEK 材料鍵），介面 SHALL 提供以瀏覽器 CSPRNG 於本地生成 KEK 的入口。新 KEK 材料 SHALL 經**伺服端**格式驗證（輸入編碼之解碼、字元集、非出廠預設值、非現行 KEK、金鑰引用未曾出現於金鑰表）；此驗證 SHALL NOT 僅實作於前端。字元集之檢查 SHALL 僅適用於原字元形態，十六進位與 base64 形態之合法性由其編碼本身界定（見「KEK 材料的輸入編碼」）。系統 SHALL NOT 宣稱可由單一值驗證其熵——格式驗證為降低常見弱值風險的務實手段。

重包目標於 sink 端之不變式重驗 SHALL 針對**解碼後的金鑰**進行（長度、非出廠預設值，且 provider 之金鑰引用等於該金鑰之指紋），SHALL NOT 宣稱於 sink 端重驗了輸入編碼之字元集——該資訊於解碼後已不存在。

#### Scenario: 伺服端拒絕不合格式的 KEK
- **WHEN** 繞過介面直接以無法解出 32 位元組、或原字元形態卻含字元集外字元的材料呼叫重包端點
- **THEN** 請求 MUST 被拒（400＋機器碼），金鑰表 MUST 零寫入

#### Scenario: 重包接受三種輸入形態
- **WHEN** 以同一把 32 位元組金鑰的原字元、十六進位或 base64 寫法呼叫重包端點
- **THEN** MUST 皆被接受，且所得金鑰引用（指紋）相同

#### Scenario: 介面本地生成
- **WHEN** 管理員於重包精靈點選「本地生成」
- **THEN** 材料由瀏覽器 CSPRNG 產生，MUST NOT 經由伺服端生成或回傳

### Requirement: KEK provider 之稽核證據雙軌
金鑰清冊 SHALL 呈現執行期 KEK 的 provider 模式與金鑰引用；該 provider 欄位 SHALL 由執行期 provider 物件導出，SHALL NOT 重新讀取環境變數（重讀將使宣告與實況同源而失去稽核價值）。部署宣告的 `KEK_PROVIDER` 與清冊呈現的執行期 provider SHALL 互為稽核證據，稽核者比對兩者即可證明未發生隱式退化。系統 SHALL 於啟動時輸出 provider 決議結果（模式、金鑰引用、決議依據）之日誌，並於審計服務就緒後補記系統事件。`ui` 模式 SHALL 另呈現封印狀態；封印期間清冊不可用，封印狀態 SHALL 由封印狀態查詢端點提供供監控取用。

封印狀態與既有的「退役收斂降級」狀態 SHALL 為正交兩軸並各自獨立呈現（前者描述服務是否已上線、後者描述服務運行中是否有未收斂狀態），SHALL NOT 以其一覆蓋或推導另一——已解封之部署仍可能同時處於降級。清冊 SHALL NOT 因新增 provider 呈現而洩漏任何金鑰材料——本地模式顯示指紋、委託模式顯示外部金鑰引用（非機密）。

#### Scenario: 清冊 provider 非重讀環境變數
- **WHEN** 檢視金鑰清冊的 KEK 項
- **THEN** provider 欄位由執行期 provider 導出；守衛 MUST 確認該值不來自環境變數重讀

#### Scenario: 宣告與實況一致可稽核
- **WHEN** 稽核者比對部署的 `KEK_PROVIDER` 與清冊顯示的 provider
- **THEN** 兩者一致；不一致即代表發生隱式退化（本設計以 fail-close 使其不可達，雙軌為驗屍證據）

#### Scenario: 委託模式顯示外部引用
- **WHEN** 以 `kms`／`hsm` 模式運行並檢視清冊
- **THEN** 顯示外部金鑰引用（ARN 或裝置金鑰標籤）供對照外部主控台，且不含任何金鑰材料

### Requirement: 雲端金鑰服務委託（KMS）
`kms` 模式下 KEK 材料 SHALL 永不進入本行程：DEK 之包裹與解包 SHALL 委託雲端金鑰服務執行。組態所給之金鑰識別 MAY 為別名、金鑰識別碼或完整資源名稱，系統 SHALL 於啟動時解析為完整資源名稱後才落庫為 KEK 識別值（見「KEKProvider 介面與金鑰引用抽象」之正規化規範）。DEK 本身 SHALL 仍由本地 CSPRNG 生成（SHALL NOT 改用雲端服務的資料金鑰生成原語），以維持與其他模式相同的 DEK 生命週期語義與可互換性。AAD SHALL 映射至雲端服務的原生加密脈絡能力。目標金鑰之權限預檢 SHALL 涵蓋實際所需的全部操作，**含解析金鑰識別所需之描述權限**——遺漏將使「組態齊備但缺該權限」之部署得到誤導性錯誤。系統 SHALL NOT 自行管理雲端憑證，SHALL 依該雲端 SDK 的預設憑證鏈取得。系統 SHALL NOT 快取解包後的 KEK 或以任何形式將 KEK 材料留存本地。

#### Scenario: DEK 生成路徑不分岔
- **WHEN** 於 `kms` 模式下建立新的 DEK 版本
- **THEN** DEK 由本地 CSPRNG 生成後委託包裹，其生命週期語義與 `env` 模式相同

#### Scenario: 加密脈絡承載 AAD
- **WHEN** 於 `kms` 模式包裹 DEK
- **THEN** 用途、版本與金鑰引用經雲端服務的加密脈絡綁定；脈絡不符時解包 MUST 失敗

### Requirement: 硬體安全模組委託（HSM）
`hsm` 模式 SHALL 經 PKCS#11 介面委託硬體安全模組執行 KEK 運算，KEK SHALL 永不離開裝置。金鑰引用之正規形式由 token 標籤與金鑰標籤組成，兩段 SHALL 各自跳脫分隔字元後再連接——標籤可含任意字元，未跳脫時不同的標籤組合會產生相同引用，污染代表列篩選、唯一索引與稽核引用。裝置存取密語 SHALL 由直接組態或檔案組態**恰一**提供——兩者皆未提供 SHALL 判為缺項、兩者皆提供 SHALL 判為組態矛盾，系統 SHALL 一律拒絕啟動並指出衝突，SHALL NOT 以任一方為優先而靜默採用。此能力 SHALL 以建置標記隔離，預設映像 SHALL NOT 含其原生相依；於未含該能力的建置中宣告 `hsm` SHALL fail-close 並明示需使用 HSM 變體映像，SHALL NOT 靜默回落至其他 provider。測試 SHALL 以軟體 HSM 靶機覆蓋，並以環境變數 gating 使無 HSM 環境的測試維持通過。

金鑰分持（split knowledge、dual control、m-of-n quorum）SHALL NOT 由本系統實作、SHALL NOT 由本系統宣稱——該等控制屬客戶於 HSM 廠商工具中執行的行政作業域。任何文件與介面 SHALL NOT 暗示本系統提供該能力。

#### Scenario: 非 HSM 建置宣告 hsm 即拒絕
- **WHEN** 於未含 HSM 能力的映像設定 `KEK_PROVIDER=hsm`
- **THEN** 系統 MUST 拒絕啟動並明示需 HSM 變體映像，MUST NOT 回落至其他 provider

#### Scenario: KEK 不離開裝置
- **WHEN** 於 `hsm` 模式包裹或解包 DEK
- **THEN** 運算於裝置內完成，KEK 材料 MUST NOT 出現於本行程記憶體、日誌或資料庫

#### Scenario: 標籤分隔字元跳脫
- **WHEN** token 標籤與金鑰標籤分別為 `("a:b", "c")` 與 `("a", "b:c")`
- **THEN** 兩者產生的金鑰引用 MUST 不同

#### Scenario: 金鑰分持界線明載
- **WHEN** 檢視 HSM 相關文件與介面說明
- **THEN** MUST 明載金鑰分持屬客戶行政作業域、本系統不實作不宣稱

### Requirement: 檢查點簽章鑰的形狀與防護

系統 SHALL 以**專用資料表**保存檢查點簽章鑰（Ed25519）：私鑰 SHALL 經 ColumnCodec 以其專屬的欄位參照（AAD 列綁定）包裹落庫，公鑰 SHALL 以明文欄保存（公鑰非機密）。該表 SHALL **自始具備 `version` 欄與 active 語義**（修正既有匯出簽章鑰無版本欄的缺陷），每個檢查點 SHALL 記錄其簽章所用的鑰版本，驗證 SHALL 依該版本取鑰。

簽章鑰 SHALL 於首次啟動時生成（比照匯出簽章鑰的首啟路徑），生成或載入失敗 SHALL fail-close 拒絕啟動，SHALL NOT 帶病運行而產生無法驗證的檢查點。

私鑰 SHALL NOT 存在任何匯出、下載或讀取端點；系統 SHALL NOT 提供任何刪除該表列的 API 或管理介面。model SHALL 掛 `BeforeUpdate`／`BeforeDelete` 守衛拒絕 ORM 路徑的改刪（比照 audit_logs 的守衛模式）。該鑰 SHALL NOT 以新的 DataKey purpose 形式納入對稱金鑰的版本鏈／輪替／清理機制（形態錯配：那套機器為對稱包裹材料而設）。

**舊版本簽章鑰 SHALL 永久保留**：刪除任一曾用於簽章的版本，將使以該版本簽章的歷史檢查點永久不可驗；此為單向不可逆的證據損毀，SHALL NOT 存在任何路徑可達成。

本規格 SHALL NOT 提供簽章鑰輪替的 UI 或 API；資料形狀 SHALL 使日後新增輪替時不需資料遷移（多版本並存、version 唯一、active 明確）。檢查點簽章鑰 SHALL NOT 與匯出 manifest 簽章鑰共用（兩者職責不同，共用會使任一鑰的洩漏或輪替綁死兩個信任面）。

#### Scenario: 私鑰無外洩路徑

- **WHEN** 稽核全部 API 路由、金鑰清冊回應與匯出內容
- **THEN** 檢查點簽章私鑰不出現於任何回應；僅公鑰可取

#### Scenario: ORM 改刪被拒

- **WHEN** 任何程式碼經 ORM 更新或刪除檢查點簽章鑰列
- **THEN** 操作被守衛拒絕並回錯誤；守衛測試在守衛被移除時轉紅

#### Scenario: 鑰不可用時 fail-close

- **WHEN** 啟動時檢查點簽章鑰無法解包（KEK 不符或密文損毀）
- **THEN** 系統拒絕啟動並輸出含排查指引的明確錯誤，SHALL NOT 以未簽章或跳過封章的方式帶病啟動

#### Scenario: 舊版本鑰保留使歷史可驗

- **WHEN** 簽章鑰存在多個版本且歷史檢查點分別以不同版本簽章
- **THEN** 各檢查點以其記錄的版本取鑰驗證皆通過；系統中不存在任何刪除舊版本鑰的入口

### Requirement: 檢查點簽章公鑰之清冊呈現與取用

金鑰清冊 SHALL 納入檢查點簽章鑰項，呈現其**公鑰指紋**（沿清冊既有 fingerprint 演算法 `hex(SHA-256(material)[:8])`，material 為原始公鑰位元組）、版本與管理方（系統管理）。該項 SHALL NOT 呈現任何私鑰材料或 wrapped 值。

系統 SHALL 提供公鑰取用入口：檢查點驗證頁與金鑰清冊 SHALL 可取得該鑰之 base64 公鑰（複製或下載 canonical JSON），其來源 SHALL 與檢查點公鑰端點同源，SHALL NOT 使用未經一致性保證的其他來源。公鑰端點 SHALL 對 admin 與 auditor 開放（供 auditor 交付 QSA 離線驗章），清冊入口維持 admin。

#### Scenario: 清冊顯示檢查點鑰指紋

- **WHEN** admin 開啟金鑰清冊
- **THEN** 檢查點簽章鑰項顯示公鑰指紋、版本與「系統管理」標示，指紋欄不留空為「—」

#### Scenario: 公鑰同源一致

- **WHEN** 分別自金鑰清冊與檢查點公鑰端點取得公鑰
- **THEN** 兩者位元組完全一致

#### Scenario: auditor 可取公鑰

- **WHEN** auditor 呼叫檢查點公鑰端點
- **THEN** 取得公鑰成功（用於離線驗章），且無任何私鑰資訊

### Requirement: KEK 材料的輸入編碼
KEK 為一把 **32 位元組**的金鑰；系統 SHALL 將「輸入編碼」與「金鑰長度」視為兩件獨立的事，SHALL NOT 以「輸入必須是 32 個字元」表述金鑰長度要求。系統 SHALL 接受下列三種輸入形態，並一律解出恰 32 位元組的金鑰：

1. **原字元形態**：恰 32 位元組的輸入，其位元組即金鑰；
2. **十六進位形態**：恰 64 個十六進位字元（大小寫不拘），解碼為 32 位元組；
3. **base64 形態**：base64 編碼且解碼結果恰 32 位元組。base64 SHALL 同時接受標準與 URL-safe 兩套字母表、並同時接受有與無 padding 之寫法；解碼 SHALL 採嚴格模式（最末量子之多餘位元須為零），且 SHALL NOT 接受混用兩套字母表之字串。

解碼結果不為 32 位元組者 SHALL 一律拒絕。系統 SHALL NOT 為使輸入合格而引入任何金鑰派生（KDF）或雜湊步驟——材料不足 32 位元組即為不合格材料，SHALL NOT 被補足。

**判定順序與歧義**：判定 SHALL 依「原字元 → 十六進位 → base64」之順序進行，且原字元形態 SHALL 於任何空白修剪之前先行判定（恰 32 位元組之輸入 SHALL 原樣採用，含其前後空白），其後之形態判定 SHALL 先修剪前後空白。恰 32 位元組之輸入即使其字元全屬十六進位字元集，仍 SHALL 視為原字元形態。此順序 SHALL NOT 被描述為「在多種可能讀法中擇一」——三種形態解出 32 位元組所需之輸入長度分別為 32、64、43 或 44，彼此互斥，任一輸入至多只有一種讀法能解出 32 位元組。

**編碼與政策的適用範圍**：字元集政策（`A-Za-z0-9`）SHALL 僅適用於**原字元形態**；十六進位與 base64 形態之字元集由其編碼本身決定，SHALL NOT 另行施加原字元形態之字元集政策。既有的「不施加格式政策」入口（未宣告 `KEK_PROVIDER` 之相容路徑、金鑰表非空之一般解封）SHALL 僅套用解碼，其原有寬鬆語義不變。

**出廠預設值之拒絕 SHALL NOT 被編碼繞過**：出廠預設值之判定 SHALL 比對**解碼後的金鑰位元組**，故該預設值之十六進位與 base64 寫法 SHALL 同樣被判為出廠預設值而拒絕。

**射程**：本要求 SHALL 適用於全部材料入口——`ENCRYPTION_KEY` 之啟動判定（含相容路徑與顯式 `env` 模式）、解封端點之初始化路徑與一般路徑、換鑰精靈之本地重包目標，以及發行模式下的出廠預設值閘。任一入口 SHALL NOT 保留只認單一形態的平行實作。

**與既有部署的關係**：本要求 SHALL NOT 改變任何今日可運作之部署所得到的金鑰——今日可運作之材料必然恰 32 位元組，於判定第一步即命中原字元形態，其金鑰與金鑰指紋逐位元組不變，SHALL NOT 需要任何遷移或重包。

**失敗回應之不可區分**：解碼失敗 SHALL 與既有材料失敗共用同一狀態碼與同一機器碼，SHALL NOT 新增任何可區分解碼子成因的機器碼、回應欄位或訊息；解碼失敗之原因字串 SHALL 僅存在於伺服端錯誤鏈與啟動期日誌。解碼所配置之中間緩衝，於解碼失敗時、以及呼叫端僅取用判定結果時，SHALL 就地歸零；既有「材料用畢即歸零」之行為與其誠實邊界不變。時間側通道不在承諾範圍（解碼耗時僅隨呼叫端自身輸入之長度變化，不與任何祕密比較），SHALL 據實記載。

#### Scenario: 三種形態皆解出同一把金鑰
- **WHEN** 以同一把 32 位元組金鑰的原字元、十六進位與 base64 三種寫法分別提交
- **THEN** 三者 MUST 皆被接受、解出逐位元組相同的金鑰，且其金鑰指紋相同

#### Scenario: openssl 標準指令的產出被接受
- **WHEN** 以 `openssl rand -hex 32` 或 `openssl rand -base64 32` 的輸出作為材料
- **THEN** MUST 被接受（含其結尾換行），MUST NOT 因字元集或長度而被拒

#### Scenario: 解碼後非 32 位元組即拒
- **WHEN** 提交長度不屬於 32／43／44／64 之輸入，或屬於該些長度但解碼失敗（如 64 個含非十六進位字元的 base64 字元、43 個非規範編碼的 base64 字元）
- **THEN** MUST 被拒，MUST NOT 以任何補足或截斷方式湊成 32 位元組

#### Scenario: 恰 32 位元組的輸入一律視為原字元形態
- **WHEN** 提交恰 32 位元組的材料（不論其字元是否恰好全屬十六進位或 base64 字元集）
- **THEN** MUST 以原字元形態採用（金鑰即該 32 位元組），MUST NOT 解讀為十六進位或 base64 而得到 16 或 24 位元組

#### Scenario: 出廠預設值換一種編碼仍被拒
- **WHEN** 以出廠預設 KEK 材料的十六進位或 base64 寫法設定 `ENCRYPTION_KEY` 或提交至解封／重包端點
- **THEN** MUST 被判為出廠預設值並拒絕，與直接使用該預設值字串同結果

#### Scenario: 混用 base64 字母表被拒
- **WHEN** 提交同時含 `+`／`/` 與 `-`／`_` 的 base64 字串
- **THEN** MUST 被拒（非任一合法字母表之編碼）

#### Scenario: 既有 32 位元組材料行為完全不變
- **WHEN** 以今日可正常啟動或解封的 32 位元組材料（含其中可能存在的空白字元）操作
- **THEN** 所得金鑰與金鑰指紋 MUST 與改動前逐位元組相同，MUST NOT 因空白修剪而改變

#### Scenario: 解碼失敗與材料失敗不可區分
- **WHEN** 分別以「十六進位字元不合法」「base64 解碼失敗」「解碼後長度不符」「字元集外」「出廠預設值」等材料呼叫解封端點
- **THEN** 各次回應的狀態碼、機器碼與回應內容 MUST 完全相同

### Requirement: 封印狀態下的介面進站導向
`ui` 模式下，介面 SHALL 於**進站時**判定封印狀態並將使用者導至解封頁——自任何網址進入（含根路徑與任一深連結）皆 SHALL 被接住，SHALL NOT 僅於登入失敗時才提示。封印期間的服務端 503 訊息 SHALL 明寫解封頁之路徑，使導向失效時仍留有可依循的線索。

已解封時解封頁 SHALL NOT 可達：對該頁之導覽 SHALL 被導離。導向規則 SHALL 為**單一守衛的兩個方向**，SHALL NOT 由兩套互相獨立的判斷各自實作。

**解封當下 SHALL NOT 中斷正在完成流程者**：解封成功時使用者仍停留於解封頁，介面 SHALL 呈現成功結果與後續入口，SHALL NOT 因狀態已轉為已解封而立即將其導離。

**封印狀態之判定 SHALL 具三個更新來源**：進站探測（狀態未知時查詢封印狀態端點）、解封頁自身的狀態讀取與解封結果、以及服務端封印機器碼之執行期訊號（使用者停留期間行程重啟而重新封印時，下一次請求之 503 SHALL 使介面回到封印相位並導向解封頁）。

**探測失敗 SHALL 放行而非導向**：封印狀態查詢失敗時，相位 SHALL 維持未知並放行本次導覽。封印的強制點在服務端（非白名單路由一律 503），介面導向只提供去向指引；以探測失敗為由將全體使用者導至解封頁，會使一次短暫的服務端不可用把**已解封**部署的使用者逐出應用，而該頁同樣讀不到狀態。放行的代價由執行期 503 訊號自我修正。

**誠實界定**：解封頁之導離縮小的是**介面可及面**（不再有可互動的對外解封表單）。封印狀態查詢端點於各模式恆註冊且不要求登入憑證，其資訊以其他方式仍可取得；系統 SHALL NOT 宣稱此導向阻止對部署狀態的探測。

#### Scenario: 封印期自根路徑進站
- **WHEN** 系統處於封印狀態，使用者開啟根路徑
- **THEN** MUST 被導向解封頁，MUST NOT 停在登入頁而無後續指引

#### Scenario: 封印期自深連結進站
- **WHEN** 系統處於封印狀態，使用者直接開啟任一內頁網址
- **THEN** MUST 被導向解封頁

#### Scenario: 已解封時解封頁不可達
- **WHEN** 系統已解封，使用者導覽至解封頁
- **THEN** MUST 被導離該頁

#### Scenario: 解封成功當下不被踢離
- **WHEN** 使用者於解封頁提交材料且解封成功
- **THEN** 使用者 MUST 仍停留於解封頁並看到成功結果與後續入口；其後由該入口離開 MUST NOT 被導回解封頁

#### Scenario: 停留期間重新封印
- **WHEN** 使用者停留於介面時服務端行程重啟而回到封印狀態
- **THEN** 下一次請求收到封印機器碼後，介面 MUST 導向解封頁

#### Scenario: 狀態探測失敗不導向
- **WHEN** 封印狀態查詢因網路或服務端錯誤而失敗
- **THEN** 本次導覽 MUST 放行，MUST NOT 將使用者導至解封頁

### Requirement: 解封頁之生成指令參考
解封頁與換鑰精靈 SHALL 於材料輸入欄位附近列出**可複製的**生成指令參考，涵蓋每一種被接受的輸入形態各至少一條。列出的每一條指令 SHALL 經自動化守衛**實際執行**驗證其產出必然通過伺服端材料驗證，SHALL NOT 僅以推論列出。

指令為**參考**而非要求：介面 SHALL 表述為「以下任一皆可」，且 SHALL 保留以瀏覽器 CSPRNG 於本地生成材料的入口（並非所有操作者都在具備 shell 的機器上操作）。「請以 CSPRNG 生成、勿自行編造」之熵警告 SHALL 保留，SHALL NOT 因提供指令而弱化——列出指令的目的正是提供現成的正確做法以取代自行編造。

部署範本與介面所列之指令集合 SHALL 為**同一份事實源**並由守衛比對；兩處不一致 SHALL 使測試失敗（不一致的指引比沒有指引更糟）。指令字串本身 SHALL NOT 被翻譯，其說明文字 SHALL 具三語譯文。

#### Scenario: 介面列出的指令逐條可用
- **WHEN** 執行介面所列的任一條生成指令
- **THEN** 其產出 MUST 通過伺服端材料驗證；守衛 MUST 以實際執行（非結構比對）驗證此性質

#### Scenario: 範本與介面的指令一致
- **WHEN** 比對部署範本與介面所列的生成指令集合
- **THEN** 兩者 MUST 逐條相同；不一致 MUST 使測試失敗

#### Scenario: 本地生成入口保留
- **WHEN** 操作者所在環境無法執行 shell 指令
- **THEN** 介面 MUST 仍提供以瀏覽器 CSPRNG 本地生成材料的按鈕

### Requirement: 換鑰精靈之切換指示依執行期 provider 分岔

換鑰精靈與金鑰管理頁上凡述及「如何完成 KEK 切換」之指示，SHALL 依**執行期 KEK provider**
呈現對應版本，SHALL NOT 無條件呈現單一模式之步驟。指示所依據之 provider SHALL 取自金鑰
清冊之執行期 provider 欄（由 provider 物件導出，見「KEK provider 之稽核證據雙軌」），
SHALL NOT 另由介面推論（如以「有封印狀態」反推模式為 `ui`）。

各模式之指示 SHALL 為：

- `env`：將新材料寫入 `ENCRYPTION_KEY` 並重啟後端服務，開機時完成切換。
- `ui`：重啟後端服務（重啟後回到封印狀態）後，**於解封頁輸入新材料**完成切換；
  且 SHALL 明確告知**不要**將新材料寫入 `.env` 或任何環境變數。此否定為本要求之核心：
  `ui` 模式之不變式為材料永不落地，照 `env` 指示操作即為自毀該不變式，
  介面 SHALL NOT 僅以省略 `env` 步驟為滿足——省略只是不再指示錯事，並未阻止操作者
  沿用他在其他文件讀到的 `env` 做法。
- `kms`／`hsm`（委託模式）：SHALL 指出其切換屬部署層之 provider 遷移並指向營運文件，
  SHALL NOT 於介面呈現未經查證之逐步指示。介面得陳述之已查證事實限於：本次重包之產物
  為本地材料（精靈之委託目標未開放），以及「自委託模式切回本地模式須經重包」。

執行期 provider 未知時（清冊尚未載入、載入失敗、欄位缺失，或值不屬已知模式集合），
介面 SHALL 呈現「請依部署之 `KEK_PROVIDER` 選擇」並列出各模式做法，**SHALL NOT 回落至
`env` 版本**。此 fail-safe 方向由誤判代價之不對稱決定：對 `env` 部署多要求一次辨識僅增加
一行閱讀，對 `ui` 部署預設呈現 `env` 版本則使根金鑰以明文落於磁碟。

上述文案 SHALL 具三語譯文，且各語言之否定 SHALL 維持禁止語氣，SHALL NOT 弱化為建議語氣；
環境變數名、模式值與檔名 SHALL NOT 被翻譯。

#### Scenario: ui 模式不指示寫入環境變數
- **WHEN** 執行期 provider 為 `ui`，管理員檢視換鑰精靈之完成步驟與金鑰管理頁之待切換提示
- **THEN** 指示 MUST 為「重啟後於解封頁輸入新 KEK」，MUST 含「不要寫入 `.env` 或環境變數」
  之明確告知，且 MUST NOT 出現「將新 KEK 寫入 `ENCRYPTION_KEY`」之步驟

#### Scenario: env 模式指示不受影響
- **WHEN** 執行期 provider 為 `env`
- **THEN** 指示 MUST 維持「寫入 `ENCRYPTION_KEY` → 重啟 → 開機完成切換」

#### Scenario: provider 未知不回落 env
- **WHEN** 清冊載入失敗或回應未含執行期 provider，管理員開啟換鑰精靈
- **THEN** 介面 MUST 呈現各模式做法並要求操作者依 `KEK_PROVIDER` 辨識，
  MUST NOT 逕自呈現 `env` 版本

#### Scenario: 委託模式不編造步驟
- **WHEN** 執行期 provider 為 `kms` 或 `hsm`
- **THEN** 介面 MUST 指出切換屬部署層之 provider 遷移並指向營運文件，
  MUST NOT 呈現任何未經查證之逐步指示

