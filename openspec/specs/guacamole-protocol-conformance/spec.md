# guacamole-protocol-conformance Specification

## Purpose
規範圖形協議（Guacamole 指令流）解析的正確性：指令長度前綴以 Unicode 字元數計算、依長度前綴界定指令邊界，以及協議解析失敗時不得造成審計盲點。

## Requirements

### Requirement: 指令長度前綴以 Unicode 字元數計算
Guacamole 協議指令的長度前綴 SHALL 為該值的 Unicode 字元數（codepoint），SHALL NOT 為位元組數。編碼與解碼兩側 MUST 採同一定義。

依 Apache Guacamole 協議規範，長度前綴計的是字元不是位元組。以位元組數編碼時，任何含多位元組字元的值都會產生大於實際字元數的前綴，導致對端 overread 並回報解析錯誤。

此缺陷在純 ASCII 輸入下**不可觀測**（該範圍內位元組數恆等於字元數），因此僅以英文測試資料無法發現；測試 MUST 包含多位元組值。

#### Scenario: 中文值的長度前綴
- **WHEN** 編碼一個含中文字元的參數值
- **THEN** 長度前綴為該值的字元數，而非其 UTF-8 位元組數

#### Scenario: 四位元組字元
- **WHEN** 編碼一個含 4 位元組 UTF-8 字元（如 emoji）的值
- **THEN** 該字元計為一個字元；長度前綴 SHALL NOT 依 UTF-16 code unit 計為二

#### Scenario: 純 ASCII 不變
- **WHEN** 編碼純 ASCII 值
- **THEN** 行為與既有實作相同（該範圍內兩種計法等價）

### Requirement: 指令解析依長度前綴界定邊界
解碼 SHALL 依長度前綴逐字元讀取以界定每個元素的邊界，SHALL NOT 以分隔符切分。

協議的值邊界由長度前綴界定，值本身合法地可以包含分隔符（`,` 與 `;`）。以分隔符切分等於放棄規範提供的邊界資訊，並使含分隔符的合法值被誤切。

實際會踩到的元素：檔案傳輸的檔名、視窗標題、log 與 error 的文字內容。

#### Scenario: 值內含逗號
- **WHEN** 解析一個元素值本身包含 `,` 的指令
- **THEN** 該值完整還原，不被切分

#### Scenario: 值內含分號
- **WHEN** 解析一個元素值本身包含 `;` 的指令
- **THEN** 指令邊界依長度前綴判定，不因值內的 `;` 提前結束

### Requirement: 協議解析失敗不得造成審計盲點
當協議指令因解析失敗而被丟棄時，若該指令屬受審計觀測的操作（檔案傳輸、剪貼簿），該次嘗試 SHALL NOT 在審計中完全消失。

解析失敗是合法的失敗模式（fail-closed 正確），但「失敗且無紀錄」使審計軌跡與實際發生的事不一致。使用者嘗試傳輸了一個檔案、傳輸沒有成功、而審計什麼都沒有——稽核無從得知該次嘗試存在。

#### Scenario: 檔名解析失敗仍留痕
- **WHEN** 檔案傳輸指令因檔名編碼問題而解析失敗
- **THEN** 該次嘗試在審計中留有可辨識的紀錄，即使檔名本身無法還原

### Requirement: guacd 握手在單一預算內完成並清理

正式圖形建線 SHALL 自開始撥 guacd 至完成 `ready` 共用不超過 30 秒的絕對期限，TCP 撥號 SHALL 同時保留不超過 10 秒的階段上限。若呼叫端期限更早，SHALL 採較早者。期限 SHALL 涵蓋 select、args、能力宣告、connect 與 ready 的全部讀寫，不因進入下一階段或收到部分指令而重新計時。

公開套件握手方法 SHALL 以方法開始時起算不超過 30 秒的單一握手預算；提供 context 的入口 SHALL 尊重較早期限及取消，無 context 的相容入口 SHALL 仍有有限預算。

期限到期或請求取消 SHALL 解除尚未完成的網路 I/O、關閉失敗 socket、結束握手工作並釋放所持鎖與憑證參照。取消路徑 SHALL NOT 依賴取得正被阻塞握手持有的 mutex，SHALL NOT 僅讓呼叫端返回而遺留阻塞工作。半包逾時後 SHALL 棄用該連線及 parser 狀態。

握手成功交接前 SHALL 停妥握手取消監視並清除握手所設的讀寫期限。已交接連線 SHALL NOT 受先前握手期限或取消回呼影響；通用指令讀取與已建線轉發 SHALL NOT 因此取得固定讀取期限。

正式建線握手失敗 SHALL 保持 WS 升級前的 HTTP 500 與 `INTERNAL_GUACD_HANDSHAKE` 泛化封套，不傳出底層原始錯誤，不新增逾時專碼或將此情形當作會話閒置逾時。已取消或斷開的呼叫端不要求收到回應，但後端 SHALL 完成清理。

#### Scenario: guacd 接受 TCP 後不送 args

- **WHEN** guacd 接受正式建線的 TCP 連線後不回任何協議指令
- **THEN** 建線於共用期限到期時失敗並關閉 socket，釋放 connection mutex，後續 Close 與就緒查詢可返回
- **AND** 未建立就緒連線或升級 WS；能回應的 HTTP 呼叫得到既有 500 泛化錯誤封套

#### Scenario: args 已消耗部分預算而 ready 不到

- **WHEN** args 在預算內收到，但 ready 尚未完整收到即達原絕對期限
- **THEN** 握手依原期限失敗並清理，不為 ready 重新給一段完整預算，也不在半包上重試

#### Scenario: 取消正在等待的握手

- **WHEN** 呼叫端在 args 或 ready 等待期間取消請求，或其較早 deadline 到期
- **THEN** 阻塞 I/O 被解除，握手工作退出，socket、持有鎖與憑證參照被釋放，不繼續等待預設 30 秒

#### Scenario: 成功後越過原握手期限

- **WHEN** 握手在期限前成功，交接後才越過原期限或發生先前父 context 的取消
- **THEN** 同一連線仍能接收後續合法指令，不被握手期限或殘留取消回呼關閉

#### Scenario: 公開握手相容入口遇無回應對端

- **WHEN** 呼叫端使用無 context 的公開握手方法，對端在 args 或 ready 階段不再回應
- **THEN** 方法於從入場起算的 30 秒握手預算內失敗並關閉該 socket；context 入口採相同清理語義且服從較早期限
