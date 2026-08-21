# oidc-auth Specification

## Purpose

外部身分提供者（OIDC）整合契約：provider 實例管理、authorization code 登入流程與 token 驗證強度、
准入控制與影子供應、外部身分對應、登入 gate chain 匯流、provider 停用／密鑰輪替的全面失效，
以及登入頁 SSO 入口與流程供應的濫用防護。
## Requirements
### Requirement: OIDC provider 實例管理
系統 SHALL 支援多個 OIDC provider 實例並存（同一部署可同時啟用 Azure AD、Okta、Google 等），每個實例含顯示名稱、issuer、client_id、client_secret、scopes、admission 模式與啟用狀態，由 admin 經 API 與管理頁 CRUD。client_secret SHALL 以信封加密落庫且為 write-only：任何讀取回應 SHALL NOT 含明文或密文，更新時空值 SHALL 沿用既有 secret 不覆寫。

issuer 與 client_id SHALL 於建立後不可變更，且 SHALL 由後端強制（不得僅以前端停用輸入達成）；`(issuer, client_id)` SHALL 唯一。provider SHALL NOT 被硬刪除：已有關聯外部身分時刪除 SHALL 回衝突錯誤，provider 識別碼 SHALL NOT 被重用。

#### Scenario: 多 provider 並存
- **WHEN** admin 建立並啟用兩個 provider（不同 issuer）
- **THEN** 登入方法清單同時含兩者，各自可獨立完成登入

#### Scenario: secret write-only
- **WHEN** admin 讀取 provider 清單或單筆詳情
- **THEN** 回應不含 client_secret 的明文或密文；更新時未附新 secret 則既有值不變

#### Scenario: 身分域欄位後端不可變
- **WHEN** 以 API 直接對既有 provider 送出變更 issuer 或 client_id 的請求（繞過前端）
- **THEN** 請求被拒絕並回明確錯誤碼，設定不變

#### Scenario: 有身分關聯不可刪
- **WHEN** admin 刪除一個已有使用者外部身分關聯的 provider
- **THEN** 回衝突錯誤並提示改用停用，資料不變

### Requirement: OIDC 登入流程與驗證強度
OIDC 登入 SHALL 採 authorization code flow：begin 端點產生授權重導向、callback 端點完成 code 交換與 id_token 驗證。state、nonce 與 PKCE(S256) SHALL 恆啟用（非可關閉選項）。

id_token 驗證 SHALL 至少涵蓋：以 provider JWKS 驗簽且簽章演算法 SHALL 限於封閉允許集合 `RS256`、`ES256`（其餘一律拒絕，含對稱演算法、`none` 與未列入的非對稱演算法）；本地允許集合 SHALL 與 provider discovery 宣告集合取交集，交集為空時該 provider SHALL 不可用、`iss` 完整字串比對、`aud` 含 client_id、多 audience 時 `azp` 等於 client_id、`exp`/`iat`/`nbf` 時間檢查（SHALL 採有界的時鐘偏移容忍）、`nonce` 比對、`sub` 為非空且長度受限的字串（SHALL 以原值比對，SHALL NOT 正規化）。任一驗證失敗 SHALL 拒絕登入且 SHALL NOT 供應帳號。

endpoint 解析 SHALL 由後端於執行期以 issuer 的 OIDC discovery 完成。系統 SHALL NOT 要求 discovery 所得的 endpoint 與 issuer 同源（真實身分提供者的 token 與 JWKS endpoint 常位於不同主機，強制同源將使其無法接入）。

對 IdP 的所有出站連線 SHALL 使用 https 並強制 TLS 憑證驗證，且 SHALL NOT 提供關閉開關。唯一例外：非 release 模式下，明確列於開發靶機允許清單的單一主機名稱得使用 http，且該 provider 的全部 endpoint SHALL 落在同一主機名稱；release 模式 SHALL NOT 有任何例外。出站目標解析所得的網路位址 SHALL NOT 落於 loopback、link-local（含雲端 metadata 位址）或私有網段，且該檢查 SHALL 於每次連線時進行（拒絕先解析為公網位址、隨後改指內部位址的重繫結攻擊）；內部網路的身分提供者 SHALL 僅能經明確的主機允許清單放行。release 模式下 issuer SHALL 為 https。

授權請求的 scope SHALL 恆含 `openid`；附加 scope SHALL 限於允許清單，未知 scope SHALL 於設定時即拒絕。

時鐘偏移容忍 SHALL 為 ±60 秒。

#### Scenario: state 不符拒絕
- **WHEN** callback 收到的 state 與本流程簽發值不符（或缺失）
- **THEN** 拒絕登入、不與 IdP 交換 code，事件入審計

#### Scenario: 驗簽失敗拒絕
- **WHEN** id_token 簽章無法以該 provider 的 JWKS 驗證通過（含演算法不在允許集合）
- **THEN** 拒絕登入且不供應帳號

#### Scenario: 跨 client 的 token 被拒
- **WHEN** id_token 帶多個 audience 且 `azp` 不等於本 provider 的 client_id
- **THEN** 拒絕登入

#### Scenario: 空 subject 被拒
- **WHEN** id_token 的 `sub` 缺失或為空字串
- **THEN** 拒絕登入且不建立任何外部身分記錄

#### Scenario: 後端 discovery
- **WHEN** admin 僅填 issuer 建立 provider
- **THEN** 登入流程可完成（authorization/token/jwks endpoint 由後端自 discovery 解析），無須手填 endpoint

#### Scenario: 不同主機的 endpoint 可接入
- **WHEN** provider 的 discovery 文件宣告的 token 與 jwks endpoint 位於與 issuer 不同的主機（真實公有身分提供者的常態）
- **THEN** 登入流程可正常完成，不因主機不同而拒絕

#### Scenario: 內部位址的出站被拒
- **WHEN** provider 的 issuer 或 discovery 所得 endpoint 解析至 loopback、link-local 或私有網段且未列於允許清單
- **THEN** 拒絕對該位址發出請求，該 provider 不可用

#### Scenario: release 模式拒 http issuer
- **WHEN** 於 release 模式啟用 issuer 為 http 的 provider
- **THEN** 拒絕啟用並回明確錯誤

#### Scenario: 未知 scope 於設定時拒絕
- **WHEN** admin 為 provider 設定允許清單以外的 scope
- **THEN** 設定被拒絕並回明確錯誤

### Requirement: 流程狀態與交棒憑證的安全性質
begin 產生的流程狀態（state、nonce、PKCE verifier）SHALL 由伺服端保存、SHALL 一次性消費，且消費 SHALL 於單一原子操作中「僅在未過期時取用並失效」——過期記錄即使尚未被清理排程移除亦 SHALL 拒絕。

流程 SHALL 綁定發起登入的瀏覽器：begin SHALL 記錄由發起端產生之秘密的雜湊，交換階段 SHALL 要求提出該秘密原文；未能提出者 SHALL 拒絕（僅持有 callback URL 或交棒憑證 SHALL NOT 足以取得會話）。

callback 至前端的交棒憑證 SHALL 一次性、SHALL 於短時效（≤60 秒）內失效、SHALL 僅以 URL fragment 傳遞、SHALL 於伺服端僅存雜湊、且 SHALL NOT 出現於任何日誌。瀏覽器綁定不符時 SHALL NOT 消耗該憑證（使正常使用者得於原發起環境重試），但 SHALL 以原子方式累計失敗次數，達三次即作廢；累計 SHALL 與成功兌換互斥。

流程狀態 SHALL 記錄簽發當下的 provider 憑證世代（流程發起時尚未認證，SHALL NOT 要求其記錄使用者憑證世代）。**與使用者綁定的憑證**（交棒憑證、待驗證狀態憑證、存取與刷新憑證、連線授權憑證）SHALL 記錄簽發當下的 provider 憑證世代**與使用者憑證世代**，並於消費時比對兩者的現行值，任一不符 SHALL 拒絕。

使用者憑證世代 SHALL 於「該使用者既有憑證應失效」時推進——管理者的顯式動作（帳號停用、刪除、改為僅外部登入、解除外部身分綁定、**變更其角色集**）與使用者自身的密碼變更皆屬之——其中角色變更 SHALL 於「新角色集與現行角色集不同」時推進，相同時 SHALL NOT 推進（純追加角色而不移除任何既有角色的路徑亦 SHALL NOT 推進，其不縮減權限）；**任何換發路徑所簽出的憑證 SHALL 攜帶簽發當下現查的世代，SHALL NOT 繼承來源憑證的世代值**（否則推進世代的操作本身會使其換發的新憑證立即失效，例如強制改密者將永久無法取得可用會話）；**因連續認證失敗而自動鎖定 SHALL NOT 推進**——鎖定可由未認證第三方觸發，若使既有存取立即失效即成為遠端斷線武器（既有設計刻意只撤刷新憑證、保留既有存取憑證與協議會話），使**尚未兌換**的能力憑證一併失效——僅掃描既有連線無法涵蓋這些憑證，且身分重新綁定時舊憑證會復活。

**凡以既有身分或憑證產生新長效能力的位置**（建立協議會話、加入唯讀訂閱、簽發交棒憑證、換發會話、輪替刷新憑證），SHALL 於對應範圍的鎖內完成「重查前提仍成立 → 讀取當下世代 → 建立」三步；推進世代的操作 SHALL 取用同一把鎖。否則已通過檢查而尚未建立者會錯過撤銷掃描而存活，或以推進後的新世代建立憑證而使撤銷失效。同時需取用多把鎖時 SHALL 採固定取鎖順序以避免死鎖。

其中**簽發交棒憑證**尤須注意：流程狀態不攜帶使用者世代（發起時尚未認證），交棒憑證是第一個攜帶者——若其簽發未與撤銷序列化，已被解除綁定的身分可在撤銷完成後才簽出帶新世代的憑證，據以取得會話。世代比對 SHALL 涵蓋**所有**憑證使用點，包括不經一般認證中介層的 WebSocket 連線端點（以查詢參數攜帶憑證的旁路）——遺漏該旁路將使停用後仍可建立連線或會話監看。憑證宣稱之 provider 已不存在時 SHALL 拒絕（不得視為「無 provider」而放行）。callback 回應 SHALL 禁止 referrer 外送與快取。

登入後的重導向目標 SHALL 限於同源相對路徑且符合既有路由白名單；scheme-relative、絕對 URL、反斜線或多重編碼形式 SHALL 被拒絕並退回預設路徑。已驗證的重導向目標 SHALL 隨交棒憑證保存並於交換成功後回傳，SHALL NOT 於交換階段重新採信前端提交值。

#### Scenario: 跨瀏覽器轉移的 callback 失敗
- **WHEN** 攻擊者自行發起流程並完成 IdP 授權後，將 callback URL 交給另一瀏覽器開啟並嘗試交換
- **THEN** 交換因缺少發起端秘密而失敗，不建立任何會話

#### Scenario: 交棒憑證一次性
- **WHEN** 同一交棒憑證被第二次提交交換
- **THEN** 第二次被拒絕

#### Scenario: 撤銷期間的交棒憑證簽發不得漏網
- **WHEN** callback 已完成 token 驗證與身分查找但尚未簽發交棒憑證時，管理者解除該外部身分綁定並完成撤銷掃描
- **THEN** 該次 callback SHALL NOT 簽出可用的交棒憑證（其前提已於鎖內重查而不成立）

#### Scenario: 綁定不符可重試但有限
- **WHEN** 同一交棒憑證連續三次以錯誤的瀏覽器綁定提交交換
- **THEN** 前兩次失敗但憑證仍可於正確環境使用，第三次後憑證作廢

#### Scenario: 過期即拒
- **WHEN** 流程狀態或交棒憑證已逾期但清理排程尚未執行，仍被提交消費
- **THEN** 拒絕

#### Scenario: 開放重導向被拒
- **WHEN** begin 帶入外部絕對網址或 scheme-relative 形式作為登入後重導向目標
- **THEN** 該目標被拒絕，登入完成後導向預設路徑

### Requirement: 自動供應的准入控制
每個 provider SHALL 具備 admission 模式，且預設 SHALL 為「僅允許已綁定身分登入」（不自動供應）。啟用自動供應時 SHALL 附帶至少一條准入規則（租戶識別、hosted domain、email 網域或等價的 claim 述詞）；規則集為空的自動供應組態 SHALL 被拒絕。採用 email 類規則時 SHALL 同時要求 email 已驗證。

**准入判定 SHALL 於每次認證求值**，不僅於首次供應——規則收緊或使用者 claim 變更後，既有身分再次登入 SHALL 依現行規則判定。認證流程順序 SHALL 為：驗證 token → 查身分 → 依現行模式求值准入 → 通過後才更新最近登入時間或供應帳號；身分已存在 SHALL NOT 使准入判定被略過。未通過者 SHALL 拒絕登入且 SHALL NOT 建立帳號，事件 SHALL 入審計。

規則語義 SHALL 完全確定：不同規則之間為 AND、同一規則的允許清單內為 OR；claim 缺失、為 null 或型別不符 SHALL 視為不匹配；已驗證旗標類 claim SHALL 僅接受布林真值。未知或畸形的規則鍵 SHALL 於設定時即拒絕（SHALL NOT 於執行期被忽略）。規則求值 SHALL 僅取用已通過簽章與 issuer/audience 驗證的 id_token claims。

使用共用身分域（同一 issuer 服務多個組織與個人帳號）的 provider，其規則集 SHALL 包含至少一條組織歸屬類規則（租戶識別或 hosted domain）；僅以 email 網域為條件的組態 SHALL 被拒絕——email 可由個人帳號綁定任意已驗證地址，不足以證明組織歸屬。

身分域是否為共用 SHALL 由系統依固定優先序**於每次判定時計算**（輸入為 canonical issuer、管理者收緊標記與部署層宣告），SHALL NOT 將計算結果持久化為單一標記（否則來源不可分辨，且宣告移除後舊值仍生效）：內建共用清單命中者為共用（最高優先）、管理者收緊標記次之、部署層專用宣告再次之、其餘一律視為共用（fail-close）。管理者 SHALL 僅能收緊（標記為共用），SHALL NOT 放寬。部署層宣告或內建清單變更時，系統 SHALL 重新驗證既有 provider 的規則集合規性，不合規者 SHALL fail-close 停止自動供應並於管理端標示。系統 SHALL 提供**部署層**（非管理者 API）的專用身分域宣告途徑，使不發送組織歸屬 claim 的身分提供者（企業專屬租戶網址、自架服務）得以組態自動供應；內建的共用清單 SHALL 優先於該宣告（已知共用身分域 SHALL NOT 被宣告為專用）。

採用租戶識別規則時，允許清單 SHALL NOT 接受身分提供者的消費者（個人帳號）租戶識別值——納入該值等同放行全部個人帳號。

自動供應模式切換為 `prebound_only` 時，先前經自動供應建立的身分 SHALL 繼續有效（沿用），管理介面 SHALL 於切換時明示既有身分數量與此語義——切換 SHALL NOT 被誤解為即時收回既有存取。

`prebound_only` 模式的准入判定即「身分是否已綁定」，其效力 SHALL 被明確理解為：可擋身分提供者端已停用的帳號，但**不涵蓋帳號仍存續而組織歸屬已變更**的情形；需涵蓋後者的部署 SHALL 採自動供應模式並設組織歸屬規則。此限制 SHALL 於管理介面明示。

#### Scenario: 共用 issuer 的外部帳號被拒
- **WHEN** provider 使用共用 issuer（如公用消費者身分服務）且設定 hosted domain 規則，一個不屬該網域的外部帳號完成 IdP 認證
- **THEN** 拒絕登入、不建立帳號，審計記錄准入拒絕事件

#### Scenario: 無規則的自動供應組態被拒
- **WHEN** admin 將 provider 設為自動供應但未提供任何准入規則
- **THEN** 設定被拒絕並回明確錯誤

#### Scenario: 預設不自動供應
- **WHEN** provider 以預設模式建立，未綁定身分的使用者完成 IdP 認證
- **THEN** 拒絕登入，提示需由管理員綁定

#### Scenario: 切換為僅預先綁定不收回既有身分
- **WHEN** provider 自自動供應模式切換為僅預先綁定模式，一名先前經自動供應建立身分的使用者再次登入
- **THEN** 登入成功（既有身分沿用），且管理介面於切換時已明示此語義與既有身分數量

#### Scenario: 規則收緊後既有身分被拒
- **WHEN** 一名使用者已通過准入並完成供應，其後 admin 收緊准入規則（或該使用者的相關 claim 已不符），該使用者再次登入
- **THEN** 拒絕登入且不發放會話，審計記錄准入拒絕事件

#### Scenario: 未知規則鍵於設定時拒絕
- **WHEN** admin 提交含未知規則鍵的准入規則集
- **THEN** 設定被拒絕並回明確錯誤（不得存入後於執行期被忽略）

#### Scenario: 專屬身分提供者可組態自動供應
- **WHEN** 部署方於部署層宣告某企業專屬身分提供者的 issuer 為專用，admin 為其設定僅含 email 網域的准入規則
- **THEN** 設定被接受，該 provider 的自動供應可正常運作

#### Scenario: 移除部署層宣告後立即回復共用
- **WHEN** 部署方移除某 issuer 的專用宣告，該 provider 原本僅設定 email 網域規則
- **THEN** 該 provider 即被視為共用身分域，其自動供應因規則不足而 fail-close 停止，管理端標示需補組織歸屬規則

#### Scenario: 已知共用身分域不可經部署層宣告為專用
- **WHEN** 部署方將內建共用清單中的 issuer 加入部署層專用宣告
- **THEN** 該宣告不生效，該 provider 仍被視為共用身分域

#### Scenario: 共用身分域不可被放寬為專用
- **WHEN** admin 嘗試將系統判定為共用身分域的 provider 標記為專用
- **THEN** 操作被拒絕並回明確錯誤

#### Scenario: 消費者租戶識別值不可加入允許清單
- **WHEN** admin 將身分提供者的消費者租戶識別值加入租戶允許清單
- **THEN** 設定被拒絕並回明確錯誤

#### Scenario: 共用身分域拒絕僅 email 網域規則
- **WHEN** admin 為使用共用身分域的 provider 設定僅含 email 網域的准入規則
- **THEN** 設定被拒絕並回明確錯誤（須加入組織歸屬類規則）

#### Scenario: claim 缺失視為不匹配
- **WHEN** 准入規則要求某 claim，而 id_token 未帶該 claim 或其型別不符
- **THEN** 判定為不匹配並拒絕登入

### Requirement: 外部身分對應與影子供應
外部身分 SHALL 以身分域（issuer 與 client_id）與 subject 的組合為唯一鍵獨立於使用者本體儲存，一個使用者可關聯多筆外部身分。SHALL NOT 以 provider 記錄識別碼作為身分唯一鍵——provider 重建或替換 SHALL NOT 使既有身分失效。

通過准入判定且無對應外部身分時 SHALL 供應影子用戶（預設 user 角色、無可用本地密碼），供應、角色綁定與外部身分建立 SHALL 於同一交易完成。SHALL NOT 以 username 靜默接管既有帳號：映射所得 username 已存在且該帳號無此外部身分時 SHALL 拒絕登入並落審計事件。回訪時 SHALL 以身分鍵對應回同一帳號。

屬性映射 SHALL 為固定順序且可觀測：username 取 `preferred_username`，缺則取已驗證 email 的本地部分，再缺則取 subject；email 僅在其已驗證旗標為真時採用，否則存 NULL，衝突時亦存 NULL 不阻斷供應；顯示名取 `name`，缺則留空。**未驗證的 email SHALL NOT 用於 username 映射、email 欄位或准入判定**；已驗證旗標 SHALL 僅接受布林真值（字串形式不算）。**回訪 SHALL NOT 改寫既有帳號的 username、email 或顯示名**——username 是授權主體識別，靜默變更會使既有授權與審計歸屬失準。回訪 SHALL 更新外部身分列的最近登入時間與其 claim 快照（身分提供者端自報的使用者名稱與已驗證 email）；快照 SHALL 僅保存已驗證的 email、SHALL 受長度上限與控制字元拒絕約束，且於管理介面 SHALL 明確標示為身分提供者自報值並與本地使用者名稱分欄呈現——快照內容完全由外部控制，混排會使管理者誤判身分。

並發首登 SHALL 收斂為單一帳號：交易因唯一約束失敗時 SHALL 重查身分鍵，命中即視為登入成功，SHALL NOT 落衝突安全事件。

#### Scenario: 首登供應
- **WHEN** IdP 驗證與准入判定通過且身分鍵無對應
- **THEN** 建立影子用戶並綁 user 角色，外部身分記錄身分域與 subject，登入成功

#### Scenario: 同名不接管
- **WHEN** 映射所得 username 與既有帳號同名且該帳號無此外部身分
- **THEN** 拒絕登入（不登入既有帳號、不建新帳號），審計事件含衝突標註

#### Scenario: 回訪以 subject 對應
- **WHEN** IdP 端使用者改名（username claim 變更）但 subject 不變，再次登入
- **THEN** 以身分鍵對應回同一帳號，不建重複帳號

#### Scenario: 停用後重新啟用不失效
- **WHEN** admin 停用某 provider 後再重新啟用
- **THEN** 既有外部身分仍可對應，使用者無須重新綁定即可登入

#### Scenario: 輪替 client_secret 不改變身分
- **WHEN** admin 原地更新某 provider 的 client_secret
- **THEN** 既有外部身分不變，使用者照常登入且不建立新身分記錄

#### Scenario: 同 issuer 不同 client_id 身分隔離
- **WHEN** 兩個 provider 使用相同 issuer 但不同 client_id，同一 subject 分別自兩者登入
- **THEN** 兩者屬不同身分域，不得互相接管既有帳號

#### Scenario: 快照不得偽裝為本地身分
- **WHEN** 外部使用者將其身分提供者端的使用者名稱設為與某管理員帳號相同的字串並登入
- **THEN** 本地帳號屬性不變，管理介面顯示該值時標示為外部自報值且與本地使用者名稱分欄，不致被誤認

#### Scenario: 回訪不改寫既有屬性
- **WHEN** 使用者於 IdP 端變更顯示名或 email 後再次登入
- **THEN** 本地帳號的 username、email、顯示名不變，僅最近登入時間更新

#### Scenario: 並發首登只建一個帳號
- **WHEN** 同一 subject 於兩個瀏覽器幾乎同時完成首次登入
- **THEN** 只產生一個帳號、兩次登入皆成功，且不產生衝突安全事件

### Requirement: 登入 gate chain 匯流
OIDC 驗證成功後 SHALL 匯入既有登入後段：帳號停用/鎖定檢查、MFA 疊加（已註冊 TOTP 者 SHALL 進入既有兩階段流程、受 MFA 強制政策者 SHALL 進入既有註冊流程）、發放正式會話前的鎖定複查、最近登入時間更新與審計。

密碼類 gate（強制改密、密碼政策合規、密碼有效期）SHALL 依**本次登入所使用的認證方式**判定：僅以本地密碼認證的登入適用；經外部身分提供者認證的登入 SHALL NOT 適用。帳號同時具備本地密碼與外部身分時，兩種登入方式各依其性質判定。

MFA 待驗證狀態 SHALL 攜帶不可竄改的認證脈絡（provider 與認證方式）；**所有正式會話發放點**（含 MFA 驗證完成與強制註冊完成）SHALL 重新載入帳號與 provider 並檢查啟用/鎖定/停用狀態。登入審計 SHALL 標註認證方式與 provider，且 SHALL 於 MFA 完成路徑一併保留。

#### Scenario: MFA 疊加
- **WHEN** 已啟用 TOTP 的使用者以 OIDC 登入且 IdP 驗證通過
- **THEN** 不直接發正式會話，進入既有 MFA 第二階段，驗證通過才發 token

#### Scenario: 外部登入不觸發密碼 gate
- **WHEN** 部署設有密碼有效期政策，一個無本地密碼的外部身分使用者經 OIDC 完成登入（含經 MFA 第二階段）
- **THEN** 直接取得正式會話，不進入強制改密流程

#### Scenario: 混合帳號各依方式判定
- **WHEN** 一個具本地密碼且已綁外部身分的帳號，其本地密碼已逾有效期
- **THEN** 以本地密碼登入時進入強制改密；以 OIDC 登入時正常取得會話

#### Scenario: MFA 完成時複查 provider
- **WHEN** 使用者已進入 MFA 待驗證階段，此時 admin 停用該 provider，使用者才提交 TOTP
- **THEN** 拒絕發放正式會話

#### Scenario: 停用帳號拒絕
- **WHEN** 已停用帳號對應的外部身分完成 IdP 認證
- **THEN** 拒絕登入

### Requirement: 外部身分帳號的憑證路徑封閉
憑證已外部化的帳號 SHALL NOT 經本地密碼路徑登入（即使密碼欄位存有值），SHALL NOT 由管理員設定或重設本地密碼，亦 SHALL NOT 經自助改密設定密碼；相關嘗試 SHALL 回明確錯誤並入審計。此規則 SHALL 由後端強制（不得僅以前端停用按鈕達成）。

**帳號 SHALL NOT 被未顯式綁定的憑證路徑接管**：OIDC 登入 SHALL 僅接受已明確綁定的外部身分；OIDC 供應的帳號 SHALL NOT 因使用者名稱相同而落入目錄驗證路徑。認證分派 SHALL 明確區分三類（目錄／本地／其他外部），SHALL NOT 以二分邏輯將非目錄的外部帳號落入目錄驗證路徑。經管理者顯式綁定的路徑不受此限（例如目錄供應帳號被綁定外部身分後，得經該身分登入）。

#### Scenario: admin 無法為外部帳號設密碼
- **WHEN** admin 對一個 OIDC 供應帳號呼叫重設密碼
- **THEN** 請求被拒絕並回明確錯誤碼，帳號密碼不變

#### Scenario: 外部帳號無法本地登入
- **WHEN** 以 OIDC 供應帳號的使用者名稱與任意密碼提交本地登入
- **THEN** 登入失敗，且不因密碼欄位比對結果而放行

#### Scenario: 外部帳號的本地登入嘗試不鎖定帳號亦不洩漏成因
- **WHEN** 未認證者以某 OIDC 供應帳號的使用者名稱與任意密碼反覆提交本地登入
- **THEN** 每次皆失敗且回應的錯誤碼與訊息與一般憑證錯誤相同（不另設可據以辨識帳號類型的專屬碼）；該帳號 SHALL NOT 因此被鎖定，其正常的外部登入不受影響

#### Scenario: OIDC 帳號不得以目錄憑證登入
- **WHEN** 系統同時啟用目錄認證與 OIDC，一個 OIDC 供應帳號的使用者名稱在目錄中亦存在，並以目錄憑證提交登入
- **THEN** 登入被拒絕並入審計（該帳號 SHALL NOT 被目錄憑證接管）

### Requirement: provider 停用的全面失效
provider 停用後 SHALL 於下列每個階段生效：登入方法清單不列、begin 拒絕、callback 拒絕、交換拒絕、MFA 完成與強制註冊完成拒絕發放會話。

provider 停用 SHALL 推進其憑證世代，且**重新啟用 SHALL NOT 回復舊世代**：所有由該 provider 認證簽發的憑證（流程狀態、交棒憑證、待驗證狀態憑證、存取憑證、刷新憑證）SHALL 記錄簽發當下的世代，驗證時世代不符 SHALL 拒絕。僅檢查「provider 當下是否啟用」SHALL NOT 視為滿足本要求——否則停用後短時間內重新啟用會使攻擊者持有的未過期憑證全部復活。

provider 刪除 SHALL 先執行與停用相同的全套失效動作（於同一序列化範圍內），否則已建立的協議連線將永久失去可按 provider 收線的途徑。

provider 的用戶端密鑰輪替 SHALL 推進其憑證世代，**並 SHALL 執行與停用相同的既有存取失效流程**（撤銷刷新憑證、拒絕既簽存取憑證、終斷進行中協議連線與唯讀訂閱）。輪替的動機是舊密鑰可能已洩漏；僅推進世代而不終斷既有連線並不足夠——進行中的協議連線與訂閱建立後不再使用憑證，世代推進對其無效。

停用 SHALL 使**經該 provider 認證所建立**的既有存取全面失效（**程序內狀態——唯讀訂閱與錄影存取憑證——的即時失效保證以單一應用實例部署為前提**；多實例部署下他實例的程序內狀態需跨實例通知機制，屬既有的高可用性前置工作）：撤銷其會話刷新憑證、**拒絕仍在有效期內的既簽存取憑證**（不得僅等待其自然到期）、終斷其衍生的進行中協議連線、收線其建立的唯讀訂閱（會話監看與會話分享觀看皆屬之），**並撤銷其持有的錄影存取憑證**（該類憑證雖短時效，其授權讀取的錄影含完整終端畫面，不得留有例外窗口）（監看訂閱不產生協議會話記錄，故不會被協議連線的終斷涵蓋；監看可讀取他人終端內容，遺漏即等同持續洩漏）（緊急切斷語義：停用的現實動機是身分提供者遭入侵或合約終止）。

為此，認證脈絡（認證方式、provider 與憑證世代）SHALL 隨會話全鏈保存：存取憑證（**含刷新換發的新存取憑證**）、刷新憑證（**輪替時 SHALL 原樣繼承**）、連線授權憑證與協議會話記錄皆須可回溯其 provider。協議連線的建立途徑不攜帶原始認證憑證時，SHALL 由簽發連線授權憑證的階段傳遞該脈絡；此脈絡為**溯源記錄，SHALL NOT 作為授權判定依據**（授權一律以現查為準）。連線兌換階段 SHALL 複查其 provider 仍啟用且世代相符。撤銷範圍 SHALL 以「該會話由哪個 provider 認證建立」判定，SHALL NOT 僅以帳號的供應來源判定——否則事後綁定外部身分的本地帳號會漏撤銷，而綁多個 provider 的帳號會被過度撤銷。脈絡缺值（升級期既有資料）SHALL 視為本地，不受任何 provider 停用影響。

#### Scenario: 停用即失效
- **WHEN** admin 停用某 provider 後，使用者以先前取得的授權重導向完成 IdP 認證並回到 callback
- **THEN** callback 拒絕、不建立會話，事件入審計

#### Scenario: 停用撤銷該 provider 建立的會話
- **WHEN** admin 停用某 provider
- **THEN** 經該 provider 認證建立的會話刷新憑證失效、其進行中協議連線終斷

#### Scenario: 混合帳號的本地會話不受牽連
- **WHEN** 一個具本地密碼且綁有外部身分的帳號，同時存在「以本地密碼登入」與「以該 provider 登入」兩個會話，admin 停用該 provider
- **THEN** 該 provider 建立的會話被撤銷，以本地密碼建立的會話不受影響

#### Scenario: 停用後 WebSocket 旁路亦拒絕
- **WHEN** admin 停用某 provider 後，使用者以停用前取得的存取憑證，經查詢參數攜帶憑證的 WebSocket 端點（連線或會話監看）發起請求
- **THEN** 請求被拒絕（該旁路不經一般認證中介層，仍須執行相同的世代與啟用檢查）

#### Scenario: 密鑰輪替亦終斷既有連線
- **WHEN** admin 因疑似密鑰洩漏而輪替某 provider 的用戶端密鑰，該 provider 既有的協議連線與監看訂閱仍在進行中
- **THEN** 這些連線與訂閱被終斷（不得因「連線已建立、不再使用憑證」而存活）

#### Scenario: 停用收線監看訂閱
- **WHEN** 一位經該 provider 認證的管理者正監看某條由本地帳號建立的會話，admin 停用該 provider
- **THEN** 該監看訂閱被收線，不再接收任何終端內容（即使被監看的會話本身不屬該 provider）；會話分享的觀看訂閱同受此治理

#### Scenario: 重新啟用不復活舊憑證
- **WHEN** 一個 OIDC 會話至少經過一次刷新輪替後，admin 停用該 provider 並隨即重新啟用
- **THEN** 停用前簽發的存取憑證、待驗證憑證與交棒憑證**永久**被拒（不因重新啟用而恢復），新的登入流程正常可用

#### Scenario: 事後綁定的帳號不漏撤銷
- **WHEN** 一個 local 供應的帳號事後綁定外部身分並以該 provider 登入，admin 隨後停用該 provider
- **THEN** 該次 provider 認證建立的會話被撤銷（不因帳號供應來源為 local 而遺漏）

### Requirement: 簽章金鑰輪替與可用性
未知金鑰識別碼 SHALL 觸發 JWKS 重新取得，且該重取 SHALL 受最小間隔（60 秒）節流以防放大攻擊。JWKS 快取 SHALL 有最大陳舊時間上限（24 小時）：超過上限即 SHALL 強制重取，重取失敗 SHALL NOT 以逾期快取放行；身分提供者宣告的快取期限長於此上限時 SHALL 以本上限為準。已自 JWKS 移除的金鑰 SHALL 於重取後不再被接受（最遲於最大陳舊時間內失效）。取得 JWKS 失敗且出現未知金鑰識別碼時 SHALL fail-close 拒絕登入。

#### Scenario: 輪替後接受新金鑰
- **WHEN** IdP 以新的金鑰識別碼簽發 id_token
- **THEN** 系統重新取得 JWKS 並驗證通過

#### Scenario: 已移除金鑰於上限內失效
- **WHEN** 某金鑰已自 JWKS 移除，且距上次成功取得已超過最大陳舊時間
- **THEN** 以該金鑰簽發的 id_token 被拒絕

#### Scenario: JWKS 不可達時拒絕
- **WHEN** provider 的 JWKS 端點暫時不可達且出現未知金鑰識別碼的 id_token
- **THEN** 拒絕登入（不放行）

#### Scenario: 未知 kid 的重取受節流
- **WHEN** 短時間內連續出現大量不同的未知金鑰識別碼
- **THEN** 對 JWKS 端點的重取次數受最小間隔約束，不隨請求量線性放大

### Requirement: 登入頁 SSO 入口
登入頁 SHALL 為每個啟用且設定完整的 provider 顯示一顆顯式按鈕（顯示名稱可辨識），SHALL NOT 自動跳轉至任一 IdP，本地帳密表單 SHALL 恆可見。設定不完整（如缺對外基準網址）的 provider SHALL NOT 出現於清單。登入方法清單 SHALL 由未認證可讀的端點提供且不洩漏 provider 憑證設定；該端點不可用時前端 SHALL 降級為僅顯示本地表單。

#### Scenario: 顯式按鈕不自動跳轉
- **WHEN** 部署啟用了一或多個 provider，使用者開啟登入頁
- **THEN** 頁面顯示本地表單與各 provider 按鈕，停留於登入頁不自動重導向

#### Scenario: 清單不洩漏設定
- **WHEN** 未認證請求登入方法清單
- **THEN** 回應僅含識別與顯示所需欄位，不含 client_id/client_secret/issuer 等設定值

#### Scenario: 設定不完整不顯示
- **WHEN** 部署未設定對外基準網址而有 provider 啟用
- **THEN** 該 provider 不出現於登入頁，管理頁以狀態標示其設定不完整

#### Scenario: 清單端點不可用時降級
- **WHEN** 登入方法清單端點回錯誤（如系統處於封印狀態）
- **THEN** 登入頁仍可正常顯示本地帳密表單

### Requirement: 流程供應的濫用防護
未認證的 begin 端點 SHALL 受速率與容量限制：SHALL 對來源施加速率限制，並 SHALL 對未消費流程狀態設全域容量上限，達上限時 SHALL 拒絕新請求而不再寫入儲存。全域容量上限 SHALL NOT 依賴任何客戶端可控輸入（來源位址在未設定可信代理時可被偽造，故不得作為唯一防線）。

**callback 端點與交換端點** SHALL 同時受來源速率限制與**全域速率上限**約束。callback 對無效、缺失或過期流程狀態的事件 SHALL 以聚合方式記錄（公開端點且失敗於狀態查找階段即發生，無須接觸身分提供者，逐筆持久化會成為無界寫入載體）。未設定可信代理時，來源位址 SHALL 取自連線對端，SHALL NOT 採信轉送標頭。已被限流的失敗 SHALL 以聚合方式記錄，SHALL NOT 逐請求持久化——否則偵測機制本身成為無界寫入的載體。

#### Scenario: 洪水下儲存量有界
- **WHEN** 未認證來源持續高速呼叫 begin（含偽造來源位址標頭）
- **THEN** 流程狀態儲存量維持有界，已發起的正常流程仍可完成交換

#### Scenario: callback 洪水下審計寫入有界
- **WHEN** 攻擊者持續以隨機流程狀態值呼叫 callback 端點
- **THEN** 請求被限流，審計與資料庫寫入量維持有界

#### Scenario: 交換洪水下審計寫入有界
- **WHEN** 攻擊者輪換偽造的轉送標頭並持續以隨機交棒憑證呼叫交換端點
- **THEN** 請求被限流，審計與資料庫寫入量維持有界

### Requirement: OIDC 登入成功留痕

OIDC 驗證成功並簽出正式會話時，系統 SHALL 寫入審計列，且 SHALL 由 handler 層寫入以取得來源欄位——service 層無法取得請求脈絡，其寫入必然缺少來源位址、路徑、方法與狀態碼。

該列 SHALL 標註認證方式為 OIDC 並帶出 provider 識別；`resource` SHALL 為 `auth`、`status` SHALL 為成功。

首次登入即時建立帳號（JIT provisioning）SHALL 另留一筆帳號建立的審計列，SHALL NOT 僅在衝突時才留痕。

多因素驗證啟用時，OIDC 驗證通過但尚待第二因素的階段 SHALL 記為待驗證狀態；正式會話的成功列 SHALL 由多因素流程寫入，兩者 SHALL NOT 重複記錄同一次登入成功。

#### Scenario: SSO 登入成功留痕

- **WHEN** 使用者經外部身分提供者完成驗證並取得正式會話
- **THEN** audit_logs 新增一筆成功登入列，含來源位址、路徑、狀態碼，且標註認證方式與 provider

#### Scenario: 首登建帳號留痕

- **WHEN** 外部身分首次登入且系統即時建立本地帳號
- **THEN** audit_logs 另留一筆帳號建立列，可查明該帳號的來源身分提供者

#### Scenario: 多因素不重複記錄

- **WHEN** OIDC 驗證通過且系統要求第二因素
- **THEN** 該階段記為待驗證，正式會話成功列僅由多因素流程寫入一次

### Requirement: OIDC 失敗留痕的欄位完整性與狀態語義

OIDC 流程的**逐筆**失敗留痕 SHALL 具備來源位址、路徑、方法與狀態碼；`resource` SHALL 為 `auth`，SHALL NOT 為 `user`。

**聚合列例外**：逾界後合併的聚合列涵蓋一個時間窗內的多個請求，其路徑、方法與狀態碼 SHALL 留空——結清該窗的請求並非事主，填入任一請求的值會使聚合列指向錯誤的單一事件。聚合列 SHALL 保留來源位址（取自聚合鍵）、次數與起訖時間。

`status` SHALL 按事件性質分流：憑證交換失敗等**認證失敗**用 `failure`；准入規則拒絕等**授權拒絕**用 `denied`。SHALL NOT 一律採用單一狀態值——`denied` 在系統中是既有的授權拒絕語義，混用會破壞既有授權列的可解釋性。

#### Scenario: 憑證交換失敗記為認證失敗

- **WHEN** 回呼帶入被竄改的授權碼，憑證交換失敗
- **THEN** audit_logs 列 `resource=auth`、`status=failure`，且來源位址與路徑非空

#### Scenario: 准入拒絕記為授權拒絕

- **WHEN** 外部身分通過驗證但不符准入規則而被拒
- **THEN** audit_logs 列 `resource=auth`、`status=denied`，並帶出未通過的規則

