# management-script Specification

## Purpose
規範安裝包部署的管理腳本 `custodexa.sh`：發行附檔組的完整性驗證、部署根目錄與 compose 呼叫的固定方式、映像取得順序與啟動後核對、狀態檔格式、改狀態子命令的互斥，以及 install／status／load 子命令、三語輸出與終端機下的互動主選單。

## Requirements

### Requirement: 發行附檔為同一組可驗證附檔

每個版本的發行附檔 SHALL 為一組：安裝包、各架構離線映像包、獨立的 `MANIFEST.json`、列出以上全部檔案校驗和的 `SHA256SUMS`，以及由發佈工作流程身分以 keyless 方式對 `SHA256SUMS` 所做的簽章。獨立 `MANIFEST.json` SHALL 與安裝包內的 MANIFEST 逐位元組相同。附檔組在發布前 SHALL 以部署端使用的同一段驗證程式重新下載並驗證：簽章與身分、每個附檔的校驗和、`SHA256SUMS` 無多列或漏列、兩份 MANIFEST 相同、MANIFEST 的映像 digest 等於發佈工作流程的輸出；任一不成立，該版 SHALL NOT 發布。發布 Release SHALL 由使用者操作，工作流程只建立草稿。簽章與發布前的重新下載驗證只在正式發佈 repository 執行（見 image-publishing「簽章、出處證明與 SBOM」）；其他 repository 產出的草稿只含未簽章的 `SHA256SUMS`，不作為可發布的版本。

MANIFEST SHALL 記載版號、最低可直接升級的來源版本、各映像的 index digest 與各架構 config digest、migration 清單、原始碼校驗和，以及 `rollback_compatible`（本版可只切映像回退到的舊版清單，只由跨版相容演練填入，未演練為空）。

#### Scenario: 兩份 MANIFEST 不一致
- **WHEN** 草稿 Release 上的獨立 `MANIFEST.json` 與安裝包內的 MANIFEST 差一個位元組
- **THEN** 發布前驗證以非零狀態失敗並指名差異，該版不得發布

#### Scenario: 校驗清單多列或漏列
- **WHEN** `SHA256SUMS` 列了不存在的附檔，或有附檔未被列出
- **THEN** 發布前驗證失敗並指名該檔

### Requirement: 部署根目錄與 compose 呼叫固定

管理腳本 SHALL 以自身實際路徑（追符號連結）或 `CUSTODEXA_HOME` 解析部署根，並確認根目錄含 `state.json` 或 `releases/`。每一次 compose 呼叫 SHALL 顯式帶固定專案名、`--project-directory <根>` 與 `-f <根>/current/compose.yml`（加上部署形態的 overlay）；首次轉換時 SHALL 改以記下的舊專案名、舊專案目錄與舊 compose 檔呼叫，三者 SHALL NOT 省略。部署根的絕對路徑 SHALL 只含 `[A-Za-z0-9._/-]`，不合即拒絕執行。本版 SHALL 只支援 Linux，其他作業系統拒絕並指向原始碼部署路徑。

#### Scenario: 由符號連結呼叫
- **WHEN** 維運經 `/usr/local/bin/custodexa.sh` 這類符號連結執行腳本
- **THEN** 腳本解析到實際部署根，所有 compose 呼叫都帶該根目錄的專案目錄、固定專案名與顯式 `-f`

#### Scenario: 路徑含不允許字元
- **WHEN** 部署根位於含空白或引號的路徑
- **THEN** 前置檢查以 FAIL 停下並說明原因，未寫入任何檔

### Requirement: 映像取得順序與啟動後核對

腳本 SHALL 對每顆映像依序嘗試本機已有、離線包、GHCR、Docker Hub、本地建置，每一步 SHALL 印出實際路徑或位址與失敗原因。取得後 SHALL 以 MANIFEST 比對內容（registry 來源比 index digest，離線來源比該架構 config digest），並記下本機 image ID；compose 引用的實際參照寫入該版本的 `images.env`，compose 的拉取政策 SHALL 為永不拉取。本地建置產物 SHALL 使用本機專用名稱，SHALL NOT 使用對外發佈的映像名稱。服務啟動後，每個容器正在執行的 image ID SHALL 等於記下的 ID，不等即視為失敗。

#### Scenario: 離線載入後啟動
- **WHEN** 主機無法連 registry，維運以離線包安裝，且主機使用 classic 或 containerd 任一種 image store
- **THEN** 服務以離線包載入的映像啟動，後端回報版本等於 MANIFEST 版號，執行中容器的 image ID 等於腳本記下的 ID

#### Scenario: 同名不同內容的映像
- **WHEN** 啟動後某容器執行的 image ID 與取得時記下的不同
- **THEN** 腳本判定失敗並印出兩個 ID，不宣告安裝或升級成功

### Requirement: 完整性驗證分層並明示未驗項

校驗和驗證 SHALL 不可略過；主機有 cosign 或 gh 時 SHALL 自動驗發行清單簽章、映像簽章與出處證明；缺工具或離線時 SHALL 明示「未驗發行者」並附可在其他電腦執行的手動驗證指令，繼續前 SHALL 經確認。驗了哪幾層 SHALL 寫入狀態檔與紀錄。`load` 使用離線包旁的發行清單時，只有該清單經 `SHA256SUMS` 的簽章驗證通過，畫面才 SHALL 標示發行者已驗證；無法驗證時 SHALL 標為略過並說明原因；簽章驗了且不符時 SHALL 停止且不載入。

#### Scenario: 主機沒有 cosign
- **WHEN** 在沒有 cosign 的主機安裝
- **THEN** 畫面標示簽章層為略過並附手動指令，互動時要求確認，非互動時須帶 `--yes` 且紀錄寫明略過原因

### Requirement: 狀態檔格式受限且原子更新

`state.json` SHALL 為單層扁平的 JSON 物件，一行一鍵，鍵只含 `[a-z0-9_.]`，值一律為不含引號、反斜線、換行與控制字元的 ASCII 字串。寫入 SHALL 經同目錄暫存檔、同步後以改名取代，並保留前一版為 `state.json.prev`。讀取 SHALL 逐行驗證格式；任一行不合、鍵重複或 `format` 不認得時 SHALL 停止執行並指出檔案、行號與 `.prev` 位置，SHALL NOT 猜測或略過。狀態檔與紀錄檔 SHALL NOT 含 `.env` 的任何值。

#### Scenario: 狀態檔被截斷
- **WHEN** `state.json` 只剩前半段
- **THEN** 任何子命令以結束碼 5 停下，印出不合的行號與 `state.json.prev` 的位置，不做其他動作

#### Scenario: 寫入中途中斷
- **WHEN** 寫入狀態檔的過程中行程被終止
- **THEN** `state.json` 仍是完整的舊內容或完整的新內容

### Requirement: 改狀態的子命令互斥且不在中斷時自行復原

會改變狀態的子命令 SHALL 互斥執行，取不到鎖即以拒絕結束。中斷（Ctrl-C、終端斷線）時腳本 SHALL 只記錄步驟並印出恢復指令，SHALL NOT 自動回退或復原；下次執行發現上次中斷時 SHALL 先印出能完成該次中斷的恢復指令，該子命令在處理前拒絕再跑（install 冪等，得直接重跑）。`load` 只載入並比對映像，中斷的 `load` SHALL NOT 阻擋任何子命令，包含再次執行 `load`；`status` SHALL 在提醒中列出中斷的 `load` 與重跑指令。stdin 不是終端又未帶 `--yes` 時，任何確認點 SHALL 以拒絕結束而不等待。

#### Scenario: 非互動缺旗標
- **WHEN** 在排程或管線中執行需要確認的子命令而未帶 `--yes`
- **THEN** 腳本不等待輸入，以拒絕結束碼離開並說明需要的旗標

#### Scenario: load 中斷後
- **WHEN** `load` 在 `docker load` 期間被中斷，之後執行 `status`、再執行同一個 `load`
- **THEN** `status` 以警告列出中斷的 `load` 與重跑指令，重跑的 `load` 照常完成，其後的 `install` 不因該次中斷而被拒

### Requirement: install 冪等並拒絕覆蓋既有部署

`install` SHALL 在任何寫入前完成前置檢查；發現既有部署（狀態檔、同名容器或 git 工作樹）SHALL 拒絕並指向 `status` 或 `upgrade`。`.env` 產生 SHALL 沿用快速啟動腳本的逐鍵規則，已設定的值不變，並寫入絕對路徑的 `DATA_PATH`、`COMPOSE_FILE` 與 `COMPOSE_PROJECT_NAME`；只回顯本次產生的初始管理者密碼。任一步失敗只停下、不清除，重跑從頭冪等執行。

#### Scenario: 已有部署時執行 install
- **WHEN** 在已有 `state.json` 或 `custodexa-backend` 容器的主機執行 install
- **THEN** 腳本拒絕，未改任何檔，並印出應使用的子命令

#### Scenario: 中斷後重跑
- **WHEN** install 在取得映像時被中斷後再次執行
- **THEN** 已產生的 `.env` 值不變，流程完成且結果與一次跑完相同

### Requirement: status 與 load 不改變服務

`status` SHALL 唯讀、不取鎖，列出版本、服務、封存、映像來源與驗證層、最近備份、上次升級與提醒；有提醒時以專用結束碼結束。`load` SHALL 只驗證並載入離線包、比對 MANIFEST，SHALL NOT 啟動服務或切換版本。

#### Scenario: load 後服務未變
- **WHEN** 維運執行 `load` 載入新版離線包
- **THEN** 映像已載入並核對，執行中的服務與 `current` 指向不變

### Requirement: 三語輸出與 ASCII 標記

腳本輸出 SHALL 依 `--lang`、`LC_ALL`、`LC_MESSAGES`、`LANG` 判定為 zh-TW、ja 或 en，其餘退回 en。狀態標記 SHALL 為各語言相同的 ASCII 字樣，不靠顏色也可判讀；顏色只在終端且未設 `NO_COLOR` 時啟用；可複製的指令獨立成行且不含控制字元。三語訊息鍵集 SHALL 相同且不含 emoji。

#### Scenario: 不支援的語系
- **WHEN** 系統語系為 `zh_CN.UTF-8` 且未帶 `--lang`
- **THEN** 輸出為英文

### Requirement: 終端機下不帶子命令顯示主選單

stdin 與 stdout 都是終端機、且未帶子命令與 `--help` 時，腳本 SHALL 在安裝包部署（含尚未安裝的安裝包目錄）顯示主選單：尚未安裝時列安裝、載入離線包、說明、離開；已安裝時列查看狀態、升級、備份、載入離線包、說明、離開。選單 SHALL 只以問答或編號取得流程需要的輸入，再以子命令呼叫既有實作，SHALL NOT 另加確認或跳過子命令自己的確認；子命令結束後回到主選單並重新判斷部署狀態。任一端不是終端機、部署目錄判定不出、或是舊的 git clone 部署時，SHALL 維持印出說明並以結束碼 2 結束。

#### Scenario: 自動化不帶子命令
- **WHEN** 在沒有終端機的環境（stdin 或 stdout 不是終端機）不帶子命令執行腳本
- **THEN** 印出說明並以結束碼 2 結束，不顯示選單、不等待輸入

#### Scenario: 選單選項對應子命令
- **WHEN** 維運在終端機的已安裝部署選「載入離線映像包」並選目前目錄列出的離線包
- **THEN** 腳本以該離線包的絕對路徑執行 `load`，結束後回到主選單

#### Scenario: 舊的 git clone 部署不進選單
- **WHEN** 在終端機對舊的 git clone 部署目錄不帶子命令執行腳本
- **THEN** 印出說明並以結束碼 2 結束
