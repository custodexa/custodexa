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

管理腳本 SHALL 以自身實際路徑（追符號連結）或 `CUSTODEXA_HOME` 解析安裝包部署根，並確認根目錄含 `state.json` 或 `releases/`。每一次 compose 呼叫 SHALL 顯式帶固定專案名、`--project-directory <根>` 與 `-f <根>/current/compose.yml`（加上部署形態的 overlay）。部署根的絕對路徑 SHALL 只含 `[A-Za-z0-9._/-]`，不合即拒絕執行。管理腳本 SHALL 只支援 Linux；其他作業系統拒絕並指向開發者與本機試用文件。辨識到舊的 git clone 部署時，所有入口 SHALL 在寫入鎖、狀態、備份或變更服務之前拒絕，說明手動遷移或在另一個乾淨目錄安裝後手動還原的文件路徑；SHALL NOT 進行首次轉換。

#### Scenario: 由符號連結呼叫
- **WHEN** 維運經 `/usr/local/bin/custodexa.sh` 這類符號連結執行腳本
- **THEN** 腳本解析到實際部署根，所有 compose 呼叫都帶該根目錄的專案目錄、固定專案名與顯式 `-f`

#### Scenario: 路徑含不允許字元
- **WHEN** 部署根位於含空白或引號的路徑
- **THEN** 前置檢查以 FAIL 停下並說明原因，未寫入任何檔

#### Scenario: 舊 git clone 部署拒絕
- **WHEN** 腳本在含 `.git`、`VERSION` 與根目錄 `docker-compose.yml` 的舊部署樹執行 install、upgrade、status 或不帶子命令
- **THEN** 以拒絕結束碼 3 說明人工處理路徑，沒有建立鎖、備份、狀態檔或更動服務

### Requirement: 映像取得順序與啟動後核對

`install` 與帶目標的 `upgrade` SHALL 接受 `--images-from auto|source`，未指定為 `auto`；無目標的唯讀 `upgrade` 查詢 SHALL 不接受此旗標。`auto` SHALL 對每顆映像依序嘗試本機已有、離線包、GHCR、Docker Hub、本地建置。`source` SHALL 對安裝包自家映像先核對 MANIFEST 的原始碼 checksum，再直接以安裝包內原始碼建置，不嘗試該映像的本機、離線包或 registry 發行映像；上游映像仍 SHALL 依本機、離線包、其來源 registry 取得並核對。`--images-from source` 與 `--images <離線包>` 同時給定 SHALL 於取得前拒絕。兩種模式的每一步 SHALL 在耗時呼叫前印出正在做的事與對象，完成後印出實際來源或位址及失敗原因。

取得的發行映像 SHALL 以 MANIFEST 比對內容（registry 來源比 index digest，離線來源比該架構 config digest）；自建映像 SHALL 記錄已核對的原始碼 checksum、本機來源與實際 image ID，不得標成已驗發行者映像簽章。所有映像的本機 image ID SHALL 記錄；compose 引用的實際參照寫入該版本的 `images.env`，compose 的拉取政策 SHALL 為永不拉取。本地建置產物 SHALL 使用本機專用名稱，SHALL NOT 使用對外發佈的映像名稱。服務啟動後，每個容器正在執行的 image ID SHALL 等於記下的 ID，不等即視為失敗。

#### Scenario: 預設自動模式
- **WHEN** 維運未指定 `--images-from` 執行 install
- **THEN** 每顆映像依原有順序取得，並記錄實際來源與 image ID

#### Scenario: 指定原始碼建置
- **WHEN** 維運執行 `install --images-from source` 且安裝包原始碼 checksum 正確
- **THEN** 自家映像直接以本機專用名稱建置，上游依賴另行取得；畫面與 state 不將自建映像稱為發行簽章已驗證

#### Scenario: 原始碼 checksum 不符
- **WHEN** 選擇 `source`，安裝包內原始碼 checksum 與 MANIFEST 不同
- **THEN** 腳本以 FAIL 停止並提示重新下載，不改用 registry 或已載入的自家映像

#### Scenario: 離線載入後啟動
- **WHEN** 主機無法連 registry，維運以離線包安裝，且主機使用 classic 或 containerd 任一種 image store
- **THEN** 服務以離線包載入的映像啟動，後端回報版本等於 MANIFEST 版號，執行中容器的 image ID 等於腳本記下的 ID

#### Scenario: 同名不同內容的映像
- **WHEN** 啟動後某容器執行的 image ID 與取得時記下的不同
- **THEN** 腳本判定失敗並印出兩個 ID，不宣告安裝或升級成功

### Requirement: 完整性驗證分層並明示未驗項

校驗和與映像摘要驗證 SHALL 不可略過；SHA256SUMS、MANIFEST、原始碼 checksum 或映像摘要不符 SHALL 以 `[FAIL]` 停止並提示重新下載。主機能執行來源驗證時 SHALL 驗發行清單簽章、映像簽章與出處證明；缺工具、缺簽章檔、離線或簽章驗證不符時 SHALL 以 `[WARN]` 說明來源未經證實並繼續，不新增確認關卡。驗證結果 SHALL 如實寫入 log 與 state，不符 SHALL 記為 mismatch 或同義值，不得記成已驗證。`load` 使用離線包旁的發行清單或已解開安裝包內的清單時，只有清單的相應簽章已驗證，畫面才 SHALL 標示發行者已驗證；無法驗證或不符 SHALL 警告並記錄真實原因，內容校驗不符仍停止。

#### Scenario: 主機沒有 cosign
- **WHEN** 在沒有 cosign 的主機安裝
- **THEN** 畫面以 WARN 說明簽章未驗與原因，繼續執行並在驗證紀錄中標示未驗

#### Scenario: 簽章驗證不符
- **WHEN** 發行清單或映像的簽章驗證完成但身分或簽章不符
- **THEN** 畫面以 WARN 說明簽章不符、來源未經證實，繼續執行，log 與 state 記 mismatch

### Requirement: 狀態檔格式受限且原子更新

`state.json` SHALL 為單層扁平的 JSON 物件，一行一鍵，鍵只含 `[a-z0-9_.]`，值一律為不含引號、反斜線、換行與控制字元的 ASCII 字串。寫入 SHALL 經同目錄暫存檔、同步後以改名取代，並保留前一版為 `state.json.prev`。讀取 SHALL 逐行驗證格式；任一行不合、鍵重複或 `format` 不認得時 SHALL 停止執行並指出檔案、行號與 `.prev` 位置，SHALL NOT 猜測或略過。狀態檔與紀錄檔 SHALL NOT 含 `.env` 的任何值。

#### Scenario: 狀態檔被截斷
- **WHEN** `state.json` 只剩前半段
- **THEN** 任何子命令以結束碼 5 停下，印出不合的行號與 `state.json.prev` 的位置，不做其他動作

#### Scenario: 寫入中途中斷
- **WHEN** 寫入狀態檔的過程中行程被終止
- **THEN** `state.json` 仍是完整的舊內容或完整的新內容

### Requirement: 改狀態的子命令互斥且不在中斷時自行復原

會改變狀態的子命令（包含 `start`／`stop`）SHALL 互斥執行，取不到鎖即以拒絕結束。中斷（Ctrl-C、終端斷線）時腳本 SHALL 只記錄步驟並印出恢復指令，SHALL NOT 自動回退或復原；下次執行發現上次中斷時 SHALL 先印出能完成該次中斷的恢復指令，該子命令在處理前拒絕再跑（install 冪等，得直接重跑）。`load` 只載入並比對映像，中斷的 `load` SHALL NOT 阻擋任何子命令，包含再次執行 `load`；`status` SHALL 在提醒中列出中斷的 `load` 與重跑指令。`start`／`stop` SHALL 記錄獨立操作 log；其中斷 SHALL 顯示 `status` 與恢復用的 `start` 指令，但不得在 state 中留下會封鎖 `start` 的 in_progress 欄位。未完成的 install／upgrade／backup SHALL 在啟停前被拒並顯示既有恢復指令。stdin 不是終端又未帶 `--yes` 時，任何確認點 SHALL 以拒絕結束而不等待。

#### Scenario: 非互動缺旗標
- **WHEN** 在排程或管線中執行需要確認的子命令而未帶 `--yes`
- **THEN** 腳本不等待輸入，以拒絕結束碼離開並說明需要的旗標

#### Scenario: load 中斷後
- **WHEN** `load` 在 `docker load` 期間被中斷，之後執行 `status`、再執行同一個 `load`
- **THEN** `status` 以警告列出中斷的 `load` 與重跑指令，重跑的 `load` 照常完成，其後的 `install` 不因該次中斷而被拒

#### Scenario: stop 中斷後可恢復
- **WHEN** `stop` 在部分容器停止後中斷，維運再執行 `start`
- **THEN** `start` 不受 stop 的 in_progress 狀態阻擋，仍受互斥鎖保護並可使整組服務恢復

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

stdin 與 stdout 都是終端機、且未帶子命令與 `--help` 時，腳本 SHALL 在安裝包部署（含尚未安裝的安裝包目錄）顯示主選單：尚未安裝時列安裝、載入離線包、說明、離開；已安裝時依序列查看狀態、啟動服務、停止服務、升級、備份、載入離線包、說明、離開。選單 SHALL 在安裝及實際升級前詢問映像來源，Enter 預設 auto，明選 source 時將 `--images-from source` 傳給同一子命令；EOF 回主選單。選單 SHALL 只以問答或編號取得流程需要的輸入，再以子命令呼叫既有實作，SHALL NOT 另加確認或跳過子命令自己的確認；子命令結束後回到主選單並重新判斷部署狀態。

選單選「升級到最新版」SHALL 只顯示版本、可否升級及必要的驗證與資料變更警告，不顯示唯讀查詢專用的執行指令或「只查詢」尾段；同一次查詢的已核對目標用於後續升級。校驗和不符 SHALL 不給升級結論。任一端不是終端機或部署目錄判定不出時，SHALL 印出說明並以結束碼 2 結束；舊 git clone 部署 SHALL 依「部署根目錄與 compose 呼叫固定」拒絕。

#### Scenario: 自動化不帶子命令
- **WHEN** 在沒有終端機的環境（stdin 或 stdout 不是終端機）不帶子命令執行腳本
- **THEN** 印出說明並以結束碼 2 結束，不顯示選單、不等待輸入

#### Scenario: 選單選項對應子命令
- **WHEN** 維運在終端機的已安裝部署選「載入離線映像包」並選目前目錄列出的離線包
- **THEN** 腳本以該離線包的絕對路徑執行 `load`，結束後回到主選單

#### Scenario: 最新版接著升級
- **WHEN** 維運從主選單選「升級到最新版」，查到可直接升級的目標版
- **THEN** 畫面只顯示可否升級及相關警告，詢問映像來源後進入升級預覽，不印唯讀查詢專用尾段

#### Scenario: 舊的 git clone 部署不進選單
- **WHEN** 在終端機對舊的 git clone 部署目錄不帶子命令執行腳本
- **THEN** 說明人工遷移或新安裝後還原的文件路徑，以結束碼 3 拒絕，不顯示選單

#### Scenario: 選單啟停整組服務
- **WHEN** 維運在已安裝部署的主選單選「停止服務」或「啟動服務」
- **THEN** 選單執行對應子命令，沿用子命令的確認與檢查，結束後重新顯示主選單

### Requirement: 發行版下載引導腳本核對安裝包後交棒

從 1.14.0 起，Release SHALL 以固定檔名提供 `get-custodexa.sh`，並將其列入已簽章的 `SHA256SUMS`；發行流程 SHALL 核對從 draft Release 下載的腳本與其餘附件。引導腳本 SHALL 僅在 Linux x86_64／aarch64 以 root 執行，預設使用 `https://github.com/custodexa/custodexa/releases`，由最新版 Release 的 `MANIFEST.json` 解析三段數字版本；`--version X.Y.Z` SHALL 改用指定版本，`--dir` SHALL 指定部署目錄，預設 `/opt/custodexa`。版本與部署目錄參數不合格式時 SHALL 在下載或寫入前拒絕。

引導腳本 SHALL 下載該版本安裝包與 `SHA256SUMS`，在解壓前核對安裝包 SHA-256；缺少對應項或雜湊不符時 SHALL 停止、提示重新下載，且不建立部署目錄。核對通過後 SHALL 確認安裝包頂層為 `custodexa/`，放入指定目錄，並 `exec` 該目錄的 `custodexa.sh`。引導腳本只核對 SHA-256；安裝包簽章由文件指示手動驗證，映像簽章交由 `custodexa.sh` 處理。已有部署時 SHALL 不下載、不解壓、不覆寫，直接交給其現有的 `custodexa.sh`。除引導腳本自身的 `--version`、`--dir` 外，其餘參數 SHALL 依原順序轉交；無參數 SHALL 交給管理選單。

交棒前 SHALL 確認部署目錄、其父目錄及實際執行的普通腳本檔由 root 擁有，且群組與其他人不可寫；部署目錄及其父目錄若為符號連結 SHALL 拒絕。安裝包既有的固定包內相對連結 `current -> releases/<版本>` 與根目錄 `custodexa.sh -> current/custodexa.sh` MAY 保留，但 SHALL 確認連結由 root 擁有、指向包內固定位置，最終腳本為同一部署樹內的普通檔案且符合上述權限；其他連結成員或外部連結 SHALL 在執行前拒絕。新安裝 SHALL 在目標父目錄下以私有暫存目錄解壓與檢查，通過後在同一檔案系統以 rename 發佈，失敗時清理暫存，不留下部分部署。

以 `curl | bash` 或等價管線執行時，若 stdin 不是終端機但 `/dev/tty` 可用，交棒前 SHALL 將子腳本 stdin 接至 `/dev/tty`。沒有可用終端機且未帶子命令時 SHALL 立即拒絕並提示 `install --yes` 等明確子命令，不得等待管線輸入。`CX_GET_RELEASE_BASE` 若由呼叫環境覆寫，SHALL 作為所有 Release 下載的來源；呼叫者設定此值即信任該來源提供的版本、安裝包及 `SHA256SUMS`，腳本的雜湊比對不證明其發行者身分。

三語安裝文件 SHALL 在引導腳本的管線指令旁給出可傳遞首次下載失敗結束碼的用法，並明示 `CX_GET_RELEASE_BASE` 覆寫等於同時信任該來源的安裝包與 `SHA256SUMS`。

#### Scenario: 解析最新版
- **WHEN** 維運未帶 `--version` 執行引導腳本，最新版 Release 的 `MANIFEST.json` 含有效的 `X.Y.Z` 版本
- **THEN** 腳本下載該版安裝包及 `SHA256SUMS`，核對後解壓到預設或指定部署目錄並交棒

#### Scenario: 指定版本與部署目錄
- **WHEN** 維運帶 `--version 1.14.0 --dir /srv/custodexa` 執行引導腳本
- **THEN** 腳本只取得 1.14.0 的安裝包與校驗和，核對後將包內 `custodexa/` 放到 `/srv/custodexa`；非三段數字版本在下載前拒絕

#### Scenario: 安裝包雜湊不符
- **WHEN** 下載的安裝包與 `SHA256SUMS` 中對應的 SHA-256 不同或清單未列該包
- **THEN** 腳本在解壓前停止並提示重新下載，目標部署目錄未建立

#### Scenario: 已有部署交棒
- **WHEN** `--dir` 指向已有 `custodexa.sh` 的安裝包部署，且帶入 `upgrade 1.14.1 --yes`
- **THEN** 引導腳本不下載或覆寫檔案，`exec` 現有管理腳本並以原順序傳入 `upgrade 1.14.1 --yes`

#### Scenario: 既有部署路徑可被他人寫入
- **WHEN** 部署目錄、其父目錄或實際執行腳本不是 root 擁有，或群組／其他人可寫，或部署目錄／父目錄是符號連結
- **THEN** 引導腳本在交棒前說明擁有者與權限問題並拒絕，不執行該腳本

#### Scenario: 安裝包連結只留在包內
- **WHEN** 安裝包包含 `current -> releases/<版本>` 及根 `custodexa.sh -> current/custodexa.sh` 的固定相對連結
- **THEN** 引導腳本核對兩個連結與解析後包內普通腳本的擁有者及權限後交棒；任何外部或其他連結成員在解壓與發佈前拒絕

#### Scenario: 解壓或發佈失敗
- **WHEN** 已核對雜湊的安裝包在解壓、結構檢查或同檔案系統 rename 時失敗
- **THEN** 私有暫存目錄被清理，目標部署目錄不留半套檔案

#### Scenario: 管線執行時讀取終端機
- **WHEN** 引導腳本從管線讀取自身內容、stdin 不是終端機而 `/dev/tty` 可用，且未帶子命令
- **THEN** 核對及交棒後，`custodexa.sh` 的選單從 `/dev/tty` 讀取輸入，不再讀取腳本管線

#### Scenario: 無終端機也未帶子命令
- **WHEN** 引導腳本的 stdin 不是終端機、`/dev/tty` 不可用，且沒有要轉交的子命令
- **THEN** 腳本立即拒絕並提示 `install --yes` 等可用形式，不等待輸入；帶有子命令時則將參數原樣轉交

#### Scenario: 覆寫 Release 來源
- **WHEN** 呼叫環境設定 `CX_GET_RELEASE_BASE` 指向其他端點
- **THEN** 腳本從該端點取得版本清單、安裝包及 `SHA256SUMS` 並核對其內容；該端點及其清單被視為呼叫者信任的來源，畫面不宣稱發行者簽章已驗證

#### Scenario: 文件中的首次下載失敗
- **WHEN** 維運照三語快速開始中的管線範例執行，而取得 `get-custodexa.sh` 的下載失敗
- **THEN** 文件提供的 `pipefail` 用法使整段管線回報非零結束碼，且相鄰說明揭露覆寫來源的信任邊界

### Requirement: 已安裝部署可控制整組服務

已安裝的安裝包部署 SHALL 提供 `start` 與 `stop` 子命令，只作用於目前版本的整組服務，使用固定專案名、專案目錄、目前 compose 與部署 overlays。`stop` SHALL 先提示現有連線會中斷並要求確認；確認後沿用升級的稽核佇列排空判定，未知或逾時 SHALL 不停止服務。排空後 SHALL 停止整組服務並確認結果。`start` SHALL 啟動目前整組服務，最多等待 180 秒確認後端 `/health` 可回應；失敗 SHALL 提示查 `status` 與後端 log，不自動回退。已全部停止／已全部執行且後端就緒時，重複指令 SHALL 提示現狀並成功結束。兩者 SHALL 不切換版本、不執行備份、不變更容量門檻。

#### Scenario: stop 前稽核佇列未知
- **WHEN** 維運確認 `stop`，但無法判定仍在執行的後端之稽核佇列是否排空
- **THEN** 指令失敗並指出服務未停止，不呼叫 compose stop

#### Scenario: start 健康檢查逾時
- **WHEN** `start` 已啟動容器，但後端在 180 秒內沒有健康回應
- **THEN** 指令以失敗結束並提示 `status` 與 log，不自動停止容器

### Requirement: 檔案大小按量級顯示

管理腳本 SHALL 以共用的 bytes 顯示函式，對備份、升級、狀態和離線包大小自動選 KB／MB／GB；1024 為級距，GB 的換算與精度沿用既有狀態畫面。大小的字串格式 SHALL 只用於顯示，剩餘空間、備份估算及其門檻 SHALL 仍用原本的 bytes 數值比較。

#### Scenario: 小型部署升級備份
- **WHEN** 升級備份的資料庫檔為 MB 級
- **THEN** 完成行顯示如 `0.3 MB`，不顯示 `0.0 GB`

#### Scenario: 大型備份與空間判斷
- **WHEN** 升級備份檔為 18.4 GiB，且備份位置可用 bytes 少於估算所需 bytes
- **THEN** 大小顯示 `18.4 GB`，空間不足仍依 bytes 比較而拒絕
