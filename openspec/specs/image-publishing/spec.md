# image-publishing Specification

## Purpose
規範預建映像的發佈：只由版本 tag 觸發且版號一致、雙架構映像、加上 tag 前通過映像契約驗證、標籤規則與 registry 鏡像、簽章與出處證明與 SBOM，以及發佈工作流程的最小權限與釘版。

## Requirements

### Requirement: 發佈只由版本 tag 觸發且版號一致

映像發佈工作流程 SHALL 只由推送符合 `v<major>.<minor>.<patch>` 或 `v<major>.<minor>.<patch>-<預發版識別>` 的 git tag 觸發，SHALL NOT 由分支推送、pull request、排程或手動觸發。

tag 的 `<major>.<minor>.<patch>` SHALL 等於該 commit 專案根 `VERSION` 檔的內容；不一致或 tag 格式不符時，工作流程 SHALL 在任何映像推送之前以非零狀態中止。正式版映像的後端版號取自 `VERSION` 檔；預發版以建置參數覆寫為完整 tag 版號（去掉前綴 `v`）。

#### Scenario: tag 與 VERSION 不一致

- **WHEN** 推送 tag `v1.13.1`，而該 commit 的 `VERSION` 為 `1.13.0`
- **THEN** 工作流程於推送任何映像前失敗，並指出兩個版號

#### Scenario: 預發版 tag

- **WHEN** 推送 tag `v1.13.0-rc.1`，且 `VERSION` 為 `1.13.0`
- **THEN** 工作流程繼續，後端映像回報的版號為 `1.13.0-rc.1`

#### Scenario: 非 tag 事件

- **WHEN** 推送分支或開啟 pull request
- **THEN** 映像發佈工作流程不執行

### Requirement: 雙架構映像且各平台內容與平台相符

每次發佈 SHALL 為後端與前端各產出一個 index，恰含 `linux/amd64` 與 `linux/arm64` 兩個平台 manifest，SHALL NOT 含平台為 `unknown/unknown` 的 manifest。每個平台 manifest 內，本專案編譯的執行檔（後端服務與資料庫 CLI 中自建者）其目標架構 SHALL 與該 manifest 的平台相同。

建置 SHALL 以交叉編譯產生目標架構的執行檔，只把必須在目標架構執行的步驟留在模擬環境；對外發佈、簽章與引用一律以 index digest 為單位。

#### Scenario: arm64 manifest 內含 amd64 執行檔

- **WHEN** 某次建置的 `linux/arm64` manifest 中，後端執行檔或自建資料庫 CLI 的目標架構為 amd64
- **THEN** 發佈前驗證失敗，該 index 不得被加上任何 tag

#### Scenario: 發佈的 index 內容

- **WHEN** 檢視任一已發佈版本的 index
- **THEN** 只列出 `linux/amd64` 與 `linux/arm64` 兩個平台

### Requirement: 加上 tag 前通過映像契約驗證

映像 SHALL 先以不帶 tag 的 digest 推送，並於加上任何 tag 之前，對 index 內每一個平台逐一驗證下列契約；任一項失敗 SHALL 使工作流程中止，該 digest SHALL NOT 被加上任何 tag：

- manifest 平台與映像設定中的架構一致。
- 後端映像內不存在可執行的 shell 解譯器（`/bin/sh`、`/bin/ash`、`/bin/bash`、`/usr/bin/sh`）。
- 後端執行檔記載的版號等於本次發佈的版號。
- 授權文件與授權標註符合 `container-build`「交付映像內含授權文件與授權標註」。
- 標註中的原始碼位置與 revision 指向觸發本次發佈的 repository 與 commit。

驗證 SHALL 以自映像取出檔案或以指定進入點執行的方式進行，SHALL NOT 依賴映像內存在 shell。驗證工具本身 SHALL 可對刻意做壞的映像實測失敗。

#### Scenario: 含 shell 的後端映像

- **WHEN** 待發佈的後端映像某平台內 `/bin/sh` 可執行
- **THEN** 驗證失敗，該 digest 不帶任何 tag

#### Scenario: 驗證工具對做壞的映像失敗

- **WHEN** 以含 shell、缺授權檔、授權檔內容不符、執行檔架構與平台不符的本機映像分別執行驗證工具
- **THEN** 每一種皆以非零狀態結束並指出失敗項目

### Requirement: 標籤規則與鏡像

主要 registry SHALL 為 GHCR（`ghcr.io/<組織>/<元件>`）。正式版 `vX.Y.Z` SHALL 加上 `X.Y.Z`；`X.Y` 只在其為該 minor 線既有正式版中最高者時加上；`latest` 只在其為全部既有正式版中最高者時加上。預發版 SHALL 只加上完整版號（`X.Y.Z-<預發版識別>`），SHALL NOT 移動 `X.Y` 或 `latest`。SHALL NOT 加上只含 major 的 tag。

Docker Hub SHALL 作為鏡像：只鏡像正式版，加上 `X.Y.Z` 與（依同一規則）`X.Y`，**SHALL NOT 推送 `latest`**。未帶 registry 前綴的本專案映像名稱即指向 Docker Hub，較早版本的編排檔以此名稱加 `latest` 引用本機建置產物，且未明示拉取策略時會先嘗試拉取；Docker Hub 出現 `latest` 會使這些部署拉到非其原始碼建置、版本不符的映像。鏡像 SHALL 保持與 GHCR 相同的 index digest，使同一份出處證明可驗兩處。

`X.Y.Z`（含預發版完整版號）SHALL NOT 被覆寫：加上前若該 tag 已存在且指向不同 digest，SHALL 以非零狀態中止；指向相同 digest 時視為重跑。修正 SHALL 以新版號發佈。

#### Scenario: 正式版且為最高版本

- **WHEN** 發佈 `v1.13.0`，既有正式版最高為 `1.12.4`
- **THEN** GHCR 得到 `1.13.0`、`1.13`、`latest`；Docker Hub 得到 `1.13.0`、`1.13`，沒有 `latest`

#### Scenario: 舊線修補

- **WHEN** 已發佈 `1.13.0` 之後發佈 `v1.12.5`
- **THEN** GHCR 得到 `1.12.5` 與 `1.12`，`latest` 仍指向 `1.13.0`

#### Scenario: 預發版不鏡像

- **WHEN** 發佈 `v1.13.0-rc.1`
- **THEN** GHCR 只得到 `1.13.0-rc.1`；Docker Hub 不推送

#### Scenario: 鏡像收到 latest

- **WHEN** 鏡像步驟的目標 tag 清單中含 `latest`
- **THEN** 鏡像步驟拒絕執行並以非零狀態結束

#### Scenario: 版號已存在且內容不同

- **WHEN** 重跑發佈時 `1.13.0` 已存在且指向另一個 digest
- **THEN** 工作流程中止，不覆寫該 tag

#### Scenario: 鏡像 digest 一致

- **WHEN** 鏡像完成後比對 Docker Hub 與 GHCR 同一版號的 digest
- **THEN** 兩者相同；不同即以非零狀態結束

### Requirement: 簽章、出處證明與 SBOM

於正式發佈 repository（`custodexa/custodexa`，比對不分大小寫），每個已發佈的 index digest SHALL 以 keyless 方式簽章（簽章涵蓋 index 與其各平台 manifest），簽署身分為觸發本次發佈的工作流程。每個已發佈的 index SHALL 附建置出處證明（provenance）與 SBOM 證明；SBOM SHALL 列出映像內套件與其版本。

keyless 簽章與證明會把 repository 名稱與工作流程路徑寫入公開透明紀錄且無法移除，因此正式發佈 repository 以外的 repository（演練用複本、fork）SHALL NOT 簽章、SHALL NOT 產生或上傳證明，也 SHALL NOT 執行依賴簽章的自驗；其建置、平台與映像契約驗證、加上 tag、鏡像與打包照常執行，SBOM 照常產出，並 SHALL 於 job summary 註明本次未簽章。

於正式發佈 repository，工作流程 SHALL 在加上 tag 並簽章後，以部署端將使用的同一組指令驗證簽章、出處證明與 SBOM 證明，任一驗證失敗即以非零狀態結束。鏡像到 Docker Hub 的 index SHALL 可用相同的簽署身分驗證。

建置參數 SHALL NOT 攜帶任何秘密：出處證明會記錄建置參數，公開 repository 的證明對外可讀。

#### Scenario: 部署端驗證簽章

- **WHEN** 部署端對已發佈的版本 tag 執行簽章驗證，並指定發佈工作流程的身分與 OIDC 簽發者
- **THEN** 驗證成功；換成其他工作流程身分即失敗

#### Scenario: 部署端驗證出處證明與 SBOM

- **WHEN** 部署端以 repository 名稱驗證已發佈映像的出處證明，並另以 SBOM 的 predicate type 驗證
- **THEN** 兩者皆驗證成功，且 SBOM 內可見映像內的系統套件與版本

#### Scenario: 發佈後自驗失敗

- **WHEN** 某次發佈加上 tag 後，簽章或任一證明無法以部署端指令驗證
- **THEN** 工作流程以非零狀態結束，發佈不視為完成

#### Scenario: 非正式發佈 repository 不簽章

- **WHEN** 同一份發佈工作流程在正式發佈 repository 以外的 repository（例如演練用複本或 fork）由版本 tag 觸發
- **THEN** 映像照常建置、驗證、加上 tag，安裝包與 `SHA256SUMS` 照常產出；沒有任何簽章、出處證明或 SBOM 證明寫入透明紀錄，`SHA256SUMS` 不附簽章，job summary 註明本次未簽章

### Requirement: 發佈工作流程的最小權限與釘版

發佈工作流程檔的頂層權限 SHALL 為空，各 job SHALL 只宣告其步驟所需的權限：推送映像到主要 registry 並在其上加上 tag 需要寫入套件；簽章需要 OIDC token，出處證明另需寫入證明；把安裝包附到 Release 草稿的 job 需要寫入 repository contents（建立 Release 與上傳附檔）。`contents: write` SHALL 只出現在該 job，其餘 job 的 repository contents 權限 SHALL 為只讀；只拉取映像的 job SHALL NOT 宣告任何寫入權限。第三方 action SHALL 以完整 commit SHA 釘版；執行環境標籤 SHALL 指定具體版本，SHALL NOT 使用 `-latest` 類浮動標籤。

鏡像 registry 的帳密 SHALL 只存放於限定版本 tag 才能使用的部署環境中，且只有鏡像 job 使用該環境。

#### Scenario: action 以浮動版本引用

- **WHEN** 發佈工作流程中任一 `uses:` 未以 40 字元 commit SHA 指定
- **THEN** 工作流程檢查以非零狀態結束並指出該行

#### Scenario: 權限超出所需

- **WHEN** 發佈工作流程頂層宣告了任何權限，或任一 job 宣告了其步驟不需要的權限（例如只拉取映像的 job 宣告寫入）
- **THEN** 工作流程檢查以非零狀態結束

#### Scenario: repository contents 的寫入權限

- **WHEN** 發佈工作流程中，附安裝包到 Release 草稿之外的任一 job 宣告 `contents: write`
- **THEN** 工作流程檢查以非零狀態結束並指出該 job

#### Scenario: 鏡像帳密的可及範圍

- **WHEN** 檢視發佈工作流程
- **THEN** 只有鏡像 job 引用存放鏡像帳密的部署環境，且該環境只允許版本 tag 使用
