<div align="center">
  <img src="../assets/brand/logo.png" alt="Custodexa — Guard Access. Preserve Evidence." width="440">
</div>

<p align="center"><a href="../../README.md">English</a> | <b>繁體中文</b> | <a href="../ja/README.md">日本語</a> | <a href="../README.md">其他語言 →</a></p>
<p align="center"><a href="https://custodexa.org/">官方網站</a> · <a href="https://custodexa.org/docs/quickstart/">線上文件</a></p>
<p align="center">
  <a href="https://sonarcloud.io/summary/new_code?id=custodexa_custodexa"><img src="https://sonarcloud.io/api/project_badges/measure?project=custodexa_custodexa&metric=alert_status" alt="Quality Gate"></a>
  <a href="https://sonarcloud.io/summary/new_code?id=custodexa_custodexa"><img src="https://sonarcloud.io/api/project_badges/measure?project=custodexa_custodexa&metric=security_rating" alt="Security Rating"></a>
  <a href="https://sonarcloud.io/summary/new_code?id=custodexa_custodexa"><img src="https://sonarcloud.io/api/project_badges/measure?project=custodexa_custodexa&metric=sqale_rating" alt="Maintainability Rating"></a>
  <a href="https://sonarcloud.io/summary/new_code?id=custodexa_custodexa"><img src="https://sonarcloud.io/api/project_badges/measure?project=custodexa_custodexa&metric=reliability_rating" alt="Reliability Rating"></a>
  <a href="https://github.com/custodexa/custodexa/releases"><img src="https://img.shields.io/github/v/release/custodexa/custodexa" alt="Latest release"></a>
  <a href="https://github.com/custodexa/custodexa/commits"><img src="https://img.shields.io/github/last-commit/custodexa/custodexa" alt="Last commit"></a>
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue" alt="License: AGPL-3.0"></a>
</p>

**誰連了什麼、做了什麼，錄影說了算。**

開源特權存取閘道。瀏覽器就是入口，靶機零安裝，每一次連線先過政策再開通。
留下的是錄影與一條指令軌跡，打包成稽核人員能離線驗證的簽章證據包。

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../assets/architecture-dark.svg">
    <img alt="架構圖：操作者用瀏覽器經 Custodexa 閘道（認證閘、政策引擎、協議代理、審計、證據出口）連向 SSH、RDP/VNC、資料庫與 Kubernetes 靶機，靶機零安裝；每一場會話都留下錄影、指令記錄與 Ed25519 封章的審計鏈。" src="../assets/architecture-light.svg" width="920">
  </picture>
</p>

## 為什麼需要它

管理一群伺服器與資料庫的團隊，遲早會撞上同一批問題：

- **出事之後查不到。** 誰在什麼時候連過哪台機器、做了什麼？只剩 shell history 和猜測。
- **憑證滿天飛。** root 密碼與資料庫帳密在筆記軟體和聊天視窗裡傳來傳去，離職一個人就要全面換密。
- **稽核要證據。** 口頭說「我們有管控」過不了關，要拿得出完整的操作紀錄與錄影。

## 一次連線，五道關卡

每一場會話都走這條路，證據在路上就做好了。

| | 做什麼 |
|---|---|
| **01 認證閘** | 本機帳號、LDAP 與 Active Directory、OIDC 單一登入、TOTP 雙因子，以及目錄服務中斷那天的破窗路徑。 |
| **02 政策引擎** | 每台資產設直連、填事由、須核准三段。核准通過的當下就發出限時授權，中間沒有空窗，「這個人為什麼能連」有答案。角色權限控到誰能用哪個帳號連哪台機器。 |
| **03 協議代理** | SSH、RDP、VNC、MySQL、PostgreSQL、SQL Server、Redis、Kubernetes exec，各自在瀏覽器開一個分頁。憑證在這一層終結，不進瀏覽器，配一次性 connect token 與 host key 驗證。危險指令與資料庫語句可告警、可當場阻斷，剪貼簿與檔案傳輸內容留痕。 |
| **04 憑證輪替** | Linux 與 Windows 本機帳號排程改密，新密碼在靶機端自驗，失敗在靶機端回滾。輪替證據報告逐帳號列出多久沒換過。 |
| **05 錄影與稽核** | 全協議錄影回放（可快轉、拖進度條），指令與語句軌跡經虛擬螢幕重組，能處理 vim 這類全螢幕程式；webhook 告警；檢查點鏈定期封章；證據包內含清單檔與簽章，異地副本存到物件儲存。 |

**真正開源，單一版本。** 沒有企業版，也沒有付費解鎖的功能。
你看到的就是全部，授權為 AGPL-3.0。

**部署簡單。** docker compose 一條指令，正式版四個容器，出廠即走 https，
啟動後不需要對外網路。

## 怎麼跟現有做法比

比的是做法，不是廠牌。每一欄描述的是常見形態，你的環境可能不同；
每一格的判讀標準與查證日期在[對照頁](https://custodexa.org/docs/compare/)。

| | SSH 跳板機 | VPN | 開源堡壘機 | 商用 PAM | Custodexa |
|---|---|---|---|---|---|
| **存取邊界** | 放行整台登入主機 | 放行一整段網路 | 以單台目標為授權單位 | 以單台目標或帳號為授權單位 | 每台資產可設直連、填事由、須核准 |
| **連線前核准** | 沒有核准環節 | 通道建立時一次性授權 | 依實作，逐次核准少見 | 具備申請與核准流程 | 核准當下發出限時授權，中間沒有空窗 |
| **資料庫語句稽核** | 不在管轄內 | 以網路層為界，不解析語句 | 依實作，涵蓋部分協定 | 依版本，部分具備 | 語句先留痕再執行，危險語句可即時阻斷 |
| **證據封裝** | 自行從日誌彙整 | 連線日誌自行彙整 | 提供紀錄與錄影匯出 | 提供報表與匯出 | 單一 ZIP 內含清單檔與簽章，逐檔雜湊可離線驗證 |
| **憑證輪替** | 人工維護 | 交由目錄服務維護 | 依實作，以人工維護 | 具備排程輪替 | Linux 與 Windows 排程改密，附輪替證據報告 |
| **授權條款** | 沿用作業系統既有元件的授權 | 依實作，開源與商用並存 | 開源授權為主 | 商用訂閱或永久授權 | 開源，AGPL-3.0，程式碼可自行查核 |

## 畫面

| | |
|---|---|
| ![儀表板總覽](../../screenshots/dashboard-overview.png) | ![工作區網頁終端](../../screenshots/workspace-terminal.png) |
| ![會話錄影回放與指令記錄](../../screenshots/session-playback.png) | ![指令審計](../../screenshots/command-audit.png) |

左上起：儀表板總覽、工作區網頁終端（含使用者浮水印）、會話錄影回放與指令記錄、指令審計搜尋。

## 快速開始

```bash
git clone https://github.com/custodexa/custodexa.git
cd custodexa
bash scripts/quickstart.sh --up
```

腳本會檢查 `.env`（沒有就從範本建立）、用 CSPRNG 生成缺少的機密、啟動服務並等待
後端健康，最後輸出連線網址與 admin 登入資訊；你已經填好的值一律不動。

出貨預設下，平台自身的根金鑰**永不落地**。首次造訪會先進入**主金鑰初始化頁**，
金鑰在你的瀏覽器本地生成。務必保存好：之後每次重啟都停在封印狀態，要再輸入才解封。
接著才是登入與強制改密。無人值守的部署可在 `.env` 改用 env 或 KMS 金鑰模式。想手動設定？照
`.env.example` 內的逐項說明複製編輯後 `docker compose up -d` 即可。
Windows 請在 WSL 內執行腳本。

服務對外走 https，埠為 443（80 會導向它），網址不必帶埠號；主機上這兩個埠已經有別的
服務時，在 `.env` 以 `TLS_HTTPS_PORT` 與 `TLS_HTTP_PORT` 改成另一組。出貨預設用產品自己產生的憑證，
故在你安裝隨附的憑證授權單位之前，瀏覽器會顯示警告：從 `/custodexa-ca.crt` 下載它，
派發到會連進來的機器即可。要換成自己的憑證，或把 TLS 交給既有的負載平衡器，
各只需改一個設定，做法見 [docs/QUICKSTART.md](../QUICKSTART.md)。

以 `admin` 加上你設定的初始密碼登入，首次登入會先引導你改密，
之後就能開始加資產、發起連線。

沒有出廠預設密碼。四項機密都要你自己設，這是刻意的：堡壘機不該帶著預設憑證上線。
完整設定選項、開發模式與故障排除見 [docs/QUICKSTART.md](../QUICKSTART.md)。

**想參與開發？** 在 `.env` 取消 `COMPOSE_FILE=docker-compose.dev.yml` 的註解即切到開發版
（前後端熱重載，並附各協議的測試靶機），入口見 [CONTRIBUTING.md](../../CONTRIBUTING.md)。

## 技術架構

**後端** Go · Gin · GORM · PostgreSQL 16　**前端** Vue 3 · Element Plus · Vite
**文字終端** xterm.js ＋ 後端原生代理　**圖形協議** Apache Guacamole（guacd，僅 RDP/VNC）

兩個貫穿全系統的架構決策：

- **握手全部在後端完成**，瀏覽器只是顯示器與鍵盤。這就是「前端拿不到明文憑證」的由來。
  實作見 `backend/internal/proxy/`。
- **SSH、資料庫 CLI、K8s exec 共用同一條文字終端鏈路**，錄影、指令審計、阻斷、監看
  四件事只實作一次，八種協議一致生效。

## 文檔地圖

三語文件索引在[文件索引](../README.md)。

| 你想做什麼 | 讀這些 |
|------|------|
| 部署與日常維運 | [QUICKSTART.md](QUICKSTART.md)（啟動、設定、故障排除）；[ops/](ops/)（備份還原、升級、部署形態、平台憑證輪替）；英文正本在 [docs/](../) |
| 參與開發 | [CONTRIBUTING.md](../../CONTRIBUTING.md)（DCO、工作流程）；[docs/dev/](../dev/)（架構與測試紀律）；[openspec/specs/](../../openspec/specs/)（行為規格，細節以此為準） |
| 查 API 與資料庫 | [docs/API_SPEC.md](../API_SPEC.md)、[docs/DB_SCHEMA.md](../DB_SCHEMA.md) |
| 回報安全問題 | [SECURITY.md](SECURITY.md)（私密回報管道與處置方式；英文版在[repo 根目錄](../../SECURITY.md)） |

## 設計邊界

部署前值得知道的界線：

- **它管的是「經過它的連線」**。若目標主機仍開放直連，那些流量不在它的視野內。
  請用網路層（防火牆／安全群組）把直連封掉，讓堡壘機成為唯一入口。
- **文字指令審計有先天極限**（例如某些全螢幕程式的邊角行為、無回顯輸入）。
  有爭議時，以**連線錄影回放**為事實來源，錄影記的是實際畫面，不經任何重組推斷。
- **審計寫入失敗不會中斷你的連線**，但介面會明確提示降級狀態，不會假裝一切正常。

## 參考專案

- [Apache Guacamole](https://guacamole.apache.org/) - 無客戶端遠端桌面閘道

## 授權

本專案以 **GNU Affero General Public License v3.0（AGPL-3.0）** 授權發佈，全文見 [LICENSE](../../LICENSE)。

AGPL-3.0 的網路服務條款（第 13 條）要求：若你修改本軟體並透過網路提供服務給使用者，
須同時向這些使用者提供修改後的完整原始碼。

**單一版本，不分級。** 沒有企業版、沒有付費解鎖的功能、也沒有另行授權的模組。
貢獻採 DCO 而非 CLA（見 [CONTRIBUTING.md](../../CONTRIBUTING.md)），
專案不要求、也不持有把外部貢獻改以閉源授權散布的權利。

### 第三方元件

散布物另含 218 個第三方元件，各自保留其原授權，清單見
[THIRD-PARTY-LICENSES.md](../../THIRD-PARTY-LICENSES.md)；
Apache License 2.0 元件的歸屬聲明見 [NOTICE](../../NOTICE)；授權正文副本在 [`licenses/`](../../licenses/)。

容器映像以 Alpine Linux 為基礎系統，內含以獨立行程執行的 GPL／LGPL 元件。
其版本表與對應源碼的取得方式（依 GPL-3.0 §6(d)／GPL-2.0 §3 末段，以指向公開源碼庫的方式提供，
取不到時可開 issue 由我們協助取得），見
[THIRD-PARTY-LICENSES.md](../../THIRD-PARTY-LICENSES.md) 第 3 節。

