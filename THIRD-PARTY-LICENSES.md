# 第三方元件與授權

> 第 1 節表格為機器生成；獨立複核方式見第 4 節。

本產品以 AGPL-3.0 授權（全文見 [LICENSE](LICENSE)）。散布物中另含下列第三方元件，
各自保留其原授權。Apache License 2.0 元件的歸屬聲明（該授權第 4(d) 條）見 [NOTICE](NOTICE)。

授權正文副本置於 [`licenses/`](licenses/)，來源與雜湊見第 2.1 節。

## 致謝

本產品建立在下列 218 個開源元件之上。

瀏覽器能操作 RDP 與 VNC，來自 Apache Guacamole；
SSH 連線與密碼雜湊來自 `golang.org/x/crypto`，
即時會話由 `gorilla/websocket` 承接。
資料層有 GORM 與各家資料庫驅動，
介面是 Vue、Element Plus 與 Vite，
執行環境則是 Alpine Linux 與其上的系統套件。

謝謝這些專案的維護者。下列清單是授權合規的記錄，也是我們用了哪些人的成果的說明。

清單若有遺漏或錯誤，歡迎依 [SECURITY.md](SECURITY.md) 的管道告知，我們會盡快更正。

---

## 1. 編入產品的第三方元件

範圍：**編入後端二進位的 Go 模組**（`go list -deps ./...` 的 build 範圍）、
**編入前端產物的 npm 套件**（`package-lock.json` 非 dev 範圍）、
以及**繞過套件管理員、隨版控直接出貨的前端資產**（`vendored-js`）。

不含：僅在建置或測試時使用而未進入產物的依賴（dev／test／graph 範圍）；
容器映像內以獨立行程執行的元件另見第 3 節。

共 **218** 個相異元件（218 ＝ 掃描輸出 220 列去重後；`emoji-regex@8.0.0` 與
`string-width@4.2.3` 在鎖檔中各出現於兩條安裝路徑，屬同一元件）。
授權分佈：MIT 144、Apache-2.0 44、BSD-3-Clause 18、ISC 9、BSD-2-Clause 3。

<!-- BEGIN GENERATED: shipped-components -->
| 生態 | 元件 | 版本 | 授權 |
|---|---|---|---|
| go | github.com/aws/aws-sdk-go-v2 | v1.43.3 | Apache-2.0 |
| go | github.com/aws/aws-sdk-go-v2/config | v1.32.34 | Apache-2.0 |
| go | github.com/aws/aws-sdk-go-v2/credentials | v1.19.33 | Apache-2.0 |
| go | github.com/aws/aws-sdk-go-v2/feature/ec2/imds | v1.18.34 | Apache-2.0 |
| go | github.com/aws/aws-sdk-go-v2/internal/configsources | v1.4.34 | Apache-2.0 |
| go | github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 | v2.7.34 | Apache-2.0 |
| go | github.com/aws/aws-sdk-go-v2/internal/v4a | v1.4.35 | Apache-2.0 |
| go | github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding | v1.13.15 | Apache-2.0 |
| go | github.com/aws/aws-sdk-go-v2/service/internal/presigned-url | v1.13.34 | Apache-2.0 |
| go | github.com/aws/aws-sdk-go-v2/service/kms | v1.55.3 | Apache-2.0 |
| go | github.com/aws/aws-sdk-go-v2/service/signin | v1.5.3 | Apache-2.0 |
| go | github.com/aws/aws-sdk-go-v2/service/sso | v1.33.3 | Apache-2.0 |
| go | github.com/aws/aws-sdk-go-v2/service/ssooidc | v1.38.3 | Apache-2.0 |
| go | github.com/aws/aws-sdk-go-v2/service/sts | v1.45.3 | Apache-2.0 |
| go | github.com/aws/smithy-go | v1.27.6 | Apache-2.0 |
| go | github.com/Azure/go-ntlmssp | v0.1.0 | MIT |
| go | github.com/beorn7/perks | v1.0.1 | MIT |
| go | github.com/boombuler/barcode | v1.0.1-0.20190219062509-6c824513bacc | MIT |
| go | github.com/cespare/xxhash/v2 | v2.3.0 | MIT |
| go | github.com/coreos/go-oidc/v3 | v3.14.1 | Apache-2.0 |
| go | github.com/creack/pty | v1.1.21 | MIT |
| go | github.com/davecgh/go-spew | v1.1.2-0.20180830191138-d8f796af33cc | ISC |
| go | github.com/emicklei/go-restful/v3 | v3.11.0 | MIT |
| go | github.com/fxamacker/cbor/v2 | v2.7.0 | MIT |
| go | github.com/gabriel-vasile/mimetype | v1.4.3 | MIT |
| go | github.com/gin-contrib/cors | v1.7.1 | MIT |
| go | github.com/gin-contrib/sse | v1.1.0 | MIT |
| go | github.com/gin-gonic/gin | v1.9.1 | MIT |
| go | github.com/go-asn1-ber/asn1-ber | v1.5.8-0.20250403174932-29230038a667 | MIT |
| go | github.com/go-jose/go-jose/v4 | v4.1.4 | Apache-2.0 |
| go | github.com/go-ldap/ldap/v3 | v3.4.13 | MIT |
| go | github.com/go-logr/logr | v1.4.2 | Apache-2.0 |
| go | github.com/go-openapi/jsonpointer | v0.19.6 | Apache-2.0 |
| go | github.com/go-openapi/jsonreference | v0.20.2 | Apache-2.0 |
| go | github.com/go-openapi/swag | v0.22.4 | Apache-2.0 |
| go | github.com/go-playground/locales | v0.14.1 | MIT |
| go | github.com/go-playground/universal-translator | v0.18.1 | MIT |
| go | github.com/go-playground/validator/v10 | v10.23.0 | MIT |
| go | github.com/gogo/protobuf | v1.3.2 | BSD-3-Clause |
| go | github.com/golang-jwt/jwt/v5 | v5.3.0 | MIT |
| go | github.com/golang/protobuf | v1.5.4 | BSD-3-Clause |
| go | github.com/google/gnostic-models | v0.6.8 | Apache-2.0 |
| go | github.com/google/go-cmp | v0.7.0 | BSD-3-Clause |
| go | github.com/google/gofuzz | v1.2.0 | Apache-2.0 |
| go | github.com/google/uuid | v1.6.0 | BSD-3-Clause |
| go | github.com/gorilla/websocket | v1.5.3 | BSD-2-Clause |
| go | github.com/jackc/pgpassfile | v1.0.0 | MIT |
| go | github.com/jackc/pgservicefile | v0.0.0-20240606120523-5a60cdf6a761 | MIT |
| go | github.com/jackc/pgx/v5 | v5.9.2 | MIT |
| go | github.com/jackc/puddle/v2 | v2.2.2 | MIT |
| go | github.com/jinzhu/inflection | v1.0.0 | MIT |
| go | github.com/jinzhu/now | v1.1.5 | MIT |
| go | github.com/josharian/intern | v1.0.0 | MIT |
| go | github.com/json-iterator/go | v1.1.12 | MIT |
| go | github.com/kr/fs | v0.1.0 | BSD-3-Clause |
| go | github.com/leodido/go-urn | v1.4.0 | MIT |
| go | github.com/mailru/easyjson | v0.7.7 | MIT |
| go | github.com/mattn/go-isatty | v0.0.20 | MIT |
| go | github.com/mattn/go-runewidth | v0.0.9 | MIT |
| go | github.com/mattn/go-sqlite3 | v1.14.22 | MIT |
| go | github.com/modern-go/concurrent | v0.0.0-20180306012644-bacd9c7ef1dd | Apache-2.0 |
| go | github.com/modern-go/reflect2 | v1.0.2 | Apache-2.0 |
| go | github.com/munnerz/goautoneg | v0.0.0-20191010083416-a7dc8b61c822 | BSD-3-Clause |
| go | github.com/pelletier/go-toml/v2 | v2.2.4 | MIT |
| go | github.com/pkg/sftp | v1.13.10 | BSD-2-Clause |
| go | github.com/pquerna/otp | v1.5.0 | Apache-2.0 |
| go | github.com/prometheus/client_golang | v1.23.2 | Apache-2.0 |
| go | github.com/prometheus/client_model | v0.6.2 | Apache-2.0 |
| go | github.com/prometheus/common | v0.66.1 | Apache-2.0 |
| go | github.com/prometheus/procfs | v0.16.1 | Apache-2.0 |
| go | github.com/robfig/cron/v3 | v3.0.1 | MIT |
| go | github.com/ugorji/go/codec | v1.3.0 | MIT |
| go | github.com/x448/float16 | v0.8.4 | MIT |
| go | go.yaml.in/yaml/v2 | v2.4.2 | Apache-2.0 |
| go | golang.org/x/crypto | v0.53.0 | BSD-3-Clause |
| go | golang.org/x/net | v0.56.0 | BSD-3-Clause |
| go | golang.org/x/oauth2 | v0.30.0 | BSD-3-Clause |
| go | golang.org/x/sync | v0.21.0 | BSD-3-Clause |
| go | golang.org/x/sys | v0.46.0 | BSD-3-Clause |
| go | golang.org/x/term | v0.44.0 | BSD-3-Clause |
| go | golang.org/x/text | v0.39.0 | BSD-3-Clause |
| go | golang.org/x/time | v0.3.0 | BSD-3-Clause |
| go | google.golang.org/protobuf | v1.36.9 | BSD-3-Clause |
| go | gopkg.in/inf.v0 | v0.9.1 | BSD-3-Clause |
| go | gopkg.in/yaml.v2 | v2.4.0 | Apache-2.0 |
| go | gopkg.in/yaml.v3 | v3.0.1 | Apache-2.0 |
| go | gorm.io/driver/postgres | v1.5.11 | MIT |
| go | gorm.io/driver/sqlite | v1.5.7 | MIT |
| go | gorm.io/gorm | v1.25.12 | MIT |
| go | k8s.io/api | v0.31.3 | Apache-2.0 |
| go | k8s.io/apimachinery | v0.31.3 | Apache-2.0 |
| go | k8s.io/client-go | v0.31.3 | Apache-2.0 |
| go | k8s.io/klog/v2 | v2.130.1 | Apache-2.0 |
| go | k8s.io/kube-openapi | v0.0.0-20240228011516-70dd3763d340 | Apache-2.0 |
| go | k8s.io/utils | v0.0.0-20240711033017-18e509b52bc8 | Apache-2.0 |
| go | sigs.k8s.io/json | v0.0.0-20221116044647-bc3834ca7abd | Apache-2.0 |
| go | sigs.k8s.io/structured-merge-diff/v4 | v4.4.1 | Apache-2.0 |
| go | sigs.k8s.io/yaml | v1.4.0 | Apache-2.0 |
| npm | @babel/helper-string-parser | 7.29.7 | MIT |
| npm | @babel/helper-validator-identifier | 7.29.7 | MIT |
| npm | @babel/parser | 7.29.7 | MIT |
| npm | @babel/runtime | 7.28.4 | MIT |
| npm | @babel/types | 7.29.7 | MIT |
| npm | @ctrl/tinycolor | 3.6.1 | MIT |
| npm | @element-plus/icons-vue | 2.3.2 | MIT |
| npm | @floating-ui/core | 1.7.3 | MIT |
| npm | @floating-ui/dom | 1.7.4 | MIT |
| npm | @floating-ui/utils | 0.2.10 | MIT |
| npm | @intlify/core-base | 11.4.2 | MIT |
| npm | @intlify/devtools-types | 11.4.2 | MIT |
| npm | @intlify/message-compiler | 11.4.2 | MIT |
| npm | @intlify/shared | 11.4.2 | MIT |
| npm | @jridgewell/sourcemap-codec | 1.5.5 | MIT |
| npm | @solid-primitives/refs | 1.1.2 | MIT |
| npm | @solid-primitives/transition-group | 1.1.2 | MIT |
| npm | @solid-primitives/utils | 6.3.2 | MIT |
| npm | @sxzz/popperjs-es | 2.11.7 | MIT |
| npm | @types/lodash | 4.17.20 | MIT |
| npm | @types/lodash-es | 4.17.12 | MIT |
| npm | @types/web-bluetooth | 0.0.16 | MIT |
| npm | @vue/compiler-core | 3.5.22 | MIT |
| npm | @vue/compiler-dom | 3.5.22 | MIT |
| npm | @vue/compiler-sfc | 3.5.22 | MIT |
| npm | @vue/compiler-ssr | 3.5.22 | MIT |
| npm | @vue/devtools-api | 6.6.4 | MIT |
| npm | @vue/reactivity | 3.5.22 | MIT |
| npm | @vue/runtime-core | 3.5.22 | MIT |
| npm | @vue/runtime-dom | 3.5.22 | MIT |
| npm | @vue/server-renderer | 3.5.22 | MIT |
| npm | @vue/shared | 3.5.22 | MIT |
| npm | @vueuse/core | 9.13.0 | MIT |
| npm | @vueuse/metadata | 9.13.0 | MIT |
| npm | @vueuse/shared | 9.13.0 | MIT |
| npm | @xterm/addon-fit | 0.10.0 | MIT |
| npm | @xterm/addon-search | 0.16.0 | MIT |
| npm | @xterm/addon-web-links | 0.11.0 | MIT |
| npm | @xterm/xterm | 5.5.0 | MIT |
| npm | ansi-regex | 5.0.1 | MIT |
| npm | ansi-styles | 4.3.0 | MIT |
| npm | asciinema-player | 3.12.1 | Apache-2.0 |
| npm | async-validator | 4.2.5 | MIT |
| npm | asynckit | 0.4.0 | MIT |
| npm | axios | 1.12.2 | MIT |
| npm | call-bind-apply-helpers | 1.0.2 | MIT |
| npm | camelcase | 5.3.1 | MIT |
| npm | cliui | 6.0.0 | ISC |
| npm | color-convert | 2.0.1 | MIT |
| npm | color-name | 1.1.4 | MIT |
| npm | combined-stream | 1.0.8 | MIT |
| npm | csstype | 3.1.3 | MIT |
| npm | dayjs | 1.11.18 | MIT |
| npm | decamelize | 1.2.0 | MIT |
| npm | delayed-stream | 1.0.0 | MIT |
| npm | dijkstrajs | 1.0.3 | MIT |
| npm | dunder-proto | 1.0.1 | MIT |
| npm | element-plus | 2.11.4 | MIT |
| npm | emoji-regex | 8.0.0 | MIT |
| npm | entities | 4.5.0 | BSD-2-Clause |
| npm | es-define-property | 1.0.1 | MIT |
| npm | es-errors | 1.3.0 | MIT |
| npm | es-object-atoms | 1.1.1 | MIT |
| npm | es-set-tostringtag | 2.1.0 | MIT |
| npm | escape-html | 1.0.3 | MIT |
| npm | estree-walker | 2.0.2 | MIT |
| npm | find-up | 4.1.0 | MIT |
| npm | follow-redirects | 1.15.11 | MIT |
| npm | form-data | 4.0.4 | MIT |
| npm | function-bind | 1.1.2 | MIT |
| npm | get-caller-file | 2.0.5 | ISC |
| npm | get-intrinsic | 1.3.0 | MIT |
| npm | get-proto | 1.0.1 | MIT |
| npm | gopd | 1.2.0 | MIT |
| npm | has-symbols | 1.1.0 | MIT |
| npm | has-tostringtag | 1.0.2 | MIT |
| npm | hasown | 2.0.2 | MIT |
| npm | is-fullwidth-code-point | 3.0.0 | MIT |
| npm | locate-path | 5.0.0 | MIT |
| npm | lodash | 4.17.21 | MIT |
| npm | lodash-es | 4.17.21 | MIT |
| npm | lodash-unified | 1.0.3 | MIT |
| npm | magic-string | 0.30.21 | MIT |
| npm | math-intrinsics | 1.1.0 | MIT |
| npm | memoize-one | 6.0.0 | MIT |
| npm | mime-db | 1.52.0 | MIT |
| npm | mime-types | 2.1.35 | MIT |
| npm | nanoid | 3.3.11 | MIT |
| npm | normalize-wheel-es | 1.2.0 | BSD-3-Clause |
| npm | p-limit | 2.3.0 | MIT |
| npm | p-locate | 4.1.0 | MIT |
| npm | p-try | 2.2.0 | MIT |
| npm | path-exists | 4.0.0 | MIT |
| npm | picocolors | 1.1.1 | ISC |
| npm | pinia | 2.3.1 | MIT |
| npm | pngjs | 5.0.0 | MIT |
| npm | postcss | 8.5.6 | MIT |
| npm | proxy-from-env | 1.1.0 | MIT |
| npm | qrcode | 1.5.4 | MIT |
| npm | require-directory | 2.1.1 | MIT |
| npm | require-main-filename | 2.0.0 | ISC |
| npm | seroval | 1.3.2 | MIT |
| npm | seroval-plugins | 1.3.3 | MIT |
| npm | set-blocking | 2.0.0 | ISC |
| npm | solid-js | 1.9.9 | MIT |
| npm | solid-transition-group | 0.2.3 | MIT |
| npm | sortablejs | 1.15.7 | MIT |
| npm | source-map-js | 1.2.1 | BSD-3-Clause |
| npm | string-width | 4.2.3 | MIT |
| npm | strip-ansi | 6.0.1 | MIT |
| npm | vue | 3.5.22 | MIT |
| npm | vue-demi | 0.14.10 | MIT |
| npm | vue-i18n | 11.4.2 | MIT |
| npm | vue-router | 4.5.1 | MIT |
| npm | which-module | 2.0.1 | ISC |
| npm | wrap-ansi | 6.2.0 | MIT |
| npm | y18n | 4.0.3 | ISC |
| npm | yargs | 15.4.1 | MIT |
| npm | yargs-parser | 18.1.3 | ISC |
| vendored-js | guacamole-1.5.5.min.js | - | Apache-2.0 |
<!-- END GENERATED: shipped-components -->

---

## 2. 授權正文與著作權聲明的載體（誠實界定）

### 2.1 `licenses/` 內的授權正文

| 檔案 | 適用於 | 取得來源 | sha256 |
|---|---|---|---|
| `licenses/Apache-2.0.txt` | 第 1 節的 44 個 Apache-2.0 元件、第 3 節映像內的 Apache-2.0 元件 | `https://www.apache.org/licenses/LICENSE-2.0.txt` | `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30` |
| `licenses/GPL-2.0.txt` | 第 3 節映像內的 GPL-2.0-only／GPL-2.0-or-later 元件 | `https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt` | `edaef632cbb643e4e7a221717a6c441a4c1a7c918e6e4d56debc3d8739b233f6` |
| `licenses/GPL-3.0.txt` | 第 3 節映像內的 GPL-3.0-or-later 元件 | `https://www.gnu.org/licenses/gpl-3.0.txt` | `3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986` |
| `licenses/LGPL-2.1.txt` | 第 3 節映像內的 LGPL-2.0-or-later／LGPL-2.1-or-later 元件 | Debian 12 `/usr/share/common-licenses/LGPL-2.1`（FSF 原文） | `dc626520dcd53a22f727af3ee42c770e56c97a64fe3adb063799d8ab032fe551` |
| `licenses/LGPL-3.0.txt` | 第 3 節映像內的 LGPL-3.0-or-later 元件 | Debian 12 `/usr/share/common-licenses/LGPL-3`（FSF 原文） | `e3a994d82e644b03a792a930f574002658412f62407f5fee083f2555c5f23118` |

AGPL-3.0 正文即本專案自身的 [LICENSE](LICENSE)，不另置副本。

交叉查核：`Apache-2.0.txt` 與 Debian 12 的
`/usr/share/common-licenses/Apache-2.0` 位元組相同；`GPL-3.0.txt` 與 Debian 12 的
`/usr/share/common-licenses/GPL-3` 位元組相同——兩份正文各有兩個獨立來源互證。
`GPL-2.0.txt` 取自 gnu.org 現行版本，與 Debian 副本的差異僅在 FSF 通訊地址與附錄
範例署名（條款本文相同）。

### 2.2 MIT／BSD／ISC 的逐套件著作權聲明——現況與缺口

MIT、BSD-2-Clause、BSD-3-Clause、ISC 都要求再散布時**保留原著作權聲明**，
而這些聲明內嵌各自的著作權人姓名，因此**一份共用正文無法替代逐套件的聲明**。
本檔不放這幾種授權的模板正文，正是為了不製造「已經涵蓋」的錯覺。

現況分兩種散布形態，誠實界定如下：

- **原始碼形態（本 repository 與公開快照）**：逐套件的授權檔隨依賴取得而取得——
  Go 模組在模組快取的各模組根、npm 套件在 `node_modules/<套件>/`。
  第 1 節的表格提供「有哪些、各是什麼授權」的索引。
- **容器映像形態**：後端二進位是 `CGO_ENABLED=0` 靜態編譯的單一執行檔
  （`docker/backend/Dockerfile:63`），**映像內不含**這些套件的授權檔；
  前端產物同理。**這是一個尚未關閉的缺口**，不是已履行的義務。
  關閉它的作法是在發佈流程把全部 build／prod 套件的授權全文匯出成單一檔案
  並複製進映像；本版本尚未實作，列為已知缺口，後續版本關閉。

### 2.3 本檔、`NOTICE` 與 `licenses/` 目前只存在於原始碼樹

同一個界線也適用於本檔自身：`LICENSE`、`NOTICE`、`THIRD-PARTY-LICENSES.md`、
`licenses/` **尚未複製進容器映像**。拿到原始碼樹的人取得的是完整的一份；
只拿到映像的人取得的不是。

以 `docker export` 逐一列舉三個映像的實測結果：
`custodexa/backend` 內無任何授權或聲明檔；`custodexa/frontend` 只有基底 nginx 映像自帶的
`/usr/share/licenses/nginx*/COPYRIGHT`（6 份）；`custodexa/guacd` 只有
`/usr/share/licenses/font-liberation-sans-narrow/License.txt`。
三者皆**不含**本專案的 AGPL-3.0 全文、`NOTICE` 或本檔。

對第 3 節的書面 offer 而言，這是實務上的弱點而非致命傷——offer 的內容公開可得，
且映像的來源即本 repository。**把授權檔複製進映像列為已知缺口，後續版本關閉。**

---

## 3. 容器映像內的 GPL／LGPL 元件與對應源碼

本產品的容器映像（`custodexa/backend`、`custodexa/frontend`、`custodexa/guacd`）以
Alpine Linux 為基礎系統，映像內含若干以 GNU General Public License（GPL）或
GNU Lesser General Public License（LGPL）授權的元件。

**這些元件不與本產品連結成單一作品。** 後端為靜態編譯的 Go 執行檔（`CGO_ENABLED=0`），
映像內其餘元件皆為獨立可執行檔或共用函式庫，由本產品以子行程呼叫（資料庫 CLI、`kubectl`）
或以獨立行程經 TCP 通訊（guacd）。就 GPL 而言，這屬於 mere aggregation：
各元件保留自身授權，不因同處一個映像而併入本產品的 AGPL-3.0 作品。

**但散布映像即散布這些二進位，因此本專案承擔 GPL-2.0 第 3 條／GPL-3.0 第 6 條的
源碼提供義務。** 以下為履行方式。

### 3.1 基礎系統與版本

下表版本號皆自建置定義與映像本體讀出。

| 我方映像 | 基礎映像（Dockerfile 內釘定值） | 映像內 `/etc/alpine-release` | 含 GPL／LGPL 的 apk 套件數 |
|---|---|---|---|
| `custodexa/backend` | `alpine:3.24.1` | 3.24.1 | 19 |
| `custodexa/frontend` | `nginx:1.31.3-alpine3.24` | 3.24.1 | 19 |
| `custodexa/guacd` | `guacamole/guacd:1.6.0` | 3.18.12 | 43 |

`postgres:16.15-alpine3.24` 由使用者自 Docker Hub 直接拉取，不經本專案重新散布，
故不在本節義務範圍內（見 `docker-compose.yml` 的 `postgres` 服務：只有 `image:`，沒有 `build:`）。

各映像實際安裝的套件與版本可由映像自身查得，**不需要信任本文件**：

    cid=$(docker create custodexa/backend:latest)
    docker cp "$cid":/lib/apk/db/installed - | tar -xO \
      | awk '/^P:/{p=substr($0,3)} /^V:/{v=substr($0,3)} /^L:/{printf "%s %s %s\n", p, v, substr($0,3)}'
    docker rm "$cid"

**關於 `custodexa/guacd` 的兩點揭露：**

1. 其基礎系統為 **Alpine 3.18**（上游 `guacamole-server` 1.6.0 的 Dockerfile 以
   `ARG ALPINE_BASE_IMAGE=3.18` 建置），該分支已停止安全維護。本專案未修改該映像內容
   （`docker/guacd/Dockerfile` 只宣告 `EXPOSE`），亦無較新基底的上游 tag 可換。
2. guacd 的協議函式庫**不在 apk 套件資料庫內**，因此上面的 apk 查詢看不到它們——
   上游是從原始碼建置後安裝到 `/opt/guacamole`。實測該目錄內含：

   | 元件 | 映像內版本證據 | 授權 | 授權判定依據 |
   |---|---|---|---|
   | Apache Guacamole（`libguac`、各協議 client） | `guacd -v` 回報 `1.6.0` | Apache-2.0 | `https://github.com/apache/guacamole-server` |
   | LibVNCServer／LibVNCClient | `libvncserver.so.0.9.15`、`libvncclient.so.0.9.15` | **GPL-2.0-or-later** | 映像內 `/opt/guacamole/include/rfb/rfb.h` 檔頭：「either version 2 of the License, or (at your option) any later version」 |
   | FreeRDP | `libfreerdp2.so.2.11.7` | Apache-2.0 | `https://raw.githubusercontent.com/FreeRDP/FreeRDP/2.11.7/LICENSE`（Apache License 2.0 正文） |
   | libssh2 | `libssh2.so.1.0.1` | BSD-3-Clause | `https://github.com/libssh2/libssh2` 的 `COPYING` |
   | libtelnet | `libtelnet.so.2.0.0` | 公眾領域奉獻（非 copyleft） | `https://raw.githubusercontent.com/seanmiddleditch/libtelnet/master/COPYING`：「libtelnet is released to the public domain」 |
   | libwebsockets | `libwebsockets.so.19` | MIT（含少數檔案為 BSD／ZLIB／CC0，見其 LICENSE） | `https://github.com/warmcat/libwebsockets` 的 `LICENSE` |

   **LibVNCServer 是本映像內最實質的 GPL 元件**，其源碼取得見 3.4。

### 3.2 Alpine 套件的對應源碼

映像內全部 Alpine 套件皆為**未經本專案修改**的上游發佈版本。其對應源碼由 Alpine
專案公開提供：

- **建置腳本（APKBUILD）與 patch**：`https://gitlab.alpinelinux.org/alpine/aports`
  - `custodexa/backend`、`custodexa/frontend` → 分支 `3.24-stable`
  - `custodexa/guacd` → 分支 `3.18-stable`
  - 每個套件位於該分支的 `main/<套件名>/` 或 `community/<套件名>/`
- **上游原始碼壓縮檔**：`https://distfiles.alpinelinux.org/distfiles/`
  （分版目錄 `.../distfiles/v3.24/`、`.../distfiles/v3.18/`）
- **二進位套件索引**：`https://dl-cdn.alpinelinux.org/alpine/v3.24/main/`、
  `https://dl-cdn.alpinelinux.org/alpine/v3.18/main/`（`community/` 同構）

本版本發行時，上列 URL 以 `curl` 實測全數回應 HTTP 200。

**「對應」的可驗證性**（實跑抽驗，非推論）：

| 映像內套件 | aports 分支 / 路徑 | APKBUILD 的 `pkgver`-`pkgrel` |
|---|---|---|
| `busybox 1.37.0-r31`（backend／frontend） | `3.24-stable` `main/busybox/` | `1.37.0`-`31` ✔ 相符 |
| `mariadb-client 11.8.8-r0`（backend） | `3.24-stable` `main/mariadb/` | `11.8.8`-`0` ✔ 相符 |
| `busybox 1.36.1-r7`（guacd） | `3.18-stable` `main/busybox/` | `1.36.1`-`7` ✔ 相符 |
| `ghostscript 10.05.1-r0`（guacd） | `3.18-stable` `main/ghostscript/` | 路徑存在（在 `main/`，不在 `community/`） |

亦即：apk 資料庫的 `<版本>-r<修訂>` 直接對應該分支 APKBUILD 的 `pkgver`-`pkgrel`，
任何第三方可循此自行取得每一個套件的完整對應源碼。

### 3.3 對應源碼的取得方式（GPL-3.0 §6(d)／GPL-2.0 §3 末段）

**中文：**

上節（§3.2）列出的資訊，足以讓任何第三方取得本產品各版本映像內全部 GPL／LGPL 元件
的完整對應源碼：套件清單可由映像自身查得，其 `<版本>-r<修訂>` 直接對應
Alpine aports 相應 `*-stable` 分支的 `pkgver`-`pkgrel`，源碼與建置腳本皆於該處公開。

**若您依上述方式仍無法取得某個元件的對應源碼**（例如上游來源暫時無法連線、
或版本對應有疑義），請於本專案 repository 開立 issue，註明映像名稱與 tag
（例如 `custodexa/backend:1.0.0`）及所需的套件名稱。我們會協助取得或直接提供。

**English:**

The information in §3.2 above is sufficient for any third party to obtain the complete
corresponding source code for all GPL- and LGPL-licensed components in the container
images of any version of this product: the package list can be queried from the image
itself, and its `<version>-r<revision>` maps directly to `pkgver`-`pkgrel` of the
corresponding `*-stable` branch of Alpine aports, where both the sources and the build
scripts are publicly available.

**If you are nonetheless unable to obtain the corresponding source for a component**
(for example, the upstream source is temporarily unreachable, or the version mapping is
unclear), please open an issue on this project's repository, stating the image name
and tag (for example `custodexa/backend:1.0.0`) and the package concerned. We will
assist in obtaining it or provide it directly.

---

**為什麼採指向式**：

GPLv3 §6 列有數種履行對應源碼義務的方式。本產品經容器 registry 散布，
適用的是 **§6(d)**——自指定地點提供目標碼存取，且對應源碼可自同一地點以同樣方式取得；
GPLv2 則對應其 §3 末段的同址提供。
（§6(b) 的書面 offer 其構成要件為「隨實體產品或實體媒介交付目標碼」，
與本產品的散布形態不符。）

§3.2 的對應資訊與上方的協助管道，即為此種履行方式的內容。

### 3.4 `custodexa/guacd` 內非 apk 元件的對應源碼

`custodexa/guacd` 建置自 Apache Guacamole 官方映像 `guacamole/guacd:1.6.0`，
本專案未對其內容做任何修改。3.1 表列的 `/opt/guacamole` 元件由上游自原始碼建置，
其對應源碼取得管道如下（本版本發行時實測均回應 HTTP 200）：

- **Apache Guacamole 1.6.0 源碼發佈物**：
  `https://archive.apache.org/dist/guacamole/1.6.0/source/guacamole-server-1.6.0.tar.gz`
- **建置定義（記載每個相依函式庫取自哪個 repository、以什麼版本規則挑選）**：
  `https://raw.githubusercontent.com/apache/guacamole-server/1.6.0/Dockerfile`
- **LibVNCServer（GPL-2.0-or-later，本映像內版本 0.9.15）**：
  `https://github.com/LibVNC/libvncserver`，
  tag `https://github.com/LibVNC/libvncserver/releases/tag/LibVNCServer-0.9.15`
- **FreeRDP（Apache-2.0，2.11.7）**：`https://github.com/FreeRDP/FreeRDP`
- **libssh2**：`https://github.com/libssh2/libssh2`
- **libtelnet**：`https://github.com/seanmiddleditch/libtelnet`
- **libwebsockets**：`https://github.com/warmcat/libwebsockets`

3.3 的書面 offer 同樣涵蓋本節元件。

---

## 4. 如何獨立複核本清單

**本清單的每一項都可用公開工具獨立驗證**，不需要信任本專案的產出：

    # Go 相依（於 backend/ 執行）
    go install github.com/google/go-licenses@latest
    go-licenses report ./... 2>/dev/null

    # 前端相依（於 frontend/ 執行）
    npx --yes license-checker --production --summary

    # 映像層（任一 SBOM 工具，對三顆正式版映像各跑一次）
    syft custodexa/backend:latest -o spdx-json | jq -r '.packages[].licenseConcluded' | sort -u

判準與本清單相同：**每個套件至少有一個 OSI 認可的授權選項**。
若您的掃描結果與第 1 節表格有出入，請依 `SECURITY.md` 的管道回報——
授權盤點的錯誤與程式碼缺陷同樣需要修正。

第 3 節的 apk 套件清單取自映像內 `/lib/apk/db/installed` 的 `P:`／`V:`／`L:` 欄，
指令見 3.1；`/opt/guacamole` 的元件版本取自該目錄的 `so` 檔名與 `guacd -v`。
