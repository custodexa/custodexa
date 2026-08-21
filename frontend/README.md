# Custodexa 前端

Vue 3 + Element Plus 實作的堡壘機管理與連線介面。

本檔只描述 `frontend/` 目錄本身。專案總覽見 [根 README](../README.md)；啟動與故障排除見
[docs/QUICKSTART.md](../docs/QUICKSTART.md)；視覺規範與品牌 token 見
[docs/DESIGN_SPEC.md](../docs/DESIGN_SPEC.md)；API 參考見 [docs/API_SPEC.md](../docs/API_SPEC.md)。

## 技術棧

- **框架**：Vue 3（Composition API，`<script setup>`）
- **建置工具**：Vite
- **UI 組件庫**：Element Plus（暗色主題，設計 token 在 `src/styles/tokens.css`）
- **路由**：Vue Router 4
- **狀態管理**：Pinia
- **HTTP 客戶端**：Axios（統一封裝在 `src/api/request.js`）
- **終端機**：xterm.js（SSH／DB CLI／K8s exec 文字流）＋ asciinema-player（文字會話回放）
- **圖形協議**：guacamole-common-js（`public/guacamole-1.5.5.min.js`，隨頁面載入而非 npm 依賴），
  負責 RDP／VNC 的畫面與回放
- **多語系**：vue-i18n，三語（`zh-TW`／`en-US`／`ja-JP`）
- **測試**：Vitest + @vue/test-utils

## 專案結構

```
frontend/
├── src/
│   ├── views/          # 頁面組件（一頁一檔，路由對應見 src/router/index.js）
│   ├── components/     # 共用組件（終端、播放器、檔案管理、政策表單等）
│   ├── composables/    # 可組合邏輯（表單、角色、傳輸能力）
│   ├── api/            # 後端 API 封裝，一模組一檔；request.js 為統一攔截層
│   ├── constants/      # 枚舉與常數（角色、審計列舉、政策領域、通知通道）
│   ├── utils/          # 純函式工具（格式化、下載、協議顯示、i18n 顯示）
│   ├── i18n/           # vue-i18n 設定與 locales/（三語訊息檔）
│   ├── styles/         # tokens.css（品牌／設計 token）、dark-theme.css、終端主題
│   ├── router/         # Vue Router 設定與路由守衛
│   ├── brand.js        # 品牌識別字的前端單一來源
│   ├── App.vue
│   └── main.js
├── public/             # 靜態資源
├── vite.config.js      # 建置與開發代理設定
├── vitest.config.js    # 單元測試設定
└── package.json
```

各層的 `__tests__/` 目錄放對應的單元測試，與被測檔同層。

## 開發與驗證

**一律在 docker-compose 內執行**：

```bash
docker compose exec frontend npm run test     # 單元測試（vitest）
docker compose exec frontend npm run build    # 生產建置
docker compose exec frontend npm run lint     # ESLint（--fix）
```

改動後看不到效果時用 `docker compose up -d --force-recreate frontend`
（macOS bind-mount 的檔案監看不可靠）；**不要用 `docker compose restart frontend`**，
會因工作目錄狀態不完整而崩潰。

開發伺服器在 `http://localhost:3000`，Vite 將 `/api`、`/ws` 等前綴代理到 `backend:8080`
（服務名，不是 localhost——前端跑在容器內）。

## 慣例

- **使用者可見文字一律走 i18n**，三語同步，不得硬編碼字面字串；
  後端錯誤以機器碼回傳、由前端翻譯（見 [docs/dev/conventions.md](../docs/dev/conventions.md)）。
- **品牌識別字從 `src/brand.js` 取**，不散落字面量。
- **前端零接觸明文憑證**：連線一律先取一次性 connect token 再建 WebSocket，
  任何形態的密碼都不得經前端傳遞或顯示。
- 測試紀律與已知陷阱（元件不卸載導致的偶發逾時等）見
  [docs/dev/testing.md](../docs/dev/testing.md)。

## 授權

AGPL-3.0，全文見 [LICENSE](../LICENSE)。
