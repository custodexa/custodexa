# 開發環境 Dockerfile
#
# build context 為專案根（見 openspec/specs/container-build）：所有 COPY 來源
# 以專案根為基準，故前端原始碼需帶 frontend/ 前綴，nginx.conf 亦得以正確解析。
#
# 基底版本釘選規則（2026-08-17 查證，本檔兩個 node stage 適用）：
# 一律釘到具體版本，不用浮動 major tag。理由有三，皆非潔癖：
# (1) AGPL 的「對應源碼」義務要指名交付二進位對應的是哪一版元件；
# (2) 離線安裝包要能指名包內是哪一版；
# (3) 漏洞公告要能說「升到 X 版」——浮動 tag 使 X 連自己都不知道。
# 不釘版，這三件事都無法履行。
#
# **釘 26.8.2（2026-09-15 查證：node:26.8.2-alpine 為當日 Node 26 線最新 alpine tag）**。
#
# **版本線選擇：追最新 LTS 線，不落後。**本專案是安全軟體，建置鏈的 Node 不停留在
# 已 EOL 或即將換代的線上。2026-09-15 的事實：Node 20（Iron）2026-04-30 EOL；
# 22（Jod）已進 maintenance；24（Krypton）2026-10-20 進 maintenance；
# 26 於 2026-05-05 發布、**2026-10-28 轉 LTS**、支援至 2029-04-30。
# 26 線內依 semver 不再有破壞性變更，轉 LTS 時內容不變、只有承諾期變長，
# 故直接釘 26 而非先釘 24 再於六週後換線。
# 前端建置鏈各套件的 engines（vite 8、@vitejs/plugin-vue 6、happy-dom 20、vitest 5）
# 皆允許 Node 26，鎖定檔內無任何套件對 Node 設上限。
# **Node 26 與 vitest 的耦合**：Node 26 內建 `localStorage` getter（未給
# `--localstorage-file` 時回 undefined），vitest 4 的 happy-dom 環境不覆蓋既有全域，
# 整包測試會在 setup 階段以 `localStorage.getItem` 為 undefined 全數失敗；
# vitest 5 已處理（vitest-dev/vitest#10293）。故本線 Node 要求 vitest >= 5。
#
# 緩解事實（降低急迫度、不解除必要性）：本階段與下方 builder 皆**不進交付映像**
# （正式版前端執行環境是 nginx stage），故 Node 的漏洞面限於建置期而非使用者的執行環境。
#
# 重評觸發點（任一成立即重新評估，不等其餘各項）：
# 1. Node 官方 schedule 出現比現釘線更新的 LTS 線（每年 10 月）→ 升到該線。
# 2. 現釘線有新 patch 版（security release 尤其）→ 更新 patch 版號。
# 3. 下次動到前端建置鏈時（升 Vite／換 bundler／改本檔的建置階段）一併核對。
# 4. 出現針對**建置期**工具鏈的供應鏈事件時。
FROM node:26.8.2-alpine AS development

WORKDIR /app

# 複製 package files
COPY frontend/package*.json ./

# 安裝依賴。
# `npm ci` 而非 `npm install`：嚴格依鎖定檔安裝，不一致時直接失敗而非改寫鎖定檔。
# 兩個 node 階段必須解析出同一組依賴：階段間分岔會讓「開發期通過、正式版建置失敗」
# 在無人改動依賴的情況下發生。
# `--ignore-scripts`：抑制第三方套件的安裝期腳本。理由是執行時機而非套件品質
# ——安裝腳本於建置階段執行，而建置階段的權限範圍大於執行階段。
RUN npm ci --ignore-scripts

# 複製所有原始碼（trailing slash：複製目錄內容而非目錄本身）
COPY frontend/ ./

# 暴露端口
EXPOSE 3000

# 啟動開發伺服器（支援 HMR）
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]

# 建置階段（版本釘選與版本線選擇的說明見檔首，兩個 stage 須同版）
FROM node:26.8.2-alpine AS builder

WORKDIR /app

COPY frontend/package*.json ./
# --ignore-scripts 的理由同 development 階段
RUN npm ci --ignore-scripts

COPY frontend/ ./

# 建置生產版本
RUN npm run build

# 生產環境 - 使用 nginx
#
# **釘 1.31.3-alpine3.24（2026-08-17 查證：當日 nginx:alpine／1.31.3-alpine／
# 1.31.3-alpine3.24 三個 tag 的 manifest digest 完全相同 sha256:4a73073b…，故本次
# 釘版不改變任何交付內容）**。1.31.3 為當時 mainline 最新版，維持與原 `:alpine`
# 相同的分支（`:alpine` 指向 mainline 而非 stable，改指 stable 才是行為變更）。
# 同時釘 alpine3.24 而非只釘 nginx 版本：本階段是**執行階段**（交付物就是這顆映像），
# OS 套件層的 CVE 直接落在使用者的執行環境，故基底 minor 也需可指名。
# 釘版理由（AGPL 對應源碼／離線包／漏洞公告需可指名版本）見 docker/backend/Dockerfile 檔首。
FROM nginx:1.31.3-alpine3.24 AS production

# 複製建置產物
COPY --from=builder /app/dist /usr/share/nginx/html

# 複製 nginx 配置
COPY docker/frontend/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
