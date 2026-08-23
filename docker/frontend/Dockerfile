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
# **釘 20.20.2（2026-08-17 查證：當日 node:20-alpine／20.20-alpine／20.20.2-alpine／
# 20.20.2-alpine3.23 四個 tag 的 manifest digest 完全相同 sha256:fb4cd12c…，故本次
# 釘版不改變任何交付內容，只是把「當時碰巧拉到什麼」變成「指名拉什麼」）**。
#
# **Node 20（Iron）已 EOL，本次刻意只釘版、不升 major**：v20.20.2（2026-03-24）
# 是該線最後一個 release，Docker Hub 的 20.x alpine tag 也停在 2026-04-17 之後不再更新
# ——意即此後 Node 本體與其基底的 CVE 都不會再有修補版。**這不是可以長期停留的狀態**，
# 但升 major（現行 LTS 為 22 Jod／24 Krypton）會換掉整條前端建置鏈的執行環境，屬取捨題
# 而非釘版的一部分，要不要升 major 得另行評估。緩解事實（降低急迫度、不解除必要性）：本階段與下方
# builder 皆**不進交付映像**（正式版前端執行環境是 nginx stage），故 Node 的漏洞面限於
# 建置期而非使用者的執行環境。
#
# 重評觸發點（任一成立即重新評估升 major，不等其餘兩項）：
# 1. 下次動到前端建置鏈時（升 Vite／換 bundler／改本檔的建置階段）一併評估
#    ——那時本來就要重測整條鏈，邊際成本最低。
# 2. 現行 LTS（22 Jod／24 Krypton）任一進入 maintenance，使可選版本收斂到只剩一個時。
# 3. 出現針對**建置期**工具鏈的供應鏈事件時（本階段雖不出貨，建置環境仍是供應鏈的一環）。
# 這三點是刻意寫成可判斷的事件而非日期：日期會過期而沒有人回頭看，事件會自己找上門。
FROM node:20.20.2-alpine AS development

WORKDIR /app

# 複製 package files
COPY frontend/package*.json ./

# 安裝依賴
RUN npm install

# 複製所有原始碼（trailing slash：複製目錄內容而非目錄本身）
COPY frontend/ ./

# 暴露端口
EXPOSE 3000

# 啟動開發伺服器（支援 HMR）
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]

# 建置階段（版本釘選與 Node 20 EOL 的說明見檔首，兩個 stage 須同版）
FROM node:20.20.2-alpine AS builder

WORKDIR /app

COPY frontend/package*.json ./
RUN npm ci

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
