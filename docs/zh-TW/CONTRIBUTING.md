# 貢獻指南

<p><a href="../../CONTRIBUTING.md">English</a> | <b>繁體中文</b></p>

感謝你願意貢獻 Custodexa。這份文件告訴你怎麼把貢獻送進來；
環境架設見 [`QUICKSTART.md`](../QUICKSTART.md)。

## 我想……

- **回報 bug 或提想法**：開 GitHub issue，附重現步驟或動機即可。
- **修文件、錯字、明顯的小 bug**：直接開 PR，不需要事前討論。
  記得 commit 加 `-s`（見下方 DCO）。
- **改行為、加功能**：先開 issue 說明動機與做法，有共識後照
  「行為變更流程」進行，免得做完才發現方向不合，白費你的工。

## 開發環境與測試

```bash
bash scripts/quickstart.sh --up                # 起整套環境
docker compose exec backend go test ./...      # 後端測試
docker compose exec frontend npm run test      # 前端測試
```

驗證一律在 docker compose 內執行。更多指令、環境陷阱與守衛測試的紀律見
[`docs/dev/testing.md`](../dev/testing.md)。

## DCO 簽署（必要）

本專案以 **AGPL-3.0** 發佈，貢獻採 **DCO**：不用簽任何協議，
只要每個 commit 帶一行簽署：

```bash
git commit -s -m "fix: 修正某某問題"
```

這行聲明「這段程式碼是你寫的、或你有權以本專案的授權提交它」，
**不轉讓你的著作權**（全文見 [`DCO.md`](../../DCO.md)）。簽署內容取自你的
git 設定（`user.name`／`user.email`），會永久留在公開歷史，請用你願意公開的資料。

- 忘了簽：最後一個 commit 用 `git commit --amend -s`；多個 commit 用
  `git rebase --signoff <base>`，然後 force push。
- 未簽署的 PR 不會被合併，但審查照常進行，維護者會提醒你補簽。
- 為什麼不用 CLA：CLA 是為了讓專案能把你的貢獻以非 AGPL 條款再授權給別人，
  本專案不做這件事，所以不需要。

## PR 檢查清單

- 每個 commit 都有 `Signed-off-by`。
- Commit 訊息用 Conventional Commits（`feat:` / `fix:` / `refactor:` / `docs:` / `test:` / `chore:`）。
- 測試全綠；行為變更附上對應測試。
- 行為變更與重構分開 commit，各自可獨立 revert。
- 使用者可見文字走 i18n（機器碼＋三語，硬編單語會被守衛測試擋下，
  見 [`docs/dev/conventions.md`](../dev/conventions.md)）。
- 沒有硬編碼密鑰；外部輸入有驗證。
- Commit 訊息與文檔可用英文或繁體中文；技術術語保持原文。

## 行為變更流程（OpenSpec）

[`openspec/specs/`](../../openspec/specs/) 描述系統**現在**的行為，是權威來源。
任何行為變更走同一條流程：

```
證據 → 提案（openspec/changes/<id>/）→ 實作 → 歸檔（併回 specs/）
```

`openspec/changes/` 下的 change 目錄只在進行中存在；歸檔會把 spec delta
併回 `openspec/specs/` 並收掉目錄。

要點：

1. **設計要有證據**：帶 file:line 的程式碼盤點、實際運行行為或截圖，不憑印象。
   參考其他同類開源專案只能觀察、不能抄碼；
   它們多為 GPL 系授權，與本專案不相容，抄了會污染授權。
2. **受守衛保護的機器產物**（路由 golden、API 端點索引）照
   [`docs/dev/testing.md`](../dev/testing.md) 的重生流程更新，不可手改。
3. **動了路由**同步 [`docs/API_SPEC.md`](../API_SPEC.md) 散文章節；
   **動了 model／migration** 同步 [`docs/DB_SCHEMA.md`](../DB_SCHEMA.md)。
4. **歸檔時 specs 只能寫系統真的做得到的事**。沒做完的部分在 PR 裡說明，
   維護者會開 issue 追蹤，不要寫進 spec。
5. **行為的權威描述在 `openspec/specs/`**。註解寫的是那一段程式碼當下的取捨，
   註解與規格衝突時以規格為準；理由不清楚就開 issue 問，維護者會補進文件。

## 設計原則（提功能前看一眼）

- **每個角色的功能頁獨立切分**，不往既有頁面塞其他角色的區塊；
  設計前先想清楚這個功能屬於哪個角色的導覽。
- **使用者卡住時要有產品層的自救路徑**（UI 動作＋API 端點）。
  答案若是「請管理員去改資料庫」，代表這個功能還沒補上。
- **視覺規範的唯一真相是 [`docs/DESIGN_SPEC.md`](../DESIGN_SPEC.md)**；
  變更品牌 token 須經維護者核可，審計用途的技術識別字不因視覺改版更名。

## 安全紅線（不可退讓）

違反任一條的 PR 不會被合併：

1. **連線收口**：前端零接觸明文憑證。憑證只存在後端，前端拿到的是一次性 connect token。
2. **全操作審計**：所有連線與管理操作留痕；審計軌跡缺失時 fail-close。
3. **輸入驗證**：所有外部輸入經驗證後才使用。

架構層的具體不變式見 [`docs/dev/conventions.md`](../dev/conventions.md)。

## 深入閱讀

| 文件 | 內容 |
|---|---|
| [`docs/dev/conventions.md`](../dev/conventions.md) | 架構不變式、安全紅線細節、i18n 規範、前端 UI 慣例、程式碼風格 |
| [`docs/dev/testing.md`](../dev/testing.md) | docker 內驗證流程、機器產物重生、守衛測試紀律、flaky 判準 |
| [`docs/dev/architecture.md`](../dev/architecture.md) | 七模組劃分與後續改動不得破壞的不變式 |
