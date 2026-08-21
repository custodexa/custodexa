# Custodexa - 視覺設計規範

> 權威來源：`frontend/src/styles/tokens.css` 的 `--ot-*` token（產品 app 本體）；品牌資產在 `docs/assets/brand/`（palette.png／icon.png／logo.png）。
> 本文件把「產品視覺識別」訂為規範：**任何產出（app、截圖、文件配圖）不得擅自更換品牌識別**。
> 變更品牌 token（主色、夜色底、字型）須先開 issue 討論，並先改本文件再改實作。

## 品牌識別

- **名稱**：Custodexa；**單一事實源 `frontend/src/brand.js`**（name/tagline/icon 路徑），頁面元件與 title/favicon 一律引用，勿硬編碼。**描述性副標位於 i18n**（key `brand.subtitle`，三語隨介面語言切換）；name/tagline/icon 為品牌識別，不進 i18n
- **標語**：Guard Access. Preserve Evidence.
- **標誌**：hex C 標記；UI 用 `frontend/public/brand/icon.png` 固定檔名，完整 logo 在 `docs/assets/brand/logo.png`
- **icon 使用鐵則**：icon 主體為 navy，深色介面上必須置於淺色徽章（`--ot-brand-badge-bg`）內，否則隱形
- **後端顯示字串**：一律引 `internal/branding.Name`（TOTP issuer／通知標頭／終端提示／啟動日誌）
- **技術識別字**：Go module path、錄影路徑 `/var/lib/custodexa/`、AAD 命名空間、JWT issuer、seed email 皆採現行品牌識別；Go 側收斂於 `backend/internal/branding`（`Name` 顯示用、`Slug` 技術識別字用）

## 暗色主題對比鐵則

- 暗色主題的 light-5..9 一律「主色往暗底混」（Element Plus dark 原生語義；light-5 是
  disabled primary 按鈕底色，往亮走會壓垮對比）。
- Element Plus dark 的 disabled 文字為 50% 半透明白，合成後對比上限僅約 3.4:1——
  彩色按鈕 disabled 文字 alpha 已中央 patch 至 0.78（實效 ≥5.8:1）。
  **驗對比一律以 alpha 合成後的實際顏色計算**，互動主色於暗底須達 WCAG AA 4.5:1。

## 品牌錨點（單一真相 = app tokens.css）

| 角色 | Token | 值 | 色盤來源 | 用途 |
|---|---|---|---|---|
| 品牌主色（暗底） | `--ot-primary` | `#4f83f1` | Primary Blue 亮階（暗底 AA 4.9:1） | 動作、連結、強調、焦點 |
| 主色 hover | `--ot-primary-hover` | `#6e9bff` | 亮一階 | 互動 hover |
| 主色 active | `--ot-primary-active` | `#2563eb` | Primary Blue 品牌原值 | 按下狀態、實底按鈕深階 |
| 夜色底（頁） | `--ot-bg-page` | `#0a1522` | Primary Navy 深化 | 深色介面底 |
| 夜色底（面板） | `--ot-bg-surface` | `#0d1b2a` | Primary Navy 原值 | 卡片/面板 |
| 夜色底（浮層） | `--ot-bg-elevated` | `#14283e` | Navy 亮階 | 彈窗/浮層 |
| 邊框 | `--ot-border` | `#334155` | Slate Gray 原值 | 分隔線/框線 |
| 資訊/提示 | `--ot-info` | `#14b8a6` | Accent Teal | 通知、tooltip、次要強調 |
| 徽章底 | `--ot-brand-badge-bg` | `#e2e8f0` | Light Gray | logo icon 淺色襯底 |
| 主文字 | `--ot-text-primary` | `#e6edf3` | — | 深底上的正文 |
| 次文字 | `--ot-text-secondary` | `#9da7b1` | — | 深底上的輔助文字 |
| 成功/在線 | `--ot-success` | `#4ec47a` | —（語意色） | 僅語意（可達、已錄製、通過） |
| 警示 | `--ot-warning` | `#d9a93e` | —（語意色） | 僅語意（注意、偏離、待處理） |
| 危險 | `--ot-danger` | `#e5604f` | —（語意色） | 僅語意（阻斷、錄製中 REC、錯誤） |

規則：**琥珀（warning）與紅（danger）是語意色，不是品牌色**——不得作為品牌主視覺使用；品牌強調一律用 Primary Blue 家族。色盤的 White/Light Gray 為亮色主題預留（app 現階段僅暗色）。

## 字型

| 角色 | 規範 | 備註 |
|---|---|---|
| 等寬（數據/終端/代碼） | `JetBrains Mono`，後備 `SF Mono`/Menlo | 與 app `--ot-font-mono` 堆疊一致 |
| 中文/正文（文件配圖等對外素材） | `Noto Sans TC` | app 本體用系統字型堆疊（效能考量），對外素材用 Noto Sans TC |
| 襯線 | app 內禁用 | 產品介面一律不使用襯線字型 |

## 各產出的引用方式

- **app（frontend/）**：直接使用 `--ot-*` token；Element Plus 變數經 `dark-theme.css` 映射（藍階三個 light 變數同步），不得繞過 token 寫死色值。
- **截圖與文件配圖**：取用品牌錨點表的實際值，不另調色；截圖一律取自未改色的 app。

## 互動慣例（新頁面一律遵守）

| # | 慣例 | 唯一規則 |
|---|---|---|
| C1 | 篩選觸發 | select／date／switch 變更即查；文字輸入 enter 或「搜尋」鈕；一律配「重設」 |
| C2 | 列內操作按鈕 | 一律 link 文字鈕（type 表語義 primary/danger/warning）；實體鈕只留頁級主動作；操作欄 fixed right 鐵則不變 |
| C3 | 刪除/危險確認 | 標題「確認刪除」；內文含「此操作無法復原」；確認鈕「確定刪除」（danger）；一律 `await ElMessageBox.confirm` |
| C4 | 重新整理 | 所有列表/總覽頁 PageHeader actions 提供「重新整理」；輪詢僅限活動監控場景 |
| C5 | dialog 寬度 | 三檔：480（小表單）／560（標準表單）／680（寬內容/詳情） |
| C6 | 表單驗證 | 提交型表單一律 rules＋validate（紅字就近提示）；純 disabled 守門僅限單欄位微表單 |
| C7 | 表單 label | dialog 表單統一 `label-position="top"` |
| C8 | tabs | 置頁面層（框外）；tab 切換即 refetch（資料新鮮優先） |
| C9 | 空狀態 | 一律共用 `EmptyState`（title＝狀態句、hint＝下一步指引）；勿直用 el-empty |
| C10 | 錯誤呈現 | 全域錯誤只走攔截器 toast；表單就近錯誤與列表 loadError 誠實呈現保留；頁內勿重複 ElMessage.error |
| C11 | 分頁 | layout `total, sizes, prev, pager, next, jumper` 恆顯；容器 class `.pagination` |
| C12 | 詞彙 | 使用者（非用戶）／連線（非會話，Session ID 技術欄位保留）／進行中·已結束·異常中斷／新增（按鈕）／已○○（成功訊息）／重新整理（非刷新）／停用（非禁用）。**本詞彙表＝zh-TW locale 的內容標準（撰寫事實源）；en-US/ja-JP 譯文循各語言自然慣用，不受中文詞對映束縛** |
| C13 | 審核域詞彙 | 五種審查動作嚴格分詞（`review` 一詞四義的顯示層防線）：**核准**＝連線申請 approve／**補審**＝破窗事後 review／**複審**＝存取複審 access review／**審閱**＝告警審閱／**簽核**＝每日簽核；「審核範圍」專指 approver scope。新頁面文案勿混用 |
| C14 | i18n | 三語 zh-TW（源）/en-US/ja-JP；譯文一律進 `src/i18n/locales/*.json`（三語 key 集合一致，結構單測釘住）；枚舉 label 走 locale＋值域留 constants；偏好存 localStorage `ot-lang`（**裝置級全域，是「localStorage 角色分域」慣例的刻意例外**——登入前就要生效）；切語言免 reload（活躍連線不斷）；勿把格式化結果存 state（斷 reactivity）；技術識別字（enum value、協議 tag、HKDF info、路徑）不譯 |

共用件（勿在頁內重新實作）：`utils/format.js`（日期 24h 含秒/時長/相對時間）、`utils/protocol.js` `protocolTagType`（協議 tag 色）、`composables/useRoles.js`（角色判定，口徑 admin>auditor>user；`hasRole`/`roleNames` 相容物件/字串兩形）、`utils/approver-scope.js`（審核範圍四維顯示＋節點全路徑）、`ApproverScopeForm`（範圍新增表單，矩陣頁與 Users 對話框共用）、`EmptyState`／`PageHeader`。

## 改視覺前的檢核清單

- [ ] 主色是否仍為 Primary Blue 家族（暗底 `#4f83f1`／品牌 `#2563eb`）？（換掉＝品牌變更，須先開 issue 討論）
- [ ] 暗底是否與 navy `#0a1522`/`#0d1b2a` 同色相？mono 是否 JetBrains Mono 堆疊？
- [ ] 琥珀/紅是否只出現在語意位置（警示、REC）？
- [ ] icon 是否置於淺色徽章上（深色介面）？品牌名是否一律 Custodexa？
- [ ] 對比：正文 ≥ 4.5:1、大字/粗體 ≥ 3:1（深色底與亮色底分開驗）。
