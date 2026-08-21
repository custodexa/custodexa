# 三大 IdP discovery 文件 fixture

供 `oidc_discovery_contract_test.go` 使用。用途是把**真實 IdP 的 discovery 文件**餵進本專案的
discovery 解析／驗證邏輯，作為「信任門檻收緊時不得誤傷真實 IdP」的回歸基準。

## 擷取資訊

| 檔案 | 來源 URL | 擷取日期 | 取得方式 |
|---|---|---|---|
| `google.json` | `https://accounts.google.com/.well-known/openid-configuration` | 2026-08-04 | curl 匿名實抓（HTTP 200） |
| `entra-common.json` | `https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration` | 2026-08-04 | curl 匿名實抓（HTTP 200） |
| `entra-tenant-specific.json` | `https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0/.well-known/openid-configuration` | 2026-08-04 | curl 匿名實抓（HTTP 200） |
| `okta.json` | `https://okta.okta.com/.well-known/openid-configuration` | 2026-08-04 | curl 匿名實抓（HTTP 200） |

四份**皆為實抓**，非依官方文件手工構造。內容為公開的 OIDC 中繼資料
（RFC 8414 / OpenID Discovery 規定為 public endpoint），不含任何憑證、token 或個資；
唯一經處理之處是以 `json.dump(indent=2, sort_keys=True)` 重排版與排序鍵，**值未修改**。

`entra-tenant-specific.json` 選用的 `9188040d-6c67-4c5b-b112-36a304b66dad` 是 Microsoft
公開文件記載的「個人 Microsoft 帳號」固定租戶 GUID，非任何客戶租戶。
`okta.json` 取自 Okta 自家正式 org（`okta.okta.com`）——Okta 官方文件的範例 domain
（`{yourOktaDomain}`、`dev-*.okta.com`）不可匿名取得，故改以真實可匿名存取的 org 實抓。

## 各檔的契約意義（測試斷言的依據）

- **google.json**：`issuer=accounts.google.com`、token 在 `oauth2.googleapis.com`、
  jwks 在 `www.googleapis.com`、userinfo 在 `openidconnect.googleapis.com`——**四個不同 host**。
  這是「不可要求 endpoint 與 issuer 同源」的實證，任何同源類信任門檻都會當場阻斷 Google。
- **entra-common.json**：`issuer` 字面為 `https://login.microsoftonline.com/{tenantid}/v2.0`，
  **帶 placeholder**。issuer 逐字比對之下多租戶 `common` 端點恆不可用，須改用 tenant-specific。
- **entra-tenant-specific.json**：同一家 IdP 的可用形狀（issuer 無 placeholder），
  與上一份構成對照，證明「不可用」的原因是 placeholder 而非我方擋掉了 Entra。
- **okta.json**：issuer 天生含組織域名、四個 endpoint 同 host；`subject_types_supported`
  為 `public`（相對於 Entra 的 `pairwise`）。

## 更新守則

重新擷取時一併更新上表日期，並確認契約測試仍綠。**測試失敗時先判斷是我方門檻改變
還是 IdP 端變更**——若為後者（例如 Google 新增演算法宣告），更新 fixture 並在
commit 訊息載明；若為前者，該門檻極可能會誤傷真實部署，應先檢討門檻本身。
