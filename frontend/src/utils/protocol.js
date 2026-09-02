// 協議分類（與後端 model.ProtocolType 對齊，database-protocol）

// 文字終端類協議：SSH、資料庫 CLI 與 K8s exec，共用 xterm 終端與審計鏈（指令審計/錄製/監看/阻斷）
export const isTextTerminal = (protocol) =>
  ['ssh', 'mysql', 'postgres', 'redis', 'mssql', 'k8s'].includes(protocol)

// 資料庫 CLI 協議（對齊後端 model.ProtocolType.IsDatabase）。
// 撥測只驗 TCP 埠可達，故可達徽章須加註說明
export const isDatabaseProtocol = (protocol) =>
  ['mysql', 'postgres', 'redis', 'mssql'].includes(protocol)

// 支援查詢主控台的協議（對齊後端主控台兌換點的協議閘）。
// 刻意是 isDatabaseProtocol 的真子集：redis 是 DB 協議但非 SQL 方言，
// 沒有語句／結果集／交易態的語義，主控台不收
export const isDBConsoleProtocol = (protocol) =>
  ['mysql', 'postgres', 'mssql'].includes(protocol)

// 僅密碼認證的協議（無使用者名稱欄位；k8s 以 Token 走密碼欄）。
// mssql 刻意不在此列：sqlcmd 未帶 -U 時不會索取密碼，後端的 PTY 密碼注入
// 因而永不觸發、連線會無聲斷掉，故 mssql 必須有使用者名稱欄位
export const isPasswordOnlyProtocol = (protocol) =>
  protocol === 'vnc' || protocol === 'redis' || protocol === 'k8s'

// 各協議預設埠號
export const PROTOCOL_DEFAULT_PORTS = {
  ssh: 22,
  rdp: 3389,
  vnc: 5900,
  mysql: 3306,
  postgres: 5432,
  redis: 6379,
  mssql: 1433,
  k8s: 6443,
}

// 協議 tag 顏色唯一映射：
// 同一資產的協議 chip 全站同色；新協議在此登記，勿在頁面內寫 inline 判斷
const PROTOCOL_TAG_TYPES = {
  ssh: 'success',
  rdp: 'primary',
  vnc: 'warning',
  mysql: 'info',
  postgres: 'info',
  redis: 'info',
  mssql: 'info',
  k8s: 'info',
}

export const protocolTagType = (protocol) =>
  PROTOCOL_TAG_TYPES[(protocol || '').toLowerCase()] || 'info'
