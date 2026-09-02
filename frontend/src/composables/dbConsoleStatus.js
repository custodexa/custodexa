// 主控台連線狀態的詞彙。
//
// 兩套詞彙刻意並存：主控台自己需要區分「連線還在但目標受限」，而工作區的分頁
// 只需要知道要不要標灰。把映射寫在一處，避免兩邊各自解讀同一個狀態。

// 五態機。`restricted`＝連線仍在、但當前目標庫落在允許清單外：
// 會話沒斷（既有結果看得到、切庫即可救回），但送出一律被拒
export const DB_CONSOLE_STATUS = Object.freeze({
  CONNECTING: 'connecting',
  CONNECTED: 'connected',
  RESTRICTED: 'restricted',
  DISCONNECTED: 'disconnected',
  ERROR: 'error',
})

// 分頁狀態詞彙（工作區以此判斷標灰）。`restricted` 不標灰——
// 標灰會讓使用者以為要重連才救得回來，實際上切個庫就好
const TAB_STATUS = Object.freeze({
  connecting: 'connecting',
  connected: 'connected',
  restricted: 'connected',
  disconnected: 'closed',
  error: 'error',
})

export const toTabStatus = (status) => TAB_STATUS[status] || 'error'

// 樹的層級
export const TREE_LEVELS = Object.freeze({
  DATABASES: 'databases',
  TABLES: 'tables',
  COLUMNS: 'columns',
})
