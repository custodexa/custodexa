import { describe, it, expect } from 'vitest'

// profile-display-name D4（安全紅線，task 6.2）：作用域收窄回歸守衛。
// local_display_name/display_name 使用者可自改且不唯一——若滲入身分敏感 UI，
// 使用者可冒充他人（改成他人姓名/admin）製造審計/授權混淆。故身分敏感頁面
// 一律 username，永不得引用 display_name/local_display_name。
//
// 以 Vite ?raw glob 冷讀所有 view 原始碼（免 fs 路徑問題），斷言身分敏感 view
// 不含 display_name（子字串亦涵蓋 local_display_name）。新增身分敏感頁面時，
// 將其加入下方清單。
const viewSources = import.meta.glob('../*.vue', {
  query: '?raw',
  eager: true,
  import: 'default',
})

const IDENTITY_SENSITIVE_VIEWS = [
  'AuditLogs.vue',       // 審計日誌 actor
  'Authorizations.vue',  // 授權 subject
  'Approvals.vue',       // 審核方顯示
  'ApproverScopes.vue',  // 審核範圍主體
  'AccessReviews.vue',   // 存取複審矩陣
  'Users.vue',           // admin 使用者管理列表
  'Sessions.vue',        // 會話 owner
  'SessionDetail.vue',   // 會話詳情 owner
  'SessionMonitor.vue',  // 即時會話監看
  'MyConnections.vue',   // 自助連線（含 owner 身分）
]

describe('display name 作用域收窄（D4 安全紅線）', () => {
  it.each(IDENTITY_SENSITIVE_VIEWS)(
    '%s 不得引用 display_name/local_display_name（身分敏感場景一律 username）',
    (file) => {
      const src = viewSources[`../${file}`]
      expect(src, `找不到 view 原始碼：${file}（請確認檔名或 glob 範圍）`).toBeTypeOf('string')
      expect(src).not.toContain('display_name')
    }
  )
})
