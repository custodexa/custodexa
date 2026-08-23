import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

// 應用對外 TLS-ready 不變式（前端側守衛）。
// WS 連線 scheme 必須依頁面協定推導（https→wss / http→ws），使 stock HTTP 部署置於外部
// TLS ingress 後即自動走 wss、無 mixed content。硬編碼 ws:// 會在 https 頁面被瀏覽器擋下，
// 破壞「置於外部 TLS edge 後無需改應用」的契約——此守衛攔截該退化。
// 路徑以 cwd（frontend 根）為錨，對齊 i18n.spec.js 讀磁碟原始檔的慣例。
const WS_COMPONENTS = ['SshTerminal.vue', 'GuacamoleClient.vue', 'MonitorTerminal.vue']

describe('WebSocket scheme TLS-ready 不變式', () => {
  for (const name of WS_COMPONENTS) {
    const src = readFileSync(join(process.cwd(), 'src/components', name), 'utf8')

    it(`${name} 依 location.protocol 推導 ws/wss`, () => {
      expect(src).toContain("window.location.protocol === 'https:'")
      expect(src).toContain("'wss:'")
      expect(src).toContain("'ws:'")
    })

    it(`${name} 不得硬編碼 ws:// 或 wss:// 完整 scheme`, () => {
      expect(src).not.toContain('ws://')
      expect(src).not.toContain('wss://')
    })
  }
})
