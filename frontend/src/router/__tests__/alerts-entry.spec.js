import { describe, it, expect, beforeEach } from 'vitest'
import router from '../index'
import { ENTRY_RULES, canEnter, entryMeta, entryRuleFor, hasEntryRule, needsCapabilities } from '../entryRules'
import { resetCapabilities, setCapabilitiesForTests } from '@/composables/useCapabilities'

// 告警頁入口：持有任一頁籤的能力（audit:view／alertrule:manage／systemalert:manage；通知通道已有獨立頁，不再算告警頁入口）即可進入。
// 側欄與路由守衛共用 canEnter，這裡以真實能力狀態驗「看得到 ⇔ 進得去」同源。

describe('告警頁入口規則（任一頁籤能力）', () => {
  beforeEach(() => resetCapabilities())

  it('三種頁籤能力各自足以進入；三種都沒有被擋', () => {
    const rule = entryRuleFor('/alerts')
    for (const perm of ['audit:view', 'alertrule:manage', 'systemalert:manage']) {
      setCapabilitiesForTests([perm])
      expect(canEnter(rule), perm).toBe(true)
    }
    setCapabilitiesForTests(['asset:view', 'alert:manage', 'notification_channel:manage'])
    expect(canEnter(rule)).toBe(false)
    setCapabilitiesForTests([])
    expect(canEnter(rule)).toBe(false)
  })

  it('路由 meta 與規則同源，且守衛會先載入能力', () => {
    const meta = router.resolve('/alerts').meta
    expect([...meta.permissionsAny].sort()).toEqual(['alertrule:manage', 'audit:view', 'systemalert:manage'])
    expect(meta.permissionsAll).toBeUndefined()
    expect(hasEntryRule(meta)).toBe(true)
    expect(needsCapabilities(meta)).toBe(true)
    expect(entryMeta('/alerts').permissionsAny).toEqual(ENTRY_RULES['/alerts'].permissionsAny)
  })

  it('形狀不明一律拒絕：permissionsAny 為空、含非字串、或與其他形狀並存', () => {
    const any = () => true
    expect(canEnter({ permissionsAny: [] }, any)).toBe(false)
    expect(canEnter({ permissionsAny: [''] }, any)).toBe(false)
    expect(canEnter({ permissionsAny: [1] }, any)).toBe(false)
    expect(canEnter({ permissionsAny: ['a:b'], permissionsAll: ['a:b'] }, any)).toBe(false)
    expect(canEnter({ permissionsAny: ['a:b'], signedIn: true }, any)).toBe(false)
  })
})
