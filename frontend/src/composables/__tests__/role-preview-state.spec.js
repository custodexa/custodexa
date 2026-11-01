import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  can,
  canSelf,
  applyCurrentUser,
  resetCapabilities,
  setCapabilitiesForTests,
  useCapabilities,
} from '@/composables/useCapabilities'
import {
  applyPreviewResponse,
  beginPreviewRequest,
  cancelPreview,
  exitPreview,
  exitedNotice,
  invalidatePreviewRequests,
  previewPageState,
  setPreviewRange,
} from '@/composables/useRolePreview'
import { isPreviewActive, getPreviewOverlay } from '@/utils/previewOverlay'
import { canEnter, entryMeta } from '@/router/entryRules'
import { buildSidebarModel } from '@/composables/useSidebarNav'
import { MENU_GROUPS } from '@/components/sidebarMenu'
import { resetSessionForTests } from '@/utils/session'

// 以此角色預覽的覆蓋狀態：can 只看覆蓋、本人集合不變、記憶體限定、請求作廢。
vi.mock('@/api/auth', () => ({ getCurrentUser: vi.fn(), logout: vi.fn() }))

const SELF = ['role:view', 'audit:view']
const resp = (id, name, permissions, extra = {}) => ({
  role: { id, name },
  previewable: true,
  permissions,
  entry_states: [],
  ...extra,
})

beforeEach(() => {
  resetSessionForTests()
  resetCapabilities()
  exitedNotice.value = null
  setCapabilitiesForTests(SELF)
})
afterEach(() => {
  cancelPreview()
  resetCapabilities()
  vi.restoreAllMocks()
})

describe('預覽覆蓋與 can / canSelf', () => {
  it('覆蓋後 can 只對覆蓋集合為真、canSelf 只對本人集合為真、本人集合內容不變', () => {
    const before = useCapabilities().permissions.value
    const token = beginPreviewRequest()
    expect(applyPreviewResponse(token, resp(7, 'R7', ['asset:view', 'asset:create']))).toEqual({ entered: true })
    expect(can('asset:view')).toBe(true)
    expect(can('role:view')).toBe(false)
    expect(canSelf('role:view')).toBe(true)
    expect(canSelf('asset:view')).toBe(false)
    expect(useCapabilities().permissions.value).toEqual(before)
    expect(getPreviewOverlay().roleId).toBe(7)
  })

  it('覆蓋期間 /auth/me 成功回應只替換本人集合，覆蓋不變', () => {
    applyPreviewResponse(beginPreviewRequest(), resp(7, 'R7', ['asset:view']))
    expect(applyCurrentUser({ id: 1, permissions: ['user:manage'] })).toBe(true)
    expect(canSelf('user:manage')).toBe(true)
    expect(canSelf('role:view')).toBe(false)
    expect(can('user:manage')).toBe(false)
    expect(can('asset:view')).toBe(true)
  })

  it('離開後 can 立即回到本人集合，且不發任何請求', () => {
    const fetchSpy = vi.fn()
    vi.stubGlobal('fetch', fetchSpy)
    applyPreviewResponse(beginPreviewRequest(), resp(7, 'R7', ['asset:view']))
    expect(exitPreview()).toEqual({ roleId: 7, roleName: 'R7' })
    expect(can('role:view')).toBe(true)
    expect(can('asset:view')).toBe(false)
    expect(fetchSpy).not.toHaveBeenCalled()
    vi.unstubAllGlobals()
  })

  it('覆蓋不寫入 localStorage 與 sessionStorage', () => {
    const local = vi.spyOn(Storage.prototype, 'setItem')
    applyPreviewResponse(beginPreviewRequest(), resp(7, 'R7', ['asset:view']))
    setPreviewRange(3)
    exitPreview()
    expect(local).not.toHaveBeenCalled()
  })

  it('previewable=false 不設覆蓋', () => {
    const r = applyPreviewResponse(beginPreviewRequest(), resp(1, 'root', [], { previewable: false, reason: 'reserved_super_admin' }))
    expect(r).toEqual({ entered: false })
    expect(isPreviewActive()).toBe(false)
    expect(can('role:view')).toBe(true)
  })
})

describe('入口守衛與側欄跟隨覆蓋', () => {
  it('守衛拒絕覆蓋集合外的路徑、放行登入即可見的路徑；側欄沒有審核中心與我的 agent', () => {
    applyPreviewResponse(beginPreviewRequest(), resp(7, 'R7', ['asset:view', 'session:view', 'ui:approvals', 'ui:my-agents']))
    expect(canEnter(entryMeta('/users'))).toBe(false)
    expect(canEnter(entryMeta('/sessions'))).toBe(true)
    expect(canEnter(entryMeta('/dashboard'))).toBe(true)
    const canSee = (item) => canEnter(entryMeta(item.path))
    const model = buildSidebarModel(MENU_GROUPS, canSee, { collapsed: [], pinned: [] })
    const ids = [...model.pinned, ...model.groups.flatMap((g) => g.items)].map((i) => i.id)
    expect(ids).toContain('sessions')
    expect(ids).not.toContain('users')
  })

  it('審核中心與我的 agent 屬個人資格：覆蓋集合不含 ui:approvals／ui:my-agents 時不出現（伺服器不下發）', () => {
    applyPreviewResponse(beginPreviewRequest(), resp(7, 'R7', ['asset:view']))
    expect(canEnter(entryMeta('/approvals'))).toBe(false)
    expect(canEnter(entryMeta('/my-agents'))).toBe(false)
  })
})

describe('頁面狀態查詢', () => {
  it('精確路徑與詳情頁前綴；覆蓋不存在時為 null', () => {
    expect(previewPageState('/credentials')).toBeNull()
    applyPreviewResponse(
      beginPreviewRequest(),
      resp(7, 'R7', ['credential:view'], { entry_states: [{ entry: 'credentials', path: '/credentials', state: 'read' }] })
    )
    expect(previewPageState('/credentials')).toBe('read')
    expect(previewPageState('/credentials/12')).toBe('read')
    expect(previewPageState('/users')).toBeNull()
  })
})

describe('預覽請求作廢', () => {
  const deferred = () => {
    let resolve
    const promise = new Promise((r) => {
      resolve = r
    })
    return { promise, resolve }
  }

  it('回應前登出或換帳號（resetCapabilities）：舊回應回 false、覆蓋不變', () => {
    const token = beginPreviewRequest()
    resetCapabilities()
    expect(applyPreviewResponse(token, resp(7, 'R7', ['asset:view']))).toBe(false)
    expect(isPreviewActive()).toBe(false)
  })

  it('回應前離開預覽、卸載發出元件、再次發出：舊回應回 false', () => {
    let token = beginPreviewRequest()
    exitPreview()
    expect(applyPreviewResponse(token, resp(7, 'R7', ['asset:view']))).toBe(false)

    token = beginPreviewRequest()
    invalidatePreviewRequests()
    expect(applyPreviewResponse(token, resp(7, 'R7', ['asset:view']))).toBe(false)

    const first = beginPreviewRequest()
    beginPreviewRequest()
    expect(applyPreviewResponse(first, resp(7, 'R7', ['asset:view']))).toBe(false)
    expect(isPreviewActive()).toBe(false)
  })

  it('已進入預覽後，先前的舊回應抵達也不覆蓋', () => {
    const a = beginPreviewRequest()
    const b = beginPreviewRequest()
    expect(applyPreviewResponse(b, resp(2, 'B', ['asset:view']))).toEqual({ entered: true })
    expect(applyPreviewResponse(a, resp(1, 'A', ['user:manage']))).toBe(false)
    expect(getPreviewOverlay().roleId).toBe(2)
  })

  it('逆序完成（第二次先回、第一次後回）只有第二次生效，roleId 為第二個角色', async () => {
    const dA = deferred()
    const dB = deferred()
    const run = async (d) => {
      const token = beginPreviewRequest()
      const res = await d.promise
      return applyPreviewResponse(token, res)
    }
    const pA = run(dA)
    const pB = run(dB)
    dB.resolve(resp(2, 'B', ['asset:view']))
    dA.resolve(resp(1, 'A', ['user:manage']))
    expect(await pB).toEqual({ entered: true })
    expect(await pA).toBe(false)
    expect(getPreviewOverlay().roleId).toBe(2)
    expect(getPreviewOverlay().roleName).toBe('B')
  })

  it('格式不合的回應回 false 且不設覆蓋', () => {
    expect(applyPreviewResponse(beginPreviewRequest(), { previewable: true })).toBe(false)
    expect(isPreviewActive()).toBe(false)
  })
})
