import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessageBox } from 'element-plus'
import GroupSetupDrawer from '../components/GroupSetupDrawer.vue'
import { sameAssignment } from '../groupSetupOutcome'
import GroupRoleEditor from '@/views/usergroups/components/GroupRoleEditor.vue'
import { ElDialogStub } from '@/__fixtures__/dialogStub'
import { applyCurrentUser, resetCapabilities } from '@/composables/useCapabilities'
import i18n from '@/i18n'
import { roleLabel } from '@/constants/roles'

enableAutoUnmount(afterEach)

const h = vi.hoisted(() => ({ request: vi.fn(), warnings: vi.fn() }))
vi.mock('@/api/request', () => ({ default: (...a) => h.request(...a) }))
vi.mock('@/utils/mappingRiskGate', () => ({ confirmWarnings: (...a) => h.warnings(...a) }))

const t = (k, p) => i18n.global.t(k, p)

// el-drawer 以過場動畫延後渲染；測試改用只依 modelValue 渲染的替身
const ElDrawerStub = {
  name: 'ElDrawer',
  props: { modelValue: Boolean, title: { type: String, default: '' } },
  emits: ['update:modelValue'],
  template:
    '<div v-if="modelValue" class="drawer-stub"><h3 class="drawer-title">{{ title }}</h3><slot /><div class="drawer-footer"><slot name="footer" /></div></div>',
}

const DEFS = [
  { id: 3, name: 'user', builtin_key: 'user', scopable: true, node_range_no_effect: true, assignment_state: 'open', management_class: false, group_bindable: true, direct_mappable: true },
  { id: 4, name: 'asset_admin', builtin_key: 'asset_admin', scopable: true, node_range_no_effect: false, assignment_state: 'open', management_class: true, group_bindable: true },
  { id: 5, name: 'security_admin', builtin_key: 'security_admin', scopable: false, node_range_no_effect: false, assignment_state: 'open', management_class: true, group_bindable: true },
]
const NODES = [
  { id: 11, name: '甲節點', parent_id: null, depth: 1, path: '甲節點', subtree_asset_count: 12 },
  { id: 12, name: '乙節點', parent_id: null, depth: 1, path: '乙節點', subtree_asset_count: 6 },
]
const OPTIONS = {
  nodes: NODES,
  node_assignable_role_ids: [3, 4],
  node_range_no_effect_role_ids: [3],
  node_range_no_effect_reasons: { 3: 'builtin_global_only' },
}
const DICT = [{ id: 21, match_value: 'cn=ops', note: '維運組' }, { id: 22, match_value: 'cn=dba', note: 'DBA 組' }]
const noOp = { marks: [], self_direction: '', routes_gained: [], routes_lost: [], evaluated: 0 }
const noHit = { total: 0, matched: 0, truncated: false, subjects: [], operation: noOp }
const markHit = { ...noHit, operation: { ...noOp, marks: ['management_grant'], evaluated: 0 } }
const GID = 77
const RULES = '/identity-sources/oidc/7/user-group-mappings'
const err = (status, code) => ({ response: { status, data: code ? { error: { code } } : {} } })
const timeout = () => Object.assign(new Error('timeout'), { code: 'ECONNABORTED' })

let cfg
let calls
const reset = (over = {}) => {
  cfg = {
    rolesPreview: noHit,
    rulePreview: noHit,
    createGroup: () => ({ id: GID, name: 'x' }),
    putRoles: () => ({ data: [] }),
    postRule: () => ({ data: { id: 1 } }),
    getGroups: () => ({ data: [] }),
    getBindings: () => ({ data: [] }),
    getRules: () => ({ data: [] }),
    ...over,
  }
  calls = []
  h.request.mockImplementation(async (c) => {
    const method = c.method.toUpperCase()
    calls.push({ method, url: c.url, data: c.data })
    const key = `${method} ${c.url}`
    const out = (v) => (typeof v === 'function' ? v(c) : v)
    const res = (v) => { const r = out(v); if (r instanceof Error || (r && r.response)) throw r; return r }
    if (key === 'GET /role-assignment-options') return OPTIONS
    if (key === 'POST /role-assignment-previews') return res(c.data.kind === 'group_roles' ? cfg.rolesPreview : cfg.rulePreview)
    if (key === 'POST /user-groups') return res(cfg.createGroup)
    if (key === 'GET /user-groups') return res(cfg.getGroups)
    if (key === `PUT /user-groups/${GID}/role-bindings`) return res(cfg.putRoles)
    if (key === `GET /user-groups/${GID}/role-bindings`) return res(cfg.getBindings)
    if (key === `POST ${RULES}`) return res(cfg.postRule)
    if (key === `GET ${RULES}`) return res(cfg.getRules)
    throw new Error(`unexpected request ${key}`)
  })
}
const callsOf = (method, url) => calls.filter((c) => c.method === method && c.url === url)
const writes = () => calls.filter((c) => ['POST', 'PUT', 'DELETE'].includes(c.method) && c.url !== '/role-assignment-previews')
const lastBody = (method, url) => callsOf(method, url).at(-1)?.data

const mountDrawer = async (props = {}) => {
  const w = mount(GroupSetupDrawer, {
    props: { sourceType: 'oidc', sourceId: 7, sourceName: '公司目錄', definitions: DEFS, externalGroups: DICT, ...props },
    global: { plugins: [ElementPlus], stubs: { ElDialog: ElDialogStub, ElDrawer: ElDrawerStub } },
    attachTo: document.body,
  })
  await flushPromises()
  return w
}
const settle = async () => {
  for (let i = 0; i < 4; i++) await flushPromises()
}
// data-test 加在 el-input 上時會落在原生輸入元素本身；el-autocomplete 則落在外層
const inputOf = (w, sel) => {
  const el = w.get(`[data-test="${sel}"]`)
  return ['INPUT', 'TEXTAREA'].includes(el.element.tagName) ? el : el.get('input')
}
const click = async (w, sel) => {
  await w.get(`[data-test="${sel}"]`).trigger('click')
  await settle()
}
const setName = async (w, v) => {
  await inputOf(w, 'setup-name').setValue(v)
}
const setMatch = async (w, v) => {
  await inputOf(w, 'setup-match').setValue(v)
}
const pickRole = async (w, id) => {
  w.findComponent(GroupRoleEditor).vm.addPicked(id)
  await settle()
}
const pickNode = async (w, role, nodeId) => {
  await w.get(`[data-test="set-range-${role}"]`).trigger('click')
  await w.get('[data-test="rnp-mode-nodes"] input').setValue(true)
  await w.get(`[data-test="rnp-check-${nodeId}"] input`).setValue(true)
  await settle()
}
// 走到第 3 步並填好外部群組
const toStep3 = async (w, { name = '資產管理組', roleId = 4, node = null, match = 'cn=new' } = {}) => {
  await setName(w, name)
  await click(w, 'setup-next')
  await pickRole(w, roleId)
  if (node) await pickNode(w, DEFS.find((d) => d.id === roleId).name, node)
  await click(w, 'setup-next')
  if (match != null) await setMatch(w, match)
  await settle()
}
const submit = async (w) => click(w, 'setup-submit')
const state = (w, n) => w.get(`[data-test="setup-row-${n}-state"]`).attributes('data-state')
const proceedConfirm = async (w) => click(w, 'danger-proceed')

beforeEach(() => {
  h.request.mockReset()
  h.warnings.mockReset()
  h.warnings.mockResolvedValue(true)
  document.body.innerHTML = ''
  resetCapabilities()
  i18n.global.locale.value = 'zh-TW'
  applyCurrentUser({ id: 1, permissions: ['usergroup:manage', 'role:assign', 'identity_source:manage', 'authorization:manage'] })
  reset()
})

describe('建立群組抽屜：第 1 步', () => {
  it('名稱空白時下一步停用；名稱上限 100、描述上限 500；帶入的外部群組顯示在第 1 步', async () => {
    const w = await mountDrawer()
    w.vm.open({ matchValue: 'cn=carry', note: '帶入備註', entry: 'groupRuleMenu' })
    await settle()
    expect(w.get('[data-test="setup-next"]').attributes('disabled')).toBeDefined()
    expect(inputOf(w, 'setup-name').attributes('maxlength')).toBe('100')
    expect(inputOf(w, 'setup-desc').attributes('maxlength')).toBe('500')
    expect(w.get('[data-test="setup-carried-match"]').text()).toBe('cn=carry')
    await setName(w, '   ')
    expect(w.get('[data-test="setup-next"]').attributes('disabled')).toBeDefined()
    await setName(w, '新群組甲')
    expect(w.get('[data-test="setup-next"]').attributes('disabled')).toBeUndefined()
    // 帶入的值不在字典：第 3 步外部群組與顯示名稱兩欄等於帶入值
    await click(w, 'setup-next')
    await pickRole(w, 4)
    await click(w, 'setup-next')
    expect(inputOf(w, 'setup-match').element.value).toBe('cn=carry')
    expect(inputOf(w, 'setup-note').element.value).toBe('帶入備註')
  })

  it('沒有帶入值時第 1 步不顯示外部群組；步驟標頭是一般編號，不含圓圈數字，元件不使用 el-steps', async () => {
    const w = await mountDrawer()
    w.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    expect(w.find('[data-test="setup-carried-match"]').exists()).toBe(false)
    expect(w.get('[data-test="setup-step-1"]').text()).toContain('1.')
    expect(w.get('[data-test="setup-step-2"]').text()).toContain('2.')
    expect(w.get('[data-test="setup-step-3"]').text()).toContain('3.')
    expect(w.html()).not.toMatch(/[\u2460-\u2473\u2776-\u277F\u2780-\u2793]/)
    const source = readFileSync(join(process.cwd(), 'src/views/identity-sources/components/GroupSetupDrawer.vue'), 'utf8')
    expect(source).not.toMatch(/el-steps|el-step\b/)
  })
})

describe('建立群組抽屜：第 2 步', () => {
  it('未選角色時下一步停用；選資產管理員並勾節點後到第 3 步再上一步，角色與節點仍在；顯示管理範圍說明；沒有寫入', async () => {
    const w = await mountDrawer()
    w.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await setName(w, '資產管理組')
    await click(w, 'setup-next')
    expect(w.get('[data-test="setup-scope-banner"]').text()).toContain(t('roleScope.bannerTitle'))
    expect(w.get('[data-test="setup-next"]').attributes('disabled')).toBeDefined()
    await pickRole(w, 4)
    await pickNode(w, 'asset_admin', 11)
    expect(w.get('[data-test="setup-next"]').attributes('disabled')).toBeUndefined()
    await click(w, 'setup-next')
    await click(w, 'setup-prev')
    expect(w.get('[data-test="group-role-asset_admin"]').exists()).toBe(true)
    expect(w.get('[data-test="range-paths-asset_admin"]').text()).toContain('甲節點')
    await click(w, 'setup-prev')
    expect(inputOf(w, 'setup-name').element.value).toBe('資產管理組')
    expect(writes()).toHaveLength(0)
  })
})

describe('建立群組抽屜：第 3 步', () => {
  it('外部群組空白時建立並儲存停用；管理類角色出現通知與外部目錄提示，一般角色兩句都不出現', async () => {
    const w = await mountDrawer()
    w.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await toStep3(w, { match: null })
    expect(w.get('[data-test="setup-submit"]').attributes('disabled')).toBeDefined()
    expect(w.get('[data-test="setup-management-hint"]').text()).toBe(t('identityGroupMappings.managementTarget', { role: roleLabel('asset_admin') }))
    expect(w.get('[data-test="setup-directory-hint"]').text()).toBe(t('identityGroupMappings.externalDirectoryDecides', { role: roleLabel('asset_admin') }))

    const w2 = await mountDrawer()
    w2.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await toStep3(w2, { roleId: 3, match: 'cn=x' })
    expect(w2.find('[data-test="setup-management-hint"]').exists()).toBe(false)
    expect(w2.find('[data-test="setup-directory-hint"]').exists()).toBe(false)
    expect(w2.get('[data-test="setup-submit"]').attributes('disabled')).toBeUndefined()
  })

  it('三件事清單依序含群組名、角色與範圍、來源與外部群組，編號為一般數字；儲存後的變化不含成員數字且含連線句', async () => {
    const w = await mountDrawer()
    w.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await toStep3(w, { name: '資產管理組', roleId: 4, node: 12, match: 'cn=new' })
    const lines = [1, 2, 3].map((n) => w.get(`[data-test="setup-task-${n}"]`).text())
    expect(lines[0]).toContain('1.')
    expect(lines[0]).toContain('資產管理組')
    expect(lines[1]).toContain('2.')
    expect(lines[1]).toContain('乙節點')
    expect(lines[1]).toContain(roleLabel('asset_admin'))
    expect(lines[2]).toContain('3.')
    expect(lines[2]).toContain('公司目錄')
    expect(lines[2]).toContain('cn=new')
    expect(lines[2]).toContain('資產管理組')
    const after = w.get('[data-test="setup-after-members"]').text()
    expect(after).toContain('cn=new')
    expect(after).not.toMatch(/\d+\s*位/)
    expect(w.get('[data-test="setup-after-connection"]').text()).toBe(t('userDetail.change.connectionFixed'))
    expect(w.get('[data-test="setup-rule-no-scope"]').text()).toBe(t('groupSetup.ruleNoScope'))
    // 全系統的情形：角色顯示名與全系統並列
    const w2 = await mountDrawer()
    w2.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await toStep3(w2, { roleId: 4, match: 'cn=new' })
    const line2 = w2.get('[data-test="setup-task-2"]').text()
    expect(line2).toContain(roleLabel('asset_admin'))
    expect(line2).toContain(t('roleNodePicker.modeAll'))
  })

  it('超級管理者選系統安全管理員時出現受保護角色提示與外部目錄提示', async () => {
    const w = await mountDrawer()
    w.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await toStep3(w, { roleId: 5, match: 'cn=sec' })
    const hint = w.get('[data-test="setup-directory-hint"]').text()
    expect(hint).toContain(t('identityGroupMappings.protectedTarget', { role: roleLabel('security_admin') }))
    expect(hint).toContain(t('identityGroupMappings.externalDirectoryDecides', { role: roleLabel('security_admin') }))
  })

  it('顯示名稱：不在字典時可編輯；在字典時唯讀並顯示字典值與共用說明；帶入值不同時另有未套用說明；改成字典中的另一值即時轉唯讀', async () => {
    const w = await mountDrawer()
    w.vm.open({ matchValue: 'cn=ops', note: '另一個名稱', entry: 'groupRuleMenu' })
    await settle()
    await toStep3(w, { match: null })
    // 帶入的外部群組在字典中
    expect(w.find('[data-test="setup-note"]').exists()).toBe(false)
    expect(inputOf(w, 'setup-note-readonly').element.value).toBe('維運組')
    expect(w.get('[data-test="setup-note-shared"]').text()).toBe(t('groupSetup.noteSharedReadonly'))
    expect(w.get('[data-test="setup-note-ignored"]').text()).toContain('另一個名稱')
    // 改成字典中的另一值
    await setMatch(w, 'cn=dba')
    expect(inputOf(w, 'setup-note-readonly').element.value).toBe('DBA 組')
    expect(w.find('[data-test="setup-note-ignored"]').exists()).toBe(false)
    // 不在字典
    await setMatch(w, 'cn=unknown')
    expect(w.find('[data-test="setup-note-readonly"]').exists()).toBe(false)
    expect(inputOf(w, 'setup-note').attributes('readonly')).toBeUndefined()
  })
})

describe('建立群組抽屜：鍵盤焦點', () => {
  const inDrawer = (w) => {
    const a = document.activeElement
    return a !== document.body && w.get('.drawer-stub').element.contains(a)
  }
  it('按下一步、上一步後焦點留在抽屜內，不掉到頁面最外層', async () => {
    const w = await mountDrawer()
    w.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await setName(w, '資產管理組')
    w.get('[data-test="setup-next"]').element.focus()
    await click(w, 'setup-next')
    expect(inDrawer(w)).toBe(true)
    await pickRole(w, 4)
    await click(w, 'setup-next')
    expect(inDrawer(w)).toBe(true)
    await click(w, 'setup-prev')
    expect(inDrawer(w)).toBe(true)
  })

  it('進入結果畫面後焦點留在抽屜內，完成按鈕可由鍵盤到達', async () => {
    const w = await mountDrawer()
    w.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await toStep3(w, { match: 'cn=new' })
    w.get('[data-test="setup-submit"]').element.focus()
    await submit(w)
    expect(inDrawer(w)).toBe(true)
    expect(w.find('[data-test="setup-finish"]').exists()).toBe(true)
  })
})

describe('建立群組抽屜：送出序列', () => {
  it('依序建立群組、群組角色預覽、寫入角色、規則預覽、建立規則；全系統角色不帶 role_nodes，規則本文鍵集合不含範圍', async () => {
    const w = await mountDrawer()
    w.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await toStep3(w, { match: 'cn=new' })
    await inputOf(w, 'setup-note').setValue('新群組備註')
    await submit(w)
    const seq = calls.filter((c) => c.method !== 'GET').map((c) => `${c.method} ${c.url}${c.data?.kind ? ` ${c.data.kind}` : ''}`)
    expect(seq).toEqual([
      'POST /user-groups',
      'POST /role-assignment-previews group_roles',
      `PUT /user-groups/${GID}/role-bindings`,
      'POST /role-assignment-previews mapping_rule_change',
      `POST ${RULES}`,
    ])
    expect(lastBody('POST', '/user-groups')).toEqual({ name: '資產管理組', description: '' })
    expect(callsOf('POST', '/role-assignment-previews')[0].data).toMatchObject({ kind: 'group_roles', group_id: GID, role_ids: [4] })
    expect(callsOf('POST', '/role-assignment-previews')[1].data).toMatchObject({ kind: 'mapping_rule_change', rule_type: 'user_group', group_id: GID, match_value: 'cn=new' })
    const put = lastBody('PUT', `/user-groups/${GID}/role-bindings`)
    expect(put.role_ids).toEqual([4])
    expect(put.role_nodes).toBeUndefined()
    const rule = lastBody('POST', RULES)
    expect(Object.keys(rule).sort()).toEqual(['enabled', 'match_value', 'note', 'risk_acknowledged', 'source_config_acknowledged', 'user_group_id'])
    expect(Object.keys(rule).some((k) => /node|scope/.test(k.replace('source_config_acknowledged', '')))).toBe(false)
    expect(rule).toMatchObject({ match_value: 'cn=new', user_group_id: GID, enabled: true, note: '新群組備註' })
    expect(state(w, 3)).toBe('done')
  })

  it('指定一個節點時 role_nodes 只含該角色；外部群組在字典時規則本文沒有 note，也不更新備註，寫入恰為三個', async () => {
    const w = await mountDrawer()
    w.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await toStep3(w, { node: 11, match: 'cn=ops' })
    await submit(w)
    expect(lastBody('PUT', `/user-groups/${GID}/role-bindings`).role_nodes).toEqual({ 4: [11] })
    const rule = lastBody('POST', RULES)
    expect(Object.keys(rule).sort()).toEqual(['enabled', 'match_value', 'risk_acknowledged', 'source_config_acknowledged', 'user_group_id'])
    expect(calls.filter((c) => c.method === 'PUT' && c.url.includes('/external-groups/'))).toHaveLength(0)
    expect(writes()).toHaveLength(3)
  })

  it('規則預覽帶管理類標記時確認框通知句為映射規則句（兩種語言），名稱是新群組名與角色顯示名，不含原始識別', async () => {
    for (const locale of ['zh-TW', 'en-US']) {
      reset({ rulePreview: markHit })
      i18n.global.locale.value = locale
      const w = await mountDrawer()
      w.vm.open({ entry: 'groupRuleMenu' })
      await settle()
      await toStep3(w, { name: `群組-${locale}` })
      await submit(w)
      const expected = i18n.global.t('dangerConfirm.notify.mappingRule', { target: `群組-${locale}`, role: roleLabel('asset_admin') })
      expect(w.get('[data-test="danger-notify"]').text()).toContain(expected)
      expect(w.get('[data-test="danger-notify"]').text()).not.toContain('asset_admin')
      expect(callsOf('POST', RULES)).toHaveLength(0)
      await proceedConfirm(w)
      expect(callsOf('POST', RULES)).toHaveLength(1)
      w.unmount()
    }
  })

  it('群組角色預覽帶管理類標記時先開確認框（空群組句），確認後才寫入角色；預覽失敗時以暫時無法取得開啟且不自行放行', async () => {
    reset({ rolesPreview: markHit })
    const w = await mountDrawer()
    w.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await toStep3(w, { name: '空群組' })
    await submit(w)
    expect(callsOf('PUT', `/user-groups/${GID}/role-bindings`)).toHaveLength(0)
    expect(w.get('[data-test="danger-notify"]').text()).toContain(
      t('dangerConfirm.notify.groupEmpty', { group: '空群組', role: roleLabel('asset_admin') })
    )
    await proceedConfirm(w)
    expect(callsOf('PUT', `/user-groups/${GID}/role-bindings`)).toHaveLength(1)

    reset({ rolesPreview: () => err(500, 'INTERNAL_X') })
    const w2 = await mountDrawer()
    w2.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await toStep3(w2)
    await submit(w2)
    expect(w2.find('[data-test="danger-preview-failed"]').exists()).toBe(true)
    expect(callsOf('PUT', `/user-groups/${GID}/role-bindings`)).toHaveLength(0)
  })

  it('規則寫入回來源設定確認時經確認後重送一次；回用途確認時顯示用途並確認後重送一次', async () => {
    let n = 0
    reset({
      postRule: () => {
        n += 1
        if (n === 1) return { response: { status: 422, data: { error: { code: 'MAPPING_ACK_REQUIRED', meta: { warnings: [{ code: 'SOURCE_ATTR_WARN' }] } } } } }
        if (n === 2) return { response: { status: 409, data: { error: { code: 'MAPPING_USAGE_ACK_REQUIRED', meta: { usage: { asset_authorizations: 2 } } } } } }
        return { data: { id: 1 } }
      },
    })
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    const w = await mountDrawer()
    w.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await toStep3(w)
    await submit(w)
    expect(h.warnings).toHaveBeenCalledWith(['SOURCE_ATTR_WARN'])
    expect(confirmSpy.mock.calls[0][0]).toContain(t('identityGroupMappings.confirmUsage'))
    const bodies = callsOf('POST', RULES).map((c) => c.data)
    expect(bodies).toHaveLength(3)
    expect(bodies[1].source_config_acknowledged).toBe(true)
    expect(bodies[2].risk_acknowledged).toBe(true)
    expect(state(w, 3)).toBe('done')
    confirmSpy.mockRestore()
  })
})

describe('建立群組抽屜：寫入結果判讀', () => {
  it('(1) 首次建立群組回 409 名稱已存在：回第 1 步顯示原因，沒有核對讀取與後續寫入', async () => {
    reset({ createGroup: () => err(409, 'CONFLICT_USER_GROUP_NAME_EXISTS') })
    const w = await mountDrawer()
    w.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await toStep3(w)
    await submit(w)
    expect(w.get('[data-test="setup-panel-1"]').isVisible()).toBe(true)
    expect(w.get('[data-test="setup-name-error"]').text()).toBe(t('apiError.CONFLICT_USER_GROUP_NAME_EXISTS'))
    expect(calls.filter((c) => c.method === 'GET' && c.url === '/user-groups')).toHaveLength(0)
    expect(writes()).toHaveLength(1)
  })

  it('(2) 規則寫入回 403：不核對，三列為已完成、已完成、被拒絕；重試只送一次規則寫入且沿用原群組', async () => {
    let first = true
    reset({ postRule: () => (first ? err(403, 'AUTH_PERMISSION_DENIED') : { data: { id: 1 } }) })
    const w = await mountDrawer()
    w.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await toStep3(w)
    await submit(w)
    expect([1, 2, 3].map((n) => state(w, n))).toEqual(['done', 'done', 'rejected'])
    expect(w.get('[data-test="setup-row-3-detail"]').text()).toBe(t('apiError.AUTH_PERMISSION_DENIED'))
    expect(callsOf('GET', RULES)).toHaveLength(0)
    first = false
    await click(w, 'setup-retry')
    expect(callsOf('POST', RULES)).toHaveLength(2)
    expect(callsOf('POST', RULES).at(-1).data.user_group_id).toBe(GID)
    expect(callsOf('POST', '/user-groups')).toHaveLength(1)
    expect(callsOf('DELETE', `/user-groups/${GID}`)).toHaveLength(0)
    expect(state(w, 3)).toBe('done')
  })

  it('(3) 規則寫入回 503 而核對清單沒有這條規則：核對一次後判為未完成，可重試', async () => {
    let fail = true
    reset({ postRule: () => (fail ? err(503) : { data: { id: 1 } }) })
    const w = await mountDrawer()
    w.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await toStep3(w)
    await submit(w)
    expect(callsOf('GET', RULES)).toHaveLength(1)
    expect(state(w, 3)).toBe('notWritten')
    expect(w.get('[data-test="setup-keep-note"]').text()).toBe(t('groupSetup.keepNote'))
    fail = false
    await click(w, 'setup-retry')
    expect(state(w, 3)).toBe('done')
    expect(callsOf('POST', '/user-groups')).toHaveLength(1)
    expect(callsOf('POST', RULES).at(-1).data.user_group_id).toBe(GID)
    expect(calls.filter((c) => c.method === 'DELETE')).toHaveLength(0)
  })

  it('(4) 規則寫入回 500 而核對清單已有同值同群組的規則：判為已完成，不重送', async () => {
    reset({
      postRule: () => err(500),
      getRules: () => ({ data: [{ id: 5, match_value: 'cn=new', user_group_id: GID }] }),
    })
    const w = await mountDrawer()
    w.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await toStep3(w)
    await submit(w)
    expect(w.find('[data-test="setup-open-group-roles"]').exists()).toBe(true)
    expect(w.get('[data-test="setup-result-title"]').text()).toBe(t('groupSetup.doneTitle'))
    expect(callsOf('POST', RULES)).toHaveLength(1)
  })

  it('(5) 規則寫入逾時而核對也失敗：結果未確認，沒有重試寫入只有重新核對；重新核對只再讀取', async () => {
    reset({ postRule: () => timeout(), getRules: () => err(500) })
    const w = await mountDrawer()
    w.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await toStep3(w)
    await submit(w)
    expect(state(w, 3)).toBe('unconfirmed')
    expect(w.text()).not.toContain('規則沒有建立')
    expect(w.text()).not.toContain('不會影響任何人')
    expect(w.find('[data-test="setup-retry"]').exists()).toBe(false)
    expect(w.find('[data-test="setup-recheck"]').exists()).toBe(true)
    expect(callsOf('POST', RULES)).toHaveLength(1)
    await click(w, 'setup-recheck')
    expect(callsOf('GET', RULES)).toHaveLength(2)
    expect(callsOf('POST', RULES)).toHaveLength(1)
  })

  it('(6) 角色指派回 500 而讀回與送出相同：第 2 步判為已完成，寫入一次，接著照常送出規則預覽', async () => {
    reset({
      putRoles: () => err(500),
      getBindings: () => ({ data: [{ role_id: 4, role_name: 'asset_admin', scope: 'global' }] }),
    })
    const w = await mountDrawer()
    w.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await toStep3(w)
    await submit(w)
    expect(callsOf('PUT', `/user-groups/${GID}/role-bindings`)).toHaveLength(1)
    expect(callsOf('POST', '/role-assignment-previews').map((c) => c.data.kind)).toEqual(['group_roles', 'mapping_rule_change'])
    expect(state(w, 2)).toBe('done')
    expect(state(w, 3)).toBe('done')
  })

  it('(7) 角色指派回 500 而讀回為不同的指派：呈現讀回的指派；重試時以讀回為基底，改回全系統後 role_nodes 為 null', async () => {
    let fail = true
    reset({
      putRoles: () => (fail ? err(500) : { data: [] }),
      getBindings: () => ({ data: [{ role_id: 4, role_name: 'asset_admin', scope: 'nodes', node_ids: [11] }] }),
    })
    const w = await mountDrawer()
    w.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await toStep3(w)
    await submit(w)
    expect(state(w, 2)).toBe('differs')
    expect(w.get('[data-test="setup-differs"]').text()).toContain(t('roleNodePicker.nodeCountOnly', { n: 1 }))
    fail = false
    await click(w, 'setup-edit-roles')
    expect(w.get('[data-test="setup-panel-2"]').isVisible()).toBe(true)
    expect(w.get('[data-test="range-paths-asset_admin"]').text()).toContain('甲節點')
    await w.get('[data-test="set-range-asset_admin"]').trigger('click')
    await w.get('[data-test="rnp-mode-all"] input').setValue(true)
    await settle()
    await click(w, 'setup-next')
    await submit(w)
    expect(lastBody('PUT', `/user-groups/${GID}/role-bindings`).role_nodes).toEqual({ 4: null })
    expect(callsOf('POST', '/user-groups')).toHaveLength(1)
    expect(state(w, 3)).toBe('done')
    // 沒有鍵的角色以編輯器基底的原範圍為期望值；沒有基底時才視為全系統
    const back = [{ role_id: 4, role_name: 'asset_admin', scope: 'nodes', node_ids: [11] }]
    expect(sameAssignment(back, [4], {}, back)).toBe(true)
    expect(sameAssignment(back, [4], {}, [])).toBe(false)
    expect(sameAssignment(back, [4], { 4: [12] }, back)).toBe(false)
  })

  it('(8) 建立群組回 503：清單查無名稱判為未建立可重試；清單已有同名則結果未確認並附連結；查無而重試回 409 同樣結果未確認', async () => {
    reset({ createGroup: () => err(503), getGroups: () => ({ data: [] }) })
    const w = await mountDrawer()
    w.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await toStep3(w)
    await submit(w)
    expect(state(w, 1)).toBe('notWritten')
    expect(w.find('[data-test="setup-retry"]').exists()).toBe(true)
    expect(w.get('[data-test="setup-keep-note"]').text()).toBe(t('groupSetup.keepNoteNone'))

    reset({ createGroup: () => err(503), getGroups: () => ({ data: [{ id: 9, name: '資產管理組' }] }) })
    const w2 = await mountDrawer()
    w2.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await toStep3(w2)
    await submit(w2)
    expect(state(w2, 1)).toBe('unconfirmed')
    expect(w2.find('[data-test="setup-go-user-groups"]').exists()).toBe(true)
    expect(writes()).toHaveLength(1)
    expect(callsOf('POST', '/user-groups')).toHaveLength(1)

    let n = 0
    reset({ createGroup: () => { n += 1; return n === 1 ? err(503) : err(409, 'CONFLICT_USER_GROUP_NAME_EXISTS') }, getGroups: () => ({ data: [] }) })
    const w3 = await mountDrawer()
    w3.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await toStep3(w3)
    await submit(w3)
    await click(w3, 'setup-retry')
    expect(state(w3, 1)).toBe('unconfirmed')
    expect(w3.find('[data-test="setup-go-user-groups"]').exists()).toBe(true)
    expect(w3.text()).not.toContain(t('apiError.CONFLICT_USER_GROUP_NAME_EXISTS'))
    expect(w3.text()).not.toContain('沒有建立任何東西')
    expect(callsOf('POST', '/user-groups')).toHaveLength(2)

    // 核對讀取也失敗：結果未確認，同樣附查看實際狀態的連結
    reset({ createGroup: () => err(503), getGroups: () => err(500) })
    const w4 = await mountDrawer()
    w4.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await toStep3(w4)
    await submit(w4)
    expect(state(w4, 1)).toBe('unconfirmed')
    expect(w4.find('[data-test="setup-go-user-groups"]').exists()).toBe(true)
  })

  it('核對讀取進行中該列顯示核對中，序列進行中不出現任何重試或寫入按鈕，結果定了才出現', async () => {
    let release
    const gate = new Promise((resolve) => { release = resolve })
    reset({ postRule: () => err(503), getRules: () => gate })
    const w = await mountDrawer()
    w.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await toStep3(w)
    await submit(w)
    expect(state(w, 3)).toBe('checking')
    expect(w.get('[data-test="setup-row-3-state"]').text()).toBe(t('groupSetup.state.checking'))
    expect(w.get('[data-test="setup-result-title"]').text()).toBe(t('groupSetup.runningTitle'))
    for (const sel of ['setup-retry', 'setup-recheck', 'setup-edit-roles']) {
      expect(w.find(`[data-test="${sel}"]`).exists()).toBe(false)
    }
    release({ data: [] })
    await settle()
    expect(state(w, 3)).toBe('notWritten')
    expect(w.find('[data-test="setup-retry"]').exists()).toBe(true)
  })

  it('(9) 群組角色確認時按返回：已完成、未執行、未執行，沒有後續寫入；重試重新跑該步預覽', async () => {
    reset({ rolesPreview: markHit })
    const w = await mountDrawer()
    w.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await toStep3(w)
    await submit(w)
    await click(w, 'danger-back')
    expect([1, 2, 3].map((n) => state(w, n))).toEqual(['done', 'notRun', 'notRun'])
    expect(writes()).toHaveLength(1)
    await click(w, 'setup-retry')
    expect(callsOf('POST', '/role-assignment-previews').filter((c) => c.data.kind === 'group_roles')).toHaveLength(2)
  })

  it('(10) 角色指派回 400 節點已不存在（清單內）：不核對；可回第 2 步改選，第 1 步欄位唯讀', async () => {
    reset({ putRoles: () => err(400, 'VALIDATION_ROLE_BINDING_NODES_INVALID') })
    const w = await mountDrawer()
    w.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await toStep3(w, { node: 11 })
    await submit(w)
    expect(state(w, 2)).toBe('rejected')
    expect(callsOf('GET', `/user-groups/${GID}/role-bindings`)).toHaveLength(0)
    await click(w, 'setup-edit-roles')
    expect(w.get('[data-test="setup-panel-2"]').isVisible()).toBe(true)
    await click(w, 'setup-prev')
    expect(inputOf(w, 'setup-name').attributes('disabled')).toBeDefined()
  })

  it('(11) 規則已提交但回 404 規則不存在：核對一次，清單已有規則判為已完成；沒有規則則判為未完成可重試', async () => {
    reset({
      postRule: () => err(404, 'MAPPING_RULE_NOT_FOUND'),
      getRules: () => ({ data: [{ id: 5, match_value: 'cn=new', user_group_id: GID }] }),
    })
    const w = await mountDrawer()
    w.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await toStep3(w)
    await submit(w)
    expect(callsOf('GET', RULES)).toHaveLength(1)
    expect(w.get('[data-test="setup-result-title"]').text()).toBe(t('groupSetup.doneTitle'))
    expect(w.find('[data-state="rejected"]').exists()).toBe(false)
    expect(callsOf('POST', RULES)).toHaveLength(1)

    reset({ postRule: () => err(404, 'MAPPING_RULE_NOT_FOUND'), getRules: () => ({ data: [] }) })
    const w2 = await mountDrawer()
    w2.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await toStep3(w2)
    await submit(w2)
    expect(state(w2, 3)).toBe('notWritten')
    expect(w2.find('[data-test="setup-retry"]').exists()).toBe(true)
  })

  it('(12) 清單外的 4xx 依寫入分表：規則寫入回 400 角色不存在先核對；角色指派回同一個碼（清單內）不核對', async () => {
    reset({ postRule: () => err(400, 'VALIDATION_ROLE_NOT_FOUND'), getRules: () => ({ data: [] }) })
    const w = await mountDrawer()
    w.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await toStep3(w)
    await submit(w)
    expect(callsOf('GET', RULES)).toHaveLength(1)
    expect(state(w, 3)).toBe('notWritten')

    reset({ putRoles: () => err(400, 'VALIDATION_ROLE_NOT_FOUND') })
    const w2 = await mountDrawer()
    w2.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await toStep3(w2)
    await submit(w2)
    expect(state(w2, 2)).toBe('rejected')
    expect(callsOf('GET', `/user-groups/${GID}/role-bindings`)).toHaveLength(0)
  })
})

describe('建立群組抽屜：完成畫面', () => {
  it('持有資產授權能力時出現前往資產授權（帶群組編號）與開啟群組角色連結；按完成關閉並發出 closed', async () => {
    const w = await mountDrawer()
    w.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await toStep3(w)
    await submit(w)
    expect(w.get('[data-test="setup-go-authorizations"]').attributes('href')).toBe(`/authorizations?user_group_id=${GID}`)
    expect(w.get('[data-test="setup-open-group-roles"]').attributes('href')).toBe(`/user-groups/${GID}?tab=roles`)
    expect(w.find('[data-test="setup-no-authz"]').exists()).toBe(false)
    expect(w.text()).toContain(t('userDetail.change.connectionFixed'))
    await click(w, 'setup-finish')
    expect(w.emitted('closed')).toHaveLength(1)
  })

  it('不持有資產授權能力時沒有前往連結，改呈說明句', async () => {
    applyCurrentUser({ id: 1, permissions: ['usergroup:manage', 'role:assign', 'identity_source:manage'] })
    const w = await mountDrawer()
    w.vm.open({ entry: 'groupRuleMenu' })
    await settle()
    await toStep3(w)
    await submit(w)
    expect(w.find('[data-test="setup-go-authorizations"]').exists()).toBe(false)
    expect(w.get('[data-test="setup-no-authz"]').text()).toBe(t('groupSetup.noAuthzNote'))
    expect(w.find('[data-test="setup-open-group-roles"]').exists()).toBe(true)
  })
})
