/* eslint-disable vue/one-component-per-file, vue/require-prop-types -- 測試替身元件 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import { defineComponent, h, ref, onMounted, provide, inject } from 'vue'
import AssetNodeTree from '../AssetNodeTree.vue'
import NodeDeleteBlockedDialog from '../NodeDeleteBlockedDialog.vue'
import zhTW from '@/i18n/locales/zh-TW.json'
import enUS from '@/i18n/locales/en-US.json'
import jaJP from '@/i18n/locales/ja-JP.json'

enableAutoUnmount(afterEach)

const getAssetListMock = vi.fn()
const getAssetNodeTreeMock = vi.fn()
const getAssetGroupsMock = vi.fn()
const deleteAssetGroupMock = vi.fn()
const requestMock = vi.fn()

vi.mock('@/api/assets', () => ({
  getAssetList: (...a) => getAssetListMock(...a),
  getAssetNodeTree: (...a) => getAssetNodeTreeMock(...a),
  getAssetGroups: (...a) => getAssetGroupsMock(...a),
  createAssetGroup: vi.fn(),
  updateAssetGroup: vi.fn(),
  moveAssetGroup: vi.fn(),
  deleteAssetGroup: (...a) => deleteAssetGroupMock(...a),
}))

vi.mock('@/api/request', () => ({ default: (...a) => requestMock(...a) }))

const capsMock = vi.hoisted(() => ({ granted: new Set() }))
vi.mock('@/composables/useCapabilities', () => ({
  can: (key) => capsMock.granted.has(key),
}))

vi.mock('element-plus', async (orig) => ({
  ...(await orig()),
  ElMessageBox: { confirm: vi.fn().mockResolvedValue('confirm') },
  ElMessage: { success: vi.fn(), error: vi.fn() },
}))

// 以輕量替身取代 Element Plus 的樹、下拉與對話框，讓選單項目與對話框內容可直接斷言
const ElTreeStub = defineComponent({
  props: ['load'],
  setup(props, { slots }) {
    const rows = ref([])
    onMounted(() => props.load({ level: 0, data: null }, (d) => (rows.value = d)))
    return () =>
      h(
        'div',
        { class: 'tree-stub' },
        rows.value.map((d) => h('div', { class: 'row', 'data-id': d.id }, slots.default?.({ data: d })))
      )
  },
})
const ElDropdownStub = defineComponent({
  emits: ['command'],
  setup(_, { slots, emit }) {
    provide('ddCommand', (c) => emit('command', c))
    return () => h('div', { class: 'dd' }, [slots.default?.(), slots.dropdown?.()])
  },
})
const passthrough = (cls) =>
  defineComponent({ setup: (_, { slots }) => () => h('div', { class: cls }, slots.default?.()) })
const ElDropdownItemStub = defineComponent({
  props: ['command', 'disabled'],
  setup(props, { slots }) {
    const fire = inject('ddCommand', () => {})
    return () =>
      h(
        'div',
        {
          class: 'dd-item',
          'data-command': props.command,
          'data-disabled': String(!!props.disabled),
          onClick: () => {
            if (!props.disabled) fire(props.command)
          },
        },
        slots.default?.()
      )
  },
})
const ElDialogStub = defineComponent({
  props: ['modelValue', 'title'],
  setup(props, { slots }) {
    return () =>
      props.modelValue
        ? h('div', { class: 'dialog' }, [slots.default?.(), slots.footer?.()])
        : null
  },
})
const ElTreeSelectStub = defineComponent({
  props: ['data', 'clearable', 'modelValue'],
  setup(props) {
    const flatten = (nodes) => nodes.flatMap((n) => [n, ...flatten(n.children || [])])
    return () =>
      h('div', { class: 'tree-select', 'data-clearable': String(!!props.clearable) },
        flatten(props.data || []).map((n) => h('span', { class: 'opt', 'data-id': n.id }, n.name)))
  },
})
const ElButtonStub = defineComponent({
  props: ['disabled'],
  emits: ['click'],
  setup(props, { slots, emit }) {
    return () =>
      h('button', { disabled: props.disabled, onClick: (e) => emit('click', e) }, slots.default?.())
  },
})
const stubs = {
  'el-tree': ElTreeStub,
  'el-dropdown': ElDropdownStub,
  'el-dropdown-menu': passthrough('dd-menu'),
  'el-dropdown-item': ElDropdownItemStub,
  'el-dialog': ElDialogStub,
  'el-tree-select': ElTreeSelectStub,
  'el-button': ElButtonStub,
  'el-form': passthrough('form'),
  'el-form-item': passthrough('form-item'),
  'el-input': true,
  'el-icon': passthrough('icon'),
}

const node = (over) => ({
  id: 1,
  name: 'n1',
  has_children: false,
  subtree_asset_count: 0,
  manageable: true,
  locator_only: false,
  scope_root: false,
  can_create_child: true,
  can_rename: true,
  can_move: true,
  can_delete: true,
  ...over,
})

const mountTree = () => mount(AssetNodeTree, { global: { stubs } })
const rowOf = (w, id) => w.find(`.row[data-id="${id}"]`)
const item = (w, id, cmd) => rowOf(w, id).find(`.dd-item[data-command="${cmd}"]`)

beforeEach(() => {
  vi.clearAllMocks()
  capsMock.granted = new Set()
  getAssetListMock.mockResolvedValue({ data: [], total: 0 })
  getAssetGroupsMock.mockResolvedValue({ data: [] })
})

describe('AssetNodeTree 列級旗標呈現', () => {
  it('範圍根的改名、搬移、刪除為停用並顯示範圍根限制原因，新增子節點可用', async () => {
    getAssetNodeTreeMock.mockResolvedValue({
      data: [node({ id: 1, scope_root: true, can_rename: false, can_move: false, can_delete: false })],
      can_create_root: false,
    })
    const w = mountTree()
    await flushPromises()
    expect(item(w, 1, 'create-child').attributes('data-disabled')).toBe('false')
    for (const cmd of ['rename', 'move', 'delete']) {
      expect(item(w, 1, cmd).attributes('data-disabled')).toBe('true')
      expect(item(w, 1, cmd).text()).toContain(zhTW.nodeTree.scopeRootLocked)
    }
    expect(rowOf(w, 1).find('.scope-badge').text()).toBe(zhTW.nodeTree.scopeBadge)
  })

  it('限超級管理者的動作停用並顯示對應原因', async () => {
    getAssetNodeTreeMock.mockResolvedValue({ data: [node({ id: 2, can_move: false })] })
    const w = mountTree()
    await flushPromises()
    expect(item(w, 2, 'move').attributes('data-disabled')).toBe('true')
    expect(item(w, 2, 'move').text()).toContain(zhTW.nodeTree.superAdminOnly)
  })

  it('四項 can_* 皆 false 的節點沒有選單', async () => {
    getAssetNodeTreeMock.mockResolvedValue({
      data: [
        node({
          id: 3,
          manageable: false,
          locator_only: true,
          can_create_child: false,
          can_rename: false,
          can_move: false,
          can_delete: false,
        }),
      ],
    })
    const w = mountTree()
    await flushPromises()
    expect(rowOf(w, 3).find('.dd').exists()).toBe(false)
    expect(rowOf(w, 3).find('.tree-node-row').classes()).toContain('is-locator')
  })

  it('manageable=false 而 can_rename=true 的節點選單含可用的改名', async () => {
    getAssetNodeTreeMock.mockResolvedValue({
      data: [
        node({
          id: 4,
          manageable: false,
          can_create_child: false,
          can_move: false,
          can_delete: false,
        }),
      ],
    })
    const w = mountTree()
    await flushPromises()
    expect(rowOf(w, 4).find('.dd').exists()).toBe(true)
    expect(item(w, 4, 'rename').attributes('data-disabled')).toBe('false')
    expect(item(w, 4, 'create-child').exists()).toBe(false)
  })

  it('locator_only=true 的節點套定位樣式，其他節點不套', async () => {
    getAssetNodeTreeMock.mockResolvedValue({
      data: [
        node({ id: 5, locator_only: true, manageable: false, can_rename: true }),
        node({ id: 6 }),
      ],
    })
    const w = mountTree()
    await flushPromises()
    expect(rowOf(w, 5).find('.tree-node-row').classes()).toContain('is-locator')
    expect(rowOf(w, 6).find('.tree-node-row').classes()).not.toContain('is-locator')
  })

  it('根層回應 can_create_root=false 時無根層建立按鈕，搬移對話框無清空選項', async () => {
    getAssetNodeTreeMock.mockResolvedValue({ data: [node({ id: 7 })], can_create_root: false })
    getAssetGroupsMock.mockResolvedValue({
      data: [
        { id: 7, name: 'n7', path: 'n7', parent_id: null, can_create_child: true },
        { id: 8, name: 'n8', path: 'n8', parent_id: null, can_create_child: true },
      ],
    })
    capsMock.granted.add('assetgroup:manage')
    const w = mountTree()
    await flushPromises()
    expect(w.find('.create-root-btn').exists()).toBe(false)
    await item(w, 7, 'move').trigger('click')
    await flushPromises()
    expect(w.find('.tree-select').attributes('data-clearable')).toBe('false')
  })

  it('搬移目的清單只含 can_create_child=true 的節點', async () => {
    getAssetNodeTreeMock.mockResolvedValue({ data: [node({ id: 10 })], can_create_root: true })
    getAssetGroupsMock.mockResolvedValue({
      data: [
        { id: 10, name: 'a', path: 'a', parent_id: null, can_create_child: true },
        { id: 11, name: 'b', path: 'b', parent_id: null, can_create_child: true },
        { id: 12, name: 'c', path: 'c', parent_id: null, can_create_child: false },
      ],
    })
    const w = mountTree()
    await flushPromises()
    await item(w, 10, 'move').trigger('click')
    await flushPromises()
    const ids = w.findAll('.tree-select .opt').map((o) => o.attributes('data-id'))
    expect(ids).toEqual(['11'])
    expect(w.find('.tree-select').attributes('data-clearable')).toBe('true')
  })

  it('回應無旗標時選單與既有 canManageNodes 行為相同', async () => {
    getAssetNodeTreeMock.mockResolvedValue({
      data: [{ id: 20, name: 'legacy', has_children: false, subtree_asset_count: 1 }],
    })
    capsMock.granted.add('assetgroup:manage')
    const w = mountTree()
    await flushPromises()
    for (const cmd of ['create-child', 'rename', 'move', 'delete']) {
      expect(item(w, 20, cmd).attributes('data-disabled')).toBe('false')
    }
    expect(w.find('.create-root-btn').exists()).toBe(true)
    expect(rowOf(w, 20).find('.scope-badge').exists()).toBe(false)
  })

  it('無能力且無旗標時沒有選單與根層建立按鈕', async () => {
    getAssetNodeTreeMock.mockResolvedValue({ data: [{ id: 21, name: 'x', has_children: false }] })
    const w = mountTree()
    await flushPromises()
    expect(rowOf(w, 21).find('.dd').exists()).toBe(false)
    expect(w.find('.create-root-btn').exists()).toBe(false)
  })
})

describe('getAssetGroups 參數物件', () => {
  it('無參數時請求與修改前相同，帶 purpose 時送出查詢參數', async () => {
    const { getAssetGroups } = await vi.importActual('@/api/assets')
    requestMock.mockResolvedValue({ data: [] })
    await getAssetGroups()
    expect(requestMock).toHaveBeenLastCalledWith({ url: '/asset-groups', method: 'get' })
    await getAssetGroups({ purpose: 'asset_update' })
    expect(requestMock).toHaveBeenLastCalledWith({
      url: '/asset-groups',
      method: 'get',
      params: { purpose: 'asset_update' },
    })
  })
})

describe('刪除被擋對話框', () => {
  const dlg = (props) =>
    mount(NodeDeleteBlockedDialog, { props: { modelValue: true, ...props }, global: { stubs } })

  it('超管版列出每筆引用、前往修改連結與群組成員數', async () => {
    const w = dlg({
      path: 'a/b',
      count: 2,
      references: [
        { subject_kind: 'user', subject_id: 5, subject_name: 'alice', role_id: 9, role_name: 'ops' },
        {
          subject_kind: 'user_group',
          subject_id: 3,
          subject_name: 'team-x',
          role_id: 9,
          role_name: 'ops',
          member_count: 4,
        },
      ],
    })
    const items = w.findAll('.blocked-item')
    expect(items).toHaveLength(2)
    expect(items[0].text()).toContain('alice')
    expect(items[1].text()).toContain('team-x')
    expect(items[1].find('.blocked-members').text()).toContain('4')
    expect(items[0].find('.blocked-go').exists()).toBe(true)
    expect(w.text()).toContain('2')
  })

  it('範圍化版只顯示筆數，不含任何人名或群組名', async () => {
    const w = dlg({ path: 'a/b', count: 7, references: null })
    expect(w.find('.blocked-list').exists()).toBe(false)
    expect(w.text()).toContain('7')
    expect(w.find('.blocked-body').text()).toBe(
      zhTW.nodeTree.deleteBlocked.scopedBody.replace('{path}', 'a/b').replace('{count}', '7')
    )
    expect(w.find('.blocked-hint').text()).toBe(zhTW.nodeTree.deleteBlocked.scopedHint)
  })

  it('刪除回 RULE_NODE_SCOPE_REFERENCED 時開啟對話框', async () => {
    getAssetNodeTreeMock.mockResolvedValue({ data: [node({ id: 30 })] })
    deleteAssetGroupMock.mockRejectedValue({
      response: { data: { code: 'RULE_NODE_SCOPE_REFERENCED', params: { path: 'p/q', count: 3 } } },
    })
    const w = mountTree()
    await flushPromises()
    await item(w, 30, 'delete').trigger('click')
    await flushPromises()
    expect(w.find('.blocked-body').text()).toContain('3')
    expect(w.find('.blocked-list').exists()).toBe(false)
  })
})

describe('三語鍵', () => {
  const leaves = (o, pre = '') =>
    Object.entries(o).flatMap(([k, v]) =>
      v && typeof v === 'object' ? leaves(v, `${pre}${k}.`) : [`${pre}${k}`]
    )

  it('nodeTree 三語鍵集合一致，且文案不含登入時點的生效說法', () => {
    const a = leaves(zhTW.nodeTree).sort()
    expect(leaves(enUS.nodeTree).sort()).toEqual(a)
    expect(leaves(jaJP.nodeTree).sort()).toEqual(a)
    for (const loc of [zhTW, enUS, jaJP]) {
      const text = JSON.stringify(loc.nodeTree.deleteBlocked)
      expect(text).not.toMatch(/下次登入|next login|次回ログイン/i)
    }
  })
})
