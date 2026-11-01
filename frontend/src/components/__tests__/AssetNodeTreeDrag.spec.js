/* eslint-disable vue/one-component-per-file, vue/require-prop-types -- 測試替身元件 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import { defineComponent, h, ref } from 'vue'
import AssetNodeTree from '../AssetNodeTree.vue'
import zhTW from '@/i18n/locales/zh-TW.json'
import { t } from '@/i18n'
import { resolveApiError } from '@/api/error'

enableAutoUnmount(afterEach)

const getAssetListMock = vi.fn()
const getAssetNodeTreeMock = vi.fn()
const getAssetGroupsMock = vi.fn()
const moveAssetGroupMock = vi.fn()
const messageMock = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }))
const loadSelectorMock = vi.hoisted(() => vi.fn())

vi.mock('@/api/assets', () => ({
  getAssetList: (...a) => getAssetListMock(...a),
  getAssetNodeTree: (...a) => getAssetNodeTreeMock(...a),
  getAssetGroups: (...a) => getAssetGroupsMock(...a),
  createAssetGroup: vi.fn(),
  updateAssetGroup: vi.fn(),
  moveAssetGroup: (...a) => moveAssetGroupMock(...a),
  deleteAssetGroup: vi.fn(),
}))
vi.mock('@/api/request', () => ({ default: vi.fn() }))
vi.mock('@/api/authorizations', () => ({ getAuthorizationTargetOptions: vi.fn() }))
vi.mock('@/utils/authzSelectors', () => ({
  isSelectableNode: () => true,
  loadSelector: (...a) => loadSelectorMock(...a),
}))
const capsMock = vi.hoisted(() => ({ granted: new Set() }))
vi.mock('@/composables/useCapabilities', () => ({ can: (key) => capsMock.granted.has(key) }))
vi.mock('element-plus', async (orig) => ({
  ...(await orig()),
  ElMessageBox: { confirm: vi.fn().mockResolvedValue('confirm') },
  ElMessage: messageMock,
}))

// el-tree 替身：記憶體內的樹，支援 lazy 載入與 remove／insertBefore／append／getNode，
// 並以 spy 記錄呼叫；事件由測試直接 emit
// 目前掛載中的 el-tree 替身（wrapper.vm 取不到 expose 的方法，改用登記表）
const treeApi = { current: null }
const ElTreeStub = defineComponent({
  props: ['load', 'draggable', 'allowDrag', 'allowDrop', 'indent'],
  emits: ['node-click', 'node-drag-start', 'node-drag-over', 'node-drag-leave', 'node-drag-end', 'node-drop'],
  setup(props, { slots, expose, emit }) {
    const nodes = new Map()
    const version = ref(0)
    const root = { level: 0, childNodes: [], data: null, loaded: true, expanded: true }
    const make = (data, parent) => {
      const n = {
        data,
        level: parent.level + 1,
        parent,
        loaded: false,
        expanded: false,
        childNodes: [],
        isLeaf: !data.has_children,
        contains(t) {
          return this.childNodes.some((c) => c === t || c.contains(t))
        },
        get nextSibling() {
          return parent.childNodes[parent.childNodes.indexOf(this) + 1] || null
        },
        expand() {
          if (this.loaded) {
            this.expanded = true
            version.value += 1
            return
          }
          props.load(this, (list) => {
            this.childNodes = []
            list.forEach((d) => this.childNodes.push(make(d, this)))
            this.loaded = true
            this.expanded = true
            version.value += 1
          }, () => {})
        },
      }
      nodes.set(data.id, n)
      return n
    }
    props.load(root, (list) => {
      list.forEach((d) => root.childNodes.push(make(d, root)))
      version.value += 1
    })
    const spies = {
      remove: vi.fn((id) => {
        const n = nodes.get(id)
        if (!n) return
        n.parent.childNodes.splice(n.parent.childNodes.indexOf(n), 1)
        nodes.delete(id)
        version.value += 1
      }),
      insertBefore: vi.fn((data, refId) => {
        const ref0 = nodes.get(refId)
        const n = make(data, ref0.parent)
        ref0.parent.childNodes.splice(ref0.parent.childNodes.indexOf(ref0), 0, n)
        version.value += 1
      }),
      append: vi.fn((data, parentId) => {
        const p = parentId == null ? root : nodes.get(parentId)
        p.childNodes.push(make(data, p))
        version.value += 1
      }),
      setCurrentKey: vi.fn(),
    }
    const api = { ...spies, getNode: (id) => nodes.get(id) || null, spies, nodes, root, $emit: (...a) => emit(...a) }
    treeApi.current = api
    expose(api)
    const renderNode = (n) => [
      // 與元件庫節點一致：dragover 在節點上就停止冒泡
      h('div', { class: 'row', 'data-id': n.data.id, 'data-key': n.data.id, onDragover: (e) => e.stopPropagation() }, slots.default?.({ node: n, data: n.data })),
      ...(n.expanded ? n.childNodes.flatMap(renderNode) : []),
    ]
    return () => {
      void version.value
      return h('div', { class: 'tree-stub', 'data-draggable': String(!!props.draggable) }, root.childNodes.flatMap(renderNode))
    }
  },
})
const passthrough = (cls) => defineComponent({ setup: (_, { slots }) => () => h('div', { class: cls }, slots.default?.()) })
const ElButtonStub = defineComponent({
  props: ['disabled', 'loading'],
  emits: ['click'],
  setup(props, { slots, emit }) {
    return () => h('button', { disabled: props.disabled, 'data-loading': String(!!props.loading), onClick: (e) => emit('click', e) }, slots.default?.())
  },
})
const ElDialogStub = defineComponent({
  props: ['modelValue'],
  setup(props, { slots }) {
    return () => (props.modelValue ? h('div', { class: 'dlg' }, [slots.default?.(), slots.footer?.()]) : null)
  },
})
const stubs = {
  'el-tree': ElTreeStub,
  'el-dropdown': true,
  'el-dialog': ElDialogStub,
  'el-tree-select': true,
  'el-button': ElButtonStub,
  'el-form': passthrough('form'),
  'el-form-item': passthrough('form-item'),
  'el-input': true,
  'el-icon': passthrough('icon'),
  teleport: true,
}

const row = (id, over = {}) => ({
  id,
  name: `n${id}`,
  parent_id: null,
  has_children: false,
  subtree_asset_count: 3,
  path: `n${id}`,
  can_create_child: true,
  can_rename: true,
  can_move: true,
  can_delete: true,
  manageable: true,
  ...over,
})

const treeOf = () => treeApi.current
const nodeOf = (w, id) => treeOf(w).getNode(id)
const mountTree = async (props = {}, rows = [row(1), row(2), row(3, { has_children: true })]) => {
  capsMock.granted = new Set(['assetgroup:manage'])
  getAssetNodeTreeMock.mockImplementation(async () => ({ data: rows }))
  const w = mount(AssetNodeTree, { props, global: { stubs } })
  await flushPromises()
  return w
}
// 模擬元件庫放下：節點已被搬進目標底下，接著發出 node-drop
const dropOnto = async (w, dragId, targetId) => {
  const tree = treeOf(w)
  const dragging = nodeOf(w, dragId)
  tree.$emit('node-drag-start', dragging, {})
  await flushPromises()
  tree.$emit('node-drag-end', dragging, nodeOf(w, targetId), 'inner', {})
  tree.$emit('node-drop', dragging, nodeOf(w, targetId), 'inner', {})
  await flushPromises()
}

// 以「父節點 id（根層用 root）→ 子層列表」模擬節點樹端點；每次回傳新複本
const setTree = (byParent) =>
  getAssetNodeTreeMock.mockImplementation(async (pid) => ({ data: (byParent[pid ?? 'root'] || []).map((r) => ({ ...r })) }))
const treeCalls = () => getAssetNodeTreeMock.mock.calls.map((c) => c[0] ?? null)
const mountBy = async (byParent, props = {}, caps = ['assetgroup:manage']) => {
  capsMock.granted = new Set(caps)
  setTree(byParent)
  const w = mount(AssetNodeTree, { props, global: { stubs } })
  await flushPromises()
  return w
}
const expandAll = async (w, ...ids) => {
  for (const id of ids) {
    nodeOf(w, id).expand()
    await flushPromises()
  }
}
const clickOk = async (w) => {
  await w.find('.btn-ok').trigger('click')
  await flushPromises()
}
const clickAck = async (w) => {
  await w.find('.btn-got-it').trigger('click')
  await flushPromises()
}
const clearSpies = (w) => {
  Object.values(treeOf(w).spies).forEach((f) => f.mockClear())
  getAssetNodeTreeMock.mockClear()
  getAssetListMock.mockClear()
  loadSelectorMock.mockClear()
}
const rejectWith = (status, code, error = 'x') => ({ response: { status, data: { code, error } } })

beforeEach(() => {
  vi.clearAllMocks()
  moveAssetGroupMock.mockReset()
  vi.spyOn(console, 'error').mockImplementation(() => {})
  loadSelectorMock.mockResolvedValue({ rows: [] })
  capsMock.granted = new Set()
  getAssetListMock.mockResolvedValue({ data: [], total: 0 })
  getAssetGroupsMock.mockResolvedValue({ data: [] })
})

describe('呈現', () => {
  it('不拖曳時沒有樹頂提示；開始後為覆蓋定位；結束後消失', async () => {
    const w = await mountTree()
    expect(w.find('.drag-root-hint').exists()).toBe(false)
    treeOf(w).$emit('node-drag-start', nodeOf(w, 1), {})
    await flushPromises()
    const hint = w.find('.drag-root-hint')
    expect(hint.exists()).toBe(true)
    expect(hint.attributes('style')).toContain('position: absolute')
    expect(hint.text()).toBe(zhTW.nodeTree.drag.rootHint)
    treeOf(w).$emit('node-drag-end', nodeOf(w, 1), null, 'none', {})
    await flushPromises()
    expect(w.find('.drag-root-hint').exists()).toBe(false)
  })

  it('allow-drop 對 prev／next 一律 false；inner 依判定', async () => {
    const w = await mountTree()
    const { allowDrop } = w.findComponent(ElTreeStub).props()
    expect(allowDrop(nodeOf(w, 1), nodeOf(w, 2), 'prev')).toBe(false)
    expect(allowDrop(nodeOf(w, 1), nodeOf(w, 2), 'next')).toBe(false)
    expect(allowDrop(nodeOf(w, 1), nodeOf(w, 2), 'inner')).toBe(true)
  })

  it('可拖的列有把手；旗標停用的列沒有把手', async () => {
    const w = await mountTree({}, [row(1), row(2, { can_move: false, scope_root: true })])
    expect(w.find('.row[data-id="1"] .drag-handle').exists()).toBe(true)
    expect(w.find('.row[data-id="2"] .drag-handle').exists()).toBe(false)
    // 不能拖的列保留把手佔位，列名不橫向位移
    expect(w.find('.row[data-id="2"] .drag-handle-slot').exists()).toBe(true)
  })

  it('停留說明是放在列右側的浮動說明卡，不用原生 title；文字等於選單同項原因；離開即消失', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    try {
      const w = await mountTree({}, [row(1), row(2, { can_move: false, scope_root: true })])
      const locked = w.find('.row[data-id="2"] .tree-node-row')
      expect(locked.attributes('title')).toBeUndefined()
      expect(w.find('.row[data-id="1"] .tree-node-row').attributes('title')).toBeUndefined()
      await locked.trigger('mouseenter')
      await vi.advanceTimersByTimeAsync(399)
      expect(w.find('.row-tip').exists()).toBe(false)
      await vi.advanceTimersByTimeAsync(1)
      const card = w.find('.row-tip')
      expect(card.exists()).toBe(true)
      expect(card.attributes('style')).toContain('position: fixed')
      expect(card.text()).toContain(zhTW.nodeTree.drag.cannotDragTitle)
      expect(card.text()).toContain(zhTW.nodeTree.scopeRootLocked)
      await locked.trigger('mouseleave')
      expect(w.find('.row-tip').exists()).toBe(false)
      await w.find('.row[data-id="1"] .drag-handle').trigger('mouseenter')
      await vi.advanceTimersByTimeAsync(400)
      expect(w.find('.row-tip').text()).toContain(zhTW.nodeTree.drag.handleTitle)
      treeOf(w).$emit('node-drag-start', nodeOf(w, 1), {})
      await flushPromises()
      expect(w.find('.row-tip').exists()).toBe(false)
    } finally {
      vi.useRealTimers()
    }
  })

  it('卡片左緣不小於樹欄右緣（放得下時）、垂直對齊該列', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    const spy = vi.spyOn(Element.prototype, 'getBoundingClientRect').mockImplementation(function () {
      const cls = this.className || ''
      if (typeof cls === 'string' && cls.includes('asset-node-tree')) return { top: 0, bottom: 600, left: 0, right: 240, width: 240, height: 600 }
      return { top: 100, bottom: 124, left: 0, right: 240, width: 240, height: 24 }
    })
    try {
      const w = await mountTree({}, [row(1), row(2, { can_move: false, scope_root: true })])
      await w.find('.row[data-id="2"] .tree-node-row').trigger('mouseenter')
      await vi.advanceTimersByTimeAsync(400)
      const style = w.find('.row-tip').attributes('style')
      expect(parseFloat(/left:\s*([\d.]+)px/.exec(style)[1])).toBeGreaterThanOrEqual(240)
      expect(parseFloat(/top:\s*([\d.]+)px/.exec(style)[1])).toBe(100)
    } finally {
      spy.mockRestore()
      vi.useRealTimers()
    }
  })

  it('可拖的列：停在把手以外的位置不出現「可以拖曳」卡，停在把手上才出現', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    try {
      const w = await mountTree()
      await w.find('.row[data-id="1"] .tree-node-row').trigger('mouseenter')
      await w.find('.row[data-id="1"] .node-label').trigger('mouseenter')
      await vi.advanceTimersByTimeAsync(1000)
      expect(w.find('.row-tip').exists()).toBe(false)
      await w.find('.row[data-id="1"] .drag-handle').trigger('mouseenter')
      await vi.advanceTimersByTimeAsync(400)
      expect(w.find('.row-tip').text()).toContain(zhTW.nodeTree.drag.handleTitle)
    } finally {
      vi.useRealTimers()
    }
  })

  it('選單展開時不渲染說明卡；卡已出現時打開選單就收起', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    try {
      const w = await mountTree()
      const handle = w.find('.row[data-id="1"] .drag-handle')
      await handle.trigger('mouseenter')
      await vi.advanceTimersByTimeAsync(400)
      expect(w.find('.row-tip').exists()).toBe(true)
      const dd = w.findAllComponents({ name: 'ElDropdown' })
      expect(dd.length).toBeGreaterThan(0)
      dd[0].vm.$emit('visible-change', true)
      await flushPromises()
      expect(w.find('.row-tip').exists()).toBe(false)
      await handle.trigger('mouseenter')
      await vi.advanceTimersByTimeAsync(1000)
      expect(w.find('.row-tip').exists()).toBe(false)
      dd[0].vm.$emit('visible-change', false)
      await handle.trigger('mouseenter')
      await vi.advanceTimersByTimeAsync(400)
      expect(w.find('.row-tip').exists()).toBe(true)
    } finally {
      vi.useRealTimers()
    }
  })

  it('無 assetgroup:manage 時 draggable 為 false 且無把手', async () => {
    capsMock.granted = new Set()
    getAssetNodeTreeMock.mockResolvedValue({ data: [row(1, { can_rename: undefined })] })
    const w = mount(AssetNodeTree, { global: { stubs } })
    await flushPromises()
    expect(w.find('.tree-stub').attributes('data-draggable')).toBe('false')
    expect(w.find('.drag-handle').exists()).toBe(false)
  })
})

describe('放下與確認', () => {
  it('放下後先還原原位，確認前不送出；取消不送出、不跳訊息、原列標亮', async () => {
    const w = await mountTree()
    await dropOnto(w, 1, 2)
    const spies = treeOf(w).spies
    expect(spies.remove).toHaveBeenCalledWith(1)
    expect(spies.insertBefore).toHaveBeenCalledWith(expect.objectContaining({ id: 1 }), 2)
    expect(moveAssetGroupMock).not.toHaveBeenCalled()
    expect(document.body.textContent + w.text()).toContain(zhTW.nodeTree.moveConfirm.title)
    expect(w.vm.busy).toBe(true)
    await w.find('.btn-cancel').trigger('click')
    await flushPromises()
    expect(moveAssetGroupMock).not.toHaveBeenCalled()
    expect(messageMock.success).not.toHaveBeenCalled()
    expect(messageMock.error).not.toHaveBeenCalled()
    expect(w.find('.row[data-id="1"] .is-flash').exists()).toBe(true)
    expect(w.vm.busy).toBe(false)
  })

  it('確定：以 skipErrorToast 呼叫一次，回應前顯示鎖定條與「搬移中…」，且不能再拖', async () => {
    const w = await mountTree()
    let release
    moveAssetGroupMock.mockReturnValue(new Promise((r) => (release = r)))
    await dropOnto(w, 1, 2)
    await w.find('.btn-ok').trigger('click')
    await flushPromises()
    expect(moveAssetGroupMock).toHaveBeenCalledTimes(1)
    expect(moveAssetGroupMock).toHaveBeenCalledWith(1, 2, { skipErrorToast: true })
    expect(w.find('.drag-lock-bar').text()).toBe(zhTW.nodeTree.drag.lockBar)
    expect(w.find('.btn-ok').text()).toBe(zhTW.nodeTree.moveConfirm.moving)
    expect(w.find('.btn-ok').attributes('disabled')).toBeDefined()
    expect(w.find('.btn-cancel').attributes('disabled')).toBeDefined()
    const { allowDrag } = w.findComponent(ElTreeStub).props()
    expect(allowDrag(nodeOf(w, 3))).toBe(false)
    release({})
  })

  it('放回原父節點：allow-drop 為 false，不進入確認流程', async () => {
    const child = row(11, { parent_id: 3 })
    const w = await mountTree({}, [row(3, { has_children: true })])
    getAssetNodeTreeMock.mockImplementation(async (pid) => ({ data: pid === 3 ? [child] : [row(3, { has_children: true })] }))
    nodeOf(w, 3).expand()
    await flushPromises()
    const { allowDrop } = w.findComponent(ElTreeStub).props()
    expect(allowDrop(nodeOf(w, 11), nodeOf(w, 3), 'inner')).toBe(false)
    expect(moveAssetGroupMock).not.toHaveBeenCalled()
  })
})

describe('失敗', () => {
  it('409 同名：確認框不關，只剩「知道了」，不跳訊息；按下後關閉並標亮原列', async () => {
    const w = await mountTree()
    moveAssetGroupMock.mockRejectedValue({ response: { status: 409, data: { code: 'CONFLICT_ASSET_NODE_NAME', error: 'x' } } })
    await dropOnto(w, 1, 2)
    await w.find('.btn-ok').trigger('click')
    await flushPromises()
    const text = w.text()
    expect(text).toContain(zhTW.nodeTree.moveConfirm.rejectHead)
    expect(text).toContain(zhTW.nodeTree.moveConfirm.rejectSameNameNext)
    expect(w.find('.btn-got-it').exists()).toBe(true)
    expect(w.find('.btn-ok').exists()).toBe(false)
    expect(w.find('[role="alert"]').exists()).toBe(false)
    expect(messageMock.error).not.toHaveBeenCalled()
    await w.find('.btn-got-it').trigger('click')
    await flushPromises()
    expect(w.find('.btn-got-it').exists()).toBe(false)
    expect(w.find('.row[data-id="1"] .is-flash').exists()).toBe(true)
    expect(w.vm.busy).toBe(false)
  })

  it('結果未知且核對仍在原位：顯示無法確認、不出現「沒有搬移」、按下後整樹重載', async () => {
    const w = await mountTree()
    moveAssetGroupMock.mockRejectedValue(new Error('Network Error'))
    getAssetGroupsMock.mockResolvedValue({ data: [row(1, { parent_id: null })] })
    const before = w.vm.treeKey
    await dropOnto(w, 1, 2)
    await w.find('.btn-ok').trigger('click')
    await flushPromises()
    const text = w.text()
    expect(text).toContain(zhTW.nodeTree.moveConfirm.unknownHead)
    expect(text).not.toContain(zhTW.nodeTree.moveConfirm.rejectHead)
    expect(getAssetGroupsMock).toHaveBeenCalledWith(undefined, { skipErrorToast: true })
    await w.find('.btn-got-it').trigger('click')
    await flushPromises()
    expect(w.vm.treeKey).toBe(before + 1)
    expect(w.vm.busy).toBe(false)
  })
})

describe('成功', () => {
  it('不重載整樹、不跳訊息；新位置標亮並顯示「已搬移」，2 秒後同時消失', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    try {
      const target = row(2, { has_children: true })
      const w = await mountTree({}, [row(1), target])
      getAssetNodeTreeMock.mockImplementation(async (pid) => ({
        data: pid === 2 ? [row(1, { parent_id: 2 })] : [target],
      }))
      moveAssetGroupMock.mockResolvedValue({})
      const before = w.vm.treeKey
      await dropOnto(w, 1, 2)
      await w.find('.btn-ok').trigger('click')
      await flushPromises()
      expect(w.vm.treeKey).toBe(before)
      expect(messageMock.success).not.toHaveBeenCalled()
      expect(nodeOf(w, 1).parent.data.id).toBe(2)
      expect(w.find('.row[data-id="1"] .moved-tag').text()).toBe(zhTW.nodeTree.movedTag)
      // 小字不在會被截斷的列名裡
      expect(w.find('.row[data-id="1"] .node-label .moved-tag').exists()).toBe(false)
      expect(w.find('.row[data-id="1"] .is-flash').exists()).toBe(true)
      // 小字出現時同列數字不渲染，其他列不受影響
      expect(w.find('.row[data-id="1"] .node-count').exists()).toBe(false)
      expect(w.find('.row[data-id="2"] .node-count').exists()).toBe(true)
      expect(getAssetListMock).toHaveBeenCalledTimes(4)
      await vi.advanceTimersByTimeAsync(2000)
      expect(w.find('.row[data-id="1"] .node-count').exists()).toBe(true)
      expect(w.find('.row[data-id="1"] .moved-tag').exists()).toBe(false)
      expect(w.find('.row[data-id="1"] .is-flash').exists()).toBe(false)
      expect(w.vm.busy).toBe(false)
    } finally {
      vi.useRealTimers()
    }
  })

  it('搬完後選取的是被搬節點：選取跟過去並以新 path 發出 select', async () => {
    const target = row(2, { has_children: true })
    const w = await mountTree({}, [row(1), target])
    w.vm.selectedKey = 1
    const moved = row(1, { parent_id: 2, path: 'n2 / n1' })
    getAssetNodeTreeMock.mockImplementation(async (pid) => ({ data: pid === 2 ? [moved] : [target] }))
    moveAssetGroupMock.mockResolvedValue({})
    await dropOnto(w, 1, 2)
    await w.find('.btn-ok').trigger('click')
    await flushPromises()
    expect(treeOf(w).spies.setCurrentKey).toHaveBeenCalledWith(1)
    const selects = w.emitted('select') || []
    expect(selects.at(-1)[0].path).toBe('n2 / n1')
  })
})

describe('停用', () => {
  it('nodeDragDisabled 為 true：draggable 為 false、無把手、無樹頂提示、allow-drag 為 false', async () => {
    const w = await mountTree({ nodeDragDisabled: true })
    expect(w.find('.tree-stub').attributes('data-draggable')).toBe('false')
    expect(w.find('.drag-handle').exists()).toBe(false)
    treeOf(w).$emit('node-drag-start', nodeOf(w, 1), {})
    await flushPromises()
    expect(w.find('.drag-root-hint').exists()).toBe(false)
    expect(w.findComponent(ElTreeStub).props().allowDrag(nodeOf(w, 1))).toBe(false)
  })

  it('確認中改為停用：比照取消', async () => {
    const w = await mountTree()
    await dropOnto(w, 1, 2)
    await w.setProps({ nodeDragDisabled: true })
    await flushPromises()
    expect(moveAssetGroupMock).not.toHaveBeenCalled()
    expect(w.find('.btn-ok').exists()).toBe(false)
    expect(w.vm.busy).toBe(false)
    expect(w.find('.row[data-id="1"] .is-flash').exists()).toBe(true)
  })
})

describe('放下（還原與鎖定）', () => {
  it('被拖節點原本展開：還原後再展開；最後一個兄弟用 append，根層父為 null', async () => {
    const w = await mountBy({
      root: [row(1, { has_children: true }), row(2)],
      1: [row(11, { parent_id: 1 })],
    })
    await expandAll(w, 1)
    clearSpies(w)
    await dropOnto(w, 1, 2)
    expect(treeOf(w).spies.remove).toHaveBeenCalledWith(1)
    expect(treeOf(w).spies.insertBefore).toHaveBeenCalledWith(expect.objectContaining({ id: 1 }), 2)
    expect(nodeOf(w, 1).expanded).toBe(true)
    await w.find('.btn-cancel').trigger('click')
    await flushPromises()
    clearSpies(w)
    await dropOnto(w, 2, 1)
    expect(treeOf(w).spies.append).toHaveBeenCalledWith(expect.objectContaining({ id: 2 }), null)
  })

  it('確認框開著時 allow-drag 對任何節點回 false', async () => {
    const w = await mountBy({ root: [row(1), row(2)] })
    const { allowDrag } = w.findComponent(ElTreeStub).props()
    expect(allowDrag(nodeOf(w, 2))).toBe(true)
    await dropOnto(w, 1, 2)
    expect(allowDrag(nodeOf(w, 1))).toBe(false)
    expect(allowDrag(nodeOf(w, 2))).toBe(false)
  })
})

// 成功後三條請求與選取的固定資料：搬移 21（在 1/11 底下）到 12（在 2 底下）
const FULL = () => ({
  root: [row(1, { has_children: true }), row(2, { has_children: true }), row(9)],
  1: [row(11, { parent_id: 1, has_children: true })],
  11: [row(21, { parent_id: 11 })],
  2: [row(12, { parent_id: 2, has_children: true })],
  12: [],
})
const AFTER = () => ({
  root: [
    row(1, { has_children: true, subtree_asset_count: 5 }),
    row(2, { has_children: true, subtree_asset_count: 6 }),
    row(9),
  ],
  1: [row(11, { parent_id: 1, has_children: false, subtree_asset_count: 7 })],
  11: [],
  2: [row(12, { parent_id: 2, has_children: true, subtree_asset_count: 8 })],
  12: [row(21, { parent_id: 12, path: 'n2 / n12 / n21' })],
})

describe('成功（請求清單與選取）', () => {
  const runA = async (sel, expandIds = [1, 11, 2, 12]) => {
    const w = await mountBy(FULL())
    await expandAll(w, ...expandIds)
    w.vm.selectedKey = sel
    await dropOnto(w, 21, 12)
    clearSpies(w)
    const selectsBefore = (w.emitted('select') || []).length
    setTree(AFTER())
    await clickOk(w)
    return { w, selectsBefore }
  }

  it('新父已載入：不重載整樹、請求清單、祖先資產數取回應值、計數與授權候選各一次', async () => {
    const w = await mountBy(FULL(), {}, ['assetgroup:manage', 'authorization:manage'])
    await expandAll(w, 1, 11, 2, 12)
    w.vm.selectedKey = 9
    await dropOnto(w, 21, 12)
    clearSpies(w)
    setTree(AFTER())
    const before = w.vm.treeKey
    await clickOk(w)
    expect(w.vm.treeKey).toBe(before)
    ;[1, 11, 2].forEach((id) => expect(nodeOf(w, id).expanded).toBe(true))
    const calls = treeCalls()
    ;[null, 1, 2, 12].forEach((id) => expect(calls).toContain(id))
    expect(getAssetGroupsMock).not.toHaveBeenCalled()
    expect(nodeOf(w, 1).data.subtree_asset_count).toBe(5)
    expect(nodeOf(w, 11).data.subtree_asset_count).toBe(7)
    expect(nodeOf(w, 2).data.subtree_asset_count).toBe(6)
    expect(nodeOf(w, 12).data.subtree_asset_count).toBe(8)
    expect(nodeOf(w, 21).parent.data.id).toBe(12)
    expect(messageMock.success).not.toHaveBeenCalled()
    expect(getAssetListMock.mock.calls.map((c) => c[0])).toEqual([
      { page: 1, page_size: 1 },
      { page: 1, page_size: 1, ungrouped: true },
    ])
    expect(loadSelectorMock).toHaveBeenCalledTimes(1)
  })

  it('新父未載入：lazy 載入 1 次、不再插入第二份、樹上只有一個該節點', async () => {
    const w = await mountBy(FULL())
    await expandAll(w, 1, 11, 2)
    w.vm.selectedKey = null
    await dropOnto(w, 21, 12)
    clearSpies(w)
    setTree(AFTER())
    await clickOk(w)
    expect(treeCalls().filter((id) => id === 12)).toHaveLength(1)
    expect(treeOf(w).spies.append).not.toHaveBeenCalled()
    expect(treeOf(w).spies.insertBefore).not.toHaveBeenCalled()
    expect(w.findAll('.row[data-id="21"]')).toHaveLength(1)
    expect(nodeOf(w, 21).parent.data.id).toBe(12)
    expect(getAssetGroupsMock).not.toHaveBeenCalled()
  })

  it('選取的是被搬節點的子孫：沿新路徑逐層載入，選取仍是該子孫並以新 path 發出', async () => {
    const w = await mountBy(FULL())
    await expandAll(w, 1, 11, 2, 12)
    w.vm.selectedKey = 21
    await dropOnto(w, 11, 12)
    clearSpies(w)
    setTree({
      root: AFTER().root,
      1: [],
      2: AFTER()[2],
      12: [row(11, { parent_id: 12, has_children: true })],
      11: [row(21, { parent_id: 11, path: 'new / path' })],
    })
    await clickOk(w)
    const calls = treeCalls()
    expect(calls).toContain(12)
    expect(calls).toContain(11)
    expect(treeOf(w).spies.setCurrentKey).toHaveBeenCalledWith(21)
    expect((w.emitted('select') || []).at(-1)[0].path).toBe('new / path')
    expect(getAssetGroupsMock).not.toHaveBeenCalled()
  })

  it('選取舊父節點：以同一鍵、寫回後的列發出 select，不改 setCurrentKey', async () => {
    const { w, selectsBefore } = await runA(11)
    expect(treeOf(w).spies.setCurrentKey).not.toHaveBeenCalled()
    const selects = w.emitted('select')
    expect(selects.length).toBe(selectsBefore + 1)
    expect(selects.at(-1)[0].id).toBe(11)
    expect(selects.at(-1)[0].subtree_asset_count).toBe(7)
  })

  it('選取新父節點的祖先：同上', async () => {
    const { w, selectsBefore } = await runA(2)
    expect(treeOf(w).spies.setCurrentKey).not.toHaveBeenCalled()
    const selects = w.emitted('select')
    expect(selects.length).toBe(selectsBefore + 1)
    expect(selects.at(-1)[0].id).toBe(2)
    expect(selects.at(-1)[0].subtree_asset_count).toBe(6)
  })

  it('選取無關節點：不發 select、不改 setCurrentKey', async () => {
    const { w, selectsBefore } = await runA(9)
    expect(treeOf(w).spies.setCurrentKey).not.toHaveBeenCalled()
    expect((w.emitted('select') || []).length).toBe(selectsBefore)
  })
})

describe('失敗（被拒呈現）', () => {
  const reasonOf = (w) => w.find('.reject-reason').text()
  const nextOf = (w) => w.find('.reject-next').text()
  const dropAndReject = async (w, from, to, err) => {
    moveAssetGroupMock.mockRejectedValue(err)
    await dropOnto(w, from, to)
    await clickOk(w)
  }
  const sameLevelFixture = () => ({
    root: [row(1), row(2), row(3, { has_children: true })],
    3: [row(31, { parent_id: 3 })],
  })

  it('409 同名：原因含目標名稱與下一步', async () => {
    const w = await mountBy(sameLevelFixture())
    await dropAndReject(w, 1, 2, rejectWith(409, 'CONFLICT_ASSET_NODE_NAME'))
    expect(reasonOf(w)).toBe(t('nodeTree.moveConfirm.rejectSameName', { target: 'n2' }))
    expect(nextOf(w)).toBe(zhTW.nodeTree.moveConfirm.rejectSameNameNext)
    expect(messageMock.error).not.toHaveBeenCalled()
  })

  it('400 深度：多層展開起始，按「知道了」後 stg 與 prod 展開、prod/web 收合', async () => {
    const w = await mountBy({
      root: [row(1, { has_children: true }), row(3, { has_children: true })],
      1: [row(11, { parent_id: 1, has_children: true })],
      11: [row(21, { parent_id: 11 })],
      3: [row(31, { parent_id: 3 })],
    })
    await expandAll(w, 1, 11, 3)
    await dropAndReject(w, 1, 3, rejectWith(400, 'RULE_NODE_DEPTH_EXCEEDED'))
    expect(reasonOf(w)).toBe(zhTW.nodeTree.moveConfirm.rejectDepth)
    expect(nextOf(w)).toBe(zhTW.nodeTree.moveConfirm.rejectDepthNext)
    expect(w.find('.btn-ok').exists()).toBe(false)
    expect(w.find('[role="alert"]').exists()).toBe(false)
    await clickAck(w)
    expect(w.find('.btn-got-it').exists()).toBe(false)
    expect(nodeOf(w, 3).expanded).toBe(true)
    expect(nodeOf(w, 1).expanded).toBe(true)
    expect(nodeOf(w, 11).expanded).toBe(false)
    expect(w.find('.row[data-id="1"] .is-flash').exists()).toBe(true)
    expect(messageMock.error).not.toHaveBeenCalled()
    expect(w.vm.busy).toBe(false)
  })

  it('404 目標被刪：按「知道了」後移除目標、來源留原位、其餘展開保留、不發 select', async () => {
    const w = await mountBy(sameLevelFixture())
    await expandAll(w, 3)
    await dropAndReject(w, 1, 2, rejectWith(404, 'NOTFOUND_ASSET_NODE'))
    expect(reasonOf(w)).toBe(zhTW.nodeTree.moveConfirm.rejectGone)
    expect(nextOf(w)).toBe(zhTW.nodeTree.moveConfirm.rejectGoneNext)
    setTree({ root: [row(1), row(3, { has_children: true })], 3: [row(31, { parent_id: 3 })] })
    clearSpies(w)
    const selectsBefore = (w.emitted('select') || []).length
    await clickAck(w)
    expect(treeOf(w).spies.remove).toHaveBeenCalledWith(2)
    expect(nodeOf(w, 2)).toBeNull()
    expect(nodeOf(w, 1).parent.level).toBe(0)
    expect(nodeOf(w, 3).expanded).toBe(true)
    expect((w.emitted('select') || []).length).toBe(selectsBefore)
    expect(w.find('.row[data-id="1"] .is-flash').exists()).toBe(true)
  })

  it('404 且被刪的是目前選取節點：改以「全部資產」發出 select', async () => {
    const w = await mountBy(sameLevelFixture())
    w.vm.selectedKey = 2
    await dropAndReject(w, 1, 2, rejectWith(404, 'NOTFOUND_ASSET_NODE'))
    setTree({ root: [row(1), row(3, { has_children: true })] })
    await clickAck(w)
    expect(w.emitted('select').at(-1)).toEqual([null])
  })

  it('403 無錯誤碼：原因句等於 resolveApiError，無下一步句', async () => {
    const w = await mountBy(sameLevelFixture())
    const data = { error: '沒有這個節點的管理權限' }
    moveAssetGroupMock.mockRejectedValue({ response: { status: 403, data } })
    await dropOnto(w, 1, 2)
    await clickOk(w)
    expect(reasonOf(w)).toBe(resolveApiError(data, 403))
    expect(w.find('.reject-next').exists()).toBe(false)
    expect(w.find('.btn-got-it').exists()).toBe(true)
    expect(messageMock.error).not.toHaveBeenCalled()
  })
})

describe('停用（中途停用）', () => {
  const successTree = () => ({
    root: [row(1), row(2, { has_children: true })],
    2: [row(1, { parent_id: 2 })],
  })

  it('已送出後停用：回應成功仍完成，之後不能拖', async () => {
    const w = await mountBy(successTree())
    let release
    moveAssetGroupMock.mockReturnValue(new Promise((r) => (release = r)))
    await dropOnto(w, 1, 2)
    await clickOk(w)
    await w.setProps({ nodeDragDisabled: true })
    release({})
    await flushPromises()
    expect(moveAssetGroupMock).toHaveBeenCalledTimes(1)
    expect(w.find('.row[data-id="1"] .is-flash').exists()).toBe(true)
    expect(w.find('.row[data-id="1"] .moved-tag').exists()).toBe(true)
    expect(w.find('.btn-ok').exists()).toBe(false)
    expect(w.find('.btn-got-it').exists()).toBe(false)
    expect(w.vm.busy).toBe(false)
    expect(w.findComponent(ElTreeStub).props().allowDrag(nodeOf(w, 2))).toBe(false)
  })

  it('停用時「⋯」選單的搬移項照常可見', async () => {
    const w = await mountBy(successTree(), { nodeDragDisabled: true })
    expect(w.vm.itemState(nodeOf(w, 1).data, 'move').visible).toBe(true)
  })
})

describe('對話框', () => {
  const flat = () => [
    row(1, { name: '生產', path: '生產' }),
    row(2, { name: '測試', path: '測試' }),
    row(3, { name: '歸檔', path: '歸檔' }),
    row(4, { name: 'web', parent_id: 1, path: '生產 / web' }),
    row(9, { name: 'x', path: 'x' }),
  ]
  const openMove = async (w, id) => {
    await w.vm.handleMenu('move', nodeOf(w, id).data)
    await flushPromises()
  }
  const confirmBtn = (w) => w.findAll('.dlg button').at(-1)

  it('候選根層依原始名稱逐碼位排序；原位時確定停用並顯示說明；改選後可按', async () => {
    const w = await mountBy({ root: [row(9, { name: 'x' })] })
    getAssetGroupsMock.mockResolvedValue({ data: flat() })
    await openMove(w, 9)
    expect(w.vm.moveOptions.map((o) => o.rawName)).toEqual(['歸檔', '測試', '生產'])
    expect(confirmBtn(w).attributes('disabled')).toBeDefined()
    expect(w.find('.move-already-here').text()).toBe(t('nodeTree.moveAlreadyHere', { target: t('nodeTree.allAssets') }))
    w.vm.moveParentId = 2
    await flushPromises()
    expect(confirmBtn(w).attributes('disabled')).toBeUndefined()
    expect(w.find('.move-already-here').exists()).toBe(false)
  })

  it('成功：樹不重載、選取跟過去、不跳訊息、對話框關閉、失敗沿用全域訊息（不帶 skipErrorToast）', async () => {
    const w = await mountBy({
      root: [row(1), row(2, { has_children: true })],
      2: [row(1, { parent_id: 2, path: 'n2 / n1' })],
    })
    getAssetGroupsMock.mockResolvedValue({ data: [row(1), row(2, { has_children: true })] })
    w.vm.selectedKey = 1
    await openMove(w, 1)
    w.vm.moveParentId = 2
    const before = w.vm.treeKey
    moveAssetGroupMock.mockResolvedValue({})
    await w.vm.submitMove()
    await flushPromises()
    expect(w.vm.treeKey).toBe(before)
    expect(moveAssetGroupMock).toHaveBeenCalledTimes(1)
    expect(moveAssetGroupMock.mock.calls[0][2]?.skipErrorToast).toBeUndefined()
    expect(treeOf(w).spies.setCurrentKey).toHaveBeenCalledWith(1)
    expect(w.emitted('select').at(-1)[0].path).toBe('n2 / n1')
    expect(messageMock.success).not.toHaveBeenCalled()
    expect(w.vm.moveVisible).toBe(false)
  })

  const deepFlat = () => [
    row(1, { name: 'dr', has_children: true }),
    row(2, { name: 'zone-a', parent_id: 1, has_children: true }),
    row(3, { name: 'rack-1', parent_id: 2, has_children: true }),
    row(9),
  ]
  const deepTree = () => ({
    root: [row(1, { has_children: true }), row(9)],
    1: [row(2, { parent_id: 1, has_children: true })],
    2: [row(3, { parent_id: 2, has_children: true })],
    3: [row(9, { parent_id: 3 })],
  })

  it('目的祖先從未展開：依序載入三層，標亮在第三層之後，不重載整樹', async () => {
    const w = await mountBy({ root: deepTree().root })
    let flashAtThird = null
    getAssetNodeTreeMock.mockImplementation(async (pid) => {
      if (pid === 3) flashAtThird = w.findAll('.is-flash').length
      return { data: (deepTree()[pid ?? 'root'] || []).map((r) => ({ ...r })) }
    })
    getAssetGroupsMock.mockResolvedValue({ data: deepFlat() })
    await openMove(w, 9)
    w.vm.moveParentId = 3
    getAssetNodeTreeMock.mockClear()
    moveAssetGroupMock.mockResolvedValue({})
    const before = w.vm.treeKey
    await w.vm.submitMove()
    await flushPromises()
    expect(treeCalls().slice(0, 3)).toEqual([1, 2, 3])
    expect(flashAtThird).toBe(0)
    expect(w.findAll('.row[data-id="9"]')).toHaveLength(1)
    expect(nodeOf(w, 9).parent.data.id).toBe(3)
    expect(w.find('.row[data-id="9"] .is-flash').exists()).toBe(true)
    expect(w.vm.treeKey).toBe(before)
  })

  it('目的祖先載入失敗：走同步失敗（整樹重載、saving 回 false、對話框關閉、無「沒有搬移」）', async () => {
    const w = await mountBy({ root: deepTree().root })
    getAssetNodeTreeMock.mockImplementation(async (pid) => {
      if (pid === 2) throw new Error('boom')
      return { data: (deepTree()[pid ?? 'root'] || []).map((r) => ({ ...r })) }
    })
    getAssetGroupsMock.mockResolvedValue({ data: deepFlat() })
    await openMove(w, 9)
    w.vm.moveParentId = 3
    moveAssetGroupMock.mockResolvedValue({})
    const before = w.vm.treeKey
    await w.vm.submitMove()
    await flushPromises()
    expect(w.vm.treeKey).toBe(before + 1)
    expect(w.vm.saving).toBe(false)
    expect(w.vm.moveVisible).toBe(false)
    expect(w.text()).not.toContain(zhTW.nodeTree.moveConfirm.rejectHead)
  })
})

describe('自動展開與捲動', () => {
  const FAKE = ['setTimeout', 'clearTimeout', 'requestAnimationFrame', 'cancelAnimationFrame']
  const treeWithTarget = () => ({
    root: [row(1), row(2, { has_children: true }), row(3, { has_children: true })],
    2: [row(21, { parent_id: 2 })],
    3: [row(31, { parent_id: 3 })],
  })
  const over = (w, dragId, targetId) => treeOf(w).$emit('node-drag-over', nodeOf(w, dragId), nodeOf(w, targetId), {})
  const startDrag = async (w, id) => {
    treeOf(w).$emit('node-drag-start', nodeOf(w, id), {})
    await flushPromises()
  }

  it('停留 699 ms 不展開、700 ms 展開；中途換目標與結束拖曳不展開', async () => {
    vi.useFakeTimers({ toFake: FAKE })
    try {
      const w = await mountBy(treeWithTarget())
      await startDrag(w, 1)
      over(w, 1, 3)
      await vi.advanceTimersByTimeAsync(699)
      expect(nodeOf(w, 3).expanded).toBe(false)
      await vi.advanceTimersByTimeAsync(1)
      expect(nodeOf(w, 3).expanded).toBe(true)
      // 換目標：第一個目標不展開
      over(w, 1, 2)
      await vi.advanceTimersByTimeAsync(400)
      treeOf(w).$emit('node-drag-leave', nodeOf(w, 1), nodeOf(w, 2), {})
      await vi.advanceTimersByTimeAsync(400)
      expect(nodeOf(w, 2).expanded).toBe(false)
      // 結束拖曳
      over(w, 1, 2)
      await vi.advanceTimersByTimeAsync(300)
      treeOf(w).$emit('node-drag-end', nodeOf(w, 1), null, 'none', {})
      await vi.advanceTimersByTimeAsync(800)
      expect(nodeOf(w, 2).expanded).toBe(false)
    } finally {
      vi.useRealTimers()
    }
  })

  it('目標是被拖節點的子孫或第 10 層時不展開', async () => {
    vi.useFakeTimers({ toFake: FAKE })
    try {
      const w = await mountBy({
        root: [row(2, { has_children: true })],
        2: [row(21, { parent_id: 2, has_children: true })],
        21: [row(211, { parent_id: 21 })],
      })
      await expandAll(w, 2)
      await startDrag(w, 2)
      over(w, 2, 21)
      await vi.advanceTimersByTimeAsync(800)
      expect(nodeOf(w, 21).expanded).toBe(false)
      const deep = { level: 10, expanded: false, isLeaf: false, loaded: false, childNodes: [], data: { id: 99, name: 'deep' }, contains: () => false }
      treeOf(w).$emit('node-drag-over', nodeOf(w, 2), deep, {})
      await vi.advanceTimersByTimeAsync(800)
      expect(getAssetNodeTreeMock.mock.calls.map((c) => c[0])).not.toContain(99)
    } finally {
      vi.useRealTimers()
    }
  })

  it('展開後子層含同名：下一次判定為不可放', async () => {
    vi.useFakeTimers({ toFake: FAKE })
    try {
      const w = await mountBy({
        root: [row(1), row(3, { has_children: true })],
        3: [row(31, { parent_id: 3, name: 'n1' })],
      })
      const { allowDrop } = w.findComponent(ElTreeStub).props()
      expect(allowDrop(nodeOf(w, 1), nodeOf(w, 3), 'inner')).toBe(true)
      await startDrag(w, 1)
      over(w, 1, 3)
      await vi.advanceTimersByTimeAsync(700)
      expect(nodeOf(w, 3).loaded).toBe(true)
      expect(allowDrop(nodeOf(w, 1), nodeOf(w, 3), 'inner')).toBe(false)
    } finally {
      vi.useRealTimers()
    }
  })

  const withScrollBox = (w) => {
    const el = w.find('.asset-node-tree').element
    let st = 50
    Object.defineProperty(el, 'scrollTop', { get: () => st, set: (v) => {
        st = v
      },
      configurable: true })
    el.getBoundingClientRect = () => ({ top: 0, bottom: 300, left: 0, right: 240, width: 240, height: 300 })
    return { el, top: () => st }
  }
  const dragOverBox = (el, clientY) => el.dispatchEvent(new MouseEvent('dragover', { clientY, bubbles: true }))

  it('邊緣捲動：近下緣每幀增加且不超過 12；離邊緣 40 px 不動；拖曳結束後停止', async () => {
    const queue = new Map()
    let nextId = 1
    vi.stubGlobal('requestAnimationFrame', (cb) => {
      queue.set(nextId, cb)
      return nextId++
    })
    vi.stubGlobal('cancelAnimationFrame', (id) => queue.delete(id))
    const runFrame = () => {
      const pending = [...queue.values()]
      queue.clear()
      pending.forEach((cb) => cb(0))
    }
    try {
      const w = await mountBy(treeWithTarget())
      const box = withScrollBox(w)
      await startDrag(w, 1)
      dragOverBox(box.el, 260)
      runFrame()
      runFrame()
      expect(box.top()).toBe(50)
      dragOverBox(box.el, 290)
      dragOverBox(box.el, 290)
      runFrame()
      const afterOne = box.top()
      expect(afterOne).toBeGreaterThan(50)
      expect(afterOne - 50).toBeLessThanOrEqual(12)
      runFrame()
      expect(box.top()).toBeGreaterThan(afterOne)
      treeOf(w).$emit('node-drag-end', nodeOf(w, 1), null, 'none', {})
      const stopped = box.top()
      runFrame()
      runFrame()
      expect(box.top()).toBe(stopped)
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('邊緣捲動：事件從節點列發出（節點會擋冒泡）也能啟動', async () => {
    const queue = new Map()
    let nextId = 1
    vi.stubGlobal('requestAnimationFrame', (cb) => {
      queue.set(nextId, cb)
      return nextId++
    })
    vi.stubGlobal('cancelAnimationFrame', (id) => queue.delete(id))
    const runFrame = () => {
      const pending = [...queue.values()]
      queue.clear()
      pending.forEach((cb) => cb(0))
    }
    try {
      const w = await mountBy(treeWithTarget())
      const box = withScrollBox(w)
      await startDrag(w, 1)
      const rowEl = w.find('.row[data-id="1"]').element
      const seenAtBubble = vi.fn()
      box.el.parentNode.addEventListener('dragover', seenAtBubble)
      dragOverBox(rowEl, 290)
      // 節點確實擋住了冒泡，容器的監聽仍須收到
      expect(seenAtBubble).not.toHaveBeenCalled()
      runFrame()
      expect(box.top()).toBeGreaterThan(50)
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('樹的縮排為 12', async () => {
    const w = await mountBy(treeWithTarget())
    expect(w.findComponent(ElTreeStub).props('indent')).toBe(12)
  })

  it('邊緣捲動：游標移出樹欄位（例如移到資產表）後立即不再捲動', async () => {
    const queue = new Map()
    let nextId = 1
    vi.stubGlobal('requestAnimationFrame', (cb) => {
      queue.set(nextId, cb)
      return nextId++
    })
    vi.stubGlobal('cancelAnimationFrame', (id) => queue.delete(id))
    const runFrame = () => {
      const pending = [...queue.values()]
      queue.clear()
      pending.forEach((cb) => cb(0))
    }
    try {
      const w = await mountBy(treeWithTarget())
      const box = withScrollBox(w)
      await startDrag(w, 1)
      dragOverBox(box.el, 290)
      runFrame()
      const scrolled = box.top()
      expect(scrolled).toBeGreaterThan(50)
      const outside = document.createElement('div')
      document.body.appendChild(outside)
      dragOverBox(outside, 290)
      runFrame()
      runFrame()
      expect(box.top()).toBe(scrolled)
      outside.remove()
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('停用時自動展開與捲動都不啟動', async () => {
    vi.useFakeTimers({ toFake: FAKE })
    try {
      const w = await mountBy(treeWithTarget(), { nodeDragDisabled: true })
      const box = withScrollBox(w)
      await startDrag(w, 1)
      over(w, 1, 3)
      dragOverBox(box.el, 290)
      await vi.advanceTimersByTimeAsync(900)
      expect(nodeOf(w, 3).expanded).toBe(false)
      expect(box.top()).toBe(50)
    } finally {
      vi.useRealTimers()
    }
  })

  it('載入失敗可重試：保持未載入、無訊息；離開再停留 700 ms 後成功展開', async () => {
    vi.useFakeTimers({ toFake: FAKE })
    try {
      const w = await mountBy(treeWithTarget())
      let tries = 0
      getAssetNodeTreeMock.mockImplementation(async (pid) => {
        if (pid === 3) {
          tries += 1
          if (tries === 1) throw new Error('boom')
          return { data: [row(31, { parent_id: 3 })] }
        }
        return { data: treeWithTarget()[pid ?? 'root'] || [] }
      })
      await startDrag(w, 1)
      over(w, 1, 3)
      await vi.advanceTimersByTimeAsync(700)
      expect(nodeOf(w, 3).expanded).toBe(false)
      expect(nodeOf(w, 3).loaded).toBe(false)
      expect(messageMock.error).not.toHaveBeenCalled()
      treeOf(w).$emit('node-drag-leave', nodeOf(w, 1), nodeOf(w, 3), {})
      over(w, 1, 3)
      await vi.advanceTimersByTimeAsync(700)
      expect(nodeOf(w, 3).expanded).toBe(true)
      expect(nodeOf(w, 3).childNodes.map((c) => c.data.id)).toEqual([31])
    } finally {
      vi.useRealTimers()
    }
  })

  it('ensureExpanded：成功 resolve、載入失敗 reject、節點不存在 reject', async () => {
    const w = await mountBy(treeWithTarget())
    await expect(w.vm.move.ensureExpanded(3)).resolves.toBeUndefined()
    expect(nodeOf(w, 3).expanded).toBe(true)
    getAssetNodeTreeMock.mockImplementation(async () => {
      throw new Error('boom')
    })
    await expect(w.vm.move.ensureExpanded(2)).rejects.toThrow()
    await expect(w.vm.move.ensureExpanded(999)).rejects.toThrow()
  })
})

describe('結果未知與同步失敗', () => {
  const twoRoots = () => ({
    root: [row(1), row(2, { has_children: true })],
    2: [row(1, { parent_id: 2 })],
  })
  const allQuiet = () => getAssetGroupsMock.mock.calls.every((c) => c[1]?.skipErrorToast === true)

  it('已搬移：核對查到已在目的地即走成功；核對進行中主按鈕仍為「搬移中…」', async () => {
    const w = await mountBy(twoRoots())
    moveAssetGroupMock.mockRejectedValue(new Error('Network Error'))
    let release
    getAssetGroupsMock.mockReturnValue(new Promise((r) => (release = r)))
    await dropOnto(w, 1, 2)
    await clickOk(w)
    expect(w.find('.btn-ok').text()).toBe(zhTW.nodeTree.moveConfirm.moving)
    release({ data: [row(1, { parent_id: 2 })] })
    await flushPromises()
    expect(w.find('.row[data-id="1"] .moved-tag').exists()).toBe(true)
    expect(w.find('.row[data-id="1"] .is-flash').exists()).toBe(true)
    expect(w.text()).not.toContain(zhTW.nodeTree.moveConfirm.rejectHead)
    expect(w.text()).not.toContain(zhTW.nodeTree.moveConfirm.unknownHead)
    expect(messageMock.error).not.toHaveBeenCalled()
    expect(allQuiet()).toBe(true)
  })

  it('仍在原位：顯示無法確認而非「沒有搬移」，按下後整樹重載並沿父鏈定位', async () => {
    let rootCalls = 1
    const w = await mountBy({ root: [row(1), row(5, { has_children: true })] })
    getAssetNodeTreeMock.mockImplementation(async (pid) => {
      if (pid == null) {
        rootCalls += 1
        return { data: rootCalls === 1 ? [row(1), row(5, { has_children: true })] : [row(5, { has_children: true })] }
      }
      const m = {
        5: [row(6, { parent_id: 5, has_children: true })],
        6: [row(7, { parent_id: 6, has_children: true })],
        7: [row(1, { parent_id: 7 })],
      }
      return { data: m[pid] || [] }
    })
    await dropOnto(w, 1, 5)
    moveAssetGroupMock.mockRejectedValue(new Error('Network Error'))
    getAssetGroupsMock
      .mockResolvedValueOnce({ data: [row(1, { parent_id: null })] })
      .mockResolvedValueOnce({
        data: [row(5), row(6, { parent_id: 5 }), row(7, { parent_id: 6 }), row(1, { parent_id: 7 })],
      })
    await clickOk(w)
    expect(w.text()).toContain(zhTW.nodeTree.moveConfirm.unknownHead)
    expect(w.text()).not.toContain(zhTW.nodeTree.moveConfirm.rejectHead)
    expect(w.find('.btn-ok').exists()).toBe(false)
    const before = w.vm.treeKey
    getAssetNodeTreeMock.mockClear()
    await clickAck(w)
    expect(w.vm.treeKey).toBe(before + 1)
    expect(treeCalls().filter((id) => id !== null)).toEqual([5, 6, 7])
    expect(w.find('.row[data-id="1"] .is-flash').exists()).toBe(true)
    expect(w.find('.row[data-id="1"] .moved-tag').exists()).toBe(false)
    expect(messageMock.error).not.toHaveBeenCalled()
    expect(allQuiet()).toBe(true)
  })

  it('無法確認：核對也失敗，顯示無法確認與下一步，按下後整樹重載、停在根層', async () => {
    const w = await mountBy(twoRoots())
    moveAssetGroupMock.mockRejectedValue(new Error('Network Error'))
    getAssetGroupsMock.mockRejectedValue(new Error('down'))
    await dropOnto(w, 1, 2)
    await clickOk(w)
    expect(w.text()).toContain(zhTW.nodeTree.moveConfirm.unknownHead)
    expect(w.find('.reject-next').text()).toBe(zhTW.nodeTree.moveConfirm.rejectGoneNext)
    expect(w.find('.btn-ok').exists()).toBe(false)
    const before = w.vm.treeKey
    await clickAck(w)
    expect(w.vm.treeKey).toBe(before + 1)
    expect(w.vm.busy).toBe(false)
    expect(messageMock.error).not.toHaveBeenCalled()
    expect(allQuiet()).toBe(true)
  })

  it('重載後取父鏈失敗：停在根層、busy 為 false、無任何訊息', async () => {
    const w = await mountBy(twoRoots())
    moveAssetGroupMock.mockRejectedValue(new Error('Network Error'))
    getAssetGroupsMock
      .mockResolvedValueOnce({ data: [row(1, { parent_id: null })] })
      .mockRejectedValueOnce(new Error('down'))
    await dropOnto(w, 1, 2)
    await clickOk(w)
    await clickAck(w)
    expect(w.vm.busy).toBe(false)
    expect(nodeOf(w, 2).expanded).toBe(false)
    expect(messageMock.error).not.toHaveBeenCalled()
    expect(allQuiet()).toBe(true)
  })

  it('同步失敗：搬移已成功、新父子層讀取失敗 → 不顯示被拒、確認框關閉、整樹重載並沿鏈定位', async () => {
    const w = await mountBy(twoRoots())
    let rootCalls = 1
    let twoCalls = 0
    getAssetNodeTreeMock.mockImplementation(async (pid) => {
      if (pid == null) {
        rootCalls += 1
        return { data: rootCalls === 1 ? [row(1), row(2, { has_children: true })] : [row(2, { has_children: true })] }
      }
      if (pid === 2) {
        twoCalls += 1
        if (twoCalls === 1) throw new Error('boom')
        return { data: [row(6, { parent_id: 2, has_children: true })] }
      }
      const m = { 6: [row(7, { parent_id: 6, has_children: true })], 7: [row(1, { parent_id: 7 })] }
      return { data: m[pid] || [] }
    })
    moveAssetGroupMock.mockResolvedValue({})
    getAssetGroupsMock.mockResolvedValue({
      data: [row(2), row(6, { parent_id: 2 }), row(7, { parent_id: 6 }), row(1, { parent_id: 7 })],
    })
    await dropOnto(w, 1, 2)
    getAssetNodeTreeMock.mockClear()
    const before = w.vm.treeKey
    await clickOk(w)
    expect(w.text()).not.toContain(zhTW.nodeTree.moveConfirm.rejectHead)
    expect(w.find('.btn-ok').exists()).toBe(false)
    expect(w.find('.btn-got-it').exists()).toBe(false)
    expect(w.find('.drag-lock-bar').exists()).toBe(false)
    expect(w.vm.treeKey).toBe(before + 1)
    expect(w.vm.busy).toBe(false)
    expect(treeCalls().filter((id) => id !== null)).toEqual([2, 2, 6, 7])
    expect(w.find('.row[data-id="1"] .is-flash').exists()).toBe(true)
    expect(w.find('.row[data-id="1"] .moved-tag').exists()).toBe(false)
    expect(messageMock.error).not.toHaveBeenCalled()
    expect(allQuiet()).toBe(true)
  })
})
