import { describe, it, expect, afterEach } from 'vitest'
import { mount, enableAutoUnmount } from '@vue/test-utils'
import { nextTick } from 'vue'
import ElementPlus from 'element-plus'
import RoleNodePicker from '../RoleNodePicker.vue'
import zhTW from '@/i18n/locales/zh-TW.json'

enableAutoUnmount(afterEach)

// 三層樹：1 總部 > 2 台中機房 > 3 核心資料庫；4 台北機房（根層）
const NODES = [
  { id: 1, name: '總部', parent_id: null, subtree_asset_count: 30 },
  { id: 2, name: '台中機房', parent_id: 1, subtree_asset_count: 20 },
  { id: 3, name: '核心資料庫', parent_id: 2, subtree_asset_count: 12 },
  { id: 4, name: '台北機房', parent_id: null, subtree_asset_count: 8 },
]

const rp = zhTW.roleNodePicker

// 受控掛載：modelValue 由測試持有，事件回寫後重設 props，等同父層 v-model
function mountPicker(props = {}) {
  return mount(RoleNodePicker, {
    props: {
      modelValue: { mode: 'nodes', nodeIds: [] },
      nodes: NODES,
      ...props,
    },
    global: { plugins: [ElementPlus] },
  })
}

async function check(wrapper, id, value = true) {
  const input = wrapper.find(`[data-test="rnp-check-${id}"] input`)
  await input.setValue(value)
  const events = wrapper.emitted('update:modelValue')
  const last = events[events.length - 1][0]
  await wrapper.setProps({ modelValue: last })
  return last
}

const stateOf = (wrapper, id) => wrapper.find(`[data-test="rnp-row-${id}"]`).attributes('data-state')

describe('RoleNodePicker', () => {
  it('不接收角色名稱或權限清單作為輸入（props 列表）', () => {
    expect(Object.keys(RoleNodePicker.props).sort()).toEqual([
      'counts',
      'countsUnavailable',
      'groupNodeIds',
      'loadFailed',
      'modelValue',
      'noEffectReason',
      'nodes',
      'variant',
    ])
  })

  it('全系統與指定節點切換：全系統時不顯示樹，切換保留草稿並回報模式', async () => {
    const wrapper = mountPicker({ modelValue: { mode: 'all', nodeIds: [] } })
    expect(wrapper.find('[data-test="rnp-tree"]').exists()).toBe(false)
    expect(wrapper.text()).toContain(rp.modeAll)
    expect(wrapper.text()).toContain(rp.modeNodes)
    await wrapper.find('[data-test="rnp-mode-nodes"] input').setValue(true)
    const emitted = wrapper.emitted('update:modelValue')
    expect(emitted.at(-1)[0]).toEqual({ mode: 'nodes', nodeIds: [] })
    await wrapper.setProps({ modelValue: { mode: 'nodes', nodeIds: [] } })
    expect(wrapper.find('[data-test="rnp-tree"]').exists()).toBe(true)
  })

  it('由 parent_id 組樹並顯示每個節點的台數', () => {
    const wrapper = mountPicker()
    const ids = wrapper.findAll('[data-test^="rnp-row-"]').map((r) => r.attributes('data-test'))
    expect(ids).toEqual(['rnp-row-1', 'rnp-row-2', 'rnp-row-3', 'rnp-row-4'])
    expect(wrapper.find('[data-test="rnp-row-3"]').attributes('style')).toContain('padding-left: 36px')
    expect(wrapper.find('[data-test="rnp-count-3"]').text()).toBe('12 台')
    expect(wrapper.find('[data-test="rnp-count-1"]').text()).toBe('30 台')
  })

  it('勾父節點：子孫為已涵蓋且不可另勾，祖先為半選', async () => {
    const wrapper = mountPicker()
    await check(wrapper, 2)
    expect(stateOf(wrapper, 2)).toBe('checked')
    expect(stateOf(wrapper, 3)).toBe('covered')
    expect(stateOf(wrapper, 1)).toBe('partial')
    expect(stateOf(wrapper, 4)).toBe('none')
    expect(wrapper.find('[data-test="rnp-check-3"] input').attributes('disabled')).toBeDefined()
    expect(wrapper.find('[data-test="rnp-includes-2"]').text()).toBe(rp.includesChildren)
  })

  it('先勾子節點再勾其父節點，草稿只剩父節點', async () => {
    const wrapper = mountPicker()
    await check(wrapper, 3)
    expect(wrapper.props('modelValue').nodeIds).toEqual([3])
    await check(wrapper, 4)
    const last = await check(wrapper, 2)
    expect(last).toEqual({ mode: 'nodes', nodeIds: [4, 2] })
    // 取消父節點後，子孫恢復可勾
    await check(wrapper, 2, false)
    expect(stateOf(wrapper, 3)).toBe('none')
  })

  it('以深層節點名搜尋：顯示該節點與祖先鏈，無命中顯示 searchEmpty', async () => {
    const wrapper = mountPicker()
    await wrapper.find('[data-test="rnp-search"]').setValue('核心')
    const ids = wrapper.findAll('[data-test^="rnp-row-"]').map((r) => r.attributes('data-test'))
    expect(ids).toEqual(['rnp-row-1', 'rnp-row-2', 'rnp-row-3'])
    await wrapper.find('[data-test="rnp-search"]').setValue('不存在的名稱')
    expect(wrapper.findAll('[data-test^="rnp-row-"]')).toHaveLength(0)
    expect(wrapper.find('[data-test="rnp-search-empty"]').text()).toBe(rp.searchEmpty)
  })

  it('來自群組的節點有標籤且仍可勾為管理者指派', async () => {
    const wrapper = mountPicker({ groupNodeIds: [4] })
    expect(wrapper.find('[data-test="rnp-from-group-4"]').text()).toBe(rp.fromGroup)
    expect(wrapper.find('[data-test="rnp-from-group-1"]').exists()).toBe(false)
    const last = await check(wrapper, 4)
    expect(last.nodeIds).toEqual([4])
    expect(wrapper.find('[data-test="rnp-check-4"] input').attributes('disabled')).toBeUndefined()
  })

  it('底部合計三個數字取自預覽，不加總各節點台數', async () => {
    // total 刻意小於各節點台數相加（20 + 8），證明元件不自行加總
    const wrapper = mountPicker({
      modelValue: { mode: 'nodes', nodeIds: [2, 4] },
      counts: { direct: 15, from_groups_extra: 3, total: 18 },
    })
    expect(wrapper.find('[data-test="rnp-footer"]').text()).toBe(
      '管理者指派 2 個節點 15 台，加上來自群組的 3 台，共可管理 18 台'
    )
  })

  it('from_groups_extra 為 0 用 footerUserNoGroup，群組模式用 footerGroup', async () => {
    const wrapper = mountPicker({
      modelValue: { mode: 'nodes', nodeIds: [2] },
      counts: { direct: 20, from_groups_extra: 0, total: 20 },
    })
    expect(wrapper.find('[data-test="rnp-footer"]').text()).toBe('管理者指派 1 個節點，共可管理 20 台')
    await wrapper.setProps({ variant: 'group', counts: { total: 6 } })
    expect(wrapper.find('[data-test="rnp-footer"]').text()).toBe('已選 1 個節點，共 6 台資產')
  })

  it('預覽失敗顯示 countsUnavailable，樹仍可操作', async () => {
    const wrapper = mountPicker({ countsUnavailable: true })
    expect(wrapper.find('[data-test="rnp-footer"]').text()).toBe(rp.countsUnavailable)
    const last = await check(wrapper, 4)
    expect(last.nodeIds).toEqual([4])
  })

  it('節點清單讀取失敗顯示 treeLoadFailed', () => {
    const wrapper = mountPicker({ nodes: [], loadFailed: true })
    expect(wrapper.find('[data-test="rnp-tree-load-failed"]').text()).toContain(rp.treeLoadFailed)
    expect(wrapper.find('[data-test="rnp-tree"]').exists()).toBe(false)
  })

  it('範圍不會生效的原因提示：兩種原因各一鍵，未知原因退回 rangeNoEffectNote，全系統不顯示', async () => {
    const wrapper = mountPicker({ noEffectReason: 'builtin_global_only' })
    expect(wrapper.find('[data-test="rnp-no-effect-note"]').text()).toBe(rp.builtinGlobalOnlyNote)
    await wrapper.setProps({ noEffectReason: 'no_scoped_permission' })
    expect(wrapper.find('[data-test="rnp-no-effect-note"]').text()).toBe(rp.rangeNoEffectNote)
    await wrapper.setProps({ noEffectReason: 'future_reason' })
    expect(wrapper.find('[data-test="rnp-no-effect-note"]').text()).toBe(rp.rangeNoEffectNote)
    await wrapper.setProps({ modelValue: { mode: 'all', nodeIds: [] } })
    await nextTick()
    expect(wrapper.find('[data-test="rnp-no-effect-note"]').exists()).toBe(false)
  })
})
