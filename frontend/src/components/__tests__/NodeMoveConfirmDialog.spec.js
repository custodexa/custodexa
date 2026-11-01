/* eslint-disable vue/one-component-per-file, vue/require-prop-types -- 測試替身元件 */
import { describe, it, expect, afterEach } from 'vitest'
import { mount, enableAutoUnmount } from '@vue/test-utils'
import { defineComponent, h } from 'vue'
import NodeMoveConfirmDialog from '../NodeMoveConfirmDialog.vue'
import { t } from '@/i18n'

enableAutoUnmount(afterEach)

const ElButtonStub = defineComponent({
  props: ['disabled', 'loading'],
  emits: ['click'],
  setup(props, { slots, emit }) {
    return () => h('button', { disabled: props.disabled, onClick: (e) => emit('click', e) }, slots.default?.())
  },
})
const mountDialog = (props = {}) =>
  mount(NodeMoveConfirmDialog, {
    props: { visible: true, nodeName: 'prod', fromPath: 'dc / a', toPath: 'dc / b', count: 5, ...props },
    global: { stubs: { teleport: true, 'el-button': ElButtonStub } },
  })

describe('NodeMoveConfirmDialog', () => {
  it('確認階段：標題、三列值、資產數、四句說明、兩個按鈕', () => {
    const w = mountDialog()
    const text = w.text()
    expect(text).toContain(t('nodeTree.moveConfirm.title'))
    expect(text).toContain('prod')
    expect(text).toContain('dc / a')
    expect(text).toContain('dc / b')
    expect(text).toContain(t('nodeTree.moveConfirm.carryCount', { n: 5 }))
    expect(text).toContain(t('nodeTree.moveConfirm.authz'))
    expect(text).toContain(t('nodeTree.moveConfirm.scope'))
    expect(text).toContain(t('nodeTree.moveConfirm.direct'))
    expect(w.find('.btn-cancel').text()).toBe(t('common.cancel'))
    expect(w.find('.btn-ok').text()).toBe(t('nodeTree.moveConfirm.ok'))
    expect(w.find('.btn-ok').attributes('disabled')).toBeUndefined()
  })

  it('根層父節點顯示「全部資產」', () => {
    const w = mountDialog({ fromPath: '', toPath: '' })
    const values = w.findAll('.confirm-row dd').map((d) => d.text())
    expect(values).toEqual(['prod', t('nodeTree.allAssets'), t('nodeTree.allAssets')])
  })

  it('處理中：主按鈕為「搬移中…」且停用，取消與關閉停用', () => {
    const w = mountDialog({ phase: 'moving' })
    expect(w.find('.btn-ok').text()).toBe(t('nodeTree.moveConfirm.moving'))
    expect(w.find('.btn-ok').attributes('disabled')).toBeDefined()
    expect(w.find('.btn-cancel').attributes('disabled')).toBeDefined()
    expect(w.find('.confirm-close').attributes('disabled')).toBeDefined()
  })

  it('被拒：只剩「知道了」，顯示原因與下一步', () => {
    const w = mountDialog({ phase: 'reject', rejectHead: '沒有搬移', rejectReason: '原因句', rejectNext: '下一步句' })
    expect(w.find('.btn-got-it').text()).toBe(t('nodeTree.moveConfirm.gotIt'))
    expect(w.find('.btn-ok').exists()).toBe(false)
    expect(w.find('.btn-cancel').exists()).toBe(false)
    expect(w.text()).toContain('原因句')
    expect(w.text()).toContain('下一步句')
  })

  it('Esc：確認階段發出 cancel，說明階段發出 ack，處理中不處理', async () => {
    const w = mountDialog()
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    expect(w.emitted('cancel')).toHaveLength(1)
    await w.setProps({ phase: 'moving' })
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    expect(w.emitted('cancel')).toHaveLength(1)
    expect(w.emitted('ack')).toBeUndefined()
    await w.setProps({ phase: 'reject' })
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    expect(w.emitted('ack')).toHaveLength(1)
  })

  it('錨定在視窗右下角的目標列時，框座標不超出視窗', () => {
    const row = { top: window.innerHeight - 30, bottom: window.innerHeight - 8, left: window.innerWidth - 120, right: window.innerWidth - 8 }
    const w = mountDialog({ anchor: row })
    const style = w.find('.node-move-confirm').attributes('style')
    const left = Number(/left:\s*([\d.]+)px/.exec(style)[1])
    const top = Number(/top:\s*([\d.]+)px/.exec(style)[1])
    expect(left).toBeGreaterThanOrEqual(0)
    expect(left + 360).toBeLessThanOrEqual(window.innerWidth)
    expect(top).toBeGreaterThanOrEqual(0)
    expect(top + 340).toBeLessThanOrEqual(window.innerHeight)
  })
})
