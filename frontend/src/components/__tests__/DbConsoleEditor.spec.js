import { describe, it, expect, afterEach } from 'vitest'
import { mount, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'

// 逐測卸載：殘留元件累積會讓後段測試逼近逾時上限
enableAutoUnmount(afterEach)

import DbConsoleEditor from '../DbConsole/DbConsoleEditor.vue'
import { splitSegments, segmentAtCursor } from '../DbConsole/statement-segments'
import { t } from '@/i18n'

const mountEditor = (props = {}) =>
  mount(DbConsoleEditor, {
    props: { modelValue: '', ...props },
    global: { plugins: [ElementPlus] },
    attachTo: document.body,
  })

describe('送出範圍切分（不解析 SQL）', () => {
  it('以分號切段，段末分號保留', () => {
    const segments = splitSegments('SELECT 1; SELECT 2;')
    expect(segments.map((s) => s.text.trim())).toEqual(['SELECT 1;', 'SELECT 2;'])
  })

  it('以空行切段，空白段落略去', () => {
    const segments = splitSegments('SELECT 1\n\n\nSELECT 2\n')
    expect(segments.map((s) => s.text.trim())).toEqual(['SELECT 1', 'SELECT 2'])
  })

  it('游標落在第二段內即取第二段', () => {
    const text = 'SELECT 1;\nSELECT 2;\nSELECT 3;'
    expect(segmentAtCursor(text, text.indexOf('SELECT 2') + 3)).toBe('SELECT 2;')
  })

  it('游標落在段間空白時取前一段（剛打完分號就按執行）', () => {
    const text = 'SELECT 1;\n\nSELECT 2;'
    expect(segmentAtCursor(text, text.indexOf('SELECT 1;') + 9)).toBe('SELECT 1;')
  })

  it('空文字回空字串，游標超界仍收斂', () => {
    expect(segmentAtCursor('', 5)).toBe('')
    expect(segmentAtCursor('   \n  ', 2)).toBe('')
    expect(segmentAtCursor('SELECT 1', 9999)).toBe('SELECT 1')
  })
})

describe('DbConsoleEditor', () => {
  it('執行游標語句只送出游標所在的那一段', async () => {
    const text = 'SELECT 1;\nSELECT 2;\nSELECT 3;'
    const wrapper = mountEditor({ modelValue: text })
    const area = wrapper.find('textarea').element
    area.selectionStart = text.indexOf('SELECT 2') + 2
    area.selectionEnd = area.selectionStart

    await wrapper.findAll('button')[2].trigger('click')
    expect(wrapper.emitted('execute')).toEqual([['SELECT 2;']])
  })

  it('執行選取只送出選取範圍，無選取時該鈕停用', async () => {
    const text = 'SELECT 1; SELECT 2;'
    const wrapper = mountEditor({ modelValue: text })
    const selectionButton = wrapper.findAll('button')[1]
    expect(selectionButton.attributes('disabled')).toBeDefined()

    const area = wrapper.find('textarea')
    area.element.selectionStart = 0
    area.element.selectionEnd = 9
    await area.trigger('keyup')
    expect(wrapper.findAll('button')[1].attributes('disabled')).toBeUndefined()

    await wrapper.findAll('button')[1].trigger('click')
    expect(wrapper.emitted('execute')).toEqual([['SELECT 1;']])
  })

  it('執行全部送出全文，Ctrl+Enter 同義', async () => {
    const wrapper = mountEditor({ modelValue: '  SELECT 1  ' })
    await wrapper.findAll('button')[0].trigger('click')
    await wrapper.find('textarea').trigger('keydown', { key: 'Enter', ctrlKey: true })
    expect(wrapper.emitted('execute')).toEqual([['SELECT 1'], ['SELECT 1']])
  })

  it('Tab 插入兩個空白而非跳離欄位', async () => {
    const wrapper = mountEditor({ modelValue: 'AB' })
    const area = wrapper.find('textarea')
    area.element.selectionStart = 1
    area.element.selectionEnd = 1
    await area.trigger('keydown', { key: 'Tab' })
    expect(wrapper.emitted('update:modelValue')).toEqual([['A  B']])
  })

  it('進行中或連線不可用時不送出', async () => {
    const busy = mountEditor({ modelValue: 'SELECT 1', busy: true })
    await busy.findAll('button')[0].trigger('click')
    expect(busy.emitted('execute')).toBeUndefined()

    const off = mountEditor({ modelValue: 'SELECT 1', disabled: true })
    await off.findAll('button')[0].trigger('click')
    expect(off.emitted('execute')).toBeUndefined()
  })

  it('錯誤面板就近呈現機器碼譯文、目標端碼與訊息原文', () => {
    const wrapper = mountEditor({
      modelValue: 'slect 1',
      error: {
        code: 'RULE_DB_CONSOLE_STATEMENT_BLOCKED',
        message: '語句已被規則阻斷',
        dbError: { code: '42601', message: 'syntax error at or near "slect"' },
      },
    })
    const text = wrapper.find('.editor-error').text()
    expect(text).toContain('語句已被規則阻斷')
    expect(text).toContain('42601')
    expect(text).toContain('syntax error at or near "slect"')
  })

  it('批次終止符提示只在 mssql 出現且可關閉', async () => {
    expect(mountEditor({ dialect: 'mysql' }).find('.editor-alert').exists()).toBe(false)
    const wrapper = mountEditor({ dialect: 'mssql' })
    expect(wrapper.find('.editor-alert').text()).toContain(
      t('dbConsole.editor.batchHint').slice(0, 6)
    )
    await wrapper.findComponent({ name: 'ElAlert' }).vm.$emit('close')
    await wrapper.vm.$nextTick()
    expect(wrapper.find('.editor-alert').exists()).toBe(false)
  })
})
