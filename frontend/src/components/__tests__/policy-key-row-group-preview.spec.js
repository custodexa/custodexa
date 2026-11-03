import { describe, it, expect, afterEach } from 'vitest'
import { mount, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import PolicyKeyRow from '../PolicyKeyRow.vue'

// 主機特權群組（POSIX）的解析預覽：只供呈現；會被後端拒收的項目標警示。
enableAutoUnmount(afterEach)

const GROUPS = { key: 'host_privileged_groups_posix', type: 'text', label: '主機特權群組（POSIX）', max_length: 8192 }
const OTHER = { key: 'login_banner_title', type: 'text', label: '登入告示標題', max_length: 120 }
const ZWSP = String.fromCodePoint(0x200b)

const mountRow = (policy, value) =>
  mount(PolicyKeyRow, { global: { plugins: [ElementPlus] }, props: { policy, value } })
const items = (w) => w.findAll('[data-test="group-preview-item"]')

describe('主機特權群組預覽', () => {
  it('切分、去空白、去空項與重複', () => {
    const w = mountRow(GROUPS, ' root, sudo ,,wheel,sudo ')
    expect(items(w).map((i) => i.text())).toEqual(['root', 'sudo', 'wheel'])
    expect(w.find('[data-test="group-preview-rejected"]').exists()).toBe(false)
  })

  it('空值：說明不以群組判定特權', () => {
    const w = mountRow(GROUPS, '')
    expect(w.find('[data-test="group-preview-empty"]').exists()).toBe(true)
    expect(items(w)).toHaveLength(0)
    expect(mountRow(GROUPS, ' , ,').find('[data-test="group-preview-empty"]').exists()).toBe(true)
  })

  it('含冒號、含控制字元、超過 256 位元組的項目標警示並提示存檔會被拒絕', () => {
    const long = 'a'.repeat(257)
    const w = mountRow(GROUPS, `ok,bad:name,ctl${String.fromCodePoint(7)}x,${long}`)
    const probs = items(w).map((i) => i.attributes('data-problem'))
    expect(probs).toEqual([undefined, 'colon', 'badChar', 'tooLong'])
    expect(w.find('[data-test="group-preview-rejected"]').exists()).toBe(true)
  })

  it('位元組長度以 UTF-8 計：128 個中文字（384 位元組）會被標警示', () => {
    const w = mountRow(GROUPS, '群'.repeat(128))
    expect(items(w)[0].attributes('data-problem')).toBe('tooLong')
  })

  it('第 33 項起標超過上限', () => {
    const list = Array.from({ length: 33 }, (_, i) => `g${i}`).join(',')
    const w = mountRow(GROUPS, list)
    expect(items(w)).toHaveLength(33)
    expect(items(w)[31].attributes('data-problem')).toBeUndefined()
    expect(items(w)[32].attributes('data-problem')).toBe('overLimit')
    expect(w.find('[data-test="group-preview-rejected"]').exists()).toBe(true)
  })

  it('隱藏字元以跳脫形式顯示', () => {
    const w = mountRow(GROUPS, `ad${ZWSP}min`)
    expect(items(w)[0].text()).toContain('<U+200B>')
  })

  it('其他政策鍵不出現預覽', () => {
    expect(mountRow(OTHER, 'a,b').find('[data-test="group-preview"]').exists()).toBe(false)
  })
})
