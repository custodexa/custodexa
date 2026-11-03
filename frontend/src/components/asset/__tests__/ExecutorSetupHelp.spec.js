import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, it, expect, afterEach } from 'vitest'
import { mount, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import ExecutorSetupHelp from '@/components/asset/ExecutorSetupHelp.vue'

enableAutoUnmount(afterEach)

const mountHelp = (slots) => mount(ExecutorSetupHelp, { global: { plugins: [ElementPlus] }, slots })

describe('ExecutorSetupHelp', () => {
  it('預設收合，第一層文字不含行話', () => {
    const wrapper = mountHelp()
    expect(wrapper.find('[data-test="executor-help-body"]').exists()).toBe(false)
    const first = wrapper.get('[data-test="executor-help-first"]').text()
    for (const word of ['sudo', 'authorized_keys', 'NOPASSWD']) expect(first).not.toContain(word)
  })

  it('hideFirst 搭配 expanded 時不渲染第一層句，只留展開內容', () => {
    const hidden = mount(ExecutorSetupHelp, { global: { plugins: [ElementPlus] }, props: { expanded: true, hideFirst: true } })
    expect(hidden.find('[data-test="executor-help-first"]').exists()).toBe(false)
    expect(hidden.find('[data-test="executor-help-body"]').exists()).toBe(true)
    const shown = mount(ExecutorSetupHelp, { global: { plugins: [ElementPlus] }, props: { expanded: true } })
    expect(shown.find('[data-test="executor-help-first"]').exists()).toBe(true)
  })

  it('展開後含 authorized_keys 與改密 sudo 範例', async () => {
    const wrapper = mountHelp()
    await wrapper.get('[data-test="executor-help-toggle"]').trigger('click')
    const body = wrapper.get('[data-test="executor-help-body"]').text()
    expect(body).toContain('authorized_keys')
    expect(wrapper.get('[data-test="executor-help-sudo"]').text()).toContain('NOPASSWD: /usr/sbin/chpasswd')
  })

  it('兩條 sudo 範例照營運文件的字面，且各自緊接警告句', async () => {
    // 字面與警告句取自營運文件升級手冊「以堡壘機專用帳號代改 Linux／Unix 帳號密碼」一節（三語）
    const wrapper = mountHelp()
    await wrapper.get('[data-test="executor-help-toggle"]').trigger('click')
    const keyRule = wrapper.get('[data-test="executor-help-sudo"]')
    const pwRule = wrapper.get('[data-test="executor-help-sudo-password"]')
    expect(keyRule.text()).toBe('cx-exec ALL=(root) NOPASSWD: /usr/sbin/chpasswd')
    expect(pwRule.text()).toBe('cx-exec ALL=(root) /usr/sbin/chpasswd')
    const keyWarning = keyRule.element.nextElementSibling
    const pwWarning = pwRule.element.nextElementSibling
    expect(keyWarning.getAttribute('data-test')).toBe('executor-help-sudo-warning')
    expect(pwWarning.getAttribute('data-test')).toBe('executor-help-sudo-password-warning')
    expect(keyWarning.textContent).toContain('root')
    expect(pwWarning.textContent).toContain('sudo')
    for (const lang of ['zh-TW', 'en-US', 'ja-JP']) {
      const help = JSON.parse(readFileSync(join(__dirname, `../../../i18n/locales/${lang}.json`), 'utf8')).assetExecutor.help
      expect(help.rotateWarning, lang).toMatch(/root/)
      expect(help.passwordSudoWarning, lang).toMatch(/sudo/)
    }
  })

  it('讀取規則插槽只在展開後出現且位於末尾；未填時沒有容器', async () => {
    const empty = mountHelp()
    await empty.get('[data-test="executor-help-toggle"]').trigger('click')
    expect(empty.find('[data-test="executor-help-read-rule"]').exists()).toBe(false)

    const filled = mountHelp({ 'read-rule': '<span data-test="probe">probe-slot</span>' })
    expect(filled.find('[data-test="probe"]').exists()).toBe(false)
    await filled.get('[data-test="executor-help-toggle"]').trigger('click')
    const body = filled.get('[data-test="executor-help-body"]')
    expect(body.get('[data-test="probe"]').exists()).toBe(true)
    expect(body.element.lastElementChild.getAttribute('data-test')).toBe('executor-help-read-rule')
  })

  it('三語 help 區段不含 tar／TAR_OPTIONS／env_reset 整詞', () => {
    for (const lang of ['zh-TW', 'en-US', 'ja-JP']) {
      const json = JSON.parse(readFileSync(join(__dirname, `../../../i18n/locales/${lang}.json`), 'utf8'))
      const text = JSON.stringify(json.assetExecutor.help)
      expect(/\b(tar|TAR_OPTIONS|env_reset)\b/.test(text)).toBe(false)
    }
  })
})
