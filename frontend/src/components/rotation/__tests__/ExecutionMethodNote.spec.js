// 紀錄的執行方式標示：代改列在帳號名下方標示專用帳號；自改、舊資料、帳號名為空不渲染；
// 提權方式放第二層，滑鼠、鍵盤聚焦、觸控點按都能打開。
import { describe, it, expect, afterEach } from 'vitest'
import { mount, enableAutoUnmount } from '@vue/test-utils'
import i18n from '@/i18n'
import ExecutionMethodNote from '../ExecutionMethodNote.vue'

enableAutoUnmount(afterEach)

// 替身依 visible 就地渲染第二層內容，方便斷言
const tooltipStub = {
  props: ['visible', 'manual', 'placement', 'popperClass'],
  template:
    '<span class="tooltip-stub"><slot /><span v-if="visible" data-test="tooltip-open"><slot name="content" /></span></span>',
}

const mountNote = (row) =>
  mount(ExecutionMethodNote, {
    props: { row },
    global: { plugins: [i18n], stubs: { 'el-tooltip': tooltipStub } },
  })

const delegatedRow = {
  account_username: 'deploy',
  execution_method: 'executor_sudo_nopasswd',
  executor_username: 'cx-exec',
}
const t = (k, p) => i18n.global.t(k, p)

describe('ExecutionMethodNote', () => {
  it('代改列顯示由哪個專用帳號代改', () => {
    const w = mountNote(delegatedRow)
    const note = w.find('[data-test="execution-method-note"]')
    expect(note.exists()).toBe(true)
    expect(note.text()).toBe(t('changeSecretPlans.methodDelegatedBy', { name: 'cx-exec' }))
  })

  it('自改列與升級前的列不顯示', () => {
    expect(mountNote({ account_username: 'app', execution_method: 'self', executor_username: '' })
      .find('[data-test="execution-method-note"]').exists()).toBe(false)
    expect(mountNote({ account_username: 'app' }).find('[data-test="execution-method-note"]').exists()).toBe(false)
  })

  it('專用帳號在檢視者範圍外時只顯示類別句，畫面與第二層都不帶名稱', async () => {
    const row = { account_username: 'deploy', execution_method: 'executor_sudo_nopasswd', executor_out_of_scope: true }
    const w = mountNote(row)
    const note = w.find('[data-test="execution-method-note"]')
    expect(note.exists()).toBe(true)
    expect(note.text()).toBe(t('changeSecretPlans.methodDelegatedByScoped'))
    await note.trigger('focus')
    const detail = w.find('[data-test="execution-method-detail"]')
    expect(detail.exists()).toBe(true)
    expect(detail.text()).toContain(t('changeSecretPlans.methodElevation', { method: t('changeSecretPlans.method.executor_sudo_nopasswd') }))
    expect(w.html()).not.toContain('cx-exec')
  })

  it('專用帳號名為空時不顯示', () => {
    const w = mountNote({ ...delegatedRow, executor_username: '' })
    expect(w.find('[data-test="execution-method-note"]').exists()).toBe(false)
  })

  it('第二層可由鍵盤聚焦開啟：tabindex 存在、focus 後出現提權方式說明', async () => {
    const w = mountNote(delegatedRow)
    const note = w.find('[data-test="execution-method-note"]')
    expect(note.attributes('tabindex')).toBe('0')
    expect(w.find('[data-test="tooltip-open"]').exists()).toBe(false)
    await note.trigger('focus')
    const open = w.find('[data-test="tooltip-open"]')
    expect(open.exists()).toBe(true)
    expect(open.text()).toContain(t('changeSecretPlans.method.executor_sudo_nopasswd'))
    expect(open.text()).toContain('cx-exec')
    expect(open.text()).toContain('deploy')
    await note.trigger('blur')
    expect(w.find('[data-test="tooltip-open"]').exists()).toBe(false)
  })

  it('改密指令被拒的列：第二層才提 sudo 並指向營運文件，第一層原因文案不提 sudo', async () => {
    const row = { ...delegatedRow, status: 'failed', error: 'CHANGE_SECRET_EXECUTOR_COMMAND_REJECTED' }
    const w = mountNote(row)
    const note = w.find('[data-test="execution-method-note"]')
    expect(note.text()).not.toContain('sudo')
    expect(w.find('[data-test="execution-method-sudo-help"]').exists()).toBe(false)
    await note.trigger('focus')
    const help = w.find('[data-test="execution-method-sudo-help"]')
    expect(help.exists()).toBe(true)
    expect(help.text()).toContain('sudo')
    expect(help.text()).toContain('docs/ops/upgrade-sop.md')
    for (const lang of ['zh-TW', 'en-US', 'ja-JP']) {
      const reason = i18n.global.t('changeSecretPlans.reason.CHANGE_SECRET_EXECUTOR_COMMAND_REJECTED', { executor: 'cx-exec' }, { locale: lang })
      expect(reason, lang).not.toMatch(/sudo|chpasswd/)
    }
  })

  it('其他列的第二層不帶 sudo 說明', async () => {
    const w = mountNote({ ...delegatedRow, status: 'failed', error: 'CHANGE_SECRET_EXECUTOR_LOGIN_FAILED' })
    await w.find('[data-test="execution-method-note"]').trigger('focus')
    expect(w.find('[data-test="execution-method-detail"]').exists()).toBe(true)
    expect(w.find('[data-test="execution-method-sudo-help"]').exists()).toBe(false)
  })

  it('第二層可由滑鼠滑過與觸控點按開啟', async () => {
    const w = mountNote(delegatedRow)
    const note = w.find('[data-test="execution-method-note"]')
    await note.trigger('mouseenter')
    expect(w.find('[data-test="tooltip-open"]').exists()).toBe(true)
    await note.trigger('mouseleave')
    expect(w.find('[data-test="tooltip-open"]').exists()).toBe(false)
    await note.trigger('click')
    expect(w.find('[data-test="tooltip-open"]').exists()).toBe(true)
    await note.trigger('keydown', { key: 'Escape' })
    expect(w.find('[data-test="tooltip-open"]').exists()).toBe(false)
  })

  it('三種提權方式各有標籤，第一層不含行話', () => {
    for (const m of ['executor_root', 'executor_sudo_nopasswd', 'executor_sudo_password']) {
      expect(t(`changeSecretPlans.method.${m}`)).not.toBe(`changeSecretPlans.method.${m}`)
    }
    const w = mountNote(delegatedRow)
    expect(w.find('[data-test="execution-method-note"]').text()).not.toMatch(/sudo|chpasswd/i)
  })

  it('專用帳號原因碼文案帶專用帳號名', () => {
    for (const code of [
      'LOGIN_FAILED', 'COMMAND_REJECTED', 'ROTATION_PENDING', 'CHANGED', 'UNAVAILABLE',
    ]) {
      const text = t(`changeSecretPlans.reason.CHANGE_SECRET_EXECUTOR_${code}`, { executor: 'cx-exec' })
      expect(text).toContain('cx-exec')
    }
  })
})
