import { computed } from 'vue'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessage } from 'element-plus'
import CredentialDetailPanel from '@/components/credential/CredentialDetailPanel.vue'
import AssetAccountRows from '@/components/asset/AssetAccountRows.vue'
import ExecutorInfoList from '@/components/asset/ExecutorInfoList.vue'
import { grantFor } from '@/composables/__tests__/capabilityFixtures'
import i18n from '@/i18n'
import zhTW from '@/i18n/locales/zh-TW.json'
import enUS from '@/i18n/locales/en-US.json'
import jaJP from '@/i18n/locales/ja-JP.json'

// 私鑰的公鑰指紋：憑證詳情與資產帳號列的三種狀態（沒有私鑰、有指紋、有私鑰但沒有指紋）
// 與範圍外的列。回應形狀：含私鑰且算得出指紋時多一個 private_key_fingerprint，否則不出現。

enableAutoUnmount(afterEach)

class ObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords() { return [] }
}
vi.stubGlobal('MutationObserver', ObserverStub)
vi.stubGlobal('ResizeObserver', ObserverStub)

const listCredentialsMock = vi.fn()
vi.mock('@/api/credentials', () => ({
  listCredentials: (...a) => listCredentialsMock(...a),
  getCredential: vi.fn().mockResolvedValue({ data: {} }),
  deleteCredential: vi.fn(),
  bindCredential: vi.fn(),
  unbindCredential: vi.fn(),
  detachCredentialBinding: vi.fn(),
  convertCredentialScope: vi.fn(),
  setCredentialSecret: vi.fn(),
  startCredentialRotation: vi.fn(),
  getCredentialRotation: vi.fn(),
  retryCredentialRotationMember: vi.fn(),
  abandonCredentialRotation: vi.fn(),
  confirmCredentialImpact: vi.fn(),
  rebindAccountCredential: vi.fn(),
}))
vi.mock('@/api/assets', () => ({
  getAssetGroups: vi.fn().mockResolvedValue({ data: [] }),
  getAssetList: vi.fn().mockResolvedValue({ data: [], total: 0 }),
}))
const listAccountsMock = vi.fn()
vi.mock('@/api/assetAccounts', () => ({
  listAssetAccounts: (...a) => listAccountsMock(...a),
  createAssetAccount: vi.fn(),
  updateAssetAccount: vi.fn(),
  deleteAssetAccount: vi.fn(),
  setDefaultAssetAccount: vi.fn(),
}))

const t = (k, p) => i18n.global.t(k, p)

// 明顯是範例的假值，不是任何真實金鑰的指紋
const FP_SHARED = 'SHA256:EXAMPLEfakeFingerprintForTestOnly0Sample1'

const dialogStub = {
  props: ['modelValue'],
  template: '<div v-if="modelValue" class="dialog-stub"><slot /><slot name="footer" /></div>',
}
// el-tooltip 的內容只在滑過時渲染到 body：替身把觸發元素與內容一起渲染，才能斷言滑過看到的字
const tooltipStub = {
  name: 'ElTooltip',
  props: ['content'],
  template: '<span class="tooltip-stub"><slot /><span class="tooltip-content">{{ content }}<slot name="content" /></span></span>',
}

const clipboard = { writeText: vi.fn() }

beforeEach(() => {
  vi.clearAllMocks()
  grantFor(['admin'])
  listCredentialsMock.mockResolvedValue({ data: [], total: 0 })
  clipboard.writeText.mockResolvedValue(undefined)
  Object.defineProperty(globalThis.navigator, 'clipboard', { value: clipboard, configurable: true })
})

// --- 憑證詳情 ---

const credential = (over = {}) => ({
  id: 41,
  name: '研發三處 Linux root 金鑰',
  scope: 'shared',
  username: 'root',
  secret_type: 'ssh_key',
  protocol_family: 'ssh',
  note: '',
  has_password: false,
  has_private_key: true,
  binding_count: 3,
  current_version_no: 3,
  rotation_active: false,
  created_at: '2026-09-14T02:22:05Z',
  updated_at: '2026-09-14T02:22:05Z',
  ownership: { kind: 'global' },
  bindings: [],
  ...over,
})

const mountDetail = async (cred) => {
  const w = mount(CredentialDetailPanel, {
    props: { credential: cred, aggregateState: 'idle' },
    global: { plugins: [ElementPlus], stubs: { 'el-dialog': dialogStub, ElTooltip: tooltipStub } },
  })
  await flushPromises()
  return w
}

describe('憑證詳情：公鑰指紋', () => {
  it('有指紋：型別下方一列，完整指紋以等寬字顯示並可複製', async () => {
    const w = await mountDetail(credential({ private_key_fingerprint: FP_SHARED }))
    expect(w.get('[data-test="detail-fingerprint-label"]').text()).toContain(t('credentials.detailFingerprint'))
    expect(w.get('[data-test="detail-fingerprint-value"]').text()).toBe(FP_SHARED)
    expect(w.get('[data-test="detail-fingerprint-value"]').element.tagName).toBe('CODE')
    expect(w.find('[data-test="detail-fingerprint-unrecorded"]').exists()).toBe(false)
    // 位置：緊接在型別之後
    const dts = w.findAll('dl.kv > dt').map((d) => d.text())
    const typeIdx = dts.indexOf(t('credentials.detailSecretType'))
    expect(dts[typeIdx + 1]).toContain(t('credentials.detailFingerprint'))

    const successSpy = vi.spyOn(ElMessage, 'success')
    await w.get('[data-test="detail-copy-fingerprint"]').trigger('click')
    await flushPromises()
    expect(clipboard.writeText).toHaveBeenCalledWith(FP_SHARED)
    expect(successSpy).toHaveBeenCalledWith(t('assetExecutor.fingerprintCopied'))
    expect(w.get('[data-test="detail-copy-fingerprint"]').attributes('aria-label')).toBe(t('assetExecutor.copyFingerprint'))
  })

  it('複製失敗時明說要手動選取', async () => {
    clipboard.writeText.mockRejectedValue(new Error('denied'))
    const errorSpy = vi.spyOn(ElMessage, 'error')
    const w = await mountDetail(credential({ private_key_fingerprint: FP_SHARED }))
    await w.get('[data-test="detail-copy-fingerprint"]').trigger('click')
    await flushPromises()
    expect(errorSpy).toHaveBeenCalledWith(t('common.copyFailed'))
  })

  it('欄名說明：是什麼、怎麼在自己電腦上比對、代表平台登記的現行版本', async () => {
    const w = await mountDetail(credential({ private_key_fingerprint: FP_SHARED }))
    const help = w.get('[data-test="detail-fingerprint-help"]').text()
    expect(help).toContain(t('credentials.fingerprintHelpTitle'))
    expect(help).toContain(t('credentials.fingerprintHelp'))
    expect(help).toContain(t('credentials.fingerprintHelpLocal'))
    expect(help).toContain(t('credentials.fingerprintHelpVersion'))
  })

  it('共用憑證有私鑰但沒有指紋：灰色「未記錄」，說明原因並指到「更正私鑰」', async () => {
    const w = await mountDetail(credential())
    expect(w.find('[data-test="detail-fingerprint"]').exists()).toBe(false)
    const cell = w.get('[data-test="detail-fingerprint-unrecorded"]')
    expect(cell.text()).toContain(t('credentials.fingerprintUnrecorded'))
    const entry = t('credentials.secretFix.entry', { noun: t('credentials.secretFix.noun.ssh_key') })
    expect(w.get('[data-test="detail-fingerprint-unrecorded-hint"]').text())
      .toBe(`${t('credentials.fingerprintWhy')}${t('credentials.fingerprintHowTo', { entry })}`)
    expect(w.find('[data-test="detail-copy-fingerprint"]').exists()).toBe(false)
  })

  it('專用憑證有私鑰但沒有指紋：說明指到資產帳號列的「編輯憑證」', async () => {
    const w = await mountDetail(credential({ scope: 'dedicated', name: 'rd3-web-01 / deploy', has_password: true, ownership: { kind: 'asset' } }))
    expect(w.get('[data-test="detail-fingerprint-unrecorded-hint"]').text())
      .toBe(`${t('credentials.fingerprintWhy')}${t('credentials.fingerprintHowToDedicated')}`)
  })

  it('只有密碼：不出現公鑰指紋這一列', async () => {
    const w = await mountDetail(credential({ secret_type: 'password', has_password: true, has_private_key: false }))
    expect(w.find('[data-test="detail-fingerprint-label"]').exists()).toBe(false)
    expect(w.find('[data-test="detail-fingerprint"]').exists()).toBe(false)
    expect(w.find('[data-test="detail-fingerprint-unrecorded"]').exists()).toBe(false)
    expect(w.text()).not.toContain(t('credentials.detailFingerprint'))
  })
})

// --- 資產帳號列 ---

// el-table 在 happy-dom 下極慢：以保留欄位模板執行的替身取代
const ROWS = Symbol('rows')
const tableStub = {
  name: 'ElTable',
  props: ['data'],
  provide() { return { [ROWS]: computed(() => this.data || []) } },
  template: '<div class="table-stub"><slot /></div>',
}
const columnStub = {
  name: 'ElTableColumn',
  props: ['label', 'prop', 'width', 'minWidth', 'className'],
  inject: { stubRows: { from: ROWS, default: null } },
  computed: {
    rows() {
      const injected = this.stubRows
      if (!injected) return []
      return Array.isArray(injected) ? injected : injected.value || []
    },
  },
  template: `<div class="col-stub"><div v-for="(row, i) in rows" :key="i" class="cell-stub">
    <slot :row="row" :column="{}" :$index="i" /></div></div>`,
}

const baseRow = (over = {}) => ({
  asset_id: 2,
  is_default: false,
  privileged: false,
  note: '',
  has_password: false,
  has_private_key: false,
  shared_credential: false,
  credential_scope: 'dedicated',
  effective_version_no: 1,
  binding_count: 1,
  ...over,
})
// 共用、有指紋
const rootRow = () => baseRow({
  id: 11, username: 'root', is_default: true, privileged: true, has_private_key: true,
  shared_credential: true, credential_scope: 'shared', credential_id: 41,
  credential_name: '研發三處 Linux root 金鑰', binding_count: 3, effective_version_no: 3,
  private_key_fingerprint: FP_SHARED,
})
// 專用、有私鑰沒有指紋
const deployRow = () => baseRow({
  id: 12, username: 'deploy', has_password: true, has_private_key: true,
  credential_id: 58, credential_name: 'rd3-web-01 / deploy',
})
// 共用、有私鑰沒有指紋
const sharedUnrecordedRow = () => baseRow({
  id: 14, username: 'ops', has_private_key: true, shared_credential: true, credential_scope: 'shared',
  credential_id: 70, credential_name: '跳板主機 ops 金鑰', binding_count: 2, effective_version_no: 2,
})
// 只有密碼
const appRow = () => baseRow({
  id: 13, username: 'app', has_password: true, credential_id: 63, credential_name: 'rd3-web-01 / app',
  effective_version_no: 2,
})
// 範圍外：伺服器拿掉名稱、台數與指紋
const outKeyRow = () => ({
  id: 21, asset_id: 2, username: 'root', is_default: true, privileged: true, note: '',
  has_password: false, has_private_key: true, shared_credential: true, credential_scope: 'shared',
  credential_out_of_scope: true, effective_version_no: 3,
})
const outPasswordRow = () => ({
  id: 22, asset_id: 2, username: 'dbops', is_default: false, privileged: false, note: '',
  has_password: true, has_private_key: false, shared_credential: true, credential_scope: 'shared',
  credential_out_of_scope: true, effective_version_no: 6,
})
// 精簡形狀：沒有任何 credential_* 欄位
const compactRow = () => ({ id: 31, username: 'svc', is_default: false, has_password: false, has_private_key: true })

const mountRows = async (rows) => {
  listAccountsMock.mockResolvedValue({ data: rows })
  const w = mount(AssetAccountRows, {
    global: {
      plugins: [ElementPlus],
      stubs: { 'el-dialog': dialogStub, ElTable: tableStub, ElTableColumn: columnStub, ElTooltip: tooltipStub },
    },
    props: { assetId: 2, assetName: 'rd3-web-01', protocol: 'ssh' },
  })
  await flushPromises()
  return w
}

describe('資產帳號列：公鑰指紋', () => {
  it('有指紋：憑證名稱下方顯示末 8 碼，滑過看到完整值，可以複製', async () => {
    const w = await mountRows([rootRow()])
    const short = w.get('[data-test="account-fingerprint-short-11"]')
    expect(short.text()).toBe('…0Sample1')
    expect(w.get('[data-test="account-fingerprint-11"]').text().startsWith(`${t('assets.editDrawer.fingerprintPrefix')}…0Sample1`)).toBe(true)
    expect(short.text()).not.toContain(FP_SHARED)
    const full = w.get('[data-test="account-fingerprint-full-11"]').text()
    expect(full).toContain(t('credentials.detailFingerprint'))
    expect(full).toContain(FP_SHARED)
    expect(w.find('[data-test="account-fingerprint-unrecorded-11"]').exists()).toBe(false)

    const successSpy = vi.spyOn(ElMessage, 'success')
    await w.get('[data-test="account-copy-fingerprint-11"]').trigger('click')
    await flushPromises()
    expect(clipboard.writeText).toHaveBeenCalledWith(FP_SHARED)
    expect(successSpy).toHaveBeenCalledWith(t('assetExecutor.fingerprintCopied'))
  })

  // 擋：複製鈕單獨掉到下一行，每列多一行高。換行只能發生在前綴與「末 8 碼加複製鈕」之間
  it('有指紋：末 8 碼與複製鈕在同一個不換行的群組，前綴在群組之外', async () => {
    const w = await mountRows([rootRow()])
    const group = w.get('[data-test="account-fingerprint-value-11"]')
    expect(group.classes()).toContain('fingerprint-value')
    expect(group.find('[data-test="account-fingerprint-short-11"]').exists()).toBe(true)
    expect(group.find('[data-test="account-copy-fingerprint-11"]').exists()).toBe(true)
    expect(group.find('.fingerprint-prefix').exists()).toBe(false)
    const line = w.get('[data-test="account-fingerprint-11"]')
    expect(line.get('.fingerprint-prefix').text()).toBe(t('assets.editDrawer.fingerprintPrefix'))
    // 群組不換行由樣式保證：樣式表裡的 .fingerprint-value 必須帶 white-space: nowrap
    const sfc = readFileSync(join(process.cwd(), 'src/components/asset/AssetAccountRows.vue'), 'utf8')
    expect(sfc).toMatch(/\.fingerprint-value\s*\{[^}]*white-space:\s*nowrap/)
  })

  it('專用列有私鑰但沒有指紋：灰色「未記錄」，說明指到「編輯憑證」，沒有複製鈕', async () => {
    const w = await mountRows([deployRow()])
    expect(w.get('[data-test="account-fingerprint-unrecorded-12"]').text())
      .toBe(`${t('assets.editDrawer.fingerprintPrefix')} ${t('credentials.fingerprintUnrecorded')}`)
    expect(w.get('[data-test="account-fingerprint-why-12"]').text())
      .toBe(`${t('credentials.fingerprintWhy')}${t('credentials.fingerprintHowTo', { entry: t('assets.editDrawer.editSecret') })}`)
    expect(w.find('[data-test="account-copy-fingerprint-12"]').exists()).toBe(false)
    expect(w.find('[data-test="account-fingerprint-short-12"]').exists()).toBe(false)
  })

  it('共用列有私鑰但沒有指紋：說明指到「更正私鑰」', async () => {
    const w = await mountRows([sharedUnrecordedRow()])
    const entry = t('credentials.secretFix.entry', { noun: t('credentials.secretFix.noun.ssh_key') })
    expect(w.get('[data-test="account-fingerprint-why-14"]').text())
      .toBe(`${t('credentials.fingerprintWhy')}${t('credentials.fingerprintHowTo', { entry })}`)
  })

  it('只有密碼：不出現指紋這一行', async () => {
    const w = await mountRows([appRow()])
    expect(w.find('[data-test="account-credential-13"]').exists()).toBe(true)
    expect(w.find('[data-test="account-fingerprint-13"]').exists()).toBe(false)
  })

  it('範圍外含私鑰：不出現指紋與「未記錄」，列下說明多一句看不到公鑰指紋', async () => {
    const w = await mountRows([outKeyRow()])
    expect(w.find('[data-test="account-fingerprint-21"]').exists()).toBe(false)
    expect(w.text()).not.toContain(t('credentials.fingerprintUnrecorded'))
    expect(w.get('[data-test="account-out-of-scope-note-21"]').text()).toBe(t('assets.editDrawer.outOfScopeNoteKey'))
  })

  it('範圍外只有密碼：說明維持原句', async () => {
    const w = await mountRows([outPasswordRow()])
    expect(w.find('[data-test="account-fingerprint-22"]').exists()).toBe(false)
    expect(w.get('[data-test="account-out-of-scope-note-22"]').text()).toBe(t('assets.editDrawer.outOfScopeNote'))
  })

  it('精簡形狀的列（沒有憑證識別）不顯示「未記錄」', async () => {
    const w = await mountRows([compactRow()])
    expect(w.find('[data-test="account-fingerprint-31"]').exists()).toBe(false)
    expect(w.text()).not.toContain(t('credentials.fingerprintUnrecorded'))
  })

  it('同一張表三種列並存：只有含私鑰的範圍內列有指紋行', async () => {
    const w = await mountRows([rootRow(), deployRow(), appRow(), outKeyRow()])
    expect(w.find('[data-test="account-fingerprint-11"]').exists()).toBe(true)
    expect(w.find('[data-test="account-fingerprint-12"]').exists()).toBe(true)
    expect(w.find('[data-test="account-fingerprint-13"]').exists()).toBe(false)
    expect(w.find('[data-test="account-fingerprint-21"]').exists()).toBe(false)
  })
})

describe('堡壘機專用帳號區塊：用語改為公鑰指紋', () => {
  it('欄名顯示「公鑰指紋」', () => {
    const w = mount(ExecutorInfoList, {
      props: {
        executor: { username: 'cx-executor', secret_type: 'ssh_key', key_source: 'generate', fingerprint: 'SHA256:EXAMPLEfakeFingerprintForTestOnly0Sample2', credential: {} },
      },
      global: { plugins: [ElementPlus] },
    })
    expect(w.text()).toContain(zhTW.assetExecutor.fields.fingerprint)
    expect(zhTW.assetExecutor.fields.fingerprint).toBe('公鑰指紋')
  })

  it('三語的欄名與範圍外說明不再用舊稱，並與憑證詳情的欄名一致', () => {
    const cases = [
      [zhTW, '金鑰指紋', '公鑰指紋'],
      [enUS, 'key fingerprint', 'public key fingerprint'],
      [jaJP, '鍵フィンガープリント', '公開鍵フィンガープリント'],
    ]
    for (const [loc, old, now] of cases) {
      expect(loc.assetExecutor.fields.fingerprint).toBe(loc.credentials.detailFingerprint)
      const note = loc.assetExecutor.outOfScopeNote
      expect(note).toContain(now)
      expect(note.toLowerCase().split(now).join('')).not.toContain(old)
    }
  })
})
