// 離機儲存設定頁。
//
// 守的是「設定看起來成功、實際上外洩憑證或把證據送錯地方」的幾個點：
//   - 憑證是 write-only：讀取回應不含值也不含遮罩，表單欄位因此**恆為空**，
//     有無憑證只靠徽章表達；
//   - 測試結果是對「送去測試的那一份設定」的背書，表單一改就必須失效——
//     否則綠色的「通過」會替一份沒測過的設定背書；
//   - 世代切換必須把回應帶回的 expected_current_generation_id 與 settings_digest
//     **原樣**送回：前端自算等於把伺服端的 CAS 變成橡皮圖章；
//   - 狀態過期的拒因不是「儲存失敗」而是「你看到的畫面不是現況」，
//     故提示重新讀取、不自動重送、不留成功樣態；
//   - 空狀態的判準是**帳冊零列**而不是「有無現行世代」：停止離機後仍有歷史
//     物件的部署，失敗清單與歷史世代必須看得見。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import OffsiteStorage from '../OffsiteStorage.vue'

enableAutoUnmount(afterEach)

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

const statusMock = vi.fn()
const failuresMock = vi.fn()
const testMock = vi.fn()
const retryFailedMock = vi.fn()
const retryObjectMock = vi.fn()
const saveMock = vi.fn()
const confirmSwitchMock = vi.fn()
const disableMock = vi.fn()
const profilesMock = vi.fn()
const revokeMock = vi.fn()

vi.mock('@/api/offsiteStorage', () => ({
  getOffsiteStatus: (...a) => statusMock(...a),
  getOffsiteFailures: (...a) => failuresMock(...a),
  testOffsiteConnection: (...a) => testMock(...a),
  retryOffsiteFailed: (...a) => retryFailedMock(...a),
  retryOffsiteObject: (...a) => retryObjectMock(...a),
  getOffsiteSettings: vi.fn(),
  saveOffsiteSettings: (...a) => saveMock(...a),
  confirmOffsiteGenerationSwitch: (...a) => confirmSwitchMock(...a),
  disableOffsiteStorage: (...a) => disableMock(...a),
  listOffsiteProfiles: (...a) => profilesMock(...a),
  revokeOffsiteProfileCredentials: (...a) => revokeMock(...a),
}))

// 政策表單走既有 composable；本檔只驗離機面，政策 API 回空集合即可
vi.mock('@/api/securityPolicies', () => ({
  getSecurityPolicies: vi.fn().mockResolvedValue({ data: [], deviation_count: 0 }),
  updateSecurityPolicies: vi.fn().mockResolvedValue({}),
}))

const messageBoxConfirm = vi.fn()
vi.mock('element-plus', async (importOriginal) => {
  const actual = await importOriginal()
  return {
    ...actual,
    ElMessage: { error: vi.fn(), success: vi.fn(), warning: vi.fn() },
    ElMessageBox: { confirm: (...a) => messageBoxConfirm(...a) },
  }
})

const zeroCounts = () => ({
  pending: 0,
  uploading: 0,
  uploaded: 0,
  failed: 0,
  integrity_mismatch: 0,
  foreign: 0,
  local_purged: 0,
})

const configuredStatus = (overrides = {}) => ({
  configured: true,
  disabled: false,
  generation_id: 7,
  profile_fingerprint: 'a1b2c3d4e5f60718',
  provider: 's3',
  endpoint_origin: 'https://s3.example.com',
  bucket: 'evidence',
  prefix: 'prod',
  region: 'ap-northeast-1',
  path_style: false,
  credential_mode: 'stored',
  has_credentials: true,
  credentials_cleared_at: null,
  created_at: '2026-08-20T02:00:00Z',
  activated_at: '2026-08-20T02:00:00Z',
  retired_at: null,
  object_count: 0,
  credential_state: 'ok',
  counts: { ...zeroCounts(), uploaded: 12 },
  total_objects: 12,
  oldest_pending_age_seconds: {},
  governance: { versioning: 'enabled', retention: 'none', retention_detail: '' },
  ...overrides,
})

const axiosError = (status, data) => {
  const err = new Error(`HTTP ${status}`)
  err.response = { status, data }
  return err
}

const RouterLinkStub = {
  props: ['to'],
  template: '<a><slot /></a>',
}

// el-dialog teleport 到 body，happy-dom 下 wrapper 撈不到——inline stub 保留
// 預設插槽與 footer，斷言仍看得到真實文案與真實按鈕（沿 AuditWorkbenchExport.spec.js）
// data-test 寫在 stub 自己的模板上：只有 v-if 而無 v-else 的單根樣板，
// Vue 會把 false 分支渲成註解節點而不再繼承 fallthrough attrs
const dialogStub = {
  props: ['modelValue'],
  template:
    '<div v-if="modelValue" data-test="offsite-switch-dialog"><slot /><slot name="footer" /></div>',
}

const mountPage = async () => {
  const wrapper = mount(OffsiteStorage, {
    global: {
      plugins: [ElementPlus],
      stubs: {
        RouterLink: RouterLinkStub,
        'router-link': RouterLinkStub,
        'el-dialog': dialogStub,
      },
    },
  })
  await flushPromises()
  return wrapper
}

const at = (wrapper, name) => wrapper.find(`[data-test="${name}"]`)

beforeEach(() => {
  vi.clearAllMocks()
  statusMock.mockResolvedValue(configuredStatus())
  failuresMock.mockResolvedValue({ data: [], total: 0, page: 1, page_size: 20 })
  profilesMock.mockResolvedValue({ data: [], total: 0 })
  messageBoxConfirm.mockResolvedValue('confirm')
})

describe('空狀態口徑＝帳冊零列', () => {
  it('帳冊零列：只有 EmptyState 與設定表單，三個帳冊面板都不渲染', async () => {
    statusMock.mockResolvedValue(
      configuredStatus({ configured: false, generation_id: 0, total_objects: 0, counts: zeroCounts() })
    )
    const wrapper = await mountPage()

    expect(at(wrapper, 'offsite-empty').exists()).toBe(true)
    // 設定表單就是空狀態的入口——不是「去 .env 設好再重啟」的提示
    expect(at(wrapper, 'offsite-settings-form').exists()).toBe(true)
    expect(at(wrapper, 'offsite-queue').exists()).toBe(false)
    expect(at(wrapper, 'offsite-failures').exists()).toBe(false)
    expect(at(wrapper, 'offsite-profiles').exists()).toBe(false)
    expect(at(wrapper, 'offsite-status-tag').text()).toBe('尚未設定')
  })

  it('帳冊非零而已停止上傳：不進空狀態，歷史面照常渲染，只收掉上傳佇列', async () => {
    statusMock.mockResolvedValue(
      configuredStatus({
        disabled: true,
        generation_id: 0,
        counts: { ...zeroCounts(), uploaded: 5, foreign: 5 },
        total_objects: 10,
      })
    )
    const wrapper = await mountPage()

    expect(at(wrapper, 'offsite-empty').exists()).toBe(false)
    expect(at(wrapper, 'offsite-queue').exists()).toBe(true)
    expect(at(wrapper, 'offsite-failures').exists()).toBe(true)
    expect(at(wrapper, 'offsite-profiles').exists()).toBe(true)
    expect(at(wrapper, 'offsite-status-tag').text()).toBe('已停止上傳')
    expect(at(wrapper, 'offsite-disabled-note').exists()).toBe(true)
    // 上傳佇列的兩個計數缺席，存量面照常
    expect(at(wrapper, 'offsite-count-pending').exists()).toBe(false)
    expect(at(wrapper, 'offsite-count-uploading').exists()).toBe(false)
    expect(at(wrapper, 'offsite-count-foreign').exists()).toBe(true)
    expect(at(wrapper, 'offsite-count-total').exists()).toBe(true)
    // 已無現行世代：不再提供「停止離機」
    expect(at(wrapper, 'offsite-disable').exists()).toBe(false)
  })
})

describe('已啟用摘要', () => {
  it('含設定指紋與 bucket 版本控制的中性揭露，且不含任何憑證欄位', async () => {
    const wrapper = await mountPage()
    const summary = at(wrapper, 'offsite-summary')
    expect(summary.exists()).toBe(true)
    expect(at(wrapper, 'offsite-summary-fingerprint').text()).toContain('a1b2c3d4e5f60718')
    expect(at(wrapper, 'offsite-governance').text()).toContain('已啟用')
    expect(summary.text()).toContain('https://s3.example.com')
  })

  it('http 端點在狀態帶標出明文風險', async () => {
    statusMock.mockResolvedValue(
      configuredStatus({ endpoint_origin: 'http://minio.internal:9000' })
    )
    const wrapper = await mountPage()
    expect(at(wrapper, 'offsite-plaintext-risk').exists()).toBe(true)
  })
})

describe('憑證欄 write-only', () => {
  it('既有憑證只顯示「已設定」徽章，輸入框恆為空且 placeholder 說明留空即沿用', async () => {
    const wrapper = await mountPage()
    expect(at(wrapper, 'offsite-credential-mode').text()).toBe('已設定')

    const accessKey = at(wrapper, 'offsite-access-key')
    const secretKey = at(wrapper, 'offsite-secret-key')
    expect(accessKey.element.value).toBe('')
    expect(secretKey.element.value).toBe('')
    expect(accessKey.attributes('placeholder')).toContain('沿用')

    // 整頁不得出現任何憑證值：回應本來就沒有，這裡釘住的是「前端不自己造一個遮罩」
    expect(wrapper.text()).not.toContain('****')
    expect(wrapper.text()).not.toContain('AKIA')
  })

  it('落點變更而憑證留空：儲存前就提示必須重新輸入', async () => {
    const wrapper = await mountPage()
    expect(at(wrapper, 'offsite-move-needs-credentials').exists()).toBe(false)

    await at(wrapper, 'offsite-bucket').setValue('another-bucket')
    await flushPromises()
    expect(at(wrapper, 'offsite-move-needs-credentials').exists()).toBe(true)
  })
})

describe('test-then-save 與結果過期', () => {
  const stagesOkWarnFail = () => ({
    passed: false,
    stages: [
      { step: 'probe_bucket', outcome: 'ok', code: '', detail: 'bucket 可達' },
      {
        step: 'versioning',
        outcome: 'warn',
        code: 'offsite.test_governance_unknown',
        detail: '',
      },
      { step: 'write', outcome: 'fail', code: 'offsite.test_write_failed', detail: '' },
    ],
  })

  it('兩段分組逐步呈現 ok/warn/fail，未回報的步驟標為未執行', async () => {
    testMock.mockResolvedValue(stagesOkWarnFail())
    const wrapper = await mountPage()
    await at(wrapper, 'offsite-test').trigger('click')
    await flushPromises()

    expect(at(wrapper, 'offsite-stage-probe_bucket').text()).toContain('通過')
    expect(at(wrapper, 'offsite-stage-versioning').text()).toContain('無法確認')
    expect(at(wrapper, 'offsite-stage-write').text()).toContain('失敗')
    // 回應沒提到的步驟＝沒跑到，不得從清單消失
    expect(at(wrapper, 'offsite-stage-read').text()).toContain('未執行')
    expect(at(wrapper, 'offsite-stage-delete').text()).toContain('未執行')
    expect(at(wrapper, 'offsite-test-headline').text()).toContain('連線測試失敗')
  })

  it('測試使用表單當下值，不要求先儲存', async () => {
    testMock.mockResolvedValue({ passed: true, stages: [] })
    const wrapper = await mountPage()
    await at(wrapper, 'offsite-bucket').setValue('draft-bucket')
    await at(wrapper, 'offsite-test').trigger('click')
    await flushPromises()

    expect(testMock).toHaveBeenCalledTimes(1)
    expect(testMock.mock.calls[0][0]).toMatchObject({ bucket: 'draft-bucket' })
    expect(saveMock).not.toHaveBeenCalled()
  })

  it('表單任一欄變動即標記結果過期，且成功樣態不得留在畫面上背書', async () => {
    testMock.mockResolvedValue({
      passed: true,
      stages: [{ step: 'probe_bucket', outcome: 'ok', code: '', detail: '' }],
    })
    const wrapper = await mountPage()
    await at(wrapper, 'offsite-test').trigger('click')
    await flushPromises()
    expect(at(wrapper, 'offsite-test-stale').exists()).toBe(false)
    expect(at(wrapper, 'offsite-test-headline').text()).toContain('通過')

    expect(at(wrapper, 'offsite-stage-probe_bucket').exists()).toBe(true)

    await at(wrapper, 'offsite-endpoint').setValue('https://s3.other.example.com')
    await flushPromises()
    expect(at(wrapper, 'offsite-test-stale').exists()).toBe(true)
    // 命題是「不留成功樣態」：過期後 headline 與逐步「通過」都不得續留在 DOM
    expect(at(wrapper, 'offsite-test-headline').exists()).toBe(false)
    expect(at(wrapper, 'offsite-stage-probe_bucket').exists()).toBe(false)
    expect(wrapper.text()).not.toContain('通過')
  })
})

describe('世代切換確認', () => {
  const needsConfirmation = {
    needs_confirmation: true,
    object_count: 42,
    expected_current_generation_id: 7,
    settings_digest: 'digest-from-server',
  }

  it('儲存回「需確認」時開 dialog 並列出舊世代的三個去向', async () => {
    saveMock.mockResolvedValue(needsConfirmation)
    const wrapper = await mountPage()
    await at(wrapper, 'offsite-bucket').setValue('new-bucket')
    await at(wrapper, 'offsite-access-key').setValue('key')
    await at(wrapper, 'offsite-secret-key').setValue('secret')
    await at(wrapper, 'offsite-save').trigger('click')
    await flushPromises()

    const dialog = at(wrapper, 'offsite-switch-dialog')
    expect(dialog.exists()).toBe(true)
    expect(dialog.text()).toContain('42')
    expect(dialog.text()).toContain('歷史世代')
    expect(dialog.text()).toContain('仍可取回')
    expect(dialog.text()).toContain('不會被刪除')
    expect(confirmSwitchMock).not.toHaveBeenCalled()
  })

  it('取消＝不呼叫 confirm 端點', async () => {
    saveMock.mockResolvedValue(needsConfirmation)
    const wrapper = await mountPage()
    await at(wrapper, 'offsite-save').trigger('click')
    await flushPromises()
    await at(wrapper, 'offsite-switch-cancel').trigger('click')
    await flushPromises()

    expect(confirmSwitchMock).not.toHaveBeenCalled()
  })

  it('確認＝呼叫 confirm 端點且把兩個值原樣攜回', async () => {
    saveMock.mockResolvedValue(needsConfirmation)
    confirmSwitchMock.mockResolvedValue(configuredStatus({ generation_id: 8 }))
    const wrapper = await mountPage()
    await at(wrapper, 'offsite-bucket').setValue('new-bucket')
    await at(wrapper, 'offsite-save').trigger('click')
    await flushPromises()
    await at(wrapper, 'offsite-switch-confirm').trigger('click')
    await flushPromises()

    expect(confirmSwitchMock).toHaveBeenCalledTimes(1)
    const [payload, expected, digest] = confirmSwitchMock.mock.calls[0]
    expect(expected).toBe(7)
    expect(digest).toBe('digest-from-server')
    // 送去確認的必須是當初被要求確認的那一份設定
    expect(payload).toEqual(saveMock.mock.calls[0][0])
  })

  it('狀態過期的拒因：提示重新讀取、不自動重送、不留成功樣態', async () => {
    saveMock.mockResolvedValue(needsConfirmation)
    confirmSwitchMock.mockRejectedValue(
      axiosError(409, { code: 'CONFLICT_OFFSITE_SETTINGS_STALE_CONFIRMATION' })
    )
    const wrapper = await mountPage()
    await at(wrapper, 'offsite-save').trigger('click')
    await flushPromises()
    await at(wrapper, 'offsite-switch-confirm').trigger('click')
    await flushPromises()

    expect(at(wrapper, 'offsite-form-error').text()).toContain('重新整理')
    expect(confirmSwitchMock).toHaveBeenCalledTimes(1)
    expect(at(wrapper, 'offsite-switch-dialog').exists()).toBe(false)
  })
})

describe('停止離機', () => {
  it('走破壞性確認，確認後進入停用態呈現', async () => {
    disableMock.mockResolvedValue(
      configuredStatus({ disabled: true, generation_id: 0, credential_mode: 'stored' })
    )
    statusMock
      .mockResolvedValueOnce(configuredStatus())
      .mockResolvedValue(
        configuredStatus({ disabled: true, generation_id: 0, total_objects: 12 })
      )
    const wrapper = await mountPage()
    await at(wrapper, 'offsite-disable').trigger('click')
    await flushPromises()

    expect(messageBoxConfirm).toHaveBeenCalled()
    const [message] = messageBoxConfirm.mock.calls[0]
    // 確認文案必須說清楚「歷史物件仍可取回、憑證不隨之撤銷、遠端不刪」
    expect(message).toContain('仍可取回')
    expect(message).toContain('不會被撤銷')
    expect(message).toContain('不會被刪除')
    expect(disableMock).toHaveBeenCalledTimes(1)
    expect(at(wrapper, 'offsite-status-tag').text()).toBe('已停止上傳')
  })

  it('取消確認＝不呼叫端點', async () => {
    messageBoxConfirm.mockRejectedValue(new Error('cancel'))
    const wrapper = await mountPage()
    await at(wrapper, 'offsite-disable').trigger('click')
    await flushPromises()
    expect(disableMock).not.toHaveBeenCalled()
  })
})

describe('歷史世代列表', () => {
  const threeProfiles = () => ({
    data: [
      { generation_id: 9, profile_fingerprint: 'ffff000011112222', provider: 'gcs',
        endpoint_origin: '', bucket: 'gcs-evidence', prefix: 'prod',
        activated_at: '2026-08-30T00:00:00Z', retired_at: null, object_count: 3,
        credential_mode: 'stored', credentials_cleared_at: null },
      { generation_id: 8, profile_fingerprint: 'aaaa000011112222', provider: 's3',
        endpoint_origin: 'https://s3.example.com', bucket: 'evidence', prefix: '',
        activated_at: '2026-08-20T00:00:00Z', retired_at: '2026-08-30T00:00:00Z',
        object_count: 12, credential_mode: 'default_chain', credentials_cleared_at: null },
      { generation_id: 7, profile_fingerprint: 'bbbb000011112222', provider: 's3',
        endpoint_origin: 'https://old.example.com', bucket: 'old-evidence', prefix: '',
        activated_at: '2026-08-10T00:00:00Z', retired_at: '2026-08-20T00:00:00Z',
        object_count: 4, credential_mode: 'revoked',
        credentials_cleared_at: '2026-08-25T00:00:00Z' },
    ],
    total: 3,
  })

  it('三種憑證狀態各自呈現，只有 stored 才提供撤銷', async () => {
    profilesMock.mockResolvedValue(threeProfiles())
    const wrapper = await mountPage()

    expect(at(wrapper, 'offsite-profile-cred-9').text()).toBe('已設定')
    expect(at(wrapper, 'offsite-profile-cred-8').text()).toBe('使用雲端預設憑證鏈')
    expect(at(wrapper, 'offsite-profile-cred-7').text()).toBe('已撤銷')
    expect(at(wrapper, 'offsite-revoke-9').exists()).toBe(true)
    expect(at(wrapper, 'offsite-revoke-8').exists()).toBe(false)
    expect(at(wrapper, 'offsite-revoke-7').exists()).toBe(false)
  })

  it('撤銷憑證走破壞性確認，文案說明不會回退到預設憑證鏈', async () => {
    profilesMock.mockResolvedValue(threeProfiles())
    revokeMock.mockResolvedValue(undefined)
    const wrapper = await mountPage()
    await at(wrapper, 'offsite-revoke-9').trigger('click')
    await flushPromises()

    const [message] = messageBoxConfirm.mock.calls[0]
    expect(message).toContain('無法取回')
    expect(message).toContain('不會改用雲端預設憑證鏈')
    expect(revokeMock).toHaveBeenCalledWith(9, expect.anything())
  })
})

describe('失敗清單與重試', () => {
  const failureRows = (page) => ({
    data: [
      {
        object_id: page * 10 + 1,
        kind: 'recording',
        owner_id: 501,
        origin: 'live',
        provider: 's3',
        bucket: 'evidence',
        attempts: 5,
        error_code: 'offsite.upload_failed',
        generation_id: 7,
        updated_at: '2026-08-30T01:00:00Z',
        label: 'web-01 · alice',
        days_to_deadline: page === 1 ? -1 : 12,
      },
    ],
    total: 40,
    page,
    page_size: 20,
  })

  it('列出原因、嘗試次數與距到期天數；逾期以警示樣式標出', async () => {
    statusMock.mockResolvedValue(
      configuredStatus({ counts: { ...zeroCounts(), failed: 1 }, total_objects: 1 })
    )
    failuresMock.mockResolvedValue(failureRows(1))
    const wrapper = await mountPage()

    const table = at(wrapper, 'offsite-failures')
    expect(table.text()).toContain('上傳失敗')
    expect(table.text()).toContain('web-01 · alice')
    const deadline = at(wrapper, 'offsite-deadline-11')
    expect(deadline.text()).toContain('已逾保留期')
    expect(deadline.classes()).toContain('deadline-overdue')
  })

  it('分頁跳轉以新頁碼重新查詢', async () => {
    failuresMock.mockResolvedValue(failureRows(1))
    const wrapper = await mountPage()
    expect(failuresMock).toHaveBeenLastCalledWith({ page: 1, size: 20 })

    failuresMock.mockResolvedValue(failureRows(2))
    const pager = wrapper.findAll('.pager .number')
    await pager[1].trigger('click')
    await flushPromises()
    expect(failuresMock).toHaveBeenLastCalledWith({ page: 2, size: 20 })
  })

  it('逐項重試呼叫單筆端點並重新讀取狀態與清單', async () => {
    failuresMock.mockResolvedValue(failureRows(1))
    retryObjectMock.mockResolvedValue({ retried: 1 })
    const wrapper = await mountPage()
    await at(wrapper, 'offsite-retry-11').trigger('click')
    await flushPromises()

    expect(retryObjectMock).toHaveBeenCalledWith(11)
    expect(statusMock).toHaveBeenCalledTimes(2)
    expect(failuresMock).toHaveBeenCalledTimes(2)
  })

  it('「重試失敗項」先確認再批次放回佇列', async () => {
    retryFailedMock.mockResolvedValue({ retried: 3 })
    const wrapper = await mountPage()
    await at(wrapper, 'offsite-retry-failed').trigger('click')
    await flushPromises()

    expect(messageBoxConfirm).toHaveBeenCalled()
    expect(retryFailedMock).toHaveBeenCalledTimes(1)
  })
})

describe('憑證解密失敗不得呈現為未設定', () => {
  it('credential_state=failed 時獨立成一則錯誤警示', async () => {
    statusMock.mockResolvedValue(configuredStatus({ credential_state: 'failed' }))
    const wrapper = await mountPage()
    const alert = at(wrapper, 'offsite-credential-failed')
    expect(alert.exists()).toBe(true)
    expect(alert.text()).toContain('金鑰')
    // 狀態帶仍說「已啟用」而不是「尚未設定」——金鑰事故不是功能關閉
    expect(at(wrapper, 'offsite-status-tag').text()).toBe('已啟用')
  })
})

describe('讀取失敗時不得以空白表單覆寫伺服端設定', () => {
  it('讀取失敗：警示出現且儲存鈕停用', async () => {
    statusMock.mockRejectedValue(axiosError(500, { code: 'INTERNAL_OFFSITE_STATUS' }))
    const wrapper = await mountPage()

    expect(at(wrapper, 'offsite-status-tag').text()).toBe('讀取失敗')
    expect(at(wrapper, 'offsite-save').attributes('disabled')).toBeDefined()
  })
})
