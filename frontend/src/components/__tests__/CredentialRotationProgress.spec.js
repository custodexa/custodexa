import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessage, ElMessageBox } from 'element-plus'
import i18n from '@/i18n'
import HostIdentityConfirmDialog from '@/components/HostIdentityConfirmDialog.vue'
import CredentialRotationProgress from '@/components/credential/CredentialRotationProgress.vue'
import { resetCapabilities, setCapabilitiesForTests } from '@/composables/useCapabilities'

// 整組改密的進行中面板。
//
// 斷言重心在四件事：
//  1. 成員狀態逐列可辨識——七個狀態各自的處置不同，混成一種即失去意義；
//  2. 輪詢到結束才停，且結束時通知外層（詳情要重新載入才看得到新的現行版本）；
//  3. **分頁不在前景就暫停**——背景分頁的輪詢沒有人在看，卻一直在留讀取記錄；
//  4. 兩個版本號而非版本清單。

enableAutoUnmount(afterEach)

class ObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords() { return [] }
}
vi.stubGlobal('MutationObserver', ObserverStub)
vi.stubGlobal('ResizeObserver', ObserverStub)

const getMock = vi.fn()
const retryMock = vi.fn()
const abandonMock = vi.fn()

vi.mock('@/api/credentials', () => ({
  getCredentialRotation: (...a) => getMock(...a),
  retryCredentialRotationMember: (...a) => retryMock(...a),
  abandonCredentialRotation: (...a) => abandonMock(...a),
}))

// happy-dom 的 visibilityState 是唯讀取值器，改由本 helper 覆寫
let visibility = 'visible'
Object.defineProperty(document, 'visibilityState', {
  configurable: true,
  get: () => visibility,
})

const setVisibility = async (value) => {
  visibility = value
  document.dispatchEvent(new Event('visibilitychange'))
  await flushPromises()
}

const memberFixture = (overrides = {}) => ({
  id: 31,
  account_id: 20113,
  asset_id: 2,
  asset_name: 'ssh-multi-test',
  username: 'shareduser',
  state: 'applied',
  attempt_count: 1,
  ...overrides,
})

const rotationFixture = (overrides = {}) => ({
  id: 7,
  credential_id: 110,
  epoch: 1,
  mode: 'group',
  status: 'running',
  requested_by: 1,
  requested_by_name: 'admin',
  started_at: '2026-09-06T02:00:00Z',
  aggregate_state: 'partial',
  members: [
    memberFixture({ id: 31, account_id: 1, asset_name: 'web-01', state: 'applied' }),
    memberFixture({ id: 32, account_id: 2, asset_name: 'web-02', state: 'changing' }),
    memberFixture({ id: 33, account_id: 3, asset_name: 'app-01', state: 'changed_unverified' }),
    memberFixture({
      id: 34, account_id: 4, asset_name: 'batch-01',
      state: 'terminal_failed', last_error: 'CHANGE_SECRET_REMOTE_REJECTED',
    }),
  ],
  ...overrides,
})

const bindings = () => [
  { account_id: 1, asset_id: 11, effective_version_no: 4, up_to_date: true },
  { account_id: 2, asset_id: 12, effective_version_no: 3, up_to_date: false },
  { account_id: 3, asset_id: 13, effective_version_no: 3, up_to_date: false },
  { account_id: 4, asset_id: 14, effective_version_no: 3, up_to_date: false },
]

const dialogStub = {
  props: ['modelValue', 'title'],
  template:
    '<div v-if="modelValue" class="dialog-stub"><h3>{{ title }}</h3><slot /><slot name="footer" /></div>',
}

async function mountProgress(props = {}) {
  const wrapper = mount(CredentialRotationProgress, {
    global: { plugins: [ElementPlus], stubs: { 'el-dialog': dialogStub } },
    props: {
      credentialId: 110,
      rotationId: 7,
      currentVersionNo: 3,
      bindings: bindings(),
      ...props,
    },
  })
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  vi.clearAllMocks()
  setCapabilitiesForTests(['credential:view', 'credential:rotate'])
  visibility = 'visible'
  getMock.mockResolvedValue({ data: rotationFixture() })
  retryMock.mockResolvedValue({ data: rotationFixture() })
  abandonMock.mockResolvedValue({ data: rotationFixture({ status: 'abandoned' }) })
})

afterEach(() => {
  vi.useRealTimers()
  resetCapabilities()
})

describe('進行中的逐台狀態', () => {
  it('四種成員狀態各自呈現，統計數與成員數一致', async () => {
    const wrapper = await mountProgress()

    expect(getMock).toHaveBeenCalledWith(110, 7)
    expect(wrapper.findAll('[data-test^="member-row-"]')).toHaveLength(4)

    expect(wrapper.find('[data-test="member-state-31"]').text()).toBe('就位')
    expect(wrapper.find('[data-test="member-state-32"]').text()).toBe('改密中')
    expect(wrapper.find('[data-test="member-state-33"]').text()).toBe('已改未驗證')
    expect(wrapper.find('[data-test="member-state-34"]').text()).toBe('失敗')

    expect(wrapper.find('[data-test="rotation-stat-applied"]').text()).toContain('1')
    expect(wrapper.find('[data-test="rotation-stat-changing"]').text()).toContain('1')
    expect(wrapper.find('[data-test="rotation-stat-unverified"]').text()).toContain('1')
    expect(wrapper.find('[data-test="rotation-stat-failed"]').text()).toContain('1')

    // 失敗那一列帶得出原因，不是只說「失敗」
    expect(wrapper.find('[data-test="member-reason-34"]').exists()).toBe(true)
  })

  it('只給兩個版本號：目標與現行，不列版本清單', async () => {
    const wrapper = await mountProgress()

    expect(wrapper.find('[data-test="version-summary"]').text()).toBe('目標版本 v4 · 現行 v3')
    // 已改未驗證的那一台不報版本號——它現在吃哪一組秘密並不確定
    expect(wrapper.find('[data-test="member-version-33"]').text()).toBe('暫停')
    expect(wrapper.find('[data-test="member-version-31"]').text()).toBe('v4')
  })

  it('聚合態與發起資訊呈現在標頭', async () => {
    const wrapper = await mountProgress()

    expect(wrapper.find('[data-test="aggregate-state"]').text()).toBe('部分就位')
    expect(wrapper.find('[data-test="rotation-started-by"]').text()).toContain('整組一起換')
    expect(wrapper.find('[data-test="rotation-started-by"]').text()).toContain('admin')
    // 輪替期間的限制寫在畫面上，不是只寫在文件裡
    expect(wrapper.find('[data-test="rotation-warning"]').text()).toContain('輪替期間無法掛載')
  })
})

describe('輪詢', () => {
  it('未完成即排下一次；下一次回到完成就停止並通知外層', async () => {
    vi.useFakeTimers()
    const wrapper = await mountProgress()
    expect(wrapper.vm.polling).toBe(true)
    expect(getMock).toHaveBeenCalledTimes(1)

    getMock.mockResolvedValue({
      data: rotationFixture({
        status: 'completed',
        aggregate_state: 'idle',
        members: [memberFixture({ id: 31, account_id: 1, state: 'applied' })],
      }),
    })
    await vi.advanceTimersByTimeAsync(5000)
    await flushPromises()

    expect(getMock).toHaveBeenCalledTimes(2)
    expect(wrapper.vm.polling).toBe(false)
    expect(wrapper.emitted('finished')).toBeTruthy()

    // 停了就是停了：再過幾個週期也不該再打
    await vi.advanceTimersByTimeAsync(20000)
    expect(getMock).toHaveBeenCalledTimes(2)
  })

  it('分頁轉為不可見即停止輪詢並就地說明，回到前景立刻補一次', async () => {
    vi.useFakeTimers()
    const wrapper = await mountProgress()
    expect(wrapper.vm.polling).toBe(true)

    await setVisibility('hidden')
    expect(wrapper.vm.polling).toBe(false)
    expect(wrapper.vm.pausedByVisibility).toBe(true)
    expect(wrapper.find('[data-test="polling-paused"]').exists()).toBe(true)

    // 暫停期間不再打 API
    await vi.advanceTimersByTimeAsync(30000)
    expect(getMock).toHaveBeenCalledTimes(1)

    await setVisibility('visible')
    expect(getMock).toHaveBeenCalledTimes(2)
    expect(wrapper.vm.pausedByVisibility).toBe(false)
  })
})

describe('補跑與放棄', () => {
  it('無輪替能力者只看進度：補跑、逐台補跑與放棄皆不呈現', async () => {
    setCapabilitiesForTests(['credential:view', 'credential:bind'])
    const wrapper = await mountProgress()
    expect(wrapper.find('[data-test="rotation-stat-applied"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="retry-failed"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="abandon-rotation"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="abandon-hint"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="member-retry-34"]').exists()).toBe(false)
  })

  it('持輪替能力者看得到補跑與放棄', async () => {
    const wrapper = await mountProgress()
    expect(wrapper.find('[data-test="retry-failed"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="abandon-rotation"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="member-retry-34"]').exists()).toBe(true)
  })

  it('失敗與已改未驗證的成員可補跑，逐台送出', async () => {
    const wrapper = await mountProgress()

    expect(wrapper.find('[data-test="retry-failed"]').text()).toContain('2')
    expect(wrapper.find('[data-test="member-retry-34"]').exists()).toBe(true)
    // 就位與改密中不給補跑：那兩個狀態沒有「再試一次」可言
    expect(wrapper.find('[data-test="member-retry-31"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="member-retry-32"]').exists()).toBe(false)

    await wrapper.find('[data-test="member-retry-34"]').trigger('click')
    await flushPromises()
    expect(retryMock).toHaveBeenCalledWith(110, 7, 34)
  })

  it('執行中的輪替：收束的成員可補跑並計入整批，排隊的成員只給逐台推進', async () => {
    getMock.mockResolvedValue({
      data: rotationFixture({
        members: [
          memberFixture({ id: 31, account_id: 1, asset_name: 'web-01', state: 'applied' }),
          memberFixture({
            id: 51, account_id: 2, asset_name: 'web-02',
            state: 'abandoned', last_error: 'CHANGE_SECRET_AUTHZ_REVOKED',
          }),
          memberFixture({ id: 52, account_id: 3, asset_name: 'app-01', state: 'queued' }),
        ],
      }),
    })
    const wrapper = await mountProgress()

    expect(wrapper.find('[data-test="member-retry-51"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="member-retry-52"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="member-retry-31"]').exists()).toBe(false)
    // 整批只算收束的那一台：排隊中的成員在正常推進時本來就存在
    expect(wrapper.find('[data-test="retry-failed"]').text()).toContain('1')

    await wrapper.find('[data-test="member-retry-52"]').trigger('click')
    await flushPromises()
    expect(retryMock).toHaveBeenCalledWith(110, 7, 52)
  })

  it('輪替已結束：收束與排隊的成員不給補跑', async () => {
    getMock.mockResolvedValue({
      data: rotationFixture({
        status: 'abandoned',
        members: [
          memberFixture({ id: 51, account_id: 2, asset_name: 'web-02', state: 'abandoned' }),
          memberFixture({ id: 52, account_id: 3, asset_name: 'app-01', state: 'queued' }),
        ],
      }),
    })
    const wrapper = await mountProgress()

    expect(wrapper.find('[data-test="member-retry-51"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="member-retry-52"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="retry-failed"]').exists()).toBe(false)
  })

  it('已放棄但未收斂的整組輪替：尚未就位且掛載仍在的成員都可補跑並計入整批', async () => {
    getMock.mockResolvedValue({
      data: rotationFixture({
        status: 'abandoned',
        unsettled: true,
        aggregate_state: 'out_of_sync',
        members: [
          memberFixture({ id: 31, account_id: 1, asset_name: 'web-01', state: 'applied' }),
          memberFixture({ id: 51, account_id: 2, asset_name: 'web-02', state: 'abandoned' }),
          memberFixture({ id: 52, account_id: 3, asset_name: 'app-01', state: 'queued' }),
          memberFixture({
            id: 53, account_id: 4, asset_name: 'batch-01',
            state: 'changed_unverified', last_error: 'CHANGE_SECRET_INTERRUPTED',
          }),
          // 掛載已卸下的那一台不再由這組秘密登入，不給補跑
          memberFixture({ id: 54, account_id: 99, asset_name: 'gone-01', state: 'retry_wait' }),
        ],
      }),
    })
    const wrapper = await mountProgress()

    expect(wrapper.vm.isUnsettled).toBe(true)
    expect(wrapper.find('[data-test="unsettled-hint"]').text()).toContain('逐台補跑')
    expect(wrapper.find('[data-test="abandon-rotation"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="member-retry-31"]').exists()).toBe(false)
    for (const id of [51, 52, 53]) {
      expect(wrapper.find(`[data-test="member-retry-${id}"]`).exists(), String(id)).toBe(true)
    }
    expect(wrapper.find('[data-test="member-retry-54"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="retry-failed"]').text()).toContain('3')
    // 服務重啟中斷的那一台說明原因，不只顯示機器碼
    expect(wrapper.find('[data-test="member-reason-53"]').text()).toContain('服務重啟')

    await wrapper.find('[data-test="member-retry-51"]').trigger('click')
    await flushPromises()
    expect(retryMock).toHaveBeenCalledWith(110, 7, 51)
  })

  it('已放棄但未收斂的拆分輪替：放棄時未動過的成員沒有可推的秘密，不給補跑；候選仍在的已收束成員照給', async () => {
    getMock.mockResolvedValue({
      data: rotationFixture({
        status: 'abandoned',
        mode: 'split',
        unsettled: true,
        members: [
          memberFixture({ id: 51, account_id: 2, asset_name: 'web-02', state: 'abandoned' }),
          memberFixture({ id: 52, account_id: 3, asset_name: 'app-01', state: 'changed_unverified' }),
          // 動過遠端後才被停成收束（例如失權期間有人按了補跑），候選仍在
          memberFixture({
            id: 53, account_id: 4, asset_name: 'batch-01', state: 'abandoned',
            last_error: 'CHANGE_SECRET_AUTHZ_REVOKED', candidate_kept: true,
          }),
        ],
      }),
    })
    const wrapper = await mountProgress()

    expect(wrapper.find('[data-test="member-retry-51"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="member-retry-52"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="member-retry-53"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="retry-failed"]').text()).toContain('2')
  })

  it('打開時已放棄的一輪不通知外層重新載入；補跑後收斂完成才通知', async () => {
    getMock.mockResolvedValue({
      data: rotationFixture({
        status: 'abandoned',
        unsettled: true,
        members: [memberFixture({ id: 51, account_id: 2, asset_name: 'web-02', state: 'abandoned' })],
      }),
    })
    const wrapper = await mountProgress()
    expect(wrapper.vm.polling).toBe(false)
    expect(wrapper.emitted('finished')).toBeFalsy()

    retryMock.mockResolvedValue({
      data: rotationFixture({
        status: 'completed',
        members: [memberFixture({ id: 51, account_id: 2, asset_name: 'web-02', state: 'applied' })],
      }),
    })
    await wrapper.find('[data-test="member-retry-51"]').trigger('click')
    await flushPromises()
    expect(wrapper.emitted('finished')).toBeTruthy()
  })

  it('放棄本輪就地說明後果，且動作前先確認', async () => {
    const wrapper = await mountProgress()

    expect(wrapper.find('[data-test="abandon-hint"]').text()).toContain('不同步')
    expect(wrapper.find('[data-test="abandon-rotation"]').exists()).toBe(true)
  })

  it('補跑鈕把待補跑的每一台都送完，且是依序逐台送（不是只送第一台）', async () => {
    const wrapper = await mountProgress()

    // 待補跑＝terminal_failed(34) ＋ changed_unverified(33)，按鈕上的數字就是這兩台
    expect(wrapper.find('[data-test="retry-failed"]').text()).toContain('2')

    const order = []
    let release
    const firstInFlight = new Promise((resolve) => { release = resolve })
    retryMock.mockImplementationOnce(async (_c, _r, memberId) => {
      order.push(memberId)
      await firstInFlight
      return { data: rotationFixture() }
    })
    retryMock.mockImplementation(async (_c, _r, memberId) => {
      order.push(memberId)
      return { data: rotationFixture() }
    })

    const done = wrapper.vm.retryFailed()
    await flushPromises()
    // 第一台還沒回來，第二台就不得已經送出——平行送出時這裡會是 2
    expect(retryMock).toHaveBeenCalledTimes(1)

    release()
    await done
    await flushPromises()

    expect(retryMock).toHaveBeenCalledTimes(2)
    expect(order).toEqual([33, 34])
  })

  it('補跑中途失敗即停，剩下的不繼續送', async () => {
    const wrapper = await mountProgress()

    retryMock.mockRejectedValueOnce(new Error('remote rejected'))
    await wrapper.vm.retryFailed()
    await flushPromises()

    expect(retryMock).toHaveBeenCalledTimes(1)
  })

  it('補跑鈕的文案不把 changed_unverified 說成「失敗」', async () => {
    const wrapper = await mountProgress()

    const label = wrapper.find('[data-test="retry-failed"]').text()
    // 面板同時把 33 標成「已改未驗證」，按鈕再說那是「失敗的」會讓值班人員
    // 推論那台沒被動過，但它的遠端可能已經吃到新秘密
    expect(label).not.toContain('失敗')
    expect(label).toContain('2')
  })

  it('本輪一台都還沒動過時，放棄的後果是整輪作廢而不是標記不同步', async () => {
    getMock.mockResolvedValue({
      data: rotationFixture({
        aggregate_state: 'changing',
        members: [
          memberFixture({ id: 41, account_id: 1, asset_name: 'web-01', state: 'queued' }),
          memberFixture({ id: 42, account_id: 2, asset_name: 'web-02', state: 'queued' }),
        ],
      }),
    })
    const wrapper = await mountProgress()

    expect(wrapper.vm.rotationTouched).toBe(false)
    const hint = wrapper.find('[data-test="abandon-hint"]').text()
    expect(hint).toContain('等於沒發生過')
    expect(hint).toContain('閒置')
    expect(hint).not.toContain('不同步')
  })

  it('輪替警告說的是「目前就位的版本」，不宣稱那一版驗證過', async () => {
    const wrapper = await mountProgress()

    // 就位版本也會由掛載與直接寫入密文這類零遠端寫入的操作改寫，
    // 說成「最後驗證可用的版本」等於宣稱一個系統不提供的保證
    const warning = wrapper.find('[data-test="rotation-warning"]').text()
    expect(warning).toContain('目前就位的版本')
    expect(warning).not.toContain('驗證可用')
  })
})

describe('主機身分變更的成員', () => {
  const STOP = 'CHANGE_SECRET_HOST_IDENTITY_CHANGED'
  const FP = 'SHA256:q3Vt9xLk2mP8rT0aZ4bN7cY1eW6sH5jD'
  const msg = (key, params) => i18n.global.t(key, params)

  const hostIdentity = (over = {}) => ({
    status: 'changed',
    detail: 'generation_changed',
    phase: 'precheck',
    verification_sent: false,
    original: {
      transport: 'ssh', record_id: 41, algorithm: 'ssh-ed25519', fingerprint: FP,
      generation: 2, binding: 'bound', bound_at: '2026-10-17T02:00:00Z',
    },
    current: {
      transport: 'ssh', record_id: 41, algorithm: 'ssh-ed25519', fingerprint: FP,
      generation: 3, reset_pending: false, recorded_at: '2026-10-17T10:05:00Z',
    },
    candidate_applied: false,
    deadline: '2026-10-18T02:00:00Z',
    expired: false,
    confirmable: true,
    ...over,
  })

  const stoppedMember = (over = {}) => memberFixture({
    id: 41, account_id: 1, asset_name: 'web-01', username: 'root',
    state: 'terminal_failed', last_error: STOP, ...over,
  })

  const rotationWith = (members) => rotationFixture({ members })
  const dialogOf = (w) => w.findComponent(HostIdentityConfirmDialog)

  async function openAndConfirm(w, member = stoppedMember()) {
    await w.vm.retryMember(member)
    await flushPromises()
    await w.find('[data-test="hic-check-identity"] input').setValue(true)
    await w.find('[data-test="hic-submit"]').trigger('click')
    await flushPromises()
  }

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('一般重試成員：請求不帶 body', async () => {
    const w = await mountProgress()
    await w.find('[data-test="member-retry-34"]').trigger('click')
    await flushPromises()
    expect(retryMock.mock.calls[0]).toEqual([110, 7, 34])
    expect(dialogOf(w).props('modelValue')).toBe(false)
  })

  it('回應的該成員帶 host_identity：開確認對話框（成員種類），不顯示「已補跑」', async () => {
    const success = vi.spyOn(ElMessage, 'success')
    const m = stoppedMember()
    getMock.mockResolvedValue({ data: rotationWith([m]) })
    const w = await mountProgress()
    retryMock.mockResolvedValue({ data: rotationWith([{ ...m, host_identity: hostIdentity() }]) })
    await w.find('[data-test="member-retry-41"]').trigger('click')
    await flushPromises()
    const dlg = dialogOf(w)
    expect(dlg.props('modelValue')).toBe(true)
    expect(dlg.props('kind')).toBe('member')
    expect(dlg.props('account')).toBe('root')
    expect(dlg.props('asset')).toBe('web-01')
    expect(dlg.props('identity').detail).toBe('generation_changed')
    expect(success).not.toHaveBeenCalled()
  })

  it('確認後帶 body 重送：body 等於 emit payload，鍵集合只含身分欄位，成功後關閉', async () => {
    const success = vi.spyOn(ElMessage, 'success')
    const m = stoppedMember()
    getMock.mockResolvedValue({ data: rotationWith([m]) })
    const w = await mountProgress()
    retryMock.mockReset()
    retryMock
      .mockResolvedValueOnce({ data: rotationWith([{ ...m, host_identity: hostIdentity() }]) })
      .mockResolvedValueOnce({ data: rotationWith([{ ...m, state: 'applied', last_error: undefined }]) })
    await openAndConfirm(w, m)
    expect(retryMock).toHaveBeenCalledTimes(2)
    const emitted = dialogOf(w).emitted('confirm')[0][0]
    const [credId, rotId, memberId, body] = retryMock.mock.calls[1]
    expect([credId, rotId, memberId]).toEqual([110, 7, 41])
    expect(Object.keys(body)).toEqual(['confirm_host_identity'])
    expect(body.confirm_host_identity).toEqual(emitted)
    expect(Object.keys(body.confirm_host_identity).sort()).toEqual(
      ['accept_different_key', 'algorithm', 'fingerprint', 'generation', 'record_id', 'transport'])
    expect(JSON.stringify(body)).not.toMatch(/password|private_key|secret/i)
    expect(success).toHaveBeenCalledWith(msg('hostIdentityConfirm.result.verified'))
    expect(dialogOf(w).props('modelValue')).toBe(false)
  })

  it('確認後驗證沒成功：說新憑證仍保留，不沿用「已補跑」', async () => {
    const success = vi.spyOn(ElMessage, 'success')
    const warning = vi.spyOn(ElMessage, 'warning')
    const m = stoppedMember()
    getMock.mockResolvedValue({ data: rotationWith([m]) })
    const w = await mountProgress()
    retryMock.mockReset()
    retryMock
      .mockResolvedValueOnce({ data: rotationWith([{ ...m, host_identity: hostIdentity() }]) })
      .mockResolvedValueOnce({ data: rotationWith([{ ...m, last_error: 'CHANGE_SECRET_VERIFY_FAILED' }]) })
    await openAndConfirm(w, m)
    expect(success).not.toHaveBeenCalled()
    expect(warning).toHaveBeenCalledWith(msg('hostIdentityConfirm.result.notVerified'))
    expect(dialogOf(w).props('modelValue')).toBe(false)
  })

  it('確認時目標已改變（reason）：顯示該原因碼文案，不算成功', async () => {
    const success = vi.spyOn(ElMessage, 'success')
    const warning = vi.spyOn(ElMessage, 'warning')
    const m = stoppedMember()
    getMock.mockResolvedValue({ data: rotationWith([m]) })
    const w = await mountProgress()
    retryMock.mockReset()
    retryMock
      .mockResolvedValueOnce({ data: rotationWith([{ ...m, host_identity: hostIdentity() }]) })
      .mockResolvedValueOnce({
        data: rotationWith([{ ...m, last_error: 'CHANGE_SECRET_AUTHZ_TARGET_CHANGED' }]),
      })
    await openAndConfirm(w, m)
    expect(warning).toHaveBeenCalledWith(msg('changeSecretPlans.reason.CHANGE_SECRET_AUTHZ_TARGET_CHANGED'))
    expect(success).not.toHaveBeenCalled()
    expect(dialogOf(w).props('modelValue')).toBe(false)
  })

  it.each([
    ['different_key_not_accepted', 'hostIdentityConfirm.differentKey.title'],
    ['not_confirmable', 'hostIdentityConfirm.blocked.contactAdmin'],
    ['confirmation_pending', 'hostIdentityConfirm.result.moved'],
  ])('確認遇 409 CONFLICT_HOST_IDENTITY_MOVED（detail=%s）：顯示對應說明、不算成功、關閉並重新載入', async (detail, key) => {
    const success = vi.spyOn(ElMessage, 'success')
    const error = vi.spyOn(ElMessage, 'error')
    const warning = vi.spyOn(ElMessage, 'warning')
    const m = stoppedMember()
    getMock.mockResolvedValue({ data: rotationWith([m]) })
    const w = await mountProgress()
    retryMock.mockReset()
    retryMock
      .mockResolvedValueOnce({ data: rotationWith([{ ...m, host_identity: hostIdentity() }]) })
      .mockRejectedValueOnce({
        response: { status: 409, data: { code: 'CONFLICT_HOST_IDENTITY_MOVED', detail } },
      })
    getMock.mockClear()
    await openAndConfirm(w, m)
    expect(error).toHaveBeenCalledTimes(1)
    expect(error).toHaveBeenCalledWith(msg(key))
    expect(warning).not.toHaveBeenCalled()
    expect(success).not.toHaveBeenCalled()
    expect(dialogOf(w).props('modelValue')).toBe(false)
    expect(getMock).toHaveBeenCalled()
    expect(i18n.global.te('apiError.CONFLICT_HOST_IDENTITY_MOVED')).toBe(true)
  })

  it('依序補跑：身分停止者不呼叫，回應帶 host_identity 者列入跳過且不中止，結束時列出兩台與原因', async () => {
    const success = vi.spyOn(ElMessage, 'success')
    const warning = vi.spyOn(ElMessage, 'warning')
    const base = [
      stoppedMember({ id: 41, asset_name: 'web-01' }),
      memberFixture({ id: 42, account_id: 2, asset_name: 'web-02', state: 'terminal_failed', last_error: 'CHANGE_SECRET_VERIFY_FAILED' }),
      memberFixture({ id: 43, account_id: 3, asset_name: 'app-01', state: 'changed_unverified' }),
      memberFixture({ id: 44, account_id: 4, asset_name: 'batch-01', state: 'terminal_failed', last_error: 'CHANGE_SECRET_REMOTE_REJECTED' }),
    ]
    getMock.mockResolvedValue({ data: rotationWith(base) })
    const w = await mountProgress()
    const order = []
    retryMock.mockReset()
    retryMock.mockImplementation(async (_c, _r, memberId) => {
      order.push(memberId)
      if (memberId === 42) {
        return { data: rotationWith(base.map((m) => (m.id === 42 ? { ...m, host_identity: hostIdentity() } : m))) }
      }
      return { data: rotationWith(base) }
    })
    await w.vm.retryFailed()
    await flushPromises()
    expect(order).toEqual([42, 43, 44])
    expect(order).not.toContain(41)
    expect(dialogOf(w).props('modelValue')).toBe(false)
    expect(success).not.toHaveBeenCalled()
    // 摘要與逐台訊息不再走會自動消失的 toast，改為常駐面板
    expect(warning).not.toHaveBeenCalled()
    const report = w.find('[data-test="host-identity-skip-report"]')
    expect(report.exists()).toBe(true)
    expect(report.text()).toContain(msg('credentials.rotation.hostIdentitySkipSummary', { done: 2, skipped: 2 }))
    const lines = report.findAll('[data-test="host-identity-skip-line"]').map((l) => l.text())
    expect(lines).toEqual([
      msg('credentials.rotation.hostIdentitySkipStopped', { asset: 'web-01' }),
      msg('credentials.rotation.hostIdentitySkipFoundOnRetry', { asset: 'web-02' }),
    ])
    // 常駐：之後重繪、時間經過都還在；下一次補跑開始才清除
    await new Promise((r) => setTimeout(r, 50))
    await flushPromises()
    expect(w.find('[data-test="host-identity-skip-report"]').exists()).toBe(true)
  })

  it('確認後主機身分又變更（回應帶 host_identity）：紅色 error，不是 warning', async () => {
    const error = vi.spyOn(ElMessage, 'error')
    const warning = vi.spyOn(ElMessage, 'warning')
    const m = stoppedMember()
    getMock.mockResolvedValue({ data: rotationWith([m]) })
    const w = await mountProgress()
    retryMock.mockReset()
    retryMock
      .mockResolvedValueOnce({ data: rotationWith([{ ...m, host_identity: hostIdentity() }]) })
      .mockResolvedValueOnce({ data: rotationWith([{ ...m, host_identity: hostIdentity() }]) })
    await openAndConfirm(w, m)
    expect(error).toHaveBeenCalledWith(msg('hostIdentityConfirm.result.moved'))
    expect(warning).not.toHaveBeenCalled()
  })

  it('依序補跑：跳過後仍遇請求失敗即停', async () => {
    const base = [
      stoppedMember({ id: 41 }),
      memberFixture({ id: 42, account_id: 2, state: 'terminal_failed' }),
      memberFixture({ id: 43, account_id: 3, state: 'terminal_failed' }),
    ]
    getMock.mockResolvedValue({ data: rotationWith(base) })
    const w = await mountProgress()
    retryMock.mockReset()
    retryMock.mockRejectedValueOnce(new Error('remote rejected'))
    await w.vm.retryFailed()
    await flushPromises()
    expect(retryMock).toHaveBeenCalledTimes(1)
    expect(retryMock.mock.calls[0][2]).toBe(42)
  })
})

// 範圍化檢視者：回應只列範圍內成員，另給範圍外台數
describe('範圍外成員的說明與放棄措辭', () => {
  const queued = (id, accountId, name) =>
    memberFixture({ id, account_id: accountId, asset_name: name, state: 'queued' })
  const scoped = (members, count = 3) => rotationFixture({
    aggregate_state: 'changing',
    members,
    out_of_scope_asset_count: count,
  })
  const outOfScope = (w) => w.find('[data-test="rotation-out-of-scope-members"]')

  it('R1 範圍內有已就位與改密中成員：說明行含台數，統計與成員數只算可見的 2 台，放棄提示照舊', async () => {
    getMock.mockResolvedValue({
      data: scoped([
        memberFixture({ id: 41, account_id: 1, asset_name: 'web-01', state: 'applied' }),
        memberFixture({ id: 42, account_id: 2, asset_name: 'web-02', state: 'changing' }),
      ]),
    })
    const w = await mountProgress()

    expect(outOfScope(w).exists()).toBe(true)
    expect(outOfScope(w).text()).toContain('3')
    expect(outOfScope(w).text()).toContain('範圍外')
    expect(w.text()).toContain('成員（2）')
    expect(w.find('[data-test="members-empty"]').exists()).toBe(false)
    const hint = w.find('[data-test="abandon-hint"]').text()
    expect(hint).toBe(i18n.global.t('credentials.rotation.abandonHint'))
    expect(hint).not.toBe(i18n.global.t('credentials.rotation.abandonHintPartial'))
  })

  it('R2 可見成員全在排隊且有範圍外成員：提示改用部分措辭，不斷言尚未改動', async () => {
    getMock.mockResolvedValue({ data: scoped([queued(41, 1, 'web-01'), queued(42, 2, 'web-02')]) })
    const w = await mountProgress()

    const hint = w.find('[data-test="abandon-hint"]').text()
    expect(hint).toBe(i18n.global.t('credentials.rotation.abandonHintPartial'))
    expect(hint).not.toContain('等於沒發生過')
    expect(outOfScope(w).exists()).toBe(true)
  })

  it('R3 同樣狀態下按放棄本輪：確認內文用部分措辭', async () => {
    getMock.mockResolvedValue({ data: scoped([queued(41, 1, 'web-01'), queued(42, 2, 'web-02')]) })
    const confirm = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    const w = await mountProgress()

    await w.find('[data-test="abandon-rotation"]').trigger('click')
    await flushPromises()

    expect(confirm).toHaveBeenCalledTimes(1)
    expect(confirm.mock.calls[0][0]).toBe(i18n.global.t('credentials.rotation.abandonMessagePartial'))
    expect(confirm.mock.calls[0][0]).not.toContain('等於沒發生過')
    confirm.mockRestore()
  })

  it('R4 範圍內成員為零而範圍外有成員：不顯示「沒有成員」，只有說明行與部分措辭', async () => {
    getMock.mockResolvedValue({ data: scoped([], 5) })
    const w = await mountProgress()

    expect(w.find('[data-test="members-empty"]').exists()).toBe(false)
    expect(outOfScope(w).exists()).toBe(true)
    expect(outOfScope(w).text()).toContain('5')
    expect(w.find('[data-test="abandon-hint"]').text())
      .toBe(i18n.global.t('credentials.rotation.abandonHintPartial'))
  })

  it('R5 全域檢視者（回應無此欄）：畫面與現行相同', async () => {
    getMock.mockResolvedValue({
      data: rotationFixture({
        aggregate_state: 'changing',
        members: [queued(41, 1, 'web-01'), queued(42, 2, 'web-02')],
      }),
    })
    const w = await mountProgress()

    expect(outOfScope(w).exists()).toBe(false)
    expect(w.find('[data-test="abandon-hint"]').text())
      .toBe(i18n.global.t('credentials.rotation.abandonHintFresh'))
  })

  it('無成員且無範圍外計數時，仍顯示「沒有成員」', async () => {
    getMock.mockResolvedValue({ data: rotationFixture({ members: [] }) })
    const w = await mountProgress()

    expect(w.find('[data-test="members-empty"]').exists()).toBe(true)
    expect(outOfScope(w).exists()).toBe(false)
  })
})
