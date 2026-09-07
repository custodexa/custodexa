import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import CredentialRotationProgress from '@/components/credential/CredentialRotationProgress.vue'

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

async function mountProgress(props = {}) {
  const wrapper = mount(CredentialRotationProgress, {
    global: { plugins: [ElementPlus] },
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
  visibility = 'visible'
  getMock.mockResolvedValue({ data: rotationFixture() })
  retryMock.mockResolvedValue({ data: rotationFixture() })
  abandonMock.mockResolvedValue({ data: rotationFixture({ status: 'abandoned' }) })
})

afterEach(() => {
  vi.useRealTimers()
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
