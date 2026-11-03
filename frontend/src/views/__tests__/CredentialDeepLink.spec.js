import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessage } from 'element-plus'
import request from '@/api/request'
import CredentialLibrary from '@/views/CredentialLibrary.vue'
import { grantFor } from '@/composables/__tests__/capabilityFixtures'

// 憑證庫的 ?credential=<id> 落點。
// 不替換 @/api/credentials：請求真的走回應攔截器，才看得到「404 不另提示」是否成立。

enableAutoUnmount(afterEach)

class ObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords() { return [] }
}
vi.stubGlobal('MutationObserver', ObserverStub)
vi.stubGlobal('ResizeObserver', ObserverStub)

const route = { query: {} }
const replaceMock = vi.fn()
vi.mock('vue-router', () => ({
  useRoute: () => route,
  useRouter: () => ({ replace: (...a) => replaceMock(...a) }),
}))

vi.mock('@/api/assets', () => ({
  getAssetList: vi.fn().mockResolvedValue({ data: [], total: 0 }),
  getAssetGroups: vi.fn().mockResolvedValue({ data: [] }),
}))

const calls = []
let detailStatus = 200
const originalAdapter = request.defaults.adapter

function installAdapter() {
  request.defaults.adapter = (config) => {
    calls.push(config.url)
    if (config.url === '/credentials') {
      return Promise.resolve({ data: { data: [], total: 0 }, status: 200, statusText: 'OK', headers: {}, config })
    }
    if (/^\/credentials\/\d+$/.test(config.url)) {
      if (detailStatus === 200) {
        return Promise.resolve({
          data: { data: { id: 12, name: 'cred-12', scope: 'shared', bindings: [] }, aggregate_state: 'idle' },
          status: 200, statusText: 'OK', headers: {}, config,
        })
      }
      const err = new Error('failed')
      err.config = config
      err.isAxiosError = true
      err.response = { status: detailStatus, data: { error: 'x', code: detailStatus === 404 ? 'NOTFOUND_CREDENTIAL' : 'INTERNAL' }, headers: {}, config }
      return Promise.reject(err)
    }
    return Promise.resolve({ data: { data: [] }, status: 200, statusText: 'OK', headers: {}, config })
  }
}

async function mountPage() {
  const wrapper = mount(CredentialLibrary, { global: { plugins: [ElementPlus] } })
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  grantFor(['admin'])
  calls.length = 0
  detailStatus = 200
  route.query = {}
  replaceMock.mockClear()
  installAdapter()
  vi.spyOn(ElMessage, 'error').mockImplementation(() => {})
})

afterEach(() => {
  request.defaults.adapter = originalAdapter
  vi.restoreAllMocks()
})

describe('CredentialDeepLink', () => {
  it('?credential=12 時以 12 載入詳情並選取，之後清掉參數', async () => {
    route.query = { credential: '12', other: 'keep' }
    const wrapper = await mountPage()
    expect(calls).toContain('/credentials/12')
    expect(wrapper.vm.selectedId).toBe(12)
    expect(replaceMock).toHaveBeenCalledTimes(1)
    expect(replaceMock.mock.calls[0][0].query).toEqual({ other: 'keep' })
  })

  it('詳情 404 時不選取、不跳全域訊息、參數照清', async () => {
    route.query = { credential: '12' }
    detailStatus = 404
    const wrapper = await mountPage()
    expect(wrapper.vm.selectedId).toBeNull()
    expect(ElMessage.error).toHaveBeenCalledTimes(0)
    expect(replaceMock.mock.calls[0][0].query).toEqual({})
  })

  it('詳情 500 時照常提示一次', async () => {
    route.query = { credential: '12' }
    detailStatus = 500
    await mountPage()
    expect(ElMessage.error).toHaveBeenCalledTimes(1)
  })

  it('未帶參數時行為不變：不載入詳情、不改網址', async () => {
    await mountPage()
    expect(calls.some((u) => /^\/credentials\/\d+$/.test(u))).toBe(false)
    expect(replaceMock).not.toHaveBeenCalled()
  })
})
