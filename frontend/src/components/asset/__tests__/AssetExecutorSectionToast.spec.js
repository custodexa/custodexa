import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessage } from 'element-plus'
import request from '@/api/request'
import AssetExecutorSection from '@/components/asset/AssetExecutorSection.vue'
import { setCapabilitiesForTests, resetCapabilities } from '@/composables/useCapabilities'

// 不替換 @/api/assetExecutor：請求真的走回應攔截器，才證明區塊的錯誤不會在頁頂多跳一則。

enableAutoUnmount(afterEach)

class ObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords() { return [] }
}
vi.stubGlobal('MutationObserver', ObserverStub)
vi.stubGlobal('ResizeObserver', ObserverStub)

const originalAdapter = request.defaults.adapter
let getStatus = 404
let deleteStatus = 409

function fail(config, status, code) {
  const err = new Error('failed')
  err.config = config
  err.isAxiosError = true
  err.response = { status, data: { error: 'x', code }, headers: {}, config }
  return Promise.reject(err)
}

function installAdapter() {
  request.defaults.adapter = (config) => {
    if (config.method === 'get' && config.url === '/assets/5/executor') {
      if (getStatus === 200) {
        return Promise.resolve({
          data: { configured: true, account_id: 7, username: 'cx-exec', secret_type: 'ssh_key', source: 'generate', has_public_key: true, credential: { credential_id: 31 } },
          status: 200, statusText: 'OK', headers: {}, config,
        })
      }
      return fail(config, getStatus, 'NOTFOUND_ASSET')
    }
    if (config.method === 'delete') return fail(config, deleteStatus, 'RULE_CREDENTIAL_ROTATION_ACTIVE')
    return fail(config, 500, 'INTERNAL')
  }
}

const mountSection = () =>
  mount(AssetExecutorSection, {
    global: { plugins: [ElementPlus] },
    props: { assetId: 5, assetName: 'web-01', protocol: 'ssh', windowsFamily: false },
    attachTo: document.body,
  })

beforeEach(() => {
  setCapabilitiesForTests(['asset:executor-manage'])
  installAdapter()
  vi.spyOn(ElMessage, 'error').mockImplementation(() => {})
})
afterEach(() => {
  request.defaults.adapter = originalAdapter
  resetCapabilities()
  vi.restoreAllMocks()
})

describe('ExecutorSectionVisibility (interceptor)', () => {
  it('讀取 404 時區塊不存在且不跳全域訊息', async () => {
    getStatus = 404
    const w = mountSection()
    await flushPromises()
    expect(w.find('[data-test="executor-section"]').exists()).toBe(false)
    expect(ElMessage.error).toHaveBeenCalledTimes(0)
  })

  it('讀取 500 時區塊內有原因句且不跳全域訊息', async () => {
    getStatus = 500
    const w = mountSection()
    await flushPromises()
    expect(w.find('[data-test="executor-load-failed"]').exists()).toBe(true)
    expect(ElMessage.error).toHaveBeenCalledTimes(0)
  })

  it('替身會觸發 toast：不帶 skipErrorToast 的請求跳 1 次', async () => {
    await request({ url: '/assets/5/other', method: 'get' }).catch(() => {})
    expect(ElMessage.error).toHaveBeenCalledTimes(1)
  })
})

describe('ExecutorClear (interceptor)', () => {
  it('清除收到 409 改密中時區塊內句子存在且不跳全域訊息', async () => {
    getStatus = 200
    const w = mountSection()
    await flushPromises()
    await w.get('[data-test="executor-clear"]').trigger('click')
    await w.get('[data-test="executor-clear-confirm-btn"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test="executor-notice-rotation"]').exists()).toBe(true)
    expect(ElMessage.error).toHaveBeenCalledTimes(0)
  })
})
