// 目錄來源詳情頁把本頁測試連線的結果交給接通前確認面板。
// 守的是「結果綁定送出當下的表單」：測 A 成功後改成 B 再儲存，不得留下 A 的綠燈；
// 較慢回來的舊測試不得蓋掉較新的結果。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import LDAPSourceDetail from '../LDAPSourceDetail.vue'
import SourceDetailLayout from '../components/SourceDetailLayout.vue'
import PreflightPanel from '../components/PreflightPanel.vue'

enableAutoUnmount(afterEach)

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  useRoute: () => ({ params: {} }),
}))

const getMock = vi.fn()
const updateMock = vi.fn()
const testMock = vi.fn()
vi.mock('@/api/ldapDirectory', () => ({
  getLDAPDirectory: (...a) => getMock(...a),
  updateLDAPDirectory: (...a) => updateMock(...a),
  deleteLDAPDirectory: vi.fn(),
  testLDAPDirectory: (...a) => testMock(...a),
}))

vi.mock('@/api/identitySources', () => ({
  getIdentitySources: vi.fn(() => Promise.resolve({ data: [] })),
  getSourceStatus: vi.fn(() => Promise.resolve({ rule_count: 1, enabled_rule_count: 1 })),
  isNotImplemented: () => false,
  errorCode: () => '',
  CODE_LDAP_DIRECTORY_NOT_FOUND: 'LDAP_DIRECTORY_NOT_FOUND',
}))

const view = (url) => ({
  configured: true,
  id: 1,
  name: '公司目錄',
  url,
  bind_dn: 'cn=svc,dc=example,dc=com',
  has_bind_password: true,
  base_dn: 'ou=users,dc=example,dc=com',
  user_filter: '(uid=%s)',
  attr_email: 'mail',
  attr_fullname: 'displayName',
  attr_group: 'memberOf',
  skip_tls_verify: false,
  enabled: true,
})

const OK_RESULT = {
  success: true,
  stages: [
    { stage: 'dial', ok: true },
    { stage: 'bind', ok: true },
    { stage: 'search', ok: true },
  ],
  attr_sample: { sampled: true, group_configured: true, group_present: true },
}

const A = 'ldaps://a.example.com:636'
const B = 'ldaps://b.example.com:636'

const mountPage = async () => {
  const wrapper = mount(LDAPSourceDetail, {
    global: { plugins: [ElementPlus], stubs: { 'router-link': { template: '<a><slot /></a>' } } },
  })
  await flushPromises()
  return wrapper
}

const layout = (w) => w.findComponent(SourceDetailLayout)
const panelLights = (w) => w.findComponent(PreflightPanel).vm.lights
const lightOf = (w, key) => panelLights(w).find((l) => l.key === key)

const deferred = () => {
  let resolve
  const promise = new Promise((r) => {
    resolve = r
  })
  return { promise, resolve }
}

describe('LDAPSourceDetail：面板接本頁測試結果', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getMock.mockResolvedValue(view(A))
  })

  it('測試成功後兩燈為通過並附時間', async () => {
    testMock.mockResolvedValue(OK_RESULT)
    const wrapper = await mountPage()
    layout(wrapper).vm.$emit('test')
    await flushPromises()
    const conn = lightOf(wrapper, 'connection')
    const attr = lightOf(wrapper, 'groupAttr')
    expect([conn.state, attr.state]).toEqual(['ok', 'ok'])
    expect(conn.text.params.time).not.toBe('')
    expect(attr.text.params.attr).toBe('memberOf')
  })

  it('測 A 成功後改成 B 並儲存：兩燈為已過期，且沒有尚未儲存註記', async () => {
    testMock.mockResolvedValue(OK_RESULT)
    updateMock.mockResolvedValue(view(B))
    const wrapper = await mountPage()
    layout(wrapper).vm.$emit('test')
    await flushPromises()
    wrapper.vm.form.url = B
    await flushPromises()
    layout(wrapper).vm.$emit('save', true)
    await flushPromises()
    expect(updateMock).toHaveBeenCalledTimes(1)
    const lights = ['connection', 'groupAttr'].map((k) => lightOf(wrapper, k))
    expect(lights.map((l) => [l.state, l.word])).toEqual([
      ['gray', 'identitySources.preflight.word.expired'],
      ['gray', 'identitySources.preflight.word.expired'],
    ])
    expect(lights.map((l) => l.note ?? null)).toEqual([null, null])
  })

  it('兩次測試的回覆逆序到達時採較新者', async () => {
    const first = deferred()
    const second = deferred()
    testMock.mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise)
    const wrapper = await mountPage()
    layout(wrapper).vm.$emit('test')
    await flushPromises()
    layout(wrapper).vm.$emit('test')
    await flushPromises()
    second.resolve(OK_RESULT)
    await flushPromises()
    first.resolve({ ...OK_RESULT, success: false, stages: [{ stage: 'dial', ok: false }] })
    await flushPromises()
    expect(lightOf(wrapper, 'connection').state).toBe('ok')
  })
})
