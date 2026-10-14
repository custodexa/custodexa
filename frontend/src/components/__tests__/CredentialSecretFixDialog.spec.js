import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import i18n from '@/i18n'
import CredentialSecretFixDialog from '@/components/credential/CredentialSecretFixDialog.vue'

// 更正共用憑證登記值的對話框（憑證庫詳情與資產抽屜共用）。
//
// 斷言重心：
//  1. 只更正憑證本身那一種秘密——密碼型只見密碼與確認欄、金鑰型只見私鑰欄，
//     送出內容也只帶那一欄（多帶私鑰會讓密碼型憑證被改判成金鑰型）；
//  2. 空白與兩次不一致擋在送出之前，錯誤貼在對應欄位下方；
//  3. 套用清單逐台列出，從某台開啟時標出「這台」；
//  4. 伺服端說私鑰無法解析時，錯誤掛在私鑰欄、對話框不關、輸入保留。

enableAutoUnmount(afterEach)

class ObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', ObserverStub)
vi.stubGlobal('ResizeObserver', ObserverStub)

const getMock = vi.fn()
const setSecretMock = vi.fn()
vi.mock('@/api/credentials', () => ({
  getCredential: (...a) => getMock(...a),
  setCredentialSecret: (...a) => setSecretMock(...a),
}))

const dialogStub = {
  props: ['modelValue', 'title'],
  template:
    '<div v-if="modelValue" class="dialog-stub"><h2 class="dialog-title">{{ title }}</h2><slot /><slot name="footer" /></div>',
}

const credentialFixture = (overrides = {}) => ({
  id: 12,
  name: 'linux-root',
  scope: 'shared',
  username: 'root',
  secret_type: 'password',
  protocol_family: 'ssh',
  rotation_active: false,
  current_version_no: 3,
  bindings: [
    { account_id: 101, asset_id: 11, asset_name: 'web-01', effective_version_no: 3 },
    { account_id: 102, asset_id: 12, asset_name: 'web-02', effective_version_no: 3 },
    { account_id: 103, asset_id: 13, asset_name: 'db-report-01', effective_version_no: 3 },
  ],
  ...overrides,
})

// 表單在 modelValue 轉為 true 時才重設與取資料，故一律關著掛、再打開
async function mountDialog(props = {}) {
  const wrapper = mount(CredentialSecretFixDialog, {
    global: { plugins: [ElementPlus], stubs: { 'el-dialog': dialogStub } },
    props: { modelValue: false, credentialId: 12, ...props },
  })
  await wrapper.setProps({ modelValue: true })
  await flushPromises()
  return wrapper
}

// el-form-item 的錯誤訊息以去抖動後的狀態渲染（約 100ms），斷言訊息文字前要等過那一段
const waitErrorRender = () => new Promise((resolve) => setTimeout(resolve, 150))

beforeEach(() => {
  vi.clearAllMocks()
  getMock.mockResolvedValue({ data: credentialFixture() })
  setSecretMock.mockResolvedValue({ id: 12 })
})

describe('依秘密型別只顯示一種欄位', () => {
  it('密碼型：密碼與確認欄，沒有私鑰欄；標題與名詞為密碼', async () => {
    const wrapper = await mountDialog({ credential: credentialFixture() })

    expect(wrapper.find('[data-test="secret-fix-password"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="secret-fix-confirm"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="secret-fix-private-key"]').exists()).toBe(false)
    expect(wrapper.find('.dialog-title').text()).toBe('更正登記的密碼')
    expect(wrapper.find('[data-test="secret-fix-info"]').text())
      .toContain('只改平台登記的密碼，主機上的密碼不會變')
  })

  it('金鑰型：只有私鑰欄（無確認欄），標題與名詞為私鑰', async () => {
    const wrapper = await mountDialog({
      credential: credentialFixture({ secret_type: 'ssh_key' }),
    })

    expect(wrapper.find('[data-test="secret-fix-private-key"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="secret-fix-password"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="secret-fix-confirm"]').exists()).toBe(false)
    expect(wrapper.find('.dialog-title').text()).toBe('更正登記的私鑰')
  })
})

describe('送出前的擋與送出內容', () => {
  it('空白不送出，錯誤在密碼欄下方', async () => {
    const wrapper = await mountDialog({ credential: credentialFixture() })

    await wrapper.find('[data-test="secret-fix-submit"]').trigger('click')
    await flushPromises()

    expect(setSecretMock).not.toHaveBeenCalled()
    const item = wrapper.find('[data-test="secret-fix-password-item"]')
    expect(item.classes()).toContain('is-error')
    await waitErrorRender()
    expect(item.find('.el-form-item__error').text()).toBe('請輸入主機上現在的密碼。')
    expect(wrapper.find('[data-test="secret-fix-confirm-item"]').classes()).not.toContain('is-error')
  })

  it('兩次輸入不一致不送出，錯誤在確認欄下方', async () => {
    const wrapper = await mountDialog({ credential: credentialFixture() })

    await wrapper.find('[data-test="secret-fix-password"]').setValue('Right-Pass-1')
    await wrapper.find('[data-test="secret-fix-confirm"]').setValue('Right-Pass-2')
    await wrapper.find('[data-test="secret-fix-submit"]').trigger('click')
    await flushPromises()

    expect(setSecretMock).not.toHaveBeenCalled()
    const item = wrapper.find('[data-test="secret-fix-confirm-item"]')
    expect(item.classes()).toContain('is-error')
    await waitErrorRender()
    expect(item.find('.el-form-item__error').text()).toBe('兩次輸入的密碼不一致，請重新輸入。')
  })

  it('金鑰型空白不送出，錯誤在私鑰欄下方', async () => {
    const wrapper = await mountDialog({
      credential: credentialFixture({ secret_type: 'ssh_key' }),
    })

    await wrapper.find('[data-test="secret-fix-submit"]').trigger('click')
    await flushPromises()

    expect(setSecretMock).not.toHaveBeenCalled()
    const item = wrapper.find('[data-test="secret-fix-key-item"]')
    expect(item.classes()).toContain('is-error')
    await waitErrorRender()
    expect(item.find('.el-form-item__error').text()).toBe('請輸入主機上現在的私鑰。')
  })

  it('密碼型送出只帶 password，成功後關閉並回報台數', async () => {
    const wrapper = await mountDialog({ credential: credentialFixture() })

    await wrapper.find('[data-test="secret-fix-password"]').setValue('Right-Pass-1')
    await wrapper.find('[data-test="secret-fix-confirm"]').setValue('Right-Pass-1')
    expect(wrapper.find('[data-test="secret-fix-submit"]').text()).toBe('儲存並套用到 3 台')
    await wrapper.find('[data-test="secret-fix-submit"]').trigger('click')
    await flushPromises()

    expect(setSecretMock).toHaveBeenCalledTimes(1)
    const [id, body] = setSecretMock.mock.calls[0]
    expect(id).toBe(12)
    expect(body).toEqual({ password: 'Right-Pass-1' })
    expect(wrapper.emitted('update:modelValue').at(-1)).toEqual([false])
    expect(wrapper.emitted('saved')[0][0]).toEqual({ count: 3, noun: '密碼' })
  })

  it('金鑰型送出只帶 private_key', async () => {
    const wrapper = await mountDialog({
      credential: credentialFixture({ secret_type: 'ssh_key' }),
    })

    // 格式由伺服端判定，前端原樣送出：測試值不必是真的私鑰
    const key = 'pasted-key-line-1\npasted-key-line-2'
    await wrapper.find('[data-test="secret-fix-private-key"]').setValue(key)
    await wrapper.find('[data-test="secret-fix-submit"]').trigger('click')
    await flushPromises()

    expect(setSecretMock).toHaveBeenCalledTimes(1)
    expect(setSecretMock.mock.calls[0][1]).toEqual({ private_key: key })
  })

  it('伺服端說私鑰無法解析：錯誤掛在私鑰欄、不出頁頂提示、對話框不關、輸入保留', async () => {
    const err = {
      response: {
        status: 400,
        data: { code: 'VALIDATION_CREDENTIAL_PRIVATE_KEY_INVALID', field: 'private_key' },
      },
    }
    setSecretMock.mockRejectedValue(err)
    const wrapper = await mountDialog({
      credential: credentialFixture({ secret_type: 'ssh_key' }),
    })

    await wrapper.find('[data-test="secret-fix-private-key"]').setValue('not-a-key')
    await wrapper.find('[data-test="secret-fix-submit"]').trigger('click')
    await flushPromises()

    // 頁頂提示由呼叫端的判斷函式關掉，只關這一種錯誤
    const skip = setSecretMock.mock.calls[0][2].skipErrorToast
    expect(skip(err)).toBe(true)
    expect(skip({ response: { status: 409, data: { code: 'RULE_CREDENTIAL_ROTATION_ACTIVE' } } }))
      .toBe(false)

    const item = wrapper.find('[data-test="secret-fix-key-item"]')
    expect(item.classes()).toContain('is-error')
    await waitErrorRender()
    expect(item.find('.el-form-item__error').text()).toContain('私鑰無法辨識')
    expect(wrapper.emitted('update:modelValue')).toBeUndefined()
    expect(wrapper.find('[data-test="secret-fix-private-key"]').element.value).toBe('not-a-key')
  })

  it('關閉即清掉輸入的明文', async () => {
    const wrapper = await mountDialog({ credential: credentialFixture() })

    await wrapper.find('[data-test="secret-fix-password"]').setValue('Right-Pass-1')
    await wrapper.find('[data-test="secret-fix-cancel"]').trigger('click')

    expect(wrapper.vm.form.secret).toBe('')
    expect(wrapper.vm.form.confirm).toBe('')
  })
})

describe('套用清單與改密入口', () => {
  it('未帶詳情時取一次詳情，逐台列出並在這台旁標示', async () => {
    const wrapper = await mountDialog({ currentAssetId: 12 })

    expect(getMock).toHaveBeenCalledWith(12)
    const apply = wrapper.find('[data-test="secret-fix-apply"]')
    expect(apply.text()).toContain('儲存後立即套用到 3 台資產')
    for (const name of ['web-01', 'web-02', 'db-report-01']) {
      expect(apply.text()).toContain(name)
    }
    const marks = wrapper.findAll('[data-test="secret-fix-this-asset"]')
    expect(marks).toHaveLength(1)
    expect(wrapper.find('[data-test="secret-fix-asset-12"]').text()).toContain('（這台）')
    expect(wrapper.find('[data-test="secret-fix-asset-11"]').text()).not.toContain('這台')
  })

  it('取詳情失敗時就地說明且主鈕停用', async () => {
    getMock.mockRejectedValue({ response: { status: 404, data: { code: 'NOTFOUND_CREDENTIAL' } } })
    const wrapper = await mountDialog({ currentAssetId: 12 })

    expect(wrapper.find('[data-test="secret-fix-load-error"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="secret-fix-submit"]').attributes('disabled')).toBeDefined()
  })

  it('能就地改密時給連結，否則改為到憑證庫操作的說明', async () => {
    const withLink = await mountDialog({ credential: credentialFixture(), rotateAvailable: true })
    await withLink.find('[data-test="secret-fix-rotate-link"]').trigger('click')
    expect(withLink.emitted('rotate')).toHaveLength(1)
    expect(withLink.emitted('update:modelValue').at(-1)).toEqual([false])

    const withoutLink = await mountDialog({ credential: credentialFixture() })
    expect(withoutLink.find('[data-test="secret-fix-rotate-link"]').exists()).toBe(false)
    expect(withoutLink.find('[data-test="secret-fix-rotate-hint"]').text()).toContain('帳號憑證庫')
  })

  it('零掛載：不顯示改密導引，套用段與主鈕不寫 0 台', async () => {
    const wrapper = await mountDialog({
      credential: credentialFixture({ bindings: [] }),
      rotateAvailable: true,
    })
    expect(wrapper.find('[data-test="secret-fix-rotate-hint"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="secret-fix-rotate-link"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="secret-fix-apply"]').text()).not.toContain('0')
    expect(wrapper.find('[data-test="secret-fix-apply"]').text()).toContain('目前沒有掛載的資產')
    expect(wrapper.find('[data-test="secret-fix-submit"]').text()).toBe('儲存')
  })

  it('en-US 主鈕帶 asset(s) 名詞', async () => {
    i18n.global.locale.value = 'en-US'
    const wrapper = await mountDialog({ credential: credentialFixture() })
    expect(wrapper.find('[data-test="secret-fix-submit"]').text()).toBe('Save and apply to 3 asset(s)')
  })
})
