import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessage } from 'element-plus'
import Unseal from '../Unseal.vue'
import { SUPPORTED_LOCALES, LOCALE_LABELS } from '@/i18n'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積會使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅，故以 enableAutoUnmount(afterEach) 確保
// 每測結束卸載元件。
enableAutoUnmount(afterEach)

// 封存期解封頁：三步（驗證身分→核對保管處→提供憑證）與全新安裝四步。
// **秘密欄位在帳密驗證通過之前一律不渲染**，這條在多處各自被斷言——
// 它是本頁最貴的性質，只靠一條測試盯著等於沒盯。

const getSealStatusMock = vi.fn()
const sealAuthorizeMock = vi.fn()
const unsealMock = vi.fn()
const routerPushMock = vi.fn()

vi.mock('@/api/seal', () => ({
  getSealStatus: (...args) => getSealStatusMock(...args),
  sealAuthorize: (...args) => sealAuthorizeMock(...args),
  unseal: (...args) => unsealMock(...args),
}))

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: routerPushMock }),
}))

const VALID_KEK = 'NEWKEK1234567890abcdefABCDEF0000'
const GRANT = 'grant-token-abc'
const DIGEST = 'a'.repeat(64)

const statusFixture = (overrides = {}) => ({
  state: 'sealed',
  mode: 'ui',
  generation: 0,
  cleanup_pending: false,
  journal_faulted: false,
  timeout_total: 0,
  trusted_proxy: false,
  source_restricted: false,
  initialization_required: false,
  authorization_required: true,
  ...overrides,
})

const vaultTopology = (overrides = {}) => ({
  provider: 'vault',
  configured: true,
  address: 'https://vault.corp.example:8200',
  transit_key_name: 'custodexa-kek',
  role_id: 'role-custodexa-operations',
  region: '',
  key_ref: 'transit/custodexa-kek',
  digest: DIGEST,
  ...overrides,
})

const delegatedStatus = (form = 'vault', topology = vaultTopology(), overrides = {}) =>
  statusFixture({ mode: 'kms', credential_form: form, topology, ...overrides })

const findButton = (wrapper, text) =>
  wrapper.findAll('button').find((b) => b.text().includes(text))

const mountPage = async () => {
  const wrapper = mount(Unseal, { global: { plugins: [ElementPlus] } })
  await flushPromises()
  return wrapper
}

const materialInputs = (wrapper) => wrapper.findAll('.material-input input')
const adminInputs = (wrapper) => wrapper.findAll('.admin-input input')
const secretInputs = (wrapper) => wrapper.findAll('.secret-input input')

// 任何「不得出現秘密欄」的斷言都打這一條：類名分散時漏掉一種即為假綠
const anySecretField = (wrapper) =>
  wrapper.findAll('.secret-input input').length +
  wrapper.findAll('.material-input input').length +
  wrapper.findAll('.gcp-input').length

// 元件狀態快照（秘密清除的斷言打在狀態本體，不只是「畫面看不到」）。
// setup scope 內含 timer handle，其物件圖有環，故序列化時丟棄重複參考
const setupStateDump = (wrapper) => {
  const seen = new WeakSet()
  return JSON.stringify(
    Object.entries(wrapper.vm.$ ? wrapper.vm.$.setupState || {} : {}).map(
      ([, v]) => (v && v.value) ?? v
    ),
    (_key, value) => {
      if (typeof value === 'object' && value !== null) {
        if (seen.has(value)) return undefined
        seen.add(value)
      }
      return value
    }
  )
}

// 走完帳密驗證（既有部署三步的第一步）
const verify = async (wrapper, user = 'admin', pw = 'pw-12345678') => {
  const [username, password] = adminInputs(wrapper)
  await username.setValue(user)
  await password.setValue(pw)
  await findButton(wrapper, '驗證身分').trigger('click')
  await flushPromises()
}

// 走完核對保管處（第二步）
const review = async (wrapper) => {
  await findButton(wrapper, '相符，下一步').trigger('click')
  await flushPromises()
}

describe('Unseal 狀態呈現（四態）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    sealAuthorizeMock.mockResolvedValue({ grant: GRANT, topology_digest: DIGEST })
  })

  it.each([
    ['sealed', '已封存'],
    ['unsealing', '解封中'],
    ['unsealed', '已解封'],
    ['sealed-faulted', '已封存（故障）'],
  ])('state=%s 顯示對應徽章', async (state, label) => {
    getSealStatusMock.mockResolvedValue(statusFixture({ state, generation: 3 }))
    const wrapper = await mountPage()

    const badge = wrapper.findComponent({ name: 'ElTag' })
    expect(badge.text()).toBe(label)
    expect(wrapper.text()).toContain('解封世代：3')
  })

  it('已解封時不再提供解封表單，改導向登入', async () => {
    getSealStatusMock.mockResolvedValue(statusFixture({ state: 'unsealed' }))
    const wrapper = await mountPage()

    expect(wrapper.text()).toContain('系統已解封，服務已上線')
    expect(anySecretField(wrapper)).toBe(0)
    await findButton(wrapper, '前往登入').trigger('click')
    expect(routerPushMock).toHaveBeenCalledWith('/login')
  })

  it('故障機器碼、稽核不可寫與待釋放各自呈現', async () => {
    getSealStatusMock.mockResolvedValue(
      statusFixture({
        state: 'sealed-faulted',
        fault_code: 'SEAL_INIT_FAILED',
        journal_faulted: true,
        cleanup_pending: true,
        cleanup_generation: 4,
        cleanup_reason: 'stage2-timeout',
        cleanup_started_at: '2026-08-02T00:00:00Z',
      })
    )
    const wrapper = await mountPage()

    expect(wrapper.text()).toContain('金鑰是對的，但服務初始化失敗')
    expect(wrapper.text()).toContain('無法寫入稽核紀錄，已暫停受理解封')
    const notes = wrapper.findAll('.status-message-note').map((n) => n.text())
    expect(notes.some((n) => n.includes('第 4 世代'))).toBe(true)
  })

  it('狀態讀取失敗：明示讀不到，不假裝已解封', async () => {
    getSealStatusMock.mockRejectedValue({
      response: { status: 500, data: { code: 'SEAL_STATUS_UNAVAILABLE' } },
    })
    const wrapper = await mountPage()

    expect(wrapper.text()).toContain('讀不到封存狀態')
    expect(wrapper.text()).not.toContain('系統已解封，服務已上線')
  })
})

describe('Unseal 阻擋頁（狀態未知）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('狀態未帶路徑判定：阻擋並要求重新查詢，不呈現任何秘密欄、也不給手動切換', async () => {
    const status = statusFixture()
    delete status.initialization_required
    getSealStatusMock.mockResolvedValue(status)
    const wrapper = await mountPage()

    expect(wrapper.find('.blocked-board').exists()).toBe(true)
    expect(wrapper.text()).toContain('還不能開始：讀不到這套系統的狀態')
    expect(anySecretField(wrapper)).toBe(0)
    expect(adminInputs(wrapper)).toHaveLength(0)
    // 舊版的「路徑未知時手動切」入口已移除：猜錯路徑＝把憑證交給判斷錯誤的流程
    expect(findButton(wrapper, '切換至初始化解封')).toBeUndefined()

    const before = getSealStatusMock.mock.calls.length
    await findButton(wrapper, '重新查詢狀態').trigger('click')
    await flushPromises()
    expect(getSealStatusMock.mock.calls.length).toBe(before + 1)
  })
})

describe('Unseal 既有部署三步', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    sealAuthorizeMock.mockResolvedValue({ grant: GRANT, topology_digest: DIGEST })
    getSealStatusMock.mockResolvedValue(delegatedStatus())
  })

  it('三步的步驟列為驗證身分、核對保管處、提供憑證', async () => {
    const wrapper = await mountPage()
    expect(wrapper.findAll('.step-rail-item').map((i) => i.text())).toEqual([
      '1驗證身分',
      '2核對保管處',
      '3提供憑證',
    ])
  })

  it('未驗證前只有帳密欄：無秘密欄、也不顯示保管處核對', async () => {
    const wrapper = await mountPage()

    expect(adminInputs(wrapper)).toHaveLength(2)
    expect(anySecretField(wrapper)).toBe(0)
    expect(wrapper.find('.review-section').exists()).toBe(false)
    expect(wrapper.find('.credentials-section').exists()).toBe(false)
  })

  it('驗證通過後進核對步驟：唯讀顯示保管處、位址、角色與金鑰，仍無秘密欄', async () => {
    const wrapper = await mountPage()
    await verify(wrapper)

    expect(sealAuthorizeMock).toHaveBeenCalledWith(
      { username: 'admin', password: 'pw-12345678' },
      { skipErrorToast: true }
    )
    expect(wrapper.find('.review-section').exists()).toBe(true)
    const card = wrapper.find('.topology-card').text()
    expect(card).toContain('HashiCorp Vault')
    expect(card).toContain('https://vault.corp.example:8200')
    expect(card).toContain('role-custodexa-operations')
    expect(card).toContain('transit/custodexa-kek')
    expect(anySecretField(wrapper)).toBe(0)
  })

  it('顯式確認相符後才進憑證步驟', async () => {
    const wrapper = await mountPage()
    await verify(wrapper)
    expect(secretInputs(wrapper)).toHaveLength(0)

    await review(wrapper)
    expect(wrapper.find('.credentials-section').exists()).toBe(true)
    expect(secretInputs(wrapper)).toHaveLength(1)
  })

  it('帳密錯誤：不進核對步驟，訊息走共用查譯（不可區分）', async () => {
    const errorSpy = vi.spyOn(ElMessage, 'error')
    sealAuthorizeMock.mockRejectedValue({
      response: { status: 401, data: { code: 'SEAL_AUTHORIZE_REJECTED' } },
    })
    const wrapper = await mountPage()
    await verify(wrapper)

    expect(errorSpy.mock.calls[0][0]).toContain('帳號或密碼不正確')
    expect(wrapper.find('.review-section').exists()).toBe(false)
    expect(anySecretField(wrapper)).toBe(0)
  })

  it('選「不相符」進停止頁：無秘密欄、無改位址控制項', async () => {
    const wrapper = await mountPage()
    await verify(wrapper)
    await findButton(wrapper, '不相符，先停止').trigger('click')
    await flushPromises()

    expect(wrapper.find('.stop-board').exists()).toBe(true)
    expect(wrapper.text()).toContain('已停止，先不要送出憑證')
    expect(anySecretField(wrapper)).toBe(0)
    // 停止頁不得有任何輸入控制項（改位址的捷徑即由此排除）
    expect(wrapper.findAll('.stop-board input')).toHaveLength(0)
    expect(wrapper.find('.stop-board .topo-input').exists()).toBe(false)

    await findButton(wrapper, '回上一步重新核對').trigger('click')
    await flushPromises()
    expect(wrapper.find('.review-section').exists()).toBe(true)
  })

  it('返回核對會清掉已輸入的秘密', async () => {
    const wrapper = await mountPage()
    await verify(wrapper)
    await review(wrapper)
    await secretInputs(wrapper)[0].setValue('secret-id-value')
    await flushPromises()
    expect(setupStateDump(wrapper)).toContain('secret-id-value')

    await findButton(wrapper, '返回核對').trigger('click')
    await flushPromises()

    expect(setupStateDump(wrapper)).not.toContain('secret-id-value')
    expect(wrapper.find('.review-section').exists()).toBe(true)
  })

  it('核對後拓撲被改：退回核對步驟並提示重新核對', async () => {
    const wrapper = await mountPage()
    await verify(wrapper)
    await review(wrapper)
    expect(wrapper.find('.credentials-section').exists()).toBe(true)

    getSealStatusMock.mockResolvedValue(
      delegatedStatus('vault', vaultTopology({ address: 'https://other.example:8200', digest: 'b'.repeat(64) }))
    )
    await wrapper.vm.loadStatus()
    await flushPromises()

    expect(wrapper.find('.credentials-section').exists()).toBe(false)
    expect(wrapper.find('.review-section').exists()).toBe(true)
    expect(wrapper.text()).toContain('保管處設定在你核對之後被改過')
  })
})

describe('Unseal 憑證輸入（三家）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    sealAuthorizeMock.mockResolvedValue({ grant: GRANT, topology_digest: DIGEST })
    unsealMock.mockResolvedValue({ state: 'unsealed', generation: 2 })
  })

  const toCredentials = async (form, topology) => {
    getSealStatusMock.mockResolvedValue(delegatedStatus(form, topology))
    const wrapper = await mountPage()
    await verify(wrapper)
    await review(wrapper)
    return wrapper
  }

  it('AWS：兩欄皆遮蔽，送出精確鍵集並帶授權脈絡', async () => {
    const wrapper = await toCredentials(
      'aws',
      vaultTopology({ provider: 'aws', address: '', role_id: '', region: 'ap-northeast-1', key_ref: 'alias/custodexa-kek' })
    )

    const inputs = secretInputs(wrapper)
    expect(inputs).toHaveLength(2)
    for (const input of inputs) expect(input.attributes('type')).toBe('password')
    await inputs[0].setValue('AKIAEXAMPLE')
    await inputs[1].setValue('secret-access-key')
    await flushPromises()

    await findButton(wrapper, '連線保管處並解封').trigger('click')
    await flushPromises()

    expect(unsealMock).toHaveBeenCalledWith(
      {
        access_key_id: 'AKIAEXAMPLE',
        secret_access_key: 'secret-access-key',
        topology_digest: DIGEST,
      },
      { grant: GRANT, skipErrorToast: true }
    )
  })

  it('GCP：只顯示大小、不回顯內容，送出單鍵', async () => {
    const wrapper = await toCredentials(
      'gcp',
      vaultTopology({ provider: 'gcp', address: '', role_id: '', transit_key_name: '', key_ref: 'projects/p/locations/l/keyRings/r/cryptoKeys/k' })
    )

    const box = wrapper.find('.gcp-input')
    expect(box.exists()).toBe(true)
    const json = `{"type":"service_account","private_key":"${'x'.repeat(100)}"}`
    box.element.value = json
    await box.trigger('input')
    await flushPromises()

    // 節點上不留內容：只報大小
    expect(box.element.value).toBe('')
    expect(wrapper.find('.gcp-size').text()).toContain('已貼上')
    expect(wrapper.html()).not.toContain('private_key')

    await findButton(wrapper, '連線保管處並解封').trigger('click')
    await flushPromises()

    expect(unsealMock).toHaveBeenCalledWith(
      { service_account_json: json, topology_digest: DIGEST },
      { grant: GRANT, skipErrorToast: true }
    )
  })

  it('Vault：兩種方式互斥，切換即清空前一種，送出只含其中一種', async () => {
    const wrapper = await toCredentials('vault', vaultTopology())

    await secretInputs(wrapper)[0].setValue('secret-id-value')
    await flushPromises()
    expect(setupStateDump(wrapper)).toContain('secret-id-value')

    const group = wrapper.findComponent({ name: 'ElRadioGroup' })
    group.vm.$emit('update:modelValue', 'token')
    group.vm.$emit('change', 'token')
    await flushPromises()

    expect(setupStateDump(wrapper)).not.toContain('secret-id-value')
    await secretInputs(wrapper)[0].setValue('token-value')
    await flushPromises()

    await findButton(wrapper, '連線保管處並解封').trigger('click')
    await flushPromises()

    expect(unsealMock).toHaveBeenCalledWith(
      { vault_token: 'token-value', topology_digest: DIGEST },
      { grant: GRANT, skipErrorToast: true }
    )
    expect(Object.keys(unsealMock.mock.calls[0][0]).sort()).toEqual([
      'topology_digest',
      'vault_token',
    ])
  })

  it('送出後秘密即清空（成敗皆清）', async () => {
    unsealMock.mockRejectedValue({
      response: { status: 400, data: { code: 'SEAL_MATERIAL_INVALID' } },
    })
    getSealStatusMock.mockResolvedValue(delegatedStatus())
    const wrapper = await toCredentials('vault', vaultTopology())

    await secretInputs(wrapper)[0].setValue('secret-id-value')
    await flushPromises()
    expect(setupStateDump(wrapper)).toContain('secret-id-value')

    await findButton(wrapper, '連線保管處並解封').trigger('click')
    await flushPromises()

    expect(setupStateDump(wrapper)).not.toContain('secret-id-value')
  })

  it('憑證步驟不提供生成指令（憑證由外部簽發）', async () => {
    const wrapper = await toCredentials('vault', vaultTopology())
    expect(wrapper.find('.format-details-toggle').exists()).toBe(false)
    expect(wrapper.find('.credentials-section').text()).toContain('本系統不提供產生方式')
  })
})

describe('Unseal 結果四態', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    sealAuthorizeMock.mockResolvedValue({ grant: GRANT, topology_digest: DIGEST })
    getSealStatusMock.mockResolvedValue(delegatedStatus())
  })

  const submitCredential = async (wrapper) => {
    await secretInputs(wrapper)[0].setValue('secret-id-value')
    await flushPromises()
    await findButton(wrapper, '連線保管處並解封').trigger('click')
    await flushPromises()
  }

  const toCredentials = async () => {
    const wrapper = await mountPage()
    await verify(wrapper)
    await review(wrapper)
    return wrapper
  }

  it.each([
    ['SEAL_CUSTODY_UNREACHABLE', 502, '連不上保管處'],
    ['SEAL_CREDENTIAL_REJECTED', 400, '保管處拒絕這份憑證'],
    ['SEAL_KEY_MISMATCH', 400, '保管處回應的金鑰與本部署不符'],
  ])('驗證後的失敗 %s 可區分並可重新輸入', async (code, httpStatus, title) => {
    unsealMock.mockRejectedValue({ response: { status: httpStatus, data: { code } } })
    const wrapper = await toCredentials()
    await submitCredential(wrapper)

    expect(wrapper.find('.failure-board').exists()).toBe(true)
    expect(wrapper.find('.failure-title').text()).toBe(title)
    // 失敗板不重呈秘密欄，要按「重新輸入憑證」才回到表單
    expect(anySecretField(wrapper)).toBe(0)

    await findButton(wrapper, '重新輸入憑證').trigger('click')
    await flushPromises()
    expect(wrapper.find('.credentials-section').exists()).toBe(true)
  })

  it('逾時：不重呈秘密表單，改為查詢最新狀態', async () => {
    unsealMock.mockRejectedValue({
      response: { status: 504, data: { code: 'SEAL_STAGE2_TIMEOUT' } },
    })
    const wrapper = await toCredentials()
    await submitCredential(wrapper)

    expect(wrapper.find('.timeout-board').exists()).toBe(true)
    expect(anySecretField(wrapper)).toBe(0)
    expect(findButton(wrapper, '重新提供憑證')).toBeUndefined()
  })

  it.each([
    [
      { cleanup_pending: false },
      '系統仍為已封存',
      true,
    ],
    [
      { cleanup_pending: true },
      '系統仍在釋放上一次解封的資源',
      false,
    ],
    // 查到已解封時，權威狀態直接把畫面換成成功板——這比在逾時板上寫一句
    // 「已解封」更強：該狀態下沒有任何可再送出的表單
    [
      { state: 'unsealed' },
      '系統已解封，服務已上線',
      false,
    ],
  ])('逾時後查狀態：%o 給出對應的下一步', async (overrides, text, canRetry) => {
    unsealMock.mockRejectedValue({
      response: { status: 504, data: { code: 'SEAL_STAGE2_TIMEOUT' } },
    })
    const wrapper = await toCredentials()
    await submitCredential(wrapper)

    getSealStatusMock.mockResolvedValue(delegatedStatus('vault', vaultTopology(), overrides))
    await findButton(wrapper, '查詢最新狀態').trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain(text)
    expect(!!findButton(wrapper, '重新提供憑證')).toBe(canRetry)
    if (canRetry) {
      await findButton(wrapper, '重新提供憑證').trigger('click')
      await flushPromises()
      expect(wrapper.find('.credentials-section').exists()).toBe(true)
    }
  })

  it('冷卻中：暫停接受輸入，顯示倒數而非表單', async () => {
    getSealStatusMock.mockResolvedValue(
      delegatedStatus('vault', vaultTopology(), {
        cooldown_until: new Date(Date.now() + 90_000).toISOString(),
      })
    )
    const wrapper = await mountPage()

    expect(wrapper.find('.cooldown-board').exists()).toBe(true)
    expect(wrapper.text()).toMatch(/還有 01:(29|30) 可再試/)
    expect(anySecretField(wrapper)).toBe(0)
    expect(adminInputs(wrapper)).toHaveLength(0)
  })
})

describe('Unseal 全新安裝四步', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    sealAuthorizeMock.mockResolvedValue({ grant: GRANT, topology_digest: '' })
    unsealMock.mockResolvedValue({ state: 'unsealed', generation: 1 })
    getSealStatusMock.mockResolvedValue(
      delegatedStatus('vault', vaultTopology({ configured: false, address: '', transit_key_name: '', role_id: '', key_ref: '' }), {
        initialization_required: true,
      })
    )
  })

  it('步驟列為四步，第一步是初始管理者驗證', async () => {
    const wrapper = await mountPage()

    expect(wrapper.findAll('.step-rail-item').map((i) => i.text())).toEqual([
      '1初始管理者驗證',
      '2設定保管處',
      '3提供憑證',
      '4建立金鑰並啟用',
    ])
    expect(wrapper.find('.create-admin-section').exists()).toBe(true)
    expect(findButton(wrapper, '驗證身分')).toBeUndefined()
    expect(anySecretField(wrapper)).toBe(0)
  })

  it('四步走完後一次送出：初始管理員、拓撲與憑證同一請求', async () => {
    const wrapper = await mountPage()

    const [user, pw] = adminInputs(wrapper)
    await user.setValue('admin')
    await pw.setValue('pw-12345678')
    await findButton(wrapper, '下一步').trigger('click')
    await flushPromises()

    // 第 2 步：拓撲（服務商唯讀，不提供切換）
    expect(wrapper.find('.topology-section').exists()).toBe(true)
    const topoInputs = wrapper.findAll('.topo-input input')
    expect(topoInputs).toHaveLength(3)
    await topoInputs[0].setValue('https://vault.corp.example:8200')
    await topoInputs[1].setValue('custodexa-kek')
    await topoInputs[2].setValue('role-custodexa-operations')
    await findButton(wrapper, '下一步').trigger('click')
    await flushPromises()

    // 第 3 步：憑證
    expect(wrapper.find('.credentials-section').exists()).toBe(true)
    await secretInputs(wrapper)[0].setValue('secret-id-value')
    await findButton(wrapper, '下一步').trigger('click')
    await flushPromises()

    // 第 4 步：建立金鑰並啟用
    expect(wrapper.find('.activate-section').exists()).toBe(true)
    expect(wrapper.text()).toContain('初始管理員：admin')
    await findButton(wrapper, '建立金鑰並啟用').trigger('click')
    await flushPromises()

    expect(unsealMock).toHaveBeenCalledWith(
      {
        username: 'admin',
        password: 'pw-12345678',
        address: 'https://vault.corp.example:8200',
        transit_key_name: 'custodexa-kek',
        role_id: 'role-custodexa-operations',
        vault_secret_id: 'secret-id-value',
      },
      { grant: GRANT, skipErrorToast: true }
    )
  })

  it('第 1 步即以初始管理員帳密換授權脈絡，其後三步帶著它走', async () => {
    const wrapper = await mountPage()

    const [user, pw] = adminInputs(wrapper)
    await user.setValue('admin')
    await pw.setValue('pw-12345678')
    await findButton(wrapper, '下一步').trigger('click')
    await flushPromises()

    expect(sealAuthorizeMock).toHaveBeenCalledWith(
      { username: 'admin', password: 'pw-12345678' },
      { skipErrorToast: true }
    )
    expect(wrapper.vm.grant).toBe(GRANT)
    expect(wrapper.find('.topology-section').exists()).toBe(true)
  })

  it('帳密未過即停在第 1 步：不前進、不取得脈絡、不渲染任何秘密欄', async () => {
    sealAuthorizeMock.mockRejectedValue({
      response: { status: 401, data: { code: 'SEAL_AUTHORIZE_REJECTED' } },
    })
    const wrapper = await mountPage()

    const [user, pw] = adminInputs(wrapper)
    await user.setValue('admin')
    await pw.setValue('wrong-password')
    await findButton(wrapper, '下一步').trigger('click')
    await flushPromises()

    expect(wrapper.vm.grant).toBe('')
    expect(wrapper.find('.create-admin-section').exists()).toBe(true)
    expect(wrapper.find('.topology-section').exists()).toBe(false)
    expect(anySecretField(wrapper)).toBe(0)
    expect(unsealMock).not.toHaveBeenCalled()
  })

  it('上一步可回頭，且第 4 步之前不會送出任何請求', async () => {
    const wrapper = await mountPage()
    const [user, pw] = adminInputs(wrapper)
    await user.setValue('admin')
    await pw.setValue('pw-12345678')
    await findButton(wrapper, '下一步').trigger('click')
    await flushPromises()

    await findButton(wrapper, '上一步').trigger('click')
    await flushPromises()

    expect(wrapper.find('.create-admin-section').exists()).toBe(true)
    expect(unsealMock).not.toHaveBeenCalled()
  })
})

describe('Unseal 本地模式（ui）與部署來源模式（env）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    sealAuthorizeMock.mockResolvedValue({ grant: GRANT })
    unsealMock.mockResolvedValue({ state: 'unsealed', generation: 1 })
  })

  it('ui 一般解封：驗證身分後才出現金鑰欄，只送 kek 一鍵', async () => {
    getSealStatusMock.mockResolvedValue(statusFixture())
    const wrapper = await mountPage()

    expect(materialInputs(wrapper)).toHaveLength(0)
    await verify(wrapper)
    expect(materialInputs(wrapper)).toHaveLength(1)

    await materialInputs(wrapper)[0].setValue(VALID_KEK)
    await flushPromises()
    await findButton(wrapper, '送出解封').trigger('click')
    await flushPromises()

    expect(unsealMock).toHaveBeenCalledWith(
      { kek: VALID_KEK },
      { grant: GRANT, skipErrorToast: true }
    )
  })

  it('ui 全新安裝：建立管理員後填金鑰，送出逐字確認與保存確認', async () => {
    getSealStatusMock.mockResolvedValue(statusFixture({ initialization_required: true }))
    const wrapper = await mountPage()

    const [user, pw] = adminInputs(wrapper)
    await user.setValue('admin')
    await pw.setValue('pw-12345678')
    await findButton(wrapper, '下一步').trigger('click')
    await flushPromises()

    const [key, confirm] = materialInputs(wrapper)
    await key.setValue(VALID_KEK)
    await confirm.setValue(VALID_KEK)
    const checkbox = wrapper
      .findAllComponents({ name: 'ElCheckbox' })
      .find((c) => c.text().includes('我已經把主金鑰存到'))
    await checkbox.find('input').setValue(true)
    await flushPromises()

    await findButton(wrapper, '送出解封').trigger('click')
    await flushPromises()

    expect(unsealMock).toHaveBeenCalledWith(
      {
        kek: VALID_KEK,
        kek_confirm: VALID_KEK,
        confirm_saved: true,
        username: 'admin',
        password: 'pw-12345678',
      },
      { grant: GRANT, skipErrorToast: true }
    )
  })

  it('env：驗證身分後只有重讀動作，送空物件且無任何輸入欄', async () => {
    getSealStatusMock.mockResolvedValue(statusFixture({ mode: 'env' }))
    const wrapper = await mountPage()
    await verify(wrapper)

    expect(wrapper.find('.env-section').exists()).toBe(true)
    expect(anySecretField(wrapper)).toBe(0)

    await findButton(wrapper, '重新讀取並解封').trigger('click')
    await flushPromises()

    expect(unsealMock).toHaveBeenCalledWith({}, { grant: GRANT, skipErrorToast: true })
  })

  it('ui 一般解封不套格式檢查（既有金鑰可能早於格式規則）', async () => {
    getSealStatusMock.mockResolvedValue(statusFixture())
    const wrapper = await mountPage()
    await verify(wrapper)

    await materialInputs(wrapper)[0].setValue('short')
    await flushPromises()
    expect(wrapper.text()).not.toContain('這不是 32 位元組的金鑰')
    expect(findButton(wrapper, '送出解封').attributes('disabled')).toBeUndefined()
  })

  it('卸載時清除秘密（離開頁面不留殘值）', async () => {
    getSealStatusMock.mockResolvedValue(statusFixture())
    const wrapper = await mountPage()
    await verify(wrapper)
    await materialInputs(wrapper)[0].setValue(VALID_KEK)
    await flushPromises()
    const vm = wrapper.vm
    expect(setupStateDump(wrapper)).toContain(VALID_KEK)

    wrapper.unmount()

    const leaked = JSON.stringify(
      Object.entries(vm.$ ? vm.$.setupState || {} : {}).map(([, v]) => (v && v.value) ?? v)
    )
    expect(leaked).not.toContain(VALID_KEK)
    expect(leaked).not.toContain(GRANT)
  })
})

// —— 封存期語言切換（i18n「Language selectable while sealed」）——
describe('Unseal 語言切換', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    getSealStatusMock.mockResolvedValue(statusFixture())
  })

  const langDropdown = (wrapper) =>
    wrapper
      .findAllComponents({ name: 'ElDropdown' })
      .find((d) => d.find('.lang-switch-label').exists())

  it('解封頁具語言切換入口，且以當前語言的原生名顯示', async () => {
    const wrapper = await mountPage()

    expect(langDropdown(wrapper), '解封頁應有語言切換入口').toBeTruthy()
    expect(wrapper.find('.lang-switch').text()).toContain(LOCALE_LABELS['zh-TW'])
  })

  it.each([
    ['en-US', 'Unseal the System', 'Lose the master key and all data is gone for good'],
    ['ja-JP', 'システムのアンシール', 'マスター鍵を失うと、全データは永久に戻りません'],
  ])('切到 %s：頁面主體文字即時改語言並寫入 ot-lang', async (lang, title, loss) => {
    const wrapper = await mountPage()
    expect(wrapper.find('.unseal-title').text()).toBe('系統解封')

    langDropdown(wrapper).vm.$emit('command', lang)
    await wrapper.vm.$nextTick()

    expect(wrapper.find('.unseal-title').text()).toBe(title)
    expect(wrapper.find('.loss-title').text()).toBe(loss)
    expect(localStorage.getItem('ot-lang')).toBe(lang)
  })

  it('三種支援語言全部可選，且當前語言項停用', async () => {
    const wrapper = await mountPage()

    langDropdown(wrapper).vm.handleOpen()
    await flushPromises()

    const items = wrapper.findAllComponents({ name: 'ElDropdownItem' })
    expect(items.map((i) => i.text())).toEqual(SUPPORTED_LOCALES.map((l) => LOCALE_LABELS[l]))
    const current = items.find((i) => i.text() === LOCALE_LABELS['zh-TW'])
    expect(current.props('disabled')).toBe(true)
  })

  it('切換不觸發任何後端呼叫（封存期後端多數端點不可用）', async () => {
    const wrapper = await mountPage()
    const callsBefore = getSealStatusMock.mock.calls.length

    langDropdown(wrapper).vm.$emit('command', 'en-US')
    await wrapper.vm.$nextTick()

    expect(getSealStatusMock.mock.calls.length).toBe(callsBefore)
    expect(unsealMock).not.toHaveBeenCalled()
    expect(wrapper.find('.unseal-title').text()).toBe('Unseal the System')
  })
})

// —— 遺失警語的版面優先度（i18n「解封頁文案的操作者可讀性」）——
describe('Unseal 遺失警語', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    sealAuthorizeMock.mockResolvedValue({ grant: GRANT })
  })

  it('未解封時顯示，且排在任何解封表單之前', async () => {
    getSealStatusMock.mockResolvedValue(statusFixture())
    const wrapper = await mountPage()

    const callout = wrapper.find('.loss-callout')
    expect(callout.exists()).toBe(true)
    expect(callout.find('.loss-title').text()).toBe('弄丟主金鑰，全部資料永久救不回')
    const html = wrapper.html()
    expect(html.indexOf('loss-callout')).toBeLessThan(html.indexOf('form-section'))
  })

  it('委託模式改呈對應陳述：主金鑰在外部保管處，失去同樣救不回', async () => {
    getSealStatusMock.mockResolvedValue(delegatedStatus())
    const wrapper = await mountPage()

    const callout = wrapper.find('.loss-callout')
    expect(callout.exists()).toBe(true)
    expect(callout.find('.loss-title').text()).toContain('主金鑰在外部保管處')
    expect(callout.text()).toContain('沒有任何救援管道')
    // 憑證只留記憶體、封存或重啟要重新提供——委託部署的操作者必讀事實
    expect(wrapper.find('.credential-memory-note').text()).toContain('封存或重啟後需要重新輸入')
  })

  it('已解封時不顯示（該狀態下不可行動，恆掛只會訓練使用者忽略它）', async () => {
    getSealStatusMock.mockResolvedValue(statusFixture({ state: 'unsealed' }))
    const wrapper = await mountPage()

    expect(wrapper.find('.loss-callout').exists()).toBe(false)
  })

  it('遺失警語在文件順序上先於任何輸入框', async () => {
    getSealStatusMock.mockResolvedValue(statusFixture({ initialization_required: true }))
    const html = (await mountPage()).html()

    expect(html.indexOf('loss-callout')).toBeGreaterThan(-1)
    expect(html.indexOf('loss-callout')).toBeLessThan(html.indexOf('<input'))
  })
})

// —— 兩欄版面（preservice-pages「服務前頁面的共同版面」）——
describe('Unseal 兩欄版面', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    sealAuthorizeMock.mockResolvedValue({ grant: GRANT })
  })

  it('狀態訊息落在左欄，右欄只有動作', async () => {
    getSealStatusMock.mockResolvedValue(
      statusFixture({ state: 'sealed-faulted', fault_code: 'SEAL_INIT_FAILED' })
    )
    const wrapper = await mountPage()

    expect(wrapper.find('.preservice-left .status-messages').exists()).toBe(true)
    expect(wrapper.find('.preservice-right .status-messages').exists()).toBe(false)
    expect(wrapper.find('.preservice-left .loss-callout').exists()).toBe(true)
    expect(wrapper.find('.preservice-right .form-section').exists()).toBe(true)
  })

  it('兩則狀態訊息同時成立時，右欄表單的版位與結構不變', async () => {
    const structure = (wrapper) =>
      wrapper.find('.preservice-right').html().replace(/id="el-id-[\d-]+"/g, 'id="el-id"')

    getSealStatusMock.mockResolvedValue(statusFixture())
    const quiet = await mountPage()
    const quietRight = structure(quiet)

    getSealStatusMock.mockResolvedValue(
      statusFixture({ state: 'sealed-faulted', fault_code: 'SEAL_INIT_FAILED', journal_faulted: true })
    )
    const noisy = await mountPage()

    expect(noisy.findAll('.status-message')).toHaveLength(2)
    expect(structure(noisy)).toBe(quietRight)
    const children = [...noisy.find('.preservice-grid').element.children]
    expect(children[0].className).toContain('preservice-left')
    expect(children[1].className).toContain('preservice-right')
  })
})

// —— 參考資料收合（preservice-pages「服務前頁面的文案密度」）——
describe('Unseal 格式與生成指令展開區', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    sealAuthorizeMock.mockResolvedValue({ grant: GRANT })
    getSealStatusMock.mockResolvedValue(statusFixture())
  })

  it('預設收合，展開後三種寫法與三條生成指令完整出現', async () => {
    const wrapper = await mountPage()
    await verify(wrapper)

    expect(wrapper.find('.format-details-body').exists(), '參考資料預設應收合').toBe(false)

    const toggle = wrapper.find('.format-details-toggle')
    expect(toggle.attributes('aria-expanded')).toBe('false')
    await toggle.trigger('click')

    const body = wrapper.find('.format-details-body')
    expect(body.exists()).toBe(true)
    expect(body.text()).toContain('32 個字元')
    expect(body.text()).toContain('64 個十六進位字元')
    expect(body.text()).toContain('base64')
    const commands = body.findAll('.kek-command').map((c) => c.text())
    expect(commands).toEqual([
      'openssl rand -hex 32',
      'openssl rand -base64 32',
      "LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32",
    ])
  })

  it('一般解封可讀到「主金鑰是 32 位元組」', async () => {
    const wrapper = await mountPage()
    await verify(wrapper)

    expect(wrapper.find('.normal-section').text()).toContain('主金鑰是 32 位元組')
  })
})

// 表單標籤關聯（ui-design-system：Form controls carry a programmatic label association）
//
// Element Plus 的 el-input **宣告了 id 這個 prop 卻不把它放到原生節點上**，
// 因此關聯改用 aria-labelledby，而驗收必須打在渲染後的原生節點上——
// 只檢查「元件接受了屬性」的測試會在關聯根本不存在時照樣全綠。
describe('解封頁的表單標籤關聯', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    sealAuthorizeMock.mockResolvedValue({ grant: GRANT, topology_digest: DIGEST })
  })

  it('管理員欄位群組以 role=group 標示，兩個輸入框各自帶可分辨的可及名稱', async () => {
    getSealStatusMock.mockResolvedValue(statusFixture())
    const wrapper = await mountPage()

    const group = wrapper.find('[role="group"]')
    expect(group.exists()).toBe(true)
    const labelledBy = group.attributes('aria-labelledby')
    expect(wrapper.find(`#${labelledBy}`).exists()).toBe(true)

    const inputs = adminInputs(wrapper)
    expect(inputs).toHaveLength(2)
    const names = inputs.map((input) => input.attributes('aria-label'))
    for (const name of names) expect(name).toBeTruthy()
    expect(new Set(names).size).toBe(2)
  })

  it('金鑰欄與三家秘密欄的 aria-labelledby 皆指向存在且有文字的標籤', async () => {
    // 釘住每個分支的關聯清單，不只釘「大於零」：鬆的版本在某分支的關聯被整個
    // 移除時照樣全綠（2026-08-29 突變自檢的結論）
    const idsOf = async (status, steps) => {
      getSealStatusMock.mockResolvedValue(status)
      const wrapper = await mountPage()
      await steps(wrapper)
      const ids = wrapper
        .findAll('[aria-labelledby]')
        .map((el) => el.attributes('aria-labelledby'))
        .filter((id) => id && id.startsWith('unseal-'))
      for (const id of ids) {
        const label = wrapper.find(`#${id}`)
        expect(label.exists(), `${id} 指向不存在的元素`).toBe(true)
        expect(label.text().trim().length).toBeGreaterThan(0)
      }
      return ids
    }

    // 步驟互斥：驗證步驟的欄位在進入金鑰步驟後即不存在，故此處只剩金鑰欄的關聯
    expect(await idsOf(statusFixture(), verify)).toEqual(['unseal-material-label'])
    expect(await idsOf(statusFixture(), async () => {})).toEqual(['unseal-admin-label'])
    expect(
      await idsOf(delegatedStatus('vault', vaultTopology()), async (w) => {
        await verify(w)
        await review(w)
      })
    ).toEqual(['unseal-vault-secret-label'])
    expect(
      await idsOf(
        delegatedStatus('aws', vaultTopology({ provider: 'aws', address: '', role_id: '', region: 'ap-northeast-1' })),
        async (w) => {
          await verify(w)
          await review(w)
        }
      )
    ).toEqual(['unseal-aws-key-label', 'unseal-aws-secret-label'])
  })
})
