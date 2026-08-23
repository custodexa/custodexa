// 使用者外部身分管理（spec user-account-administration）。
//
// 守的是三件「錯了不會有任何報錯、只會讓管理者做出錯誤決定」的事：
//   - claim 快照是 IdP 自報值，必須與本地 username 分區且標示來源（低權使用者
//     可把自己的 preferred_username 設成 admin，混排即誤判）；
//   - 解綁的後果（該使用者全部工作階段登出）必須在**確認之前**說清楚；
//   - 「解綁後無登入途徑」被後端拒絕時，必須就近給出「解綁並停用帳號」的出路，
//     否則管理者卡在「不能解綁、也不知道還能做什麼」。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessage, ElMessageBox } from 'element-plus'
import UserExternalIdentities from '../UserExternalIdentities.vue'

// 本檔多數案例掛載後從不卸載（僅 3 處顯式 wrapper.unmount()，部分覆蓋），
// 殘留元件在 document 上累積使單測耗時隨測試序上升——全量並行時末幾格
// 逼近逾時上限而轉紅（單跑穩綠）。與 Assets.spec.js／AuditLogs.spec.js 同型
// 根因，治法相同：逐測卸載。既有的顯式 wrapper.unmount() 保留（不衝突，
// enableAutoUnmount 對已卸載的 wrapper 為 no-op）。
enableAutoUnmount(afterEach)

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

const listMock = vi.fn()
const bindMock = vi.fn()
const unbindMock = vi.fn()
const unbindDisableMock = vi.fn()
const providersMock = vi.fn()
const externalOnlyMock = vi.fn()

vi.mock('@/api/user', () => ({
  getExternalIdentities: (...a) => listMock(...a),
  bindExternalIdentity: (...a) => bindMock(...a),
  unbindExternalIdentity: (...a) => unbindMock(...a),
  unbindExternalIdentityAndDisable: (...a) => unbindDisableMock(...a),
  convertUserToExternalOnly: (...a) => externalOnlyMock(...a),
}))

vi.mock('@/api/oidc', () => ({
  getOIDCProviders: (...a) => providersMock(...a),
}))

// dex 實測回應形狀（live 取自 user_id=165）：claim_username 為空——dex 的 local
// 連接器不發 preferred_username，正是「自報值可能不存在」的真實案例
const dexIdentity = {
  id: 1,
  user_id: 165,
  provider_id: 2,
  provider_name: 'e2e-dex-sso',
  issuer: 'https://dex.example.com/dex',
  client_id: 'custodexa-dev',
  subject: 'CiQxMTExMTExMS0xMTExLTQxMTE',
  claim_username: '',
  claim_email: 'oidcuser@dex.example.com',
  last_login_at: '2026-08-04T04:45:59Z',
  created_at: '2026-08-04T03:59:18Z',
}

const oktaIdentity = {
  ...dexIdentity,
  id: 2,
  provider_id: 3,
  provider_name: 'Okta',
  subject: 'okta-sub-2',
  claim_username: 'admin',
  claim_email: '',
  last_login_at: null,
}

const externalUser = {
  id: 165,
  username: 'oidcuser',
  external_credential: true,
  provisioning_origin: 'oidc',
}

const localUser = {
  id: 7,
  username: 'carol',
  external_credential: false,
  provisioning_origin: 'local',
}

const mountPanel = (user = externalUser) =>
  mount(UserExternalIdentities, {
    props: { user },
    global: { plugins: [ElementPlus] },
  })

describe('UserExternalIdentities 外部身分表格', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    listMock.mockResolvedValue({ data: [dexIdentity], total: 1 })
    providersMock.mockResolvedValue({
      data: [{ id: 2, name: 'e2e-dex-sso', enabled: true }],
    })
  })

  it('列出 provider 實例名、subject、綁定與最近登入時間', async () => {
    const wrapper = mountPanel()
    await flushPromises()

    expect(listMock).toHaveBeenCalledWith(165)
    const text = wrapper.text()
    expect(text).toContain('e2e-dex-sso')
    expect(text).toContain('CiQxMTExMTExMS0xMTExLTQxMTE')
    expect(text).toContain('https://dex.example.com/dex')
  })

  it('claim 欄標示為 IdP 自報值，且與本地帳號分區呈現', async () => {
    // 防混淆約束（design 行 68）：claim 快照由 IdP 端控制，若與本地帳號混排，
    // 管理者會把「自報 admin」當成本系統的 admin
    const wrapper = mountPanel()
    await flushPromises()

    // 本地帳號在專屬區塊，帶明確標籤
    const local = wrapper.get('.local-identity')
    expect(local.text()).toContain('本系統帳號')
    expect(local.text()).toContain('oidcuser')

    // 兩個 claim 欄的表頭都帶「IdP 自報」字樣
    const text = wrapper.text()
    expect(text).toContain('IdP 自報使用者名稱')
    expect(text).toContain('IdP 自報 Email')
    expect(text).toContain('IdP 自報值不等於本系統身分')
  })

  it('claim 快照為空時顯示「無自報值」，不留白讓人誤以為載入失敗', async () => {
    const wrapper = mountPanel()
    await flushPromises()
    expect(wrapper.text()).toContain('無自報值')
    expect(wrapper.text()).toContain('oidcuser@dex.example.com')
  })

  it('尚未經此身分登入者標示「尚未經此身分登入」', async () => {
    listMock.mockResolvedValue({ data: [oktaIdentity], total: 1 })
    const wrapper = mountPanel()
    await flushPromises()
    expect(wrapper.text()).toContain('尚未經此身分登入')
  })

  it('解綁後果於表格上方常駐明示（按下按鈕之前就看得到）', async () => {
    const wrapper = mountPanel()
    await flushPromises()
    expect(wrapper.text()).toContain('解除綁定會登出該使用者的全部工作階段')
  })

  it('無外部身分時給空狀態與可操作提示', async () => {
    listMock.mockResolvedValue({ data: [], total: 0 })
    const wrapper = mountPanel()
    await flushPromises()
    expect(wrapper.text()).toContain('此帳號尚未綁定任何外部身分')
  })
})

describe('UserExternalIdentities 解綁確認與後果明示', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    listMock.mockResolvedValue({ data: [dexIdentity], total: 1 })
    providersMock.mockResolvedValue({ data: [] })
  })

  it('確認文案明示「所有工作階段將被登出」與此身分不可再登入', async () => {
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    unbindMock.mockResolvedValue({})
    const wrapper = mountPanel()
    await flushPromises()

    await wrapper.vm.handleUnbind(dexIdentity)
    await flushPromises()

    const message = confirmSpy.mock.calls[0][0]
    expect(message).toContain('所有工作階段將立即被登出')
    expect(message).toContain('e2e-dex-sso')
    expect(unbindMock).toHaveBeenCalledWith(165, 1)
    confirmSpy.mockRestore()
  })

  it('憑證已外部化者的確認文案指出「無本地密碼」並預告可改用解綁＋停用', async () => {
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    unbindMock.mockResolvedValue({})
    const wrapper = mountPanel(externalUser)
    await flushPromises()

    await wrapper.vm.handleUnbind(dexIdentity)
    const message = confirmSpy.mock.calls[0][0]
    expect(message).toContain('沒有本地密碼')
    expect(message).toContain('解除綁定並停用帳號')
    // 僅剩一筆時額外點出「這是最後一筆」
    expect(message).toContain('最後一筆外部身分')
    confirmSpy.mockRestore()
  })

  it('仍具本地密碼者的確認文案說明不會失去登入途徑（兩種風險不可混為一談）', async () => {
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    unbindMock.mockResolvedValue({})
    const wrapper = mountPanel(localUser)
    await flushPromises()

    await wrapper.vm.handleUnbind(dexIdentity)
    const message = confirmSpy.mock.calls[0][0]
    expect(message).toContain('仍可使用本地密碼登入')
    confirmSpy.mockRestore()
  })

  it('取消確認即不呼叫 API', async () => {
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockRejectedValue('cancel')
    const wrapper = mountPanel()
    await flushPromises()

    await wrapper.vm.handleUnbind(dexIdentity)
    await flushPromises()

    expect(unbindMock).not.toHaveBeenCalled()
    confirmSpy.mockRestore()
  })

  it('解綁成功後通知父層並重載清單', async () => {
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    unbindMock.mockResolvedValue({})
    const wrapper = mountPanel()
    await flushPromises()
    listMock.mockClear()

    await wrapper.vm.handleUnbind(dexIdentity)
    await flushPromises()

    expect(wrapper.emitted('changed')).toBeTruthy()
    expect(listMock).toHaveBeenCalledWith(165)
    confirmSpy.mockRestore()
  })
})

describe('UserExternalIdentities 登入途徑歸零的出路（RULE_USER_LAST_LOGIN_PATH）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    listMock.mockResolvedValue({ data: [dexIdentity], total: 1 })
    providersMock.mockResolvedValue({ data: [] })
  })

  it('後端拒絕時就近提供「解綁並停用帳號」，確認後呼叫原子端點', async () => {
    unbindMock.mockRejectedValue({
      response: { status: 400, data: { code: 'RULE_USER_LAST_LOGIN_PATH' } },
    })
    unbindDisableMock.mockResolvedValue({})
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    const wrapper = mountPanel()
    await flushPromises()

    await wrapper.vm.handleUnbind(dexIdentity)
    await flushPromises()

    // 第二次 confirm 即被拒後的出路對話框：標題與確認鈕都指向「解綁並停用」
    expect(confirmSpy).toHaveBeenCalledTimes(2)
    const [message, title, options] = confirmSpy.mock.calls[1]
    expect(title).toContain('無法解除綁定')
    expect(message).toContain('解除綁定並停用帳號')
    expect(options.confirmButtonText).toBe('解除綁定並停用帳號')
    expect(unbindDisableMock).toHaveBeenCalledWith(165, 1)
    confirmSpy.mockRestore()
  })

  it('出路對話框被取消時不停用帳號（拒絕不等於自動升級為停用）', async () => {
    unbindMock.mockRejectedValue({
      response: { status: 400, data: { code: 'RULE_USER_LAST_LOGIN_PATH' } },
    })
    const confirmSpy = vi
      .spyOn(ElMessageBox, 'confirm')
      .mockResolvedValueOnce('confirm')
      .mockRejectedValueOnce('cancel')
    const wrapper = mountPanel()
    await flushPromises()

    await wrapper.vm.handleUnbind(dexIdentity)
    await flushPromises()

    expect(unbindDisableMock).not.toHaveBeenCalled()
    confirmSpy.mockRestore()
  })

  it('其他錯誤碼不觸發停用出路（只有登入途徑歸零才給這條路）', async () => {
    unbindMock.mockRejectedValue({
      response: { status: 404, data: { code: 'NOTFOUND_EXTERNAL_IDENTITY' } },
    })
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    const wrapper = mountPanel()
    await flushPromises()

    await wrapper.vm.handleUnbind(dexIdentity)
    await flushPromises()

    expect(confirmSpy).toHaveBeenCalledTimes(1)
    expect(unbindDisableMock).not.toHaveBeenCalled()
    confirmSpy.mockRestore()
  })

  it('直接執行「解綁並停用」時，確認文案明示帳號將無法登入', async () => {
    unbindDisableMock.mockResolvedValue({})
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    const wrapper = mountPanel()
    await flushPromises()

    await wrapper.vm.handleUnbindAndDisable(dexIdentity)
    await flushPromises()

    const message = confirmSpy.mock.calls[0][0]
    expect(message).toContain('停用該帳號')
    expect(message).toContain('直到管理員重新啟用')
    expect(unbindDisableMock).toHaveBeenCalledWith(165, 1)
    expect(wrapper.emitted('changed')).toBeTruthy()
    confirmSpy.mockRestore()
  })
})

describe('UserExternalIdentities admin 代綁', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    listMock.mockResolvedValue({ data: [], total: 0 })
    providersMock.mockResolvedValue({
      data: [
        { id: 2, name: 'e2e-dex-sso', enabled: true },
        { id: 3, name: 'Okta', enabled: false },
      ],
    })
  })

  it('缺 provider 或 subject 時就近擋下，不打 API', async () => {
    const wrapper = mountPanel()
    await flushPromises()

    await wrapper.vm.handleBind()
    expect(bindMock).not.toHaveBeenCalled()

    wrapper.vm.bindForm.providerId = 2
    wrapper.vm.bindForm.subject = '   '
    await wrapper.vm.handleBind()
    expect(bindMock).not.toHaveBeenCalled()
  })

  it('送出 provider_id 與去頭尾空白後的 subject，成功後重載並通知父層', async () => {
    bindMock.mockResolvedValue({ data: { id: 9 } })
    const wrapper = mountPanel()
    await flushPromises()
    listMock.mockClear()

    wrapper.vm.bindForm.providerId = 2
    wrapper.vm.bindForm.subject = '  sub-abc  '
    await wrapper.vm.handleBind()
    await flushPromises()

    expect(bindMock).toHaveBeenCalledWith(165, 2, 'sub-abc')
    expect(wrapper.emitted('changed')).toBeTruthy()
    expect(listMock).toHaveBeenCalledWith(165)
  })

  it('provider 清單含已停用者並標示（綁定不受停用限制，但要看得出來）', async () => {
    const wrapper = mountPanel()
    await flushPromises()
    expect(wrapper.vm.providers.map((p) => p.name)).toEqual(['e2e-dex-sso', 'Okta'])
  })
})

describe('UserExternalIdentities 破壞性動作的誤觸面（UI 對抗審查 HIGH-1/HIGH-2）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    listMock.mockResolvedValue({ data: [dexIdentity], total: 1 })
    providersMock.mockResolvedValue({ data: [] })
  })

  it('列上只有「解除綁定」是可直接按的按鈕，停用出路收在「更多」選單內', async () => {
    // 兩個同色同權、字首相同的 danger 按鈕緊鄰擺放時，誤點代價是整個帳號被停用
    const wrapper = mountPanel()
    await flushPromises()

    const rowButtons = wrapper
      .findAll('.el-table__row button')
      .map((b) => b.text())
      .filter(Boolean)
    expect(rowButtons).toContain('解除綁定')
    expect(rowButtons).not.toContain('解除綁定並停用帳號')
    expect(rowButtons.some((text) => text.includes('更多'))).toBe(true)

    // 選單命令仍直達同一 handler（入口收起來不等於拿掉這條路）
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockRejectedValue('cancel')
    wrapper.vm.handleRowCommand('unbindAndDisable', dexIdentity)
    await flushPromises()
    expect(confirmSpy).toHaveBeenCalledTimes(1)
    expect(confirmSpy.mock.calls[0][1]).toContain('確認解除綁定並停用帳號')
    confirmSpy.mockRestore()
  })

  it('所有破壞性確認框都關閉 autofocus（Enter 不得落在危險鈕上）', async () => {
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockRejectedValue('cancel')
    unbindMock.mockRejectedValue({
      response: { status: 400, data: { code: 'RULE_USER_LAST_LOGIN_PATH' } },
    })
    const wrapper = mountPanel()
    await flushPromises()

    await wrapper.vm.handleUnbind(dexIdentity)
    await wrapper.vm.handleUnbindAndDisable(dexIdentity)
    wrapper.vm.identities = [dexIdentity]
    await wrapper.vm.handleExternalOnly()
    await flushPromises()

    expect(confirmSpy.mock.calls.length).toBeGreaterThanOrEqual(3)
    for (const [, , options] of confirmSpy.mock.calls) {
      expect(options.autofocus).toBe(false)
      expect(options.confirmButtonClass).toBe('el-button--danger')
    }
    confirmSpy.mockRestore()
  })

  it('後端拒絕後的出路對話框帶完整後果（不只顯示規則錯誤訊息）', async () => {
    unbindMock.mockRejectedValue({
      response: { status: 400, data: { code: 'RULE_USER_LAST_LOGIN_PATH' } },
    })
    const confirmSpy = vi
      .spyOn(ElMessageBox, 'confirm')
      .mockResolvedValueOnce('confirm')
      .mockRejectedValueOnce('cancel')
    const wrapper = mountPanel()
    await flushPromises()

    await wrapper.vm.handleUnbind(dexIdentity)
    await flushPromises()

    const message = confirmSpy.mock.calls[1][0]
    expect(message).toContain('oidcuser')
    expect(message).toContain('e2e-dex-sso')
    expect(message).toContain('直到管理員重新啟用')
    expect(unbindDisableMock).not.toHaveBeenCalled()
    confirmSpy.mockRestore()
  })
})

describe('UserExternalIdentities 跨使用者競態與互斥（讀碼審查 HIGH-1/HIGH-2）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    providersMock.mockResolvedValue({ data: [] })
  })

  it('切換使用者時立即清空清單，較晚返回的前一位結果一律丟棄', async () => {
    // 舊結果覆蓋新清單後，接下來的解綁會拿新 user id 配舊 identity id
    let resolveSlow
    listMock.mockImplementationOnce(
      () => new Promise((resolve) => { resolveSlow = resolve })
    )
    const wrapper = mountPanel()
    await flushPromises()
    expect(wrapper.vm.identities).toEqual([])

    listMock.mockResolvedValue({ data: [], total: 0 })
    await wrapper.setProps({ user: localUser })
    await flushPromises()

    resolveSlow({ data: [dexIdentity], total: 1 })
    await flushPromises()

    expect(wrapper.vm.identities).toEqual([])
    expect(listMock).toHaveBeenLastCalledWith(7)
  })

  it('確認框開著期間切換使用者，確認後不對新使用者執行舊操作', async () => {
    listMock.mockResolvedValue({ data: [dexIdentity], total: 1 })
    let confirmUser
    const confirmSpy = vi
      .spyOn(ElMessageBox, 'confirm')
      .mockImplementation(() => new Promise((resolve) => { confirmUser = resolve }))
    const wrapper = mountPanel()
    await flushPromises()

    const pending = wrapper.vm.handleUnbind(dexIdentity)
    await flushPromises()
    await wrapper.setProps({ user: localUser })
    confirmUser('confirm')
    await pending
    await flushPromises()

    expect(unbindMock).not.toHaveBeenCalled()
    confirmSpy.mockRestore()
  })

  it('元件卸載後才按下的確認框不得送出（確認框在 body，不隨卸載失效）', async () => {
    // 父層以 `:key="user.id"` 重掛面板時本實例被卸載，但 ElMessageBox 是 teleport
    // 到 body 的全域節點，畫面上那個框還在。舊實例閉包裡的 props.user 停在舊值，
    // 只比對 user id 的守衛會回 true——按下確認就對「抽屜上已經不是他」的帳號送出
    listMock.mockResolvedValue({ data: [dexIdentity], total: 1 })
    let confirmUser
    const confirmSpy = vi
      .spyOn(ElMessageBox, 'confirm')
      .mockImplementation(() => new Promise((resolve) => { confirmUser = resolve }))
    const wrapper = mountPanel()
    await flushPromises()

    const pending = wrapper.vm.handleUnbind(dexIdentity)
    await flushPromises()
    // 抽屜換人＝舊實例卸載、新實例掛載；殘留的確認框此刻才被按下
    wrapper.unmount()
    confirmUser('confirm')
    await pending
    await flushPromises()

    expect(unbindMock).not.toHaveBeenCalled()
    expect(unbindDisableMock).not.toHaveBeenCalled()
    confirmSpy.mockRestore()
  })

  it('卸載後的「解除綁定並停用」殘窗同樣不得停用帳號', async () => {
    listMock.mockResolvedValue({ data: [dexIdentity], total: 1 })
    let confirmUser
    const confirmSpy = vi
      .spyOn(ElMessageBox, 'confirm')
      .mockImplementation(() => new Promise((resolve) => { confirmUser = resolve }))
    const wrapper = mountPanel()
    await flushPromises()

    const pending = wrapper.vm.handleUnbindAndDisable(dexIdentity)
    await flushPromises()
    wrapper.unmount()
    confirmUser('confirm')
    await pending
    await flushPromises()

    expect(unbindDisableMock).not.toHaveBeenCalled()
    confirmSpy.mockRestore()
  })

  it('切換使用者後，舊 handler 的 finally 不得釋放新操作的鎖', async () => {
    // 舊版 finally 無條件 `busy.value = false`：切換使用者後新操作已經上鎖，
    // 舊 handler 一收尾就把新操作的鎖清掉，第二個破壞性動作因此得以並行進場
    listMock.mockResolvedValue({ data: [dexIdentity], total: 1 })
    const resolvers = []
    const confirmSpy = vi
      .spyOn(ElMessageBox, 'confirm')
      .mockImplementation(() => new Promise((resolve, reject) => { resolvers.push({ resolve, reject }) }))
    const wrapper = mountPanel()
    await flushPromises()

    const stale = wrapper.vm.handleUnbind(dexIdentity)
    await flushPromises()
    expect(wrapper.vm.busy).toBe(true)

    // 換人：舊操作失效、鎖釋出
    await wrapper.setProps({ user: localUser })
    await flushPromises()
    expect(wrapper.vm.busy).toBe(false)

    // 新使用者上的新操作取得鎖
    const fresh = wrapper.vm.handleUnbind(dexIdentity)
    await flushPromises()
    expect(wrapper.vm.busy).toBe(true)

    // 舊 handler 此刻才收尾（使用者按了殘窗的取消）
    resolvers[0].reject('cancel')
    await stale
    await flushPromises()

    // 新操作仍持有鎖
    expect(wrapper.vm.busy).toBe(true)

    resolvers[1].reject('cancel')
    await fresh
    await flushPromises()
    expect(wrapper.vm.busy).toBe(false)
    confirmSpy.mockRestore()
  })

  it('確認框開啟到重載完成期間維持單一互斥鎖，第二個操作直接被擋', async () => {
    listMock.mockResolvedValue({ data: [dexIdentity, oktaIdentity], total: 2 })
    let releaseConfirm
    const confirmSpy = vi
      .spyOn(ElMessageBox, 'confirm')
      .mockImplementation(() => new Promise((resolve) => { releaseConfirm = resolve }))
    unbindMock.mockResolvedValue({})
    const wrapper = mountPanel()
    await flushPromises()

    const first = wrapper.vm.handleUnbind(dexIdentity)
    await flushPromises()
    expect(wrapper.vm.busy).toBe(true)

    // 第二列的解綁、選單的停用、綁定送出在鎖住期間全部不得進場
    await wrapper.vm.handleUnbind(oktaIdentity)
    await wrapper.vm.handleUnbindAndDisable(oktaIdentity)
    wrapper.vm.bindForm.providerId = 2
    wrapper.vm.bindForm.subject = 'sub-x'
    await wrapper.vm.handleBind()
    expect(confirmSpy).toHaveBeenCalledTimes(1)
    expect(bindMock).not.toHaveBeenCalled()

    releaseConfirm('confirm')
    await first
    await flushPromises()
    expect(unbindMock).toHaveBeenCalledTimes(1)
    expect(unbindMock).toHaveBeenCalledWith(165, 1)
    expect(wrapper.vm.busy).toBe(false)
    confirmSpy.mockRestore()
  })

  it('切換使用者後才成功的 mutation：changed 事件帶原目標 userId', async () => {
    // 舊實例仍要通知父層「後端資料已變」，但父層必須分辨得出這是**誰**的變更——
    // 不帶 userId 時，父層只能無條件刷新目前抽屜，等於用舊操作驅動新使用者的狀態
    listMock.mockResolvedValue({ data: [dexIdentity], total: 1 })
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    let resolveUnbind
    unbindMock.mockImplementationOnce(
      () => new Promise((resolve) => { resolveUnbind = resolve })
    )
    const wrapper = mountPanel()
    await flushPromises()

    const pending = wrapper.vm.handleUnbind(dexIdentity)
    await flushPromises()
    // 請求在途期間換人：成功回應落地時，抽屜上已經是別人
    await wrapper.setProps({ user: localUser })
    resolveUnbind({})
    await pending
    await flushPromises()

    const events = wrapper.emitted('changed')
    expect(events).toBeTruthy()
    expect(events[0]).toEqual([165])
    confirmSpy.mockRestore()
  })

  it('正常成功路徑的 changed 事件同樣帶目前 userId', async () => {
    listMock.mockResolvedValue({ data: [dexIdentity], total: 1 })
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    unbindMock.mockResolvedValue({})
    const wrapper = mountPanel()
    await flushPromises()

    await wrapper.vm.handleUnbind(dexIdentity)
    await flushPromises()

    expect(wrapper.emitted('changed')[0]).toEqual([165])
    confirmSpy.mockRestore()
  })

  it('換人後按下舊確認框的破壞性鈕：中止要有回饋，不得靜默（輪 3 NEW-LOW-2）', async () => {
    // 按下紅色破壞性按鈕卻什麼都沒發生，管理者會誤以為已執行
    listMock.mockResolvedValue({ data: [dexIdentity], total: 1 })
    const infoSpy = vi.spyOn(ElMessage, 'info').mockImplementation(() => {})
    let confirmUser
    const confirmSpy = vi
      .spyOn(ElMessageBox, 'confirm')
      .mockImplementation(() => new Promise((resolve) => { confirmUser = resolve }))
    const wrapper = mountPanel()
    await flushPromises()

    const pending = wrapper.vm.handleUnbind(dexIdentity)
    await flushPromises()
    await wrapper.setProps({ user: localUser })
    confirmUser('confirm')
    await pending
    await flushPromises()

    expect(unbindMock).not.toHaveBeenCalled()
    expect(infoSpy).toHaveBeenCalledWith('使用者已切換，本次操作未執行')
    infoSpy.mockRestore()
    confirmSpy.mockRestore()
  })

  it('複製 subject 的結果提示在卸載後不得再彈出', async () => {
    // toast 出現在「已經是別人」的畫面上，會被讀成剛才複製的是這個帳號的 subject
    listMock.mockResolvedValue({ data: [dexIdentity], total: 1 })
    const successSpy = vi.spyOn(ElMessage, 'success').mockImplementation(() => {})
    let resolveWrite
    const writeText = vi.fn(() => new Promise((resolve) => { resolveWrite = resolve }))
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      configurable: true,
    })
    const wrapper = mountPanel()
    await flushPromises()

    const pending = wrapper.vm.copySubject(dexIdentity.subject)
    await flushPromises()
    wrapper.unmount()
    resolveWrite()
    await pending
    await flushPromises()

    expect(writeText).toHaveBeenCalled()
    expect(successSpy).not.toHaveBeenCalled()
    successSpy.mockRestore()
  })
})

describe('UserExternalIdentities 載入失敗的錯誤態（UI 對抗審查 HIGH-4）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    providersMock.mockResolvedValue({ data: [] })
  })

  it('載入失敗時呈現錯誤態，不得斷言「此帳號尚未綁定任何外部身分」', async () => {
    // 空態是事實斷言：管理者會據此判定帳號沒有外部登入途徑而停掉本地密碼或刪帳號
    listMock.mockRejectedValue({ response: { status: 500, data: { code: 'INTERNAL_EXTERNAL_IDENTITY_QUERY' } } })
    const wrapper = mountPanel()
    await flushPromises()

    expect(wrapper.vm.loadError).toBe(true)
    const text = wrapper.text()
    expect(text).toContain('無法載入外部身分')
    expect(text).not.toContain('此帳號尚未綁定任何外部身分')
    // 綁定與轉換入口在狀態未知時一律停用
    expect(wrapper.vm.identities).toEqual([])
  })

  it('重試成功後回到正常清單並清除錯誤態', async () => {
    listMock.mockRejectedValueOnce({ response: { status: 500, data: {} } })
    const wrapper = mountPanel()
    await flushPromises()
    expect(wrapper.vm.loadError).toBe(true)

    listMock.mockResolvedValue({ data: [dexIdentity], total: 1 })
    await wrapper.vm.loadIdentities()
    await flushPromises()

    expect(wrapper.vm.loadError).toBe(false)
    expect(wrapper.vm.identities).toHaveLength(1)
  })

  it('失敗日誌只留事件名與白名單欄位，不寫入原始錯誤物件', async () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    listMock.mockRejectedValue({
      response: { status: 500, data: { code: 'INTERNAL_EXTERNAL_IDENTITY_QUERY' } },
      config: { headers: { Authorization: 'Bearer leak-me' }, data: '{"subject":"secret-sub"}' },
    })
    mountPanel()
    await flushPromises()

    expect(spy).toHaveBeenCalledWith('external_identity_list_failed', {
      status: 500,
      code: 'INTERNAL_EXTERNAL_IDENTITY_QUERY',
    })
    const dumped = JSON.stringify(spy.mock.calls)
    expect(dumped).not.toContain('leak-me')
    expect(dumped).not.toContain('secret-sub')
    spy.mockRestore()
  })
})

describe('UserExternalIdentities 改為僅外部登入（2.8 端點 d）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    listMock.mockResolvedValue({ data: [dexIdentity], total: 1 })
    providersMock.mockResolvedValue({ data: [] })
    externalOnlyMock.mockResolvedValue({})
  })

  it('確認文案帶帳號、既綁身分數與「本地密碼作廢」後果，確認後呼叫端點', async () => {
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    const wrapper = mountPanel(localUser)
    await flushPromises()

    await wrapper.vm.handleExternalOnly()
    await flushPromises()

    const [message, title] = confirmSpy.mock.calls[0]
    expect(title).toContain('改為僅外部登入')
    expect(message).toContain('carol')
    expect(message).toContain('本地密碼立即作廢')
    expect(message).toContain('1 筆外部身分')
    expect(externalOnlyMock).toHaveBeenCalledWith(7)
    expect(wrapper.emitted('changed')).toBeTruthy()
    confirmSpy.mockRestore()
  })

  it('取消時不呼叫端點', async () => {
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockRejectedValue('cancel')
    const wrapper = mountPanel(localUser)
    await flushPromises()

    await wrapper.vm.handleExternalOnly()
    await flushPromises()

    expect(externalOnlyMock).not.toHaveBeenCalled()
    confirmSpy.mockRestore()
  })

  it('無既綁身分時入口停用且按下不打 API（否則必被後端拒絕）', async () => {
    listMock.mockResolvedValue({ data: [], total: 0 })
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    const wrapper = mountPanel(localUser)
    await flushPromises()

    expect(wrapper.text()).toContain('需先綁定至少一筆外部身分')
    await wrapper.vm.handleExternalOnly()
    await flushPromises()

    expect(confirmSpy).not.toHaveBeenCalled()
    expect(externalOnlyMock).not.toHaveBeenCalled()
    confirmSpy.mockRestore()
  })

  it('已是僅外部登入的帳號不再提供轉換入口', async () => {
    const wrapper = mountPanel(externalUser)
    await flushPromises()
    expect(wrapper.text()).toContain('此帳號已是僅外部登入')
    expect(wrapper.text()).not.toContain('需先綁定至少一筆外部身分')
  })

  it('父層列表刷新失敗時停用轉換入口並就地說明', async () => {
    // 刷新失敗＝畫面上的「具本地密碼／帳號啟用中」還是操作前的舊值；
    // 讓管理者依舊值再按一次不可逆的轉換，是拿過期事實做決定
    const wrapper = mount(UserExternalIdentities, {
      props: { user: localUser, accountStateStale: true },
      global: { plugins: [ElementPlus] },
    })
    await flushPromises()

    expect(wrapper.text()).toContain('帳號狀態可能已過期')
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    await wrapper.vm.handleExternalOnly()
    await flushPromises()
    expect(confirmSpy).not.toHaveBeenCalled()
    expect(externalOnlyMock).not.toHaveBeenCalled()
    confirmSpy.mockRestore()
  })

  it('規則拒絕（最後一個本地管理員）就近顯示譯文，不靜默失敗', async () => {
    externalOnlyMock.mockRejectedValue({
      response: { status: 400, data: { code: 'RULE_USER_LAST_LOCAL_ADMIN' } },
    })
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    const errorSpy = vi.spyOn(ElMessage, 'error').mockImplementation(() => {})
    const wrapper = mountPanel(localUser)
    await flushPromises()

    await wrapper.vm.handleExternalOnly()
    await flushPromises()

    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('最後一個本地管理員'))
    confirmSpy.mockRestore()
    errorSpy.mockRestore()
  })
})

describe('UserExternalIdentities subject 送出值與重複綁定', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    listMock.mockResolvedValue({ data: [dexIdentity], total: 1 })
    providersMock.mockResolvedValue({ data: [{ id: 2, name: 'e2e-dex-sso', enabled: true }] })
  })

  it('輸入帶頭尾空白時，送出前先攤開實際會送出的 subject', async () => {
    // subject 大小寫敏感且不正規化，「你打的」與「實際送的」不同時必須先看到
    const wrapper = mountPanel()
    await flushPromises()

    wrapper.vm.bindForm.subject = '  sub-abc  '
    await flushPromises()
    expect(wrapper.text()).toContain('實際送出的 subject')
    expect(wrapper.text()).toContain('sub-abc')
  })

  it('與本帳號既有綁定完全重複時就近擋下（衝突對象就在同一畫面上）', async () => {
    const warnSpy = vi.spyOn(ElMessage, 'warning').mockImplementation(() => {})
    const wrapper = mountPanel()
    await flushPromises()

    wrapper.vm.bindForm.providerId = 2
    wrapper.vm.bindForm.subject = dexIdentity.subject
    await wrapper.vm.handleBind()

    expect(bindMock).not.toHaveBeenCalled()
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('已綁定於本帳號'))
    warnSpy.mockRestore()
  })
})
