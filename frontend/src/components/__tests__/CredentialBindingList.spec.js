import { describe, it, expect, afterEach, beforeEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import CredentialBindingList from '@/components/credential/CredentialBindingList.vue'
import { resetCapabilities, setCapabilitiesForTests } from '@/composables/useCapabilities'

// 憑證的掛載清單。
//
// 斷言重心在三件會靜默出錯的事：
//  1. 每列的就位版本——版本號錯一位，看的人會以為那台已經換過了；
//  2. 脫離與卸載是兩件事（一個動遠端、一個不動），兩顆鈕必須各自可辨識；
//  3. 輪替進行中時動作不可執行，且**就地寫出原因**——只把鈕灰掉等於沒說。

enableAutoUnmount(afterEach)

// 兩顆動作鈕依能力顯示（credential:detach、credential:bind）；本檔的斷言對象是清單本身，
// 故預設持有兩項能力
beforeEach(() => setCapabilitiesForTests(['credential:detach', 'credential:bind']))
afterEach(() => resetCapabilities())

const bindingFixture = (overrides = {}) => ({
  account_id: 20113,
  asset_id: 2,
  asset_name: 'ssh-multi-test',
  username: 'shareduser',
  is_default: true,
  privileged: false,
  note: '',
  effective_version_no: 1,
  up_to_date: true,
  ...overrides,
})

const threeBindings = () => [
  bindingFixture({ account_id: 1, asset_id: 11, asset_name: 'web-01', effective_version_no: 4 }),
  bindingFixture({
    account_id: 2, asset_id: 12, asset_name: 'web-02',
    effective_version_no: 3, up_to_date: false, is_default: false, privileged: true,
  }),
  bindingFixture({
    account_id: 3, asset_id: 13, asset_name: 'app-01',
    effective_version_no: 0, up_to_date: false, is_default: false,
  }),
]

const mountList = (props = {}) => mount(CredentialBindingList, {
  global: { plugins: [ElementPlus] },
  props: { bindings: threeBindings(), scope: 'shared', ...props },
})

describe('掛載清單', () => {
  it('列出三台且各標就位版本，未就位者標「待更新」', () => {
    const wrapper = mountList()

    expect(wrapper.findAll('[data-test^="binding-row-"]')).toHaveLength(3)
    expect(wrapper.text()).toContain('掛載資產（3）')

    expect(wrapper.find('[data-test="binding-version-1"]').text()).toBe('v4')
    expect(wrapper.find('[data-test="binding-version-2"]').text()).toBe('v3')
    // 尚未取得任何密文的那一台不報一個假的版本號
    expect(wrapper.find('[data-test="binding-version-3"]').text()).toBe('尚無版本')

    expect(wrapper.find('[data-test="binding-state-1"]').text()).toBe('就位')
    expect(wrapper.find('[data-test="binding-state-2"]').text()).toBe('待更新')

    // 預設與特權逐掛載獨立，各自呈現在自己那一列
    expect(wrapper.find('[data-test="binding-row-1"]').text()).toContain('預設')
    expect(wrapper.find('[data-test="binding-row-2"]').text()).toContain('特權')
  })

  it('脫離與卸載各自送出事件，帶的是被點的那一列', async () => {
    const wrapper = mountList()

    await wrapper.find('[data-test="binding-detach-2"]').trigger('click')
    await wrapper.find('[data-test="binding-unbind-3"]').trigger('click')

    expect(wrapper.emitted('detach')[0][0].account_id).toBe(2)
    expect(wrapper.emitted('unbind')[0][0].account_id).toBe(3)
  })

  it('專用憑證沒有「脫離」這個動作，卸載仍在', () => {
    const wrapper = mountList({ scope: 'dedicated', bindings: [bindingFixture()] })

    expect(wrapper.find('[data-test="binding-detach-20113"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="binding-unbind-20113"]').exists()).toBe(true)
  })

  it('輪替進行中：兩個動作都不可執行，清單就地說明原因一次', () => {
    const wrapper = mountList({ rotationActive: true })

    for (const id of [1, 2, 3]) {
      expect(wrapper.find(`[data-test="binding-detach-${id}"]`).classes()).toContain('is-disabled')
      expect(wrapper.find(`[data-test="binding-unbind-${id}"]`).classes()).toContain('is-disabled')
    }

    // 擋住每一列的是同一件事：說一次，不是說三次
    const reason = wrapper.find('[data-test="bindings-blocked"]')
    expect(reason.exists()).toBe(true)
    expect(reason.text()).toContain('輪替進行中')
    expect(wrapper.findAll('.list-reason')).toHaveLength(1)
  })

  it('未在輪替時不出現那一句', () => {
    const wrapper = mountList()
    expect(wrapper.find('[data-test="bindings-blocked"]').exists()).toBe(false)
  })

  it('零掛載是合法的待用狀態，以空狀態呈現而非錯誤', () => {
    const wrapper = mountList({ bindings: [] })

    expect(wrapper.text()).toContain('尚未掛到任何資產')
    expect(wrapper.findAll('[data-test^="binding-row-"]')).toHaveLength(0)
  })
})

describe('BindingPurpose', () => {
  const executorRows = () => [
    bindingFixture({ account_id: 1, asset_id: 11, asset_name: 'web-01', purpose: 'executor' }),
    bindingFixture({ account_id: 2, asset_id: 12, asset_name: 'web-02', purpose: 'executor', is_default: false }),
    bindingFixture({ account_id: 3, asset_id: 13, asset_name: 'web-03', purpose: 'executor', is_default: false }),
  ]

  it('三列 executor 顯示用途字，卸載停用、脫離可用', () => {
    const wrapper = mountList({ bindings: executorRows() })
    for (const id of [1, 2, 3]) {
      expect(wrapper.get(`[data-test="binding-purpose-${id}"]`).text()).toBe('堡壘機專用')
      expect(wrapper.get(`[data-test="binding-unbind-${id}"]`).attributes('disabled')).toBeDefined()
      expect(wrapper.get(`[data-test="binding-detach-${id}"]`).attributes('disabled')).toBeUndefined()
    }
  })

  it('無 actions 旗標的全域主體列只靠 purpose 即停用卸載', () => {
    const rows = [bindingFixture({ account_id: 9, purpose: 'executor' })]
    expect(rows[0].actions).toBeUndefined()
    const wrapper = mountList({ bindings: rows })
    expect(wrapper.get('[data-test="binding-unbind-9"]').attributes('disabled')).toBeDefined()
  })

  it('login 列用途為人員連線，卸載可用性與以前相同', () => {
    const wrapper = mountList({ bindings: [bindingFixture({ account_id: 5, purpose: 'login' }), bindingFixture({ account_id: 6 })] })
    expect(wrapper.get('[data-test="binding-purpose-5"]').text()).toBe('人員連線')
    expect(wrapper.get('[data-test="binding-purpose-6"]').text()).toBe('人員連線')
    expect(wrapper.get('[data-test="binding-unbind-5"]').attributes('disabled')).toBeUndefined()
    expect(wrapper.get('[data-test="binding-unbind-6"]').attributes('disabled')).toBeUndefined()
  })

  it('聚焦停用外層後說明與連結出現且 href 正確', async () => {
    const wrapper = mount(CredentialBindingList, {
      global: { plugins: [ElementPlus] },
      props: { bindings: executorRows(), scope: 'shared' },
      attachTo: document.body,
    })
    await wrapper.get('[data-test="binding-unbind-wrap-2"]').trigger('focus')
    await flushPromises()
    expect(wrapper.get('[data-test="binding-unbind-wrap-2"]').attributes('tabindex')).toBe('0')
    const note = wrapper.get('[data-test="binding-unbind-note-2"]')
    expect(note.text()).toContain('堡壘機專用帳號不能在這裡卸載')
    const link = wrapper.get('[data-test="binding-unbind-link-2"]')
    expect(link.attributes('href')).toBe('/assets?edit=12&focus=executor')
    expect(link.text()).toContain('web-02')
    expect(link.classes()).toContain('unbind-note-link')
  })

  it('解除綁定提示內連結用站內連結色、無底線', () => {
    const sfc = readFileSync(join(process.cwd(), 'src/components/credential/CredentialBindingList.vue'), 'utf8')
    const rule = /\.unbind-note-link \{[^}]*\}/.exec(sfc)?.[0] || ''
    expect(rule).toMatch(/color: var\(--ot-primary\)/)
    expect(rule).toMatch(/text-decoration: none/)
  })

  it('範圍化檢視者的 executor 列帶 unbind 不可用旗標時，標頭下方不出現該原因；login 列同碼仍彙整', () => {
    const flag = { unbind: { allowed: false, reason: 'no_capability' } }
    const wrapper = mountList({
      bindings: [
        bindingFixture({ account_id: 1, purpose: 'executor', actions: flag }),
      ],
    })
    expect(wrapper.find('[data-test^="bindings-denied-"]').exists()).toBe(false)
    const login = mountList({ bindings: [bindingFixture({ account_id: 2, purpose: 'login', actions: flag })] })
    expect(login.find('[data-test="bindings-denied-no_capability"]').exists()).toBe(true)
  })
})
