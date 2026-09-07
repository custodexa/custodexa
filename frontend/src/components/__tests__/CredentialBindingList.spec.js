import { describe, it, expect, afterEach } from 'vitest'
import { mount, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import CredentialBindingList from '@/components/credential/CredentialBindingList.vue'

// 憑證的掛載清單。
//
// 斷言重心在三件會靜默出錯的事：
//  1. 每列的就位版本——版本號錯一位，看的人會以為那台已經換過了；
//  2. 脫離與卸載是兩件事（一個動遠端、一個不動），兩顆鈕必須各自可辨識；
//  3. 輪替進行中時動作不可執行，且**就地寫出原因**——只把鈕灰掉等於沒說。

enableAutoUnmount(afterEach)

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
