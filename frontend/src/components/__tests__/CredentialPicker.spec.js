import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import CredentialPicker from '@/components/credential/CredentialPicker.vue'

// 共用憑證選擇器。
//
// 斷言重心在兩件事：
//  1. 相容性判準在伺服端，故 picker 必須把「表單當下的協定」送出去，而且協定一變就重問。
//     忘了送、或送了卻沿用上一次的清單，畫面上都只是「多了幾筆看起來也能選的憑證」，
//     直到掛載被拒才知道。本檔的替身伺服端會照參數過濾，漏送即失敗。
//  2. `windows_openssh` 只在 ssh 上成立：別的協定帶著它是不相容組合，端點會整筆拒絕。
//  3. 就地新增之後那一筆要被選起來——不然使用者得再開一次下拉找自己剛建的東西。

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

const listMock = vi.fn()
vi.mock('@/api/credentials', () => ({
  listCredentials: (...a) => listMock(...a),
}))

const cred = (over = {}) => ({
  id: 1,
  name: '正式區 root',
  scope: 'shared',
  username: 'root',
  secret_type: 'password',
  protocol_family: 'ssh',
  binding_count: 12,
  rotation_active: false,
  ...over,
})

const SERVER_ROWS = [
  cred({ id: 1, name: '正式區 root', protocol_family: 'ssh' }),
  cred({ id: 2, name: 'ops 部署金鑰', protocol_family: 'ssh', secret_type: 'ssh_key', binding_count: 8 }),
  cred({ id: 3, name: 'DB 維運 postgres', protocol_family: 'database', username: 'postgres', binding_count: 3 }),
]

// 照契約過濾的替身伺服端：picker 沒送 protocol 就會拿到全部，
// 於是「只列相容者」的斷言會直接失敗
const PROTOCOL_FAMILY = { ssh: 'ssh', mysql: 'database', postgres: 'database', rdp: 'windows' }

const fakeServer = (rows = SERVER_ROWS) => (params = {}) => {
  const family = PROTOCOL_FAMILY[params.protocol]
  const data = params.protocol ? rows.filter((row) => row.protocol_family === family) : rows
  return Promise.resolve({ data, total: data.length })
}

const formDialogStub = {
  name: 'CredentialFormDialog',
  props: ['modelValue'],
  emits: ['update:modelValue', 'saved'],
  template: '<button class="form-dialog-stub" @click="$emit(\'saved\')">saved</button>',
}

async function mountPicker(props = {}) {
  const wrapper = mount(CredentialPicker, {
    global: {
      plugins: [ElementPlus],
      stubs: { CredentialFormDialog: formDialogStub },
    },
    props: { protocol: 'ssh', ...props },
  })
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  vi.clearAllMocks()
  listMock.mockImplementation(fakeServer())
})

describe('協定相容性由伺服端回答', () => {
  it('資料庫協定下清單只列相容者（ssh 憑證不出現）', async () => {
    const wrapper = await mountPicker({ protocol: 'mysql' })

    expect(listMock).toHaveBeenCalledWith({ scope: 'shared', protocol: 'mysql' })
    const names = wrapper.vm.options.map((item) => item.name)
    expect(names).toEqual(['DB 維運 postgres'])
    expect(names).not.toContain('正式區 root')
  })

  it('協定改變即重問伺服端，並清掉在舊協定下才成立的選擇', async () => {
    const wrapper = await mountPicker({ protocol: 'ssh', modelValue: 1 })
    expect(wrapper.vm.options).toHaveLength(2)

    await wrapper.setProps({ protocol: 'mysql' })
    await flushPromises()

    expect(wrapper.emitted('update:modelValue')[0]).toEqual([null])
    expect(wrapper.vm.options.map((item) => item.id)).toEqual([3])
  })

  it('windows_openssh 只在 ssh 上送出（其他協定帶著它會被端點整筆拒絕）', async () => {
    await mountPicker({ protocol: 'ssh', windowsOpenssh: true })
    expect(listMock).toHaveBeenLastCalledWith({
      scope: 'shared',
      protocol: 'ssh',
      windows_openssh: true,
    })

    listMock.mockClear()
    await mountPicker({ protocol: 'rdp', windowsOpenssh: true })
    expect(listMock).toHaveBeenLastCalledWith({ scope: 'shared', protocol: 'rdp' })
  })

  it('已掛在這台上的憑證不出現（同一台不會掛兩次同一筆）', async () => {
    const wrapper = await mountPicker({ protocol: 'ssh', excludeIds: [1] })
    expect(wrapper.vm.options.map((item) => item.id)).toEqual([2])
  })
})

describe('就地新增共用憑證', () => {
  it('新增後被直接選用（不必再開一次下拉找自己剛建的那一筆）', async () => {
    const wrapper = await mountPicker({ protocol: 'ssh' })
    expect(wrapper.vm.options).toHaveLength(2)

    // 建立對話框只回報「存好了」：重載後新出現的識別即本次建立的那一筆
    const created = cred({ id: 9, name: '新的共用憑證', protocol_family: 'ssh' })
    listMock.mockImplementation(fakeServer([...SERVER_ROWS, created]))

    await wrapper.find('.form-dialog-stub').trigger('click')
    await flushPromises()

    const picked = wrapper.emitted('update:modelValue').at(-1)
    expect(picked).toEqual([9])
    expect(wrapper.vm.options.map((item) => item.id)).toEqual([1, 2, 9])
  })

  it('新憑證與這台的協定不相容時就地說明，不靜默什麼都沒發生', async () => {
    const wrapper = await mountPicker({ protocol: 'ssh' })

    // 使用者在對話框裡選了資料庫協定：重載後它不會出現在這台的清單裡
    listMock.mockImplementation(
      fakeServer([...SERVER_ROWS, cred({ id: 9, name: '別的協定', protocol_family: 'database' })])
    )
    await wrapper.find('.form-dialog-stub').trigger('click')
    await flushPromises()

    expect(wrapper.emitted('update:modelValue')).toBeUndefined()
    expect(wrapper.vm.options.map((item) => item.id)).toEqual([1, 2])
  })
})
