import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, enableAutoUnmount, flushPromises } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import SubjectPicker from '../SubjectPicker.vue'
import { setCapabilitiesForTests, resetCapabilities } from '@/composables/useCapabilities'

// 深連結帶入的主體：首次載入對上選項時回報 resolve（給頁面當顯示名），
// 對不上時補佔位項；兩者都不得冒充使用者挑選（不發 change）

enableAutoUnmount(afterEach)

const subjectsMock = vi.fn()
vi.mock('@/api/auditTimeline', () => ({
  getAuditSubjects: (...args) => subjectsMock(...args),
}))
const getCurrentUserMock = vi.fn()
vi.mock('@/api/auth', () => ({ getCurrentUser: (...a) => getCurrentUserMock(...a) }))
const userDetailMock = vi.fn()
vi.mock('@/api/user', () => ({
  getUserDetail: (...args) => userDetailMock(...args),
}))

const mountPicker = async (props) => {
  const w = mount(SubjectPicker, {
    props: { subjectType: 'user', ...props },
    global: { plugins: [ElementPlus], stubs: { 'el-select': true, 'el-option': true } },
  })
  await flushPromises()
  return w
}

beforeEach(() => {
  vi.clearAllMocks()
  resetCapabilities()
  getCurrentUserMock.mockResolvedValue({ id: 1, permissions: [] })
  subjectsMock.mockResolvedValue({
    data: [
      { id: 84, name: 'operator-a', active: true },
      { id: 85, name: 'operator-b', active: true },
    ],
  })
})

describe('SubjectPicker 深連結', () => {
  it('帶入的 id 在清單內 → 發 resolve 帶該選項，不發 change', async () => {
    const w = await mountPicker({ modelValue: 84 })
    expect(w.emitted('resolve')).toEqual([[{ id: 84, name: 'operator-a', active: true }]])
    expect(w.emitted('change')).toBeUndefined()
  })

  it('帶入的 id 不在清單內、檢視者進不了使用者管理 → 不查、不發 resolve（維持 #編號）', async () => {
    const w = await mountPicker({ modelValue: 999 })
    expect(userDetailMock).not.toHaveBeenCalled()
    expect(w.emitted('resolve')).toBeUndefined()
  })

  it('帶入的 id 不在清單內、能進使用者管理 → 以編號查名稱後發 resolve', async () => {
    setCapabilitiesForTests(['user:manage'])
    userDetailMock.mockResolvedValue({ data: { id: 112, username: 'operator-c', full_name: '', active: true } })
    const w = await mountPicker({ modelValue: 112 })
    expect(userDetailMock).toHaveBeenCalledWith(112, { quiet: true })
    expect(w.emitted('resolve')).toEqual([[{ id: 112, name: 'operator-c', display_name: '', active: true }]])
  })

  it('以編號查不到 → 不發 resolve', async () => {
    setCapabilitiesForTests(['user:manage'])
    userDetailMock.mockRejectedValue(new Error('404'))
    const w = await mountPicker({ modelValue: 112 })
    expect(w.emitted('resolve')).toBeUndefined()
  })

  it('資產樞紐不以使用者編號查詢', async () => {
    setCapabilitiesForTests(['user:manage'])
    const w = await mountPicker({ modelValue: 999, subjectType: 'asset' })
    expect(userDetailMock).not.toHaveBeenCalled()
    expect(w.emitted('resolve')).toBeUndefined()
  })

  it('沒有帶入主體 → 不發 resolve', async () => {
    const w = await mountPicker({ modelValue: null })
    expect(w.emitted('resolve')).toBeUndefined()
  })
})
