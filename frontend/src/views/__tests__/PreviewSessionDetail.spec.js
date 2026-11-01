// 以角色預覽時，會話詳情不簽發錄影票證，播放區改為停用說明。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import { resetCapabilities } from '@/composables/useCapabilities'
import { grantFor } from '@/composables/__tests__/capabilityFixtures'
import { applyPreviewResponse, beginPreviewRequest, cancelPreview } from '@/composables/useRolePreview'
import i18n from '@/i18n'

enableAutoUnmount(afterEach)

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)
vi.setConfig({ testTimeout: 20_000 })

const getSessionMock = vi.fn()
const tokenMock = vi.fn()
vi.mock('@/api/sessions', () => ({
  getSession: (...a) => getSessionMock(...a),
  getRecordingUrl: () => '',
  getRecordingToken: (...a) => tokenMock(...a),
  recordingStreamUrlByToken: () => 'blob:rec',
  downloadRecording: vi.fn(),
}))
vi.mock('@/api/commands', () => ({
  getSessionCommands: vi.fn().mockResolvedValue({ data: [] }),
}))
vi.mock('@/api/clipboardEvents', () => ({
  getSessionClipboardEvents: vi.fn().mockResolvedValue({ data: [] }),
  getClipboardEventContent: vi.fn(),
}))
const { rejectAll } = vi.hoisted(() => ({
  rejectAll: async (importOriginal) => {
    const actual = await importOriginal()
    return Object.fromEntries(
      Object.entries(actual).map(([k, v]) => [k, typeof v === 'function' ? vi.fn(() => Promise.reject(new Error('not mocked'))) : v]),
    )
  },
}))
vi.mock('@/api/alerts', rejectAll)
vi.mock('@/api/agentTasks', rejectAll)
vi.mock('@/api/offsiteStorage', () => ({
  getOffsiteSettings: vi.fn().mockResolvedValue({ configured: true, disabled: false }),
  retryOffsiteObject: vi.fn(),
}))
vi.mock('vue-router', () => ({
  useRoute: () => ({ params: { id: 's-1' } }),
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}))
vi.mock('element-plus', async (importOriginal) => {
  const actual = await importOriginal()
  return { ...actual, ElMessage: { error: vi.fn(), success: vi.fn(), warning: vi.fn() } }
})

import SessionDetail from '../SessionDetail.vue'

const session = {
  id: 1,
  session_id: 's-1',
  protocol: 'ssh',
  status: 'closed',
  end_reason: 'normal',
  client_ip: '127.0.0.1',
  start_time: '2026-07-20T08:00:00Z',
  end_time: '2026-07-20T08:10:00Z',
  duration: 600,
  has_recording: true,
  recording_error: '',
}

const mountPage = async () => {
  const w = mount(SessionDetail, { global: { plugins: [ElementPlus] } })
  await flushPromises()
  return w
}

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
  localStorage.setItem('user', JSON.stringify({ id: 2 }))
  resetCapabilities()
  grantFor(['auditor'])
  getSessionMock.mockResolvedValue(session)
  tokenMock.mockResolvedValue({ token: 't' })
})
afterEach(() => {
  cancelPreview()
})

describe('預覽中的會話詳情', () => {
  it('預覽中不呼叫錄影票證端點，播放區顯示停用說明', async () => {
    applyPreviewResponse(beginPreviewRequest(), {
      role: { id: 7, name: 'R7' },
      previewable: true,
      permissions: ['session:view'],
      entry_states: [],
    })
    const w = await mountPage()
    expect(tokenMock).not.toHaveBeenCalled()
    const note = w.get('[data-test="preview-recording-disabled"]')
    expect(note.text()).toContain(i18n.global.t('rolePreview.disabledTicket'))
  })

  it('非預覽時照常取得錄影票證', async () => {
    const w = await mountPage()
    expect(tokenMock).toHaveBeenCalledTimes(1)
    expect(w.find('[data-test="preview-recording-disabled"]').exists()).toBe(false)
  })
})
