import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import ExportReportDialog from '../ExportReportDialog.vue'

// 匯出對話框的**兩種包型**。
//
// 斷言重心在五件「錯了就讓稽核拿著誤導文件或空手離開」的事：
// 1) 選了證據包就走非同步發起，且送出的參數形態合後端契約——**必須明示
//    `pack=evidence_bundle`**：缺席時後端沿舊推斷（帶 subject＝事件報告）會把它
//    判成報告並當場拒絕，畫面上卻看起來像成功送出；
// 2) 預填的樞紐／時窗／類別**照原樣呈現且真的送出去**（4b.1 起證據包也套類別）
//    ——過渡期的「證據包不套用類別篩選」現在是假的，退回即轉紅；
// 3) 聲明段隨包型整組換掉：報告的「不含錄影檔與剪貼簿內容」對證據包**逐句為假**，
//    留著就是對取件者說謊；
// 4) 入口帶進來的包型要生效（工具列兩顆按鈕各自預選），且 radio 仍可切；
// 5) 發起成功要導引到下載中心——這一按沒有檔案落下來，不導引使用者不知道發生過什麼。

enableAutoUnmount(afterEach)

const pushMock = vi.fn()
vi.mock('vue-router', () => ({
  useRouter: () => ({ push: pushMock }),
  useRoute: () => ({ path: '/audit/workbench', query: {} }),
}))

const exportMock = vi.fn()
const publicKeyMock = vi.fn()
const createJobMock = vi.fn()
vi.mock('@/api/auditExport', () => ({
  exportAuditEvidence: (...args) => exportMock(...args),
  getExportSigningPublicKey: (...args) => publicKeyMock(...args),
  createAuditExportJob: (...args) => createJobMock(...args),
}))

// el-dialog teleport 到 body，happy-dom 下 wrapper 撈不到——inline stub 保留
// 預設插槽與 footer，斷言仍看得到真實文案與真實按鈕
const dialogStub = {
  props: ['modelValue'],
  template:
    '<div v-if="modelValue" data-test="export-dialog"><slot /><slot name="footer" /></div>',
}

const FROM = '2026-08-12T00:00:00+08:00'
const TO = '2026-08-12T12:00:00+08:00'
const ALL_TYPES = ['session', 'command', 'audit_log', 'file_transfer', 'clipboard', 'alert']

const baseProps = (over = {}) => ({
  modelValue: true,
  params: {
    subject: 'user',
    user_id: 1,
    start_time: FROM,
    end_time: TO,
    types: 'clipboard,file_transfer',
  },
  subject: 'user',
  subjectName: 'admin',
  from: FROM,
  to: TO,
  types: ['clipboard', 'file_transfer'],
  counts: { clipboard: 3, file_transfer: 2 },
  coverage: ALL_TYPES.map((type) => ({ type, state: 'present' })),
  truncated: false,
  ...over,
})

const mountDialog = async (over = {}) => {
  const wrapper = mount(ExportReportDialog, {
    props: baseProps(over),
    global: { plugins: [ElementPlus], stubs: { 'el-dialog': dialogStub } },
  })
  await flushPromises()
  return wrapper
}

// EP 的 el-radio 實際可點的是內部 input
const pickBundle = async (wrapper) => {
  await wrapper.find('[data-test="export-pack-evidence_bundle"] input').setValue(true)
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  vi.clearAllMocks()
  publicKeyMock.mockResolvedValue({ data: { algorithm: 'Ed25519', public_key: 'AAA=' } })
  exportMock.mockResolvedValue(new Blob(['zip'], { type: 'application/zip' }))
  createJobMock.mockResolvedValue({ data: { id: 7, status: 'pending' }, deduplicated: false })
})

describe('兩種包型的選擇', () => {
  it('兩個選項都在，且入口就講得出差別（陳述 vs 證物、同步 vs 非同步）', async () => {
    const wrapper = await mountDialog()
    expect(wrapper.find('[data-test="export-pack-event_report"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="export-pack-evidence_bundle"]').exists()).toBe(true)
    const diff = wrapper.find('[data-test="export-pack-diff"]').text()
    expect(diff).toContain('陳述')
    expect(diff).toContain('證物')
    expect(diff).toContain('背景打包')
    expect(diff).toContain('下載中心')
  })

  it('預設是事件報告：確認鈕說「產生報告」，按下走同步端點', async () => {
    const wrapper = await mountDialog()
    expect(wrapper.find('[data-test="export-confirm"]').text()).toBe('產生報告')
    await wrapper.find('[data-test="export-confirm"]').trigger('click')
    await flushPromises()
    expect(exportMock).toHaveBeenCalledTimes(1)
    expect(createJobMock).not.toHaveBeenCalled()
  })

  it('切到證據包：確認鈕改說「發起打包」，按下改走 job 端點、不觸發同步匯出', async () => {
    const wrapper = await pickBundle(await mountDialog())
    expect(wrapper.find('[data-test="export-confirm"]').text()).toBe('發起打包')
    await wrapper.find('[data-test="export-confirm"]').trigger('click')
    await flushPromises()
    expect(createJobMock).toHaveBeenCalledTimes(1)
    expect(exportMock).not.toHaveBeenCalled()
  })

  it('重開對話框回到入口指定的包型（上次在框內切過不得沾黏，否則「按下即下載」的預期會落空）', async () => {
    const wrapper = await pickBundle(await mountDialog())
    expect(wrapper.find('[data-test="export-confirm"]').text()).toBe('發起打包')
    await wrapper.setProps({ modelValue: false })
    await wrapper.setProps({ modelValue: true })
    await flushPromises()
    expect(wrapper.find('[data-test="export-confirm"]').text()).toBe('產生報告')
  })

  // 工具列兩顆按鈕靠這個 prop 分工：按哪一顆就停在哪一種包
  it('入口指定證據包：開起來就是證據包態，不必再點一次 radio', async () => {
    const wrapper = await mountDialog({ pack: 'evidence_bundle' })
    expect(wrapper.find('[data-test="export-confirm"]').text()).toBe('發起打包')
    expect(wrapper.find('[data-test="export-limits"]').text()).toContain('這一包不能證明什麼')
  })

  it('預選只是省一次點擊，不是把另一種包鎖起來（radio 仍可切回事件報告）', async () => {
    const wrapper = await mountDialog({ pack: 'evidence_bundle' })
    await wrapper.find('[data-test="export-pack-event_report"] input').setValue(true)
    await flushPromises()
    expect(wrapper.find('[data-test="export-confirm"]').text()).toBe('產生報告')
    await wrapper.find('[data-test="export-confirm"]').trigger('click')
    await flushPromises()
    expect(exportMock).toHaveBeenCalledTimes(1)
    expect(createJobMock).not.toHaveBeenCalled()
  })

  it('證據包入口重開後仍是證據包（重置對象是入口指定值，不是寫死的事件報告）', async () => {
    const wrapper = await mountDialog({ pack: 'evidence_bundle' })
    await wrapper.find('[data-test="export-pack-event_report"] input').setValue(true)
    await flushPromises()
    await wrapper.setProps({ modelValue: false })
    await wrapper.setProps({ modelValue: true })
    await flushPromises()
    expect(wrapper.find('[data-test="export-confirm"]').text()).toBe('發起打包')
  })
})

describe('證據包的發起參數合後端契約', () => {
  it('明示 pack=evidence_bundle 並帶齊樞紐、時窗與類別（範圍＝畫面上的那一段）', async () => {
    const wrapper = await pickBundle(await mountDialog())
    await wrapper.find('[data-test="export-confirm"]').trigger('click')
    await flushPromises()
    expect(createJobMock.mock.calls.at(-1)[0]).toEqual({
      pack: 'evidence_bundle',
      subject: 'user',
      user_id: 1,
      start_time: FROM,
      end_time: TO,
      types: 'clipboard,file_transfer',
    })
  })

  it('pack 是必填不是裝飾：缺席時後端會把帶 subject 的請求判成事件報告而拒絕', async () => {
    const wrapper = await pickBundle(await mountDialog())
    await wrapper.find('[data-test="export-confirm"]').trigger('click')
    await flushPromises()
    expect(createJobMock.mock.calls.at(-1)[0].pack).toBe('evidence_bundle')
  })

  it('以資產調查時帶 asset_id（樞紐不會帶錯欄）', async () => {
    const wrapper = await pickBundle(
      await mountDialog({
        subject: 'asset',
        params: {
          subject: 'asset',
          asset_id: 7,
          start_time: FROM,
          end_time: TO,
          types: 'session',
        },
      })
    )
    await wrapper.find('[data-test="export-confirm"]').trigger('click')
    await flushPromises()
    const sent = createJobMock.mock.calls.at(-1)[0]
    expect(sent).toMatchObject({
      pack: 'evidence_bundle',
      subject: 'asset',
      asset_id: 7,
      types: 'session',
    })
    expect(sent.user_id).toBeUndefined()
  })

  it('父層日後多帶的範圍參數原樣送出（白名單會靜默丟掉，範圍與畫面不符卻沒人看得出來）', async () => {
    const wrapper = await pickBundle(
      await mountDialog({
        params: {
          subject: 'user',
          user_id: 1,
          start_time: FROM,
          end_time: TO,
          types: 'clipboard',
          session_id: 42,
        },
      })
    )
    await wrapper.find('[data-test="export-confirm"]').trigger('click')
    await flushPromises()
    expect(createJobMock.mock.calls.at(-1)[0].session_id).toBe(42)
  })
})

describe('預填的類別兩種包型都生效', () => {
  it('兩種包型都把預填的樞紐、時窗、類別逐項寫出來', async () => {
    const wrapper = await mountDialog()
    const assertPrefill = () => {
      expect(wrapper.find('[data-test="export-scope-subject"]').text()).toContain('admin')
      expect(wrapper.find('[data-test="export-scope-window"]').text()).toContain('2026')
      const types = wrapper.find('[data-test="export-scope-types"]').text()
      expect(types).toContain('剪貼簿')
      expect(types).toContain('檔案傳輸')
      expect(types).toContain('共 2 類')
    }
    assertPrefill() // 事件報告
    await pickBundle(wrapper)
    assertPrefill() // 證據包：同一組預填，一項都沒少
  })

  it('過渡期的「不套用類別篩選」整句退場（4b.1 起它是假的，退回即讓稽核多篩一輪或改選錯包型）', async () => {
    const wrapper = await mountDialog()
    await pickBundle(wrapper)
    const dialog = wrapper.find('[data-test="export-dialog"]').text()
    expect(dialog).not.toContain('不套用類別篩選')
    expect(dialog).not.toContain('收錄範圍內全部證物')
    // 兩種包型共用同一句類別說明——證據包不再有但書
    expect(wrapper.find('[data-test="export-scope-types"]').text()).toBe(
      '類別：剪貼簿、檔案傳輸（共 2 類）'
    )
  })

  it('改以「未勾選者整段不入包」這條邊界說明類別的射程（範圍不是該期間的全部證物）', async () => {
    const wrapper = await pickBundle(await mountDialog())
    const line = wrapper.find('[data-test="export-limit-bundle_category_scope"]')
    expect(line.exists()).toBe(true)
    expect(line.text()).toContain('只收錄勾選中的類別')
    expect(line.text()).toContain('不入包')
  })

  it('證據包的留存狀況蓋住勾選中的類別（它收的就是這幾類，多列會讓人以為包內有那些證物）', async () => {
    const wrapper = await mountDialog()
    expect(wrapper.findAll('[data-test^="export-coverage-"]')).toHaveLength(2)
    await pickBundle(wrapper)
    expect(wrapper.findAll('[data-test^="export-coverage-"]')).toHaveLength(2)
  })
})

describe('聲明段隨包型換掉（報告那組對證據包逐句為假）', () => {
  it('證據包不得留著「不含剪貼簿內容、檔案本體與錄影檔」那條——它正是含這些的那一種', async () => {
    const wrapper = await mountDialog()
    expect(wrapper.find('[data-test="export-limit-payload_excluded"]').exists()).toBe(true)
    await pickBundle(wrapper)
    expect(wrapper.find('[data-test="export-limit-payload_excluded"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="export-proves-bundle_contents"]').text()).toContain(
      '錄影'
    )
  })

  it('證據包的四條專屬邊界到齊：明文保管、非同步取件、只限本人、類別射程', async () => {
    const wrapper = await pickBundle(await mountDialog())
    for (const code of [
      'bundle_plaintext',
      'bundle_async',
      'bundle_requester_only',
      'bundle_category_scope',
      'bundle_clipboard_gap',
      'bundle_manifest_required',
    ]) {
      expect(
        wrapper.find(`[data-test="export-limit-${code}"]`).exists(),
        `缺邊界 ${code}`
      ).toBe(true)
    }
    expect(wrapper.find('[data-test="export-limit-bundle_requester_only"]').text()).toContain(
      '本人'
    )
    expect(wrapper.find('[data-test="export-limit-bundle_async"]').text()).toContain('逾期')
  })

  it('四段標題也跟著換：證據包不是「報告」，留著舊標題就是在描述另一種東西', async () => {
    const wrapper = await mountDialog()
    expect(wrapper.find('[data-test="export-proves"]').text()).toContain('這份報告能證明')
    await pickBundle(wrapper)
    for (const [block, expected] of [
      ['export-scope', '這一包涵蓋'],
      ['export-proves', '這一包能證明什麼'],
      ['export-limits', '這一包不能證明什麼'],
      ['export-coverage', '包內逐類別'],
    ]) {
      expect(wrapper.find(`[data-test="${block}"]`).text(), block).toContain(expected)
    }
    expect(wrapper.find('[data-test="export-dialog"]').text()).not.toContain('這份報告')
  })

  it('「能證明什麼」仍排在「不能證明什麼」之前（用語紀律不因包型改變）', async () => {
    const wrapper = await pickBundle(await mountDialog())
    const html = wrapper.html()
    expect(html.indexOf('data-test="export-proves"')).toBeLessThan(
      html.indexOf('data-test="export-limits"')
    )
  })

  it('簽章問不到時，證據包也不宣稱可獨立驗證', async () => {
    publicKeyMock.mockRejectedValue(new Error('network'))
    const wrapper = await pickBundle(await mountDialog())
    expect(wrapper.find('[data-test="export-proves-bundle_signature"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="export-signing-unknown"]').exists()).toBe(true)
  })
})

describe('發起成功導引至下載中心', () => {
  it('成功即導向 /audit/exports 並關閉對話框（沒有檔案落下來，不導引就等於沒回饋）', async () => {
    const wrapper = await pickBundle(await mountDialog())
    await wrapper.find('[data-test="export-confirm"]').trigger('click')
    await flushPromises()
    expect(pushMock).toHaveBeenCalledWith('/audit/exports')
    expect(wrapper.emitted('update:modelValue').at(-1)).toEqual([false])
  })

  it('命中去重（同範圍已在打包）也照樣導引——那份就是使用者要的', async () => {
    createJobMock.mockResolvedValue({ data: { id: 3, status: 'running' }, deduplicated: true })
    const wrapper = await pickBundle(await mountDialog())
    await wrapper.find('[data-test="export-confirm"]').trigger('click')
    await flushPromises()
    expect(pushMock).toHaveBeenCalledWith('/audit/exports')
  })

  it('發起失敗：不關對話框、不導引，且明說沒有建立任何打包工作', async () => {
    createJobMock.mockRejectedValue(new Error('boom'))
    const wrapper = await pickBundle(await mountDialog())
    await wrapper.find('[data-test="export-confirm"]').trigger('click')
    await flushPromises()
    expect(pushMock).not.toHaveBeenCalled()
    expect(wrapper.emitted('update:modelValue')).toBeUndefined()
    expect(wrapper.find('[data-test="export-failed"]').text()).toContain(
      '沒有建立任何打包工作'
    )
  })
})
