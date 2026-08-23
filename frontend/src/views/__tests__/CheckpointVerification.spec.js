import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import CheckpointVerification from '../CheckpointVerification.vue'
import zhTW from '@/i18n/locales/zh-TW.json'
import enUS from '@/i18n/locales/en-US.json'
import jaJP from '@/i18n/locales/ja-JP.json'

// 檢查點驗證頁（audit-checkpoint-chain 第 9 組）。
//
// 本檔的斷言重心不在版面，而在三件 spec 明文要求的事：
// R0-R6 全部承載、九態各有可辨識文案且 purged_legal 不是錯誤色、
// 以及**頁面沒有任何寫操作入口**（auditor 可入本頁）。

enableAutoUnmount(afterEach)

const LIMIT_CODES = ['R0', 'R1', 'R2', 'R3', 'R4', 'R5', 'R6']
// P4 為自動驗證那條：保護範圍的條數
// 只增不減，少一條即為事實被砍掉
const PROTECTION_CODES = ['P1', 'P2', 'P3', 'P4']

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

const verifyChainMock = vi.fn()
const listCheckpointsMock = vi.fn()
const getPublicKeyMock = vi.fn()
const verifyContentMock = vi.fn()

vi.mock('@/api/auditCheckpoints', () => ({
  verifyChain: (...a) => verifyChainMock(...a),
  listCheckpoints: (...a) => listCheckpointsMock(...a),
  getCheckpointPublicKey: (...a) => getPublicKeyMock(...a),
  verifyCheckpointContent: (...a) => verifyContentMock(...a),
}))

const chainFixture = (overrides = {}) => ({
  data: {
    chain: {
      total: 12,
      latest_seq: 12,
      oldest_seq: 1,
      passed: 12,
      failed: 0,
      status: 'passed',
      failures: [],
      unsealed_rows: 37,
      unsealed_from_id: 5001,
      anchor_disabled: false,
      seal_interval_seconds: 3600,
      seal_row_threshold: 10000,
      ...overrides,
    },
  },
})

const mountPage = () =>
  mount(CheckpointVerification, { global: { plugins: [ElementPlus] } })

// 以 zh-TW 樣板重算 R5 應顯示的窗口敘述。測試自己算而非寫死字串，
// 才驗得到「數字來自 API」；期望值若寫死，前端改回硬編碼一樣會綠
const expandWindow = (raw, secs, rows) => {
  if (!raw.includes('{window}')) return raw
  const L = zhTW.checkpointVerification.limits
  const interval =
    secs % 3600 === 0
      ? L.intervalHours.replace('{n}', String(secs / 3600))
      : L.intervalMinutes.replace('{n}', String(secs / 60))
  return raw.replace(
    '{window}',
    L.window.replace('{interval}', interval).replace('{rows}', rows.toLocaleString())
  )
}

beforeEach(() => {
  localStorage.setItem(
    'user',
    JSON.stringify({ id: 3, username: 'auditor1', roles: ['auditor'] })
  )
  verifyChainMock.mockResolvedValue(chainFixture())
  listCheckpointsMock.mockResolvedValue({
    data: {
      items: [
        {
          seq: 12,
          id_from: 4900,
          id_to: 5000,
          row_count: 101,
          sealed_at: '2026-08-12T01:00:00Z',
          anchor_status: 'disabled',
          purged_at: null,
        },
      ],
      total: 1,
    },
  })
  getPublicKeyMock.mockResolvedValue({
    data: {
      algorithm: 'Ed25519',
      version: 1,
      public_key: 'AAAA',
      fingerprint: '0123456789abcdef',
    },
  })
  verifyContentMock.mockResolvedValue({ data: { content: { intervals: [] } } })
})

describe('檢查點驗證頁', () => {
  it('掛載即載入結構層、清單與公鑰（無需先輸入參數）', async () => {
    mountPage()
    await flushPromises()
    expect(verifyChainMock).toHaveBeenCalledTimes(1)
    expect(listCheckpointsMock).toHaveBeenCalledTimes(1)
    expect(getPublicKeyMock).toHaveBeenCalledTimes(1)
    // 結構層是預設面；內容層必須手動觸發（它會重掃 audit_logs）
    expect(verifyContentMock).not.toHaveBeenCalled()
  })

  it('鏈健康總覽含未封尾段列數（R5 窗口）', async () => {
    const wrapper = mountPage()
    await flushPromises()
    expect(wrapper.find('[data-test="unsealed-rows"]').text()).toBe('37')
    expect(wrapper.find('[data-test="chain-status"]').text()).toBe(
      zhTW.checkpointVerification.status.passed
    )
  })

  it('未啟用離機錨定時顯示降級橫幅，且不可關閉', async () => {
    verifyChainMock.mockResolvedValue(chainFixture({ anchor_disabled: true }))
    const wrapper = mountPage()
    await flushPromises()
    const banner = wrapper.find('.degrade-banner')
    expect(banner.exists()).toBe(true)
    expect(banner.text()).toContain(
      zhTW.checkpointVerification.degraded.title
    )
    // 關閉鈕不得存在（spec：SHALL NOT 可被關閉或摺疊至不可見）
    expect(banner.find('.el-alert__close-btn').exists()).toBe(false)
  })

  it('啟用錨定時不顯示降級橫幅（橫幅不是常駐裝飾）', async () => {
    const wrapper = mountPage()
    await flushPromises()
    expect(wrapper.find('.degrade-banner').exists()).toBe(false)
  })

  it('邊界 R0-R6 全數承載，且每條同時呈現情境與承擔', async () => {
    const wrapper = mountPage()
    await flushPromises()
    for (const code of LIMIT_CODES) {
      const limit = zhTW.checkpointVerification.limits[code]
      // 兩部分缺一即不合規：只列防不了什麼會使讀者誤判整體控制失效
      expect(
        wrapper.find(`[data-test="limit-${code}-scenario"]`).text()
      ).toBe(expandWindow(limit.scenario, 3600, 10000))
      expect(
        wrapper.find(`[data-test="limit-${code}-mitigation"]`).text()
      ).toBe(limit.mitigation)
    }
  })

  it('R5 的窗口上界取自現行門檻，不是寫死的一小時', async () => {
    // 封章週期自 audit-checkpoint-chain 起可由管理員調整（上限 24 小時／
    // 百萬筆）。文案若寫死，管理員一調就成了對稽核的假陳述——邊界聲明
    // 錯得比沒有更糟，故此處驗「換一組門檻，頁面跟著換」
    verifyChainMock.mockResolvedValue(
      chainFixture({ seal_interval_seconds: 1800, seal_row_threshold: 5000 })
    )
    const wrapper = mountPage()
    await flushPromises()
    const text = wrapper.find('[data-test="limit-R5-scenario"]').text()
    expect(text).toBe(
      expandWindow(zhTW.checkpointVerification.limits.R5.scenario, 1800, 5000)
    )
    expect(text).toContain('30 分鐘')
    expect(text).toContain('5,000')
    // 舊的寫死值不得殘留在任何語言的樣板裡
    for (const locale of [zhTW, enUS, jaJP]) {
      const raw = locale.checkpointVerification.limits.R5.scenario
      expect(raw).toContain('{window}')
      expect(raw).not.toMatch(/一小時|一萬筆|one hour|ten thousand|1 時間|1 万件/)
    }
  })

  it('門檻未載入時 R5 不顯示任何窗口數字（寧缺勿錯）', async () => {
    // 載入失敗或尚未回應時，句子少掉括號仍是完整且為真的敘述；
    // 若在此時 fallback 到預設值，顯示的就是一個未經證實的數字
    verifyChainMock.mockRejectedValue(new Error('boom'))
    const wrapper = mountPage()
    await flushPromises()
    const text = wrapper.find('[data-test="limit-R5-scenario"]').text()
    expect(text).toBe(
      zhTW.checkpointVerification.limits.R5.scenario.replace('{window}', '')
    )
    expect(text).not.toMatch(/\d/)
  })

  it('保護範圍三點呈現於邊界之前（稽核先讀到證明什麼）', async () => {
    const wrapper = mountPage()
    await flushPromises()
    const scope = wrapper.find('[data-test="protection-scope"]')
    expect(scope.exists()).toBe(true)
    for (const code of PROTECTION_CODES) {
      expect(scope.text()).toContain(
        zhTW.checkpointVerification.limits.protection[code]
      )
    }
    // 順序是規範要求而非版面偏好：先讀到保護範圍，邊界才會被讀成範圍界定
    const html = wrapper.html()
    expect(html.indexOf('data-test="protection-scope"')).toBeGreaterThan(-1)
    expect(html.indexOf('data-test="protection-scope"')).toBeLessThan(
      html.indexOf('data-test="honest-limits"')
    )
  })

  it('降級橫幅為狀態描述＋為什麼＋怎麼做＋既有缺口如何處置', async () => {
    verifyChainMock.mockResolvedValue(chainFixture({ anchor_disabled: true }))
    const wrapper = mountPage()
    await flushPromises()
    const banner = wrapper.find('.degrade-banner')
    for (const part of ['why', 'action', 'gap']) {
      expect(banner.find(`[data-test="degraded-${part}"]`).text()).toBe(
        zhTW.checkpointVerification.degraded[part]
      )
    }
    // 「怎麼啟用」不得只講後果：行動段必須指出設定所在
    expect(zhTW.checkpointVerification.degraded.action).toContain('安全政策')
    // 事實不得弱化：啟用前的缺口無法回溯補上，此句必須留著
    expect(zhTW.checkpointVerification.degraded.gap).toContain('無法回溯補上')
  })

  it('內容層未填範圍即擋下，不打 API', async () => {
    const wrapper = mountPage()
    await flushPromises()
    await wrapper.find('[data-test="run-content"]').trigger('click')
    await flushPromises()
    expect(verifyContentMock).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain(
      zhTW.checkpointVerification.content.rangeRequired
    )
  })

  it('頁面無任何寫操作入口（auditor 可入本頁）', async () => {
    const wrapper = mountPage()
    await flushPromises()
    // 唯一的按鈕是「重新整理」與「執行內容層驗證」，兩者皆唯讀
    const labels = wrapper.findAll('button').map((b) => b.text())
    const writeWords = ['刪除', '新增', '儲存', '編輯', '重簽', '補蓋', '設定']
    for (const label of labels) {
      for (const w of writeWords) {
        expect(label).not.toContain(w)
      }
    }
  })
})

// 邊界聲明的可讀性守衛（spec scenario「邊界聲明以稽核可理解的語言撰寫」）。
//
// 讀者是合規稽核人員不是工程師：頁面出現內部函式名、狀態機器碼或實作術語，
// 稽核只會讀到「一堆洞」。本組守衛掃的是**整個頁面 namespace 的三語文案**，
// 不只邊界段——同一把尺也適用於降級橫幅與九態研判說明。
//
// **與後端完整版守衛的分工（勿讓兩份規則漂移）**：
// `backend/internal/auditcopy/auditor_copy_guard_test.go` 是完整射程版，掃四個對外
// namespace（checkpointVerification、auditorWorkbench、policyNote、policyLabel）
// × 三語 × 全部葉鍵，並多帶「邊界兩部分齊備」「保護範圍鍵序在前」「豁免上限釘定」
// 三支。本檔射程是它的子集，保留的理由是它守著 Go 到不了的東西——渲染後 DOM 的
// 段落順序（見上方 protection-scope／honest-limits 的 indexOf 斷言）與元件行為，
// 外加編輯 Vue 時的秒級回饋。
// 下方 JARGON／CJK_JARGON 的每個詞在後端詞表中都有對應（後端為超集，2026-08-13 對齊）；
// **改動任一邊的詞表都必須同步另一邊**。此約束無法機械化：backend 容器只掛得到
// locale 目錄，掛不到本檔，於容器內讀它只會得到一個永遠 skip 的測試。
describe('對外文案的可讀性（無內部函式名與狀態機器碼）', () => {
  // 機器碼形態：snake_case（extra_rows_valid_hmac、anchor_status）
  const SNAKE_CASE = /[a-z0-9]+_[a-z0-9_]+/
  // 內部函式名形態：camelCase（writeToFile、sealCheckpoint）
  const CAMEL_CASE = /\b[a-z]+[A-Z][A-Za-z]*/
  // 實作術語：稽核讀不懂，且多半是把內部詞彙直接搬到介面上
  const JARGON =
    /\b(hmac|kek|udp|tcp|syslog|grace|payload|seq|tombstone|enqueue[a-z]*|sql|api|json|hash|nonce)\b/i
  // 中日文的實作術語（照抄內部用語，稽核同樣讀不懂）
  const CJK_JARGON = /封章|列級|聚合|入列|蓋章|機器碼|行レベル|キュー投入/

  const collect = (node, prefix, out) => {
    for (const [k, v] of Object.entries(node)) {
      if (v && typeof v === 'object') collect(v, `${prefix}${k}.`, out)
      // 插值變數是程式碼契約而非可讀文案，掃描前先剝除
      else if (typeof v === 'string')
        out.push([`${prefix}${k}`, v.replace(/\{[^}]*\}/g, '')])
    }
    return out
  }

  for (const [name, locale] of [
    ['zh-TW', zhTW],
    ['en-US', enUS],
    ['ja-JP', jaJP],
  ]) {
    it(`${name} 的驗證頁文案不含機器碼、函式名或實作術語`, () => {
      const entries = collect(locale.checkpointVerification, '', [])
      expect(entries.length).toBeGreaterThan(30)
      for (const [key, text] of entries) {
        expect(SNAKE_CASE.test(text), `${key} 出現機器碼：${text}`).toBe(false)
        expect(CAMEL_CASE.test(text), `${key} 出現函式名：${text}`).toBe(false)
        expect(JARGON.test(text), `${key} 出現實作術語：${text}`).toBe(false)
        expect(CJK_JARGON.test(text), `${key} 出現實作術語：${text}`).toBe(
          false
        )
      }
    })
  }

  // 同一把尺延伸到封章門檻兩個政策鍵的對外文案（讀者同為稽核：
  // 安全政策頁的說明會被當成控制描述引用，出現機器碼一樣毀掉可讀性）。
  //
  // **掃描範圍限定 audit_checkpoint_* 兩鍵**：policyLabel 其餘四十餘鍵
  // 早於本標準存在，且合法帶有協定專名（syslog／RDP／VNC／LDAP），全族掃描只能
  // 靠豁免清單成立——而「豁免清單只驗刪除不驗放寬」是 docs/dev/testing.md §5
  // 點名的假綠形態。與其造一份會被逐鍵放寬的清單，不如誠實界定射程。
  // 為免射程靜默縮成空集合（鍵改名／namespace 改動），逐鍵斷言存在且斷言總數。
  const POLICY_KEYS = [
    'audit_checkpoint_interval_seconds',
    'audit_checkpoint_row_threshold',
  ]
  const POLICY_FAMILIES = ['policyNote', 'policyLabel']

  for (const [name, locale] of [
    ['zh-TW', zhTW],
    ['en-US', enUS],
    ['ja-JP', jaJP],
  ]) {
    it(`${name} 的封章政策鍵文案不含機器碼、函式名或實作術語`, () => {
      const entries = []
      for (const family of POLICY_FAMILIES) {
        for (const key of POLICY_KEYS) {
          const value = locale[family]?.[key]
          expect(typeof value, `${family}.${key} 缺譯文`).toBe('string')
          entries.push([`${family}.${key}`, value.replace(/\{[^}]*\}/g, '')])
        }
      }
      expect(entries.length).toBe(POLICY_FAMILIES.length * POLICY_KEYS.length)
      for (const [key, text] of entries) {
        expect(SNAKE_CASE.test(text), `${key} 出現機器碼：${text}`).toBe(false)
        expect(CAMEL_CASE.test(text), `${key} 出現函式名：${text}`).toBe(false)
        expect(JARGON.test(text), `${key} 出現實作術語：${text}`).toBe(false)
        expect(CJK_JARGON.test(text), `${key} 出現實作術語：${text}`).toBe(
          false
        )
      }
    })
  }

  it('保護範圍與七條邊界的兩部分在三語皆齊備', () => {
    for (const [name, locale] of [
      ['zh-TW', zhTW],
      ['en-US', enUS],
      ['ja-JP', jaJP],
    ]) {
      const limits = locale.checkpointVerification.limits
      for (const p of PROTECTION_CODES) {
        expect(limits.protection[p], `${name} 缺保護範圍 ${p}`).toBeTruthy()
      }
      for (const code of LIMIT_CODES) {
        expect(limits[code]?.scenario, `${name} 缺 ${code} 情境`).toBeTruthy()
        expect(
          limits[code]?.mitigation,
          `${name} 缺 ${code} 承擔`
        ).toBeTruthy()
      }
      for (const k of ['scenarioLabel', 'mitigationLabel', 'boundaryTitle']) {
        expect(limits[k], `${name} 缺 ${k}`).toBeTruthy()
      }
      for (const k of ['title', 'why', 'action', 'gap']) {
        expect(
          locale.checkpointVerification.degraded[k],
          `${name} 缺降級橫幅 ${k}`
        ).toBeTruthy()
      }
    }
  })

  it('舊的扁平邊界字串已移除（否則守衛掃不到新結構下的術語）', () => {
    for (const locale of [zhTW, enUS, jaJP]) {
      for (const code of LIMIT_CODES) {
        expect(typeof locale.checkpointVerification.limits[code]).toBe('object')
      }
      expect(locale.checkpointVerification.degraded.desc).toBeUndefined()
    }
  })
})

describe('九態文案與視覺分級', () => {
  const STATUSES = [
    'passed',
    'purged_legal',
    'purged_invalid',
    'count_mismatch',
    'hash_mismatch',
    'extra_rows_valid_hmac',
    'signature_invalid',
    'chain_broken',
    'seq_gap',
  ]

  it('九態在三語皆有狀態名，且彼此不重複（可辨識）', () => {
    for (const locale of [zhTW, enUS, jaJP]) {
      const names = STATUSES.map(
        (s) => locale.checkpointVerification.status[s]
      )
      for (const n of names) {
        expect(n, `狀態名缺譯文：${names}`).toBeTruthy()
      }
      expect(new Set(names).size).toBe(STATUSES.length)
    }
  })

  it('purged_legal 不得呈現為錯誤色（合法清除不是異常）', async () => {
    verifyContentMock.mockResolvedValue({
      data: {
        content: {
          intervals: [
            {
              seq: 3,
              id_from: 1,
              id_to: 10,
              row_count: 10,
              remain_rows: 0,
              anchor_status: 'enqueued',
              status: 'purged_legal',
            },
          ],
        },
      },
    })
    const wrapper = mountPage()
    await flushPromises()
    wrapper.vm.seqFrom = 3
    wrapper.vm.seqTo = 3
    await wrapper.find('[data-test="run-content"]').trigger('click')
    await flushPromises()
    const tags = wrapper.findAll('.content-table .el-tag')
    expect(tags.length).toBeGreaterThan(0)
    expect(tags[0].classes().join(' ')).not.toContain('el-tag--danger')
    expect(tags[0].text()).toBe(
      zhTW.checkpointVerification.status.purged_legal
    )
  })

  it('每個非通過狀態都有研判說明（不把成因壓成單一失敗）', () => {
    for (const s of STATUSES.filter((s) => s !== 'passed')) {
      for (const locale of [zhTW, enUS, jaJP]) {
        expect(
          locale.checkpointVerification.statusHint[s],
          `${s} 缺研判說明`
        ).toBeTruthy()
      }
    }
  })
})

// 自動驗證的運作狀態區塊。
//
// 這組守的是兩件事，缺任一件這個區塊就會誤導稽核：
//   1. **它必須看得見**——偵測控制若在畫面上不存在，稽核只能假設它沒在跑，
//      而排程靜默停擺時不會有任何告警（沒跑就沒有異常可報）；
//   2. **它必須明說自己不是證明**——這份狀態不在鏈的覆蓋範圍內，可被資料庫
//      直寫改成「最近驗過、全數通過」。那句話得在畫面上，不是在註解或 spec 裡。
describe('自動驗證狀態區塊', () => {
  const AUTO_VERIFY = {
    recent_last_run_at: '2026-08-14T02:00:00Z',
    recent_last_status: 'passed',
    recent_window_days_effective: 7,
    full_last_run_at: '2026-08-14T01:00:00Z',
    full_last_status: 'failed',
    full_interval_seconds: 3600,
    content_cursor_seq: 42,
    last_full_cycle_at: null,
    open_failed_intervals: 2,
    structure_failed_count: 0,
    rows_per_hour: 1000000,
    cycle_estimate_hours: 96,
  }

  const AV = zhTW.checkpointVerification.autoVerify

  it('兩層各自的最近執行時點與結果、生效窗口、進度、繞行預估、未結案數全部呈現', async () => {
    verifyChainMock.mockResolvedValue(chainFixture({ auto_verify: AUTO_VERIFY }))
    const wrapper = mountPage()
    await flushPromises()
    const panel = wrapper.find('[data-test="auto-verify"]')
    expect(panel.exists()).toBe(true)

    // 兩層各記一組：壓成一個欄位會讓「其中一層已死」在畫面上看不出來
    expect(panel.find('[data-test="auto-verify-recent-run"]').text()).not.toBe('')
    expect(panel.find('[data-test="auto-verify-full-run"]').text()).not.toBe('')
    expect(panel.find('[data-test="auto-verify-recent-result"]').text()).toBe(
      AV.resultPassed
    )
    expect(panel.find('[data-test="auto-verify-full-result"]').text()).toBe(
      AV.resultFailed
    )
    // 顯示的是生效值（政策值經保留天數 clamp 後），不是設定值
    expect(panel.find('[data-test="auto-verify-window"]').text()).toBe(
      AV.windowDays.replace('{n}', '7')
    )
    expect(panel.find('[data-test="auto-verify-interval"]').text()).toBe(
      zhTW.checkpointVerification.limits.intervalHours.replace('{n}', '1')
    )
    expect(panel.find('[data-test="auto-verify-progress"]').text()).toBe('42')
    // 繞行一輪的成本照實顯示，不隱藏（96 小時＝約 4 天）
    expect(panel.find('[data-test="auto-verify-cycle"]').text()).toBe(
      AV.cycleDays.replace('{n}', '4')
    )
    expect(panel.find('[data-test="auto-verify-open-failed"]').text()).toBe('2')
  })

  it('明示為營運狀態而非完整性證明，且該句在畫面上', async () => {
    verifyChainMock.mockResolvedValue(chainFixture({ auto_verify: AUTO_VERIFY }))
    const wrapper = mountPage()
    await flushPromises()
    const note = wrapper.find('[data-test="auto-verify-not-evidence"]')
    expect(note.exists()).toBe(true)
    expect(note.text()).toBe(AV.notEvidence)
    // 三語都得把「不是證明」講出來，且指出真正的證據在哪
    expect(AV.notEvidence).toContain('不是完整性證明')
    expect(enUS.checkpointVerification.autoVerify.notEvidence).toContain(
      'not proof of integrity'
    )
    expect(jaJP.checkpointVerification.autoVerify.notEvidence).toContain(
      '完全性の証明ではありません'
    )
  })

  it('狀態取不到時明說取不到，不隱藏整個區塊', async () => {
    // 隱藏區塊會讓稽核讀成「沒有這個機制」，比顯示一個取不到值的區塊更糟
    verifyChainMock.mockResolvedValue(chainFixture())
    const wrapper = mountPage()
    await flushPromises()
    const panel = wrapper.find('[data-test="auto-verify"]')
    expect(panel.exists()).toBe(true)
    expect(panel.find('[data-test="auto-verify-unavailable"]').exists()).toBe(
      true
    )
    expect(panel.text()).toContain(AV.notEvidence)
  })

  it('某一層從未執行過時顯示「尚未執行過」，不留白', async () => {
    verifyChainMock.mockResolvedValue(
      chainFixture({
        auto_verify: {
          ...AUTO_VERIFY,
          recent_last_run_at: null,
          recent_last_status: '',
          recent_window_days_effective: 0,
        },
      })
    )
    const wrapper = mountPage()
    await flushPromises()
    const panel = wrapper.find('[data-test="auto-verify"]')
    expect(panel.find('[data-test="auto-verify-recent-run"]').text()).toBe(
      AV.never
    )
    // 未跑過不是「通過」：色階必須為中性
    const tag = panel.find('[data-test="auto-verify-recent-result"]')
    expect(tag.text()).toBe(AV.never)
    expect(tag.classes().join(' ')).not.toContain('el-tag--success')
  })

  it('自動驗證的三語文案齊備（缺一即該語系讀到鍵名）', () => {
    const keys = Object.keys(AV)
    expect(keys.length).toBeGreaterThan(20)
    for (const [name, locale] of [
      ['en-US', enUS],
      ['ja-JP', jaJP],
    ]) {
      for (const k of keys) {
        expect(
          locale.checkpointVerification.autoVerify?.[k],
          `${name} 缺 autoVerify.${k}`
        ).toBeTruthy()
      }
    }
  })

  it('保護範圍 P4 與 R5 承擔句釘住「範圍相同、只縮短發現時間」與「不涵蓋未封存區間」', () => {
    // 少了這兩句，「系統會自動驗證」會被讀成「所以什麼都逃不掉」
    expect(zhTW.checkpointVerification.limits.protection.P4).toContain(
      '縮短的是'
    )
    expect(enUS.checkpointVerification.limits.protection.P4).toContain(
      'not the range of what can be detected'
    )
    expect(jaJP.checkpointVerification.limits.protection.P4).toContain(
      '検出できる範囲が広がるわけではありません'
    )
    expect(zhTW.checkpointVerification.limits.R5.mitigation).toContain(
      '不涵蓋本條所述的尚未封存區間'
    )
    expect(enUS.checkpointVerification.limits.R5.mitigation).toContain(
      'does not cover the not-yet-sealed stretch'
    )
    expect(jaJP.checkpointVerification.limits.R5.mitigation).toContain(
      '未封印の区間は対象外'
    )
  })
})
