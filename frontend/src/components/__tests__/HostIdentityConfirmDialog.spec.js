import { describe, it, expect, afterEach } from 'vitest'
import { mount, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import HostIdentityConfirmDialog from '../HostIdentityConfirmDialog.vue'
import i18n from '@/i18n'
import { formatDateTime } from '@/utils/format'

enableAutoUnmount(afterEach)

// el-dialog teleport 到 body，happy-dom 下 wrapper 撈不到——就地渲染的替身保留預設插槽與 footer
const dialogStub = {
  props: ['modelValue', 'title'],
  template:
    '<div v-if="modelValue" class="dialog-stub"><h3>{{ title }}</h3><slot /><slot name="footer" /></div>',
}

const FP_A = 'SHA256:q3Vt9xLk2mP8rT0aZ4bN7cY1eW6sH5jD'
const FP_B = 'SHA256:Zp7Qe2Rk9Lm4Xv8Bn3Tc6Ya1Wd5Hs0Uj'
const DEADLINE = '2026-10-18T02:00:00Z'
const SENT = '2026-10-17T02:00:00Z'
const RECORDED = '2026-10-17T10:05:00Z'

const identity = (over = {}) => ({
  status: 'changed',
  detail: 'generation_changed',
  phase: 'precheck',
  verification_sent: false,
  original: {
    transport: 'ssh',
    record_id: 41,
    algorithm: 'ssh-ed25519',
    fingerprint: FP_A,
    generation: 2,
    binding: 'bound',
    bound_at: SENT,
  },
  current: {
    transport: 'ssh',
    record_id: 41,
    algorithm: 'ssh-ed25519',
    fingerprint: FP_A,
    generation: 3,
    reset_pending: false,
    recorded_at: RECORDED,
  },
  candidate_applied: false,
  deadline: DEADLINE,
  expired: false,
  confirmable: true,
  ...over,
})

const differentKey = (over = {}) => {
  const base = identity()
  return identity({ current: { ...base.current, fingerprint: FP_B }, ...over })
}

const mountDialog = (id = identity(), props = {}) =>
  mount(HostIdentityConfirmDialog, {
    global: { plugins: [ElementPlus], stubs: { 'el-dialog': dialogStub } },
    props: {
      modelValue: true,
      asset: 'db-core-02.prod.tpe.example.internal',
      account: 'postgres',
      identity: id,
      ...props,
    },
  })

// 斷言實際渲染的文案：從 locale 取原句，不寫死也不只比鍵名
const msg = (key, params) => i18n.global.t(key, params)

const submitButton = (w) => w.find('[data-test="hic-submit"]')
const tickIdentity = (w) => w.find('[data-test="hic-check-identity"] input').setValue(true)
const tickDifferent = (w) => w.find('[data-test="hic-check-different-key"] input').setValue(true)

describe('第一層說明依 verification_sent 選句', () => {
  it('false：沒有拿新憑證去登入', () => {
    const w = mountDialog(identity({ verification_sent: false }))
    const text = w.find('[data-test="hic-intro"]').text()
    expect(text).toBe(msg('hostIdentityConfirm.intro.notSent'))
    expect(text).toContain('這次沒有拿新憑證去登入變更後的主機')
  })

  it('true：已登入驗證過但尚未套用', () => {
    const w = mountDialog(identity({ verification_sent: true, phase: 'commit' }))
    const text = w.find('[data-test="hic-intro"]').text()
    expect(text).toBe(msg('hostIdentityConfirm.intro.verifiedNotApplied'))
    expect(text).toContain('這次已用新憑證登入這台主機驗證過，但尚未套用')
    expect(text).not.toContain('沒有拿新憑證去登入')
  })

  it("'unknown'：無法確定是否已登入", () => {
    const w = mountDialog(identity({ verification_sent: 'unknown' }))
    const text = w.find('[data-test="hic-intro"]').text()
    expect(text).toBe(msg('hostIdentityConfirm.intro.unknown'))
    expect(text).toContain('無法確定這次是否已用新憑證登入')
    expect(text).not.toContain('沒有拿新憑證去登入')
  })

  it("phase='handshake' 且 true：看送出事實不看 phase，仍是已登入驗證版", () => {
    const w = mountDialog(identity({ phase: 'handshake', verification_sent: true }))
    const text = w.find('[data-test="hic-intro"]').text()
    expect(text).toBe(msg('hostIdentityConfirm.intro.verifiedNotApplied'))
    expect(text).not.toContain('沒有拿新憑證去登入')
  })

  it('標題與目標資產帳號顯示', () => {
    const w = mountDialog()
    expect(w.find('h3').text()).toBe('確認主機身分後再驗證')
    expect(w.find('[data-test="hic-target"]').text()).toBe(
      'db-core-02.prod.tpe.example.internal・帳號 postgres'
    )
  })
})

describe('同鑰', () => {
  it('標示相同、沒有不同鑰警示與第二勾選、詳細資訊預設收合', () => {
    const w = mountDialog()
    expect(w.find('[data-test="hic-relation"]').text()).toBe('相同')
    expect(w.find('[data-test="hic-relation"]').classes()).toContain('hic-tag-success')
    expect(w.find('[data-test="hic-different-key"]').exists()).toBe(false)
    expect(w.find('[data-test="hic-check-different-key"]').exists()).toBe(false)
    expect(w.find('[data-test="hic-details"]').exists()).toBe(false)
    expect(w.find('[data-test="hic-details-toggle"]').text()).toBe(
      '詳細資訊（指紋、演算法、記錄版次）'
    )
    const deadline = formatDateTime(DEADLINE)
    expect(w.find('[data-test="hic-deadline"]').text()).toBe(`${deadline}（尚未到期）`)
    expect(w.find('[data-test="hic-foot"]').text()).toBe(
      msg('hostIdentityConfirm.foot.default', { deadline })
    )
    expect(w.find('[data-test="hic-foot"]').text()).toContain('不會重新改密')
  })
})

describe('不同鑰', () => {
  it('紅字警示、標示不同、第二勾選存在、詳細資訊預設展開', () => {
    const w = mountDialog(differentKey())
    const box = w.find('[data-test="hic-different-key"]')
    expect(box.exists()).toBe(true)
    expect(box.find('.hic-danger').text()).toBe('這台主機出示的是另一把金鑰')
    expect(box.text()).toContain(msg('hostIdentityConfirm.differentKey.body'))
    expect(w.find('[data-test="hic-relation"]').text()).toBe('不同')
    expect(w.find('[data-test="hic-relation"]').classes()).toContain('hic-tag-danger')
    expect(w.find('[data-test="hic-check-different-key"]').exists()).toBe(true)
    expect(w.find('[data-test="hic-check-different-key"]').text()).toBe(
      msg('hostIdentityConfirm.confirm.differentKey')
    )
    expect(w.find('[data-test="hic-details"]').exists()).toBe(true)
    expect(w.find('[data-test="hic-details-toggle"]').text()).toBe('收起詳細資訊')
    expect(w.find('[data-test="hic-foot"]').text()).toContain('接受不同金鑰')
  })

  it('只勾第一項時送出仍停用，兩項都勾才啟用，且 payload 標示接受不同金鑰', async () => {
    const w = mountDialog(differentKey())
    expect(submitButton(w).attributes('disabled')).toBeDefined()
    await tickIdentity(w)
    expect(submitButton(w).attributes('disabled')).toBeDefined()
    await tickDifferent(w)
    expect(submitButton(w).attributes('disabled')).toBeUndefined()
    await submitButton(w).trigger('click')
    expect(w.emitted('confirm')).toHaveLength(1)
    expect(w.emitted('confirm')[0][0].accept_different_key).toBe(true)
  })

  it('verification_sent 為 true 時仍顯示第一層，免得與不同鑰說明矛盾', () => {
    const w = mountDialog(differentKey({ verification_sent: true }))
    expect(w.find('[data-test="hic-intro"]').text()).toBe(
      msg('hostIdentityConfirm.intro.verifiedNotApplied')
    )
  })
})

describe('逾期', () => {
  it('顯示逾期句與已過標記，說明句不再說期限不變，詳細資訊預設收合', () => {
    const w = mountDialog(identity({ expired: true, deadline: '2026-10-16T02:00:00Z' }))
    const time = formatDateTime('2026-10-16T02:00:00Z')
    expect(w.find('[data-test="hic-expired-notice"]').text()).toBe(
      msg('hostIdentityConfirm.expiredNotice', { time })
    )
    expect(w.find('[data-test="hic-expired-notice"]').text()).toContain('只做一次驗證')
    expect(w.find('[data-test="hic-deadline"]').text()).toBe(`${time}（已過）`)
    expect(w.find('[data-test="hic-foot"]').text()).toBe(msg('hostIdentityConfirm.foot.expired'))
    expect(w.find('[data-test="hic-foot"]').text()).not.toContain('期限也不變')
    expect(w.find('[data-test="hic-details"]').exists()).toBe(false)
  })

  it('未逾期時沒有逾期句', () => {
    expect(mountDialog().find('[data-test="hic-expired-notice"]').exists()).toBe(false)
  })
})

describe('送出條件與 payload', () => {
  it('未勾選時送出停用，勾選後啟用；停用時點擊不 emit', async () => {
    const w = mountDialog()
    expect(submitButton(w).attributes('disabled')).toBeDefined()
    await submitButton(w).trigger('click')
    expect(w.emitted('confirm')).toBeUndefined()
    await tickIdentity(w)
    expect(submitButton(w).attributes('disabled')).toBeUndefined()
    expect(submitButton(w).text()).toBe('只驗證，不重新改密')
  })

  it('emit 的 payload 逐欄等於 current（含 transport）', async () => {
    const id = identity()
    const w = mountDialog(id)
    await tickIdentity(w)
    await submitButton(w).trigger('click')
    const payload = w.emitted('confirm')[0][0]
    const cur = id.current
    expect(payload).toEqual({
      transport: cur.transport,
      record_id: cur.record_id,
      algorithm: cur.algorithm,
      fingerprint: cur.fingerprint,
      generation: cur.generation,
      accept_different_key: false,
    })
  })

  it('取消只關閉，不 emit confirm', async () => {
    const w = mountDialog()
    await w.find('[data-test="hic-cancel"]').trigger('click')
    expect(w.emitted('update:modelValue')[0]).toEqual([false])
    expect(w.emitted('confirm')).toBeUndefined()
  })

  it('換一筆身分時勾選重置，不沿用上一筆的同意', async () => {
    const w = mountDialog()
    await tickIdentity(w)
    expect(submitButton(w).attributes('disabled')).toBeUndefined()
    await w.setProps({ identity: identity({ current: { ...identity().current, record_id: 42 } }) })
    expect(submitButton(w).attributes('disabled')).toBeDefined()
  })
})

describe('詳細資訊', () => {
  it('收合時看不到指紋與 recorded_at，展開後顯示並可再收起', async () => {
    const w = mountDialog()
    const updated = msg('hostIdentityConfirm.details.updatedAt', { time: formatDateTime(RECORDED) })
    expect(w.text()).not.toContain(FP_A)
    expect(w.text()).not.toContain(updated)
    await w.find('[data-test="hic-details-toggle"]').trigger('click')
    expect(w.find('[data-test="hic-details"]').text()).toContain(FP_A)
    expect(w.find('[data-test="hic-recorded-at"]').text()).toBe(updated)
    expect(w.find('[data-test="hic-sent-at"]').text()).toBe(
      msg('hostIdentityConfirm.details.sentAt', { time: formatDateTime(SENT) })
    )
    expect(w.find('[data-test="hic-details"]').text()).toContain('#41・第 3 版')
    expect(w.find('[data-test="hic-details-toggle"]').text()).toBe('收起詳細資訊')
    await w.find('[data-test="hic-details-toggle"]').trigger('click')
    expect(w.find('[data-test="hic-details"]').exists()).toBe(false)
  })
})

describe('不顯示秘密、公鑰本體與來源資產', () => {
  it('即使 identity 夾帶其他欄位，也不渲染', async () => {
    const id = identity({
      secret: 'S3CR3T-PASSWORD',
      public_key: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5-PUBKEY-BODY',
      source_asset: 'SOURCE-ASSET-NAME',
      source_asset_id: 987654,
    })
    id.current.public_key = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5-PUBKEY-BODY'
    id.original.source_asset = 'SOURCE-ASSET-NAME'
    const w = mountDialog(id)
    await w.find('[data-test="hic-details-toggle"]').trigger('click')
    const text = w.text()
    for (const leak of ['S3CR3T-PASSWORD', 'PUBKEY-BODY', 'SOURCE-ASSET-NAME', '987654']) {
      expect(text).not.toContain(leak)
    }
  })
})

const NOT_SENT = '沒有拿新憑證去登入'

describe('不同鑰：說明段與送出狀態分開，三值皆不自相矛盾', () => {
  it.each([[true], ['unknown']])('verification_sent=%s：整個畫面不出現「沒有拿新憑證去登入」', (v) => {
    const w = mountDialog(differentKey({ verification_sent: v }))
    expect(w.find('[data-test="hic-different-key"]').exists()).toBe(true)
    expect(w.text()).not.toContain(NOT_SENT)
    expect(w.find('[data-test="hic-intro"]').text()).toBe(
      msg(v === true ? 'hostIdentityConfirm.intro.verifiedNotApplied' : 'hostIdentityConfirm.intro.unknown')
    )
  })

  it('false：送出狀態只由第一層交代，說明段本身不帶該句', () => {
    const w = mountDialog(differentKey({ verification_sent: false }))
    expect(w.find('[data-test="hic-intro"]').text()).toBe(msg('hostIdentityConfirm.intro.notSent'))
    expect(w.find('[data-test="hic-different-key"]').text()).not.toContain(NOT_SENT)
  })
})

describe('不可確認態', () => {
  const blocked = (status, over = {}) =>
    identity({ status, detail: status, confirmable: false, ...over })

  it('記錄已重置：說明、聯絡管理者、目前記錄為已重置，只有關閉，沒有勾選與送出', async () => {
    const base = identity()
    const w = mountDialog(
      blocked('reset_pending', { current: { ...base.current, reset_pending: true } })
    )
    expect(w.find('[data-test="hic-blocked-body"]').text()).toBe(msg('hostIdentityConfirm.blocked.resetPending'))
    expect(w.find('[data-test="hic-blocked-action"]').text()).toBe(msg('hostIdentityConfirm.blocked.contactAdmin'))
    expect(w.find('[data-test="hic-current-reset"]').text()).toBe(msg('hostIdentityConfirm.summary.currentReset'))
    expect(w.find('[data-test="hic-submit"]').exists()).toBe(false)
    expect(w.find('[data-test="hic-cancel"]').exists()).toBe(false)
    expect(w.find('[data-test="hic-check-identity"]').exists()).toBe(false)
    expect(w.find('[data-test="hic-intro"]').text()).toBe(msg('hostIdentityConfirm.intro.notSent'))
    await w.find('[data-test="hic-close"]').trigger('click')
    expect(w.emitted('update:modelValue')[0]).toEqual([false])
    expect(w.emitted('confirm')).toBeUndefined()
  })

  it.each([
    [false, 'hostIdentityConfirm.intro.notSent'],
    [true, 'hostIdentityConfirm.intro.verifiedNotApplied'],
    ['unknown', 'hostIdentityConfirm.intro.unknown'],
  ])('記錄已重置、verification_sent=%s：第一層依送出狀態交代，說明框本身不聲稱登入與否', (v, key) => {
    const w = mountDialog(blocked('reset_pending', { verification_sent: v }))
    expect(w.find('[data-test="hic-intro"]').text()).toBe(msg(key))
    const body = w.find('[data-test="hic-blocked-body"]').text()
    expect(body).toBe(msg('hostIdentityConfirm.blocked.resetPending'))
    expect(body).not.toContain(NOT_SENT)
    if (v !== false) expect(w.text()).not.toContain(NOT_SENT)
    expect(w.find('[data-test="hic-submit"]').exists()).toBe(false)
  })

  it('不可確認時不出現不同鑰警示與逾期單次驗證句，即使指紋不同或已逾期', () => {
    const w = mountDialog(
      blocked('reset_pending', {
        expired: true,
        current: { ...identity().current, fingerprint: FP_B, reset_pending: true },
      })
    )
    expect(w.find('[data-test="hic-different-key"]').exists()).toBe(false)
    expect(w.find('[data-test="hic-expired-notice"]').exists()).toBe(false)
    expect(w.find('[data-test="hic-check-different-key"]').exists()).toBe(false)
  })

  it('沒有可核對的記錄：說明與聯絡管理者，無目前記錄列，只有關閉', () => {
    const w = mountDialog(blocked('record_missing', { current: null }))
    expect(w.find('[data-test="hic-blocked-body"]').text()).toBe(msg('hostIdentityConfirm.blocked.recordMissing'))
    expect(w.find('[data-test="hic-blocked-action"]').text()).toBe(msg('hostIdentityConfirm.blocked.contactAdmin'))
    expect(w.find('[data-test="hic-current-reset"]').exists()).toBe(false)
    expect(w.find('[data-test="hic-submit"]').exists()).toBe(false)
    expect(w.find('[data-test="hic-close"]').exists()).toBe(true)
  })

  it('通道改變（候選）：顯示兩個通道、改回通道與清除候選的指引', () => {
    const base = identity()
    const w = mountDialog(
      blocked('transport_changed', { current: { ...base.current, transport: 'winrm' } })
    )
    expect(w.find('[data-test="hic-blocked-body"]').text()).toBe(
      msg('hostIdentityConfirm.blocked.transportChanged', { from: 'SSH', to: 'WinRM' })
    )
    expect(w.find('[data-test="hic-blocked-action"]').text()).toBe(
      msg('hostIdentityConfirm.blocked.transportRestore', { from: 'SSH' })
    )
    expect(w.find('[data-test="hic-channel-original"]').text()).toBe('SSH')
    expect(w.find('[data-test="hic-channel-current"]').text()).toBe('WinRM')
    expect(w.find('[data-test="hic-blocked-new-work"]').text()).toBe(
      msg('hostIdentityConfirm.blocked.newWorkCandidate')
    )
    expect(w.find('[data-test="hic-submit"]').exists()).toBe(false)
  })

  it('通道改變（輪替成員）：改用放棄本輪重新輪替的指引', () => {
    const base = identity()
    const w = mountDialog(
      blocked('transport_changed', { current: { ...base.current, transport: 'winrm' } }),
      { kind: 'member' }
    )
    expect(w.find('[data-test="hic-blocked-new-work"]').text()).toBe(
      msg('hostIdentityConfirm.blocked.newWorkMember')
    )
  })
})

describe('升級前舊工作（original 為 null）', () => {
  const legacy = (over = {}) =>
    identity({ status: 'unbound_legacy', detail: 'unbound_legacy', original: null, verification_sent: 'unknown', ...over })

  it('顯示舊工作說明與無法比對，沒有第二勾選，詳細資訊的送出時欄為升級前說明', async () => {
    const w = mountDialog(legacy())
    expect(w.find('[data-test="hic-legacy-intro"]').text()).toBe(msg('hostIdentityConfirm.legacy.intro'))
    expect(w.find('[data-test="hic-intro"]').exists()).toBe(false)
    expect(w.find('[data-test="hic-relation"]').text()).toBe(msg('hostIdentityConfirm.summary.relationUnavailable'))
    expect(w.find('[data-test="hic-relation-hint"]').text()).toBe(msg('hostIdentityConfirm.summary.relationUnavailableHint'))
    expect(w.find('[data-test="hic-different-key"]').exists()).toBe(false)
    expect(w.find('[data-test="hic-check-different-key"]').exists()).toBe(false)
    await w.find('[data-test="hic-details-toggle"]').trigger('click')
    expect(w.find('[data-test="hic-legacy-original"]').text()).toBe(msg('hostIdentityConfirm.details.legacyOriginal'))
    expect(w.find('[data-test="hic-foot"]').text()).toBe(msg('hostIdentityConfirm.foot.expired'))
  })

  it('只勾一個確認即可送出，payload 不接受不同金鑰（單次驗證）', async () => {
    const w = mountDialog(legacy())
    await tickIdentity(w)
    expect(submitButton(w).attributes('disabled')).toBeUndefined()
    await submitButton(w).trigger('click')
    expect(w.emitted('confirm')[0][0]).toEqual({
      transport: 'ssh',
      record_id: 41,
      algorithm: 'ssh-ed25519',
      fingerprint: FP_A,
      generation: 3,
      accept_different_key: false,
    })
  })
})

describe('WinRM 變體', () => {
  const winrmCurrent = { transport: 'winrm', record_id: null, algorithm: '', fingerprint: '', generation: 0, reset_pending: false, recorded_at: null }

  it('舊工作：WinRM 說明、沒有主機金鑰、無詳細資訊表，emit 只帶 transport 與 accept_different_key', async () => {
    const w = mountDialog(
      identity({ status: 'unbound_legacy', detail: 'unbound_legacy', original: null, current: winrmCurrent })
    )
    expect(w.find('[data-test="hic-legacy-intro"]').text()).toBe(msg('hostIdentityConfirm.legacy.introWinrm'))
    expect(w.find('[data-test="hic-winrm-no-key"]').text()).toContain(msg('hostIdentityConfirm.summary.winrmNoKey'))
    expect(w.find('[data-test="hic-relation"]').exists()).toBe(false)
    expect(w.find('[data-test="hic-details-toggle"]').exists()).toBe(false)
    expect(w.find('[data-test="hic-foot"]').text()).toBe(msg('hostIdentityConfirm.foot.winrm'))
    await tickIdentity(w)
    await submitButton(w).trigger('click')
    expect(w.emitted('confirm')[0][0]).toEqual({ transport: 'winrm', accept_different_key: false })
  })

  it('原本即 WinRM 的工作：不標「相同」，也不 emit 身分欄', async () => {
    const w = mountDialog(
      identity({ original: { ...identity().original, transport: 'winrm' }, current: winrmCurrent })
    )
    expect(w.find('[data-test="hic-relation"]').exists()).toBe(false)
    await tickIdentity(w)
    await submitButton(w).trigger('click')
    expect(w.emitted('confirm')[0][0]).toEqual({ transport: 'winrm', accept_different_key: false })
  })
})

describe('M-5D 版面與畫板對照', () => {
  it('寬度不超過視窗，按鈕在窄畫面也存在', () => {
    const w = mountDialog()
    const width = w.find('.dialog-stub').attributes('width')
    expect(width).toBe('min(560px, calc(100vw - 32px))')
    expect(width).not.toBe('560px')
    expect(w.find('[data-test="hic-submit"]').exists()).toBe(true)
    expect(w.find('[data-test="hic-cancel"]').exists()).toBe(true)
  })

  it('不同鑰：目前記錄的指紋與版次以紅字標示，危險框有圖示', async () => {
    const w = mountDialog(differentKey())
    expect(w.find('[data-test="hic-different-key"] svg').exists()).toBe(true)
    const mono = w.findAll('[data-test="hic-details"] .hic-mono')
    expect(mono[0].classes()).not.toContain('hic-danger')
    expect(mono[1].classes()).toContain('hic-danger')
    expect(w.find('[data-test="hic-foot"] svg').exists()).toBe(true)
    expect(w.find('[data-test="hic-foot"]').classes()).toContain('hic-callout-info')
  })

  it('同鑰：指紋不標紅', async () => {
    const w = mountDialog()
    await w.find('[data-test="hic-details-toggle"]').trigger('click')
    expect(w.findAll('[data-test="hic-details"] .hic-mono')[1].classes()).not.toContain('hic-danger')
  })

  it('不可確認（記錄已重置）：說明為一般段落，聯絡超級管理者是獨立黃色警示框，關閉為次要按鈕，可展開詳細資訊', async () => {
    const base = identity()
    const w = mountDialog(
      identity({ status: 'reset_pending', confirmable: false, current: { ...base.current, reset_pending: true } })
    )
    expect(w.find('.hic-callout-danger').exists()).toBe(false)
    expect(w.find('[data-test="hic-blocked-body"]').element.tagName).toBe('P')
    const box = w.find('[data-test="hic-blocked"]')
    expect(box.classes()).toContain('hic-callout-warning')
    expect(box.find('svg').exists()).toBe(true)
    expect(box.text()).toContain(msg('hostIdentityConfirm.blocked.contactAdmin'))
    expect(w.find('[data-test="hic-close"]').classes()).not.toContain('el-button--primary')
    expect(w.find('[data-test="hic-details"]').exists()).toBe(false)
    await w.find('[data-test="hic-details-toggle"]').trigger('click')
    expect(w.find('[data-test="hic-details"]').exists()).toBe(true)
  })

  it('無記錄：詳細資訊可展開且不顯示 undefined', async () => {
    const w = mountDialog(identity({ status: 'record_missing', confirmable: false, current: null }))
    await w.find('[data-test="hic-details-toggle"]').trigger('click')
    expect(w.find('[data-test="hic-details"]').text()).not.toContain('undefined')
  })

  it('升級前舊工作（SSH）：第一層為黃色警示框加圖示，「無法比對」粗體加徽章「沒有送出時的紀錄」', () => {
    const w = mountDialog(identity({ status: 'unbound_legacy', original: null, verification_sent: 'unknown' }))
    const box = w.find('[data-test="hic-legacy-intro"]')
    expect(box.classes()).toContain('hic-callout-warning')
    expect(box.find('svg').exists()).toBe(true)
    expect(w.find('[data-test="hic-relation"]').element.tagName).toBe('STRONG')
    expect(w.find('[data-test="hic-relation-hint"]').classes()).toContain('hic-tag')
    expect(w.text()).not.toContain(msg('hostIdentityConfirm.summary.relationLabel'))
  })

  it('升級前舊工作（WinRM）：改密通道與目前記錄的金鑰分成兩列', () => {
    const winrmCurrent = { transport: 'winrm', record_id: null, algorithm: '', fingerprint: '', generation: 0, reset_pending: false, recorded_at: null }
    const w = mountDialog(identity({ status: 'unbound_legacy', original: null, current: winrmCurrent }))
    expect(w.find('[data-test="hic-channel-winrm"]').text()).toBe('WinRM')
    const keyRow = w.find('[data-test="hic-winrm-no-key"]').element.parentElement.parentElement
    expect(keyRow.textContent).toContain(msg('hostIdentityConfirm.summary.keyLabel'))
    expect(keyRow.textContent).toContain(msg('hostIdentityConfirm.summary.relationUnavailable'))
    expect(w.find('[data-test="hic-winrm-no-key"]').classes()).toContain('hic-tag')
    expect(w.find('[data-test="hic-channel-winrm"]').element.parentElement).not.toBe(keyRow)
  })
})

describe('三語切換下用到的鍵都有值', () => {
  const KEYS = [
    'title', 'target', 'intro.notSent', 'intro.verifiedNotApplied', 'intro.unknown',
    'summary.keyLabel', 'summary.relationLabel', 'summary.relationSame', 'summary.relationDifferent',
    'summary.relationUnavailable', 'summary.relationUnavailableHint', 'summary.currentReset',
    'summary.deadlineLabel', 'summary.deadlineActive', 'summary.deadlineExpired', 'summary.channelLabel',
    'summary.channelOriginalLabel', 'summary.channelCurrentLabel', 'summary.winrmNoKey',
    'checkHint', 'checkHintWinrm', 'details.show', 'details.hide', 'details.original', 'details.current',
    'details.fingerprint', 'details.algorithm', 'details.record', 'details.recordValue', 'details.time',
    'details.sentAt', 'details.updatedAt', 'details.copy', 'details.legacyOriginal', 'expiredNotice',
    'foot.default', 'foot.differentKey', 'foot.expired', 'foot.winrm', 'confirm.identity',
    'confirm.differentKey', 'differentKey.title', 'differentKey.body', 'blocked.resetPending',
    'blocked.recordMissing', 'blocked.transportChanged', 'blocked.contactAdmin', 'blocked.transportRestore',
    'blocked.newWorkCandidate', 'blocked.newWorkMember', 'legacy.intro', 'legacy.introWinrm',
    'button.cancel', 'button.close', 'button.submit',
  ]
  it.each([['zh-TW'], ['en-US'], ['ja-JP']])('%s：每個鍵有非空值（不回傳鍵名本身）', (locale) => {
    const prev = i18n.global.locale.value
    i18n.global.locale.value = locale
    try {
      for (const k of KEYS) {
        const full = `hostIdentityConfirm.${k}`
        expect(i18n.global.te(full, locale), full).toBe(true)
        const text = i18n.global.t(full, { asset: 'a', account: 'b', time: 't', deadline: 'd', from: 'SSH', to: 'WinRM', id: 1, generation: 2 })
        expect(text.trim().length, full).toBeGreaterThan(0)
        expect(text, full).not.toBe(full)
      }
    } finally {
      i18n.global.locale.value = prev
    }
  })

  it('三語切換後對話框以該語系渲染', () => {
    const prev = i18n.global.locale.value
    i18n.global.locale.value = 'en-US'
    try {
      const w = mountDialog(identity({ confirmable: false, status: 'record_missing', current: null }))
      expect(w.find('[data-test="hic-blocked-body"]').text()).toBe(i18n.global.t('hostIdentityConfirm.blocked.recordMissing', 'en-US'))
      expect(w.find('[data-test="hic-close"]').text()).toBe('Close')
    } finally {
      i18n.global.locale.value = prev
    }
  })
})
