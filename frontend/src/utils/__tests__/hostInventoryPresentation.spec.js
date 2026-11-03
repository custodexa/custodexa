import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import { t, te } from '@/i18n'
import {
  FAILURE_REASONS,
  REASON_KINDS,
  COVERAGE_CHECKS,
  COVERAGE_STATES,
  COVERAGE_REASONS,
  FIXED_NOTES,
  failureInfo,
  parseReason,
  filterParams,
  sortFindings,
  isCoverageGap,
} from '../hostInventoryPresentation'

// 後端常數以唯讀掛載（/repo）讀取；無掛載時跳過比對（與其他枚舉守衛同作法）
const MODEL = '/repo/backend/internal/model/host_account_inventory.go'
const hasModel = fs.existsSync(MODEL)
const modelSrc = hasModel ? fs.readFileSync(MODEL, 'utf8') : ''

describe('hostInventoryPresentation 值域', () => {
  it('結束原因碼 16 個，逐一有說明', () => {
    expect(FAILURE_REASONS).toHaveLength(16)
    for (const code of FAILURE_REASONS) {
      expect(te(`hostInventory.failure.${code}`), code).toBe(true)
    }
  })

  it('特權理由碼 8 種，逐一有說明', () => {
    expect(Object.keys(REASON_KINDS)).toHaveLength(8)
    for (const kind of Object.keys(REASON_KINDS)) {
      expect(te(`hostInventory.reason.${kind}`), kind).toBe(true)
    }
  })

  it('檢查範圍 5 項目、6 狀態、5 原因碼、3 固定說明逐一有說明', () => {
    expect(COVERAGE_CHECKS).toHaveLength(5)
    expect(COVERAGE_STATES).toHaveLength(6)
    expect(COVERAGE_REASONS).toHaveLength(7)
    expect(FIXED_NOTES).toHaveLength(3)
    for (const c of COVERAGE_CHECKS) expect(te(`hostInventory.coverage.check.${c}`), c).toBe(true)
    for (const s of COVERAGE_STATES) expect(te(`hostInventory.coverage.state.${s}`), s).toBe(true)
    for (const r of COVERAGE_REASONS) expect(te(`hostInventory.coverage.reason.${r}`), r).toBe(true)
    for (const n of FIXED_NOTES) expect(te(`hostInventory.coverage.fixed.${n}`), n).toBe(true)
  })

  it.skipIf(!hasModel)('原因碼與理由碼和後端常數一致', () => {
    const backendReasons = [...modelSrc.matchAll(/= "(INVENTORY_[A-Z_]+)"/g)].map((m) => m[1])
    expect([...backendReasons].sort()).toEqual([...FAILURE_REASONS].sort())
    const backendKinds = [...modelSrc.matchAll(/PrivReason\w+\s+= "([a-z0-9_]+)"/g)].map((m) => m[1])
    expect([...backendKinds].sort()).toEqual(Object.keys(REASON_KINDS).sort())
  })

  it('未知原因碼回通用說明並保留原碼', () => {
    const info = failureInfo('INVENTORY_FUTURE_THING')
    expect(info.known).toBe(false)
    expect(info.code).toBe('INVENTORY_FUTURE_THING')
    expect(t('hostInventory.failure.generic')).toContain('沒有完成')
  })

  it('理由碼拆出名稱，依規則判斷者另標，未知碼保留原字串', () => {
    expect(parseReason('group:wheel')).toMatchObject({ known: true, kind: 'group', name: 'wheel', bySudoRules: false })
    expect(parseReason('sudoers_alias:ADMINS')).toMatchObject({ kind: 'sudoers_alias', name: 'ADMINS', bySudoRules: true })
    expect(parseReason('sudoers_all_targetpw')).toMatchObject({ muted: true, bySudoRules: true })
    expect(parseReason('future:x')).toMatchObject({ known: false, raw: 'future:x' })
  })

  it('篩選對應查詢參數', () => {
    expect(filterParams('needs')).toEqual({ privileged: true, managed: false, present: true, status: 'open', actionable: true })
    expect(filterParams('gone')).toEqual({ present: false })
    expect(filterParams('all')).toEqual({})
  })

  it('排序：特權在前，同組未納管在前，再依帳號名', () => {
    const out = sortFindings([
      { username: 'b', privileged: false, managed: false },
      { username: 'z', privileged: true, managed: true },
      { username: 'a', privileged: true, managed: false },
    ])
    expect(out.map((f) => f.username)).toEqual(['a', 'z', 'b'])
  })

  it('缺項判定：已檢查與主機上沒有不算缺項', () => {
    expect(isCoverageGap({ state: 'checked' })).toBe(false)
    expect(isCoverageGap({ state: 'absent' })).toBe(false)
    expect(isCoverageGap({ state: 'unreadable' })).toBe(true)
    expect(isCoverageGap({ state: 'undetermined' }), '無從判斷是另一項缺漏的後果，不重複列').toBe(false)
  })
})
