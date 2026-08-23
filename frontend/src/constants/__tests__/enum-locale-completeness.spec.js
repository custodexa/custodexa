// 枚舉三語完備性（3.3——枚舉顯示鐵則升級版）：
// 對每個「後端值域值 × 支援 locale」斷言 locale 檔存在非空 key。
// 後端加值時：值域模組補一筆＋三語 locale 補 key，缺任一語此測試即紅燈——
// 防護面較舊版（僅中文 label）更廣。值域硬拷檢查仍在各模組原測試檔。
import { describe, it, expect } from 'vitest'
import {
  AUDIT_ACTION_VALUES,
  AUDIT_RESOURCE_VALUES,
  AUDIT_MECHANISM_VALUES,
  AUDIT_CAUSE_VALUES,
} from '../audit-enums'
import {
  POLICY_DOMAINS,
  SECURITY_SECTIONS,
  ACCESS_SECTIONS,
  TRANSPORT_SECTIONS,
  KEY_SECTIONS,
} from '../policyDomains'
import { ACCOUNT_CREDENTIAL_VALUES } from '../assetAccounts'
import { END_REASON_VALUES } from '@/utils/end-reason'
import zhTW from '@/i18n/locales/zh-TW.json'
import enUS from '@/i18n/locales/en-US.json'
import jaJP from '@/i18n/locales/ja-JP.json'

const LOCALES = { 'zh-TW': zhTW, 'en-US': enUS, 'ja-JP': jaJP }

const lookup = (messages, path) =>
  path.split('.').reduce((o, k) => (o == null ? o : o[k]), messages)

const expectKeyInAllLocales = (path) => {
  for (const [locale, messages] of Object.entries(LOCALES)) {
    const value = lookup(messages, path)
    expect(value, `${locale} 缺 ${path}`).toBeTruthy()
    expect(typeof value, `${locale} 的 ${path} 應為字串`).toBe('string')
  }
}

describe('枚舉三語完備性（值域 × locale）', () => {
  it('auditAction：每個後端動作三語皆有非空 key', () => {
    for (const v of AUDIT_ACTION_VALUES) {
      expectKeyInAllLocales(`enum.auditAction.${v}`)
    }
  })

  it('auditResource：每個後端資源三語皆有非空 key', () => {
    for (const v of AUDIT_RESOURCE_VALUES) {
      expectKeyInAllLocales(`enum.auditResource.${v}`)
    }
  })

  it('mechanism：每個失效機制三語皆有非空 key', () => {
    for (const v of AUDIT_MECHANISM_VALUES) {
      expectKeyInAllLocales(`enum.mechanism.${v}`)
    }
  })

  it('cause：每個失效原因碼三語皆有非空 key', () => {
    for (const v of AUDIT_CAUSE_VALUES) {
      expectKeyInAllLocales(`enum.cause.${v}`)
    }
  })

  it('endReason：每個結束原因三語皆有非空 key', () => {
    for (const v of END_REASON_VALUES) {
      expectKeyInAllLocales(`enum.endReason.${v}`)
    }
  })

  it('accountCredential：每個憑證型別三語皆有非空 key', () => {
    for (const v of ACCOUNT_CREDENTIAL_VALUES) {
      expectKeyInAllLocales(`enum.accountCredential.${v}`)
    }
  })

  it('role：seeded 四角色三語皆有 label 與 description（roles 為開放集僅鎖 seeded）', () => {
    for (const role of ['admin', 'auditor', 'approver', 'user']) {
      expectKeyInAllLocales(`enum.role.${role}.label`)
      expectKeyInAllLocales(`enum.role.${role}.description`)
    }
  })

  it('approverScope：四維客體與兩類審核方三語皆有 key', () => {
    for (const v of ['asset', 'asset_group', 'subject_user', 'subject_group']) {
      expectKeyInAllLocales(`enum.scopeType.${v}`)
    }
    for (const v of ['user', 'group']) {
      expectKeyInAllLocales(`enum.actorType.${v}`)
    }
  })

  it('政策枚舉：policyEnum/transportLevel/accessPolicy 三語皆有 key', () => {
    for (const v of ['off', 'admin_only', 'all']) {
      expectKeyInAllLocales(`enum.policyEnum.${v}`)
    }
    for (const v of ['off', 'warn', 'strict']) {
      expectKeyInAllLocales(`enum.transportLevel.${v}`)
    }
    for (const v of ['open', 'reason', 'approval']) {
      expectKeyInAllLocales(`enum.accessPolicy.${v}`)
    }
  })

  it('policyDomain：四域 label 與各 section title/hint 三語皆有 key', () => {
    // id 清單由 policyDomains.js exports 導出，勿手抄
    //（手抄清單會漂移——新 section 三語全缺 key 時對齊測試照過、UI 顯裸 key）
    for (const d of POLICY_DOMAINS.map((x) => x.id)) {
      expectKeyInAllLocales(`policyDomain.${d}`)
    }
    const sectionIds = [
      ...SECURITY_SECTIONS,
      ...ACCESS_SECTIONS,
      ...TRANSPORT_SECTIONS,
      ...KEY_SECTIONS,
    ].map((s) => s.id)
    expect(sectionIds.length).toBeGreaterThanOrEqual(10)
    for (const s of sectionIds) {
      expectKeyInAllLocales(`policyDomain.section.${s}.title`)
      expectKeyInAllLocales(`policyDomain.section.${s}.hint`)
    }
  })
})
