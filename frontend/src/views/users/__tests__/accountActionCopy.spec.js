// 刪除使用者／停用 MFA 確認框的帳號類型判定與選字。
//
// 守的是「同一個確認框對不同帳號說錯後果」：已綁外部身分的帳號必須講出
// 一併解除綁定；只經身分提供者登入的帳號停用 MFA 不得說「只需密碼」。
import { describe, it, expect, afterEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { t, setLanguage } from '@/i18n'
import {
  ACCOUNT_KIND,
  accountKind,
  deleteConfirmCopy,
  disableMFAConfirmCopy,
  renderDeleteConfirm,
  renderDisableMFAConfirm,
} from '../accountActionCopy'

const ROWS = {
  local: { username: 'carol', provisioning_origin: 'local', external_credential: false },
  localBound: {
    username: 'dave',
    provisioning_origin: 'local',
    external_credential: false,
    auth_provider_names: ['Azure AD', 'Okta'],
  },
  oidcBound: {
    username: 'erin',
    provisioning_origin: 'oidc',
    external_credential: true,
    auth_provider_names: ['Azure AD'],
  },
  ldap: { username: 'frank', provisioning_origin: 'ldap', is_ldap: true, external_credential: true },
  // 僅外部身分、綁定已全數解除（列上無 provider 名）
  externalOnly: { username: 'gina', provisioning_origin: 'oidc', external_credential: true },
}

const renderText = (vnode) => mount({ render: () => vnode }).text()

afterEach(() => setLanguage('zh-TW'))

describe('accountKind 四類判定', () => {
  it.each([
    ['local', ACCOUNT_KIND.LOCAL],
    ['localBound', ACCOUNT_KIND.MIXED],
    ['oidcBound', ACCOUNT_KIND.EXTERNAL],
    ['ldap', ACCOUNT_KIND.LDAP],
    ['externalOnly', ACCOUNT_KIND.EXTERNAL],
  ])('%s → %s', (name, kind) => {
    expect(accountKind(ROWS[name])).toBe(kind)
  })

  it('舊後端無 provisioning_origin 時以 is_ldap 判定目錄帳號', () => {
    expect(accountKind({ username: 'x', is_ldap: true })).toBe(ACCOUNT_KIND.LDAP)
    expect(accountKind({ username: 'x' })).toBe(ACCOUNT_KIND.LOCAL)
  })

  it('目錄帳號即使綁了外部身分，停用 MFA 仍以目錄帳號選字', () => {
    const row = { ...ROWS.ldap, auth_provider_names: ['Azure AD'] }
    expect(accountKind(row)).toBe(ACCOUNT_KIND.LDAP)
    expect(disableMFAConfirmCopy(row).main.key).toBe('users.disableMFAConfirmLdap')
  })
})

describe('deleteConfirmCopy 選鍵與參數', () => {
  it.each([
    ['local', 'users.deleteConfirmLocal', 'users.deleteTipLocal', null],
    ['localBound', 'users.deleteConfirmExternal', 'users.deleteTipExternal', 'Azure AD、Okta'],
    ['oidcBound', 'users.deleteConfirmExternal', 'users.deleteTipExternal', 'Azure AD'],
    ['ldap', 'users.deleteConfirmLdap', 'users.deleteTipLdap', null],
    ['externalOnly', 'users.deleteConfirmLocal', 'users.deleteTipLocal', null],
  ])('%s → %s', (name, key, tip, providers) => {
    const copy = deleteConfirmCopy(ROWS[name], 'zh-TW')
    expect(copy.main.key).toBe(key)
    expect(copy.tip).toBe(tip)
    expect(copy.main.params.name).toBe(ROWS[name].username)
    expect(copy.main.params.providers ?? null).toBe(providers)
  })

  it('已綁外部身分優先於目錄帳號（綁定會被解除，後果要講出來）', () => {
    const row = { ...ROWS.ldap, auth_provider_names: ['Azure AD'] }
    expect(deleteConfirmCopy(row, 'zh-TW').main.key).toBe('users.deleteConfirmExternal')
  })

  it('英文介面以逗號串接 provider 名', () => {
    expect(deleteConfirmCopy(ROWS.localBound, 'en-US').main.params.providers).toBe('Azure AD, Okta')
  })

  it('外部身分的後果列兩點，目錄帳號一段，本地帳號無後果段', () => {
    expect(deleteConfirmCopy(ROWS.oidcBound, 'zh-TW').impact.items).toHaveLength(2)
    expect(deleteConfirmCopy(ROWS.ldap, 'zh-TW').impact.items).toEqual(['users.deleteImpactLdap'])
    expect(deleteConfirmCopy(ROWS.local, 'zh-TW').impact).toBeNull()
  })
})

describe('disableMFAConfirmCopy 選鍵', () => {
  it.each([
    ['local', 'users.disableMFAConfirmLocal'],
    ['localBound', 'users.disableMFAConfirmMixed'],
    ['oidcBound', 'users.disableMFAConfirmExternal'],
    ['ldap', 'users.disableMFAConfirmLdap'],
    ['externalOnly', 'users.disableMFAConfirmExternal'],
  ])('%s → %s', (name, key) => {
    const copy = disableMFAConfirmCopy(ROWS[name])
    expect(copy.main.key).toBe(key)
    expect(copy.main.params).toEqual({ name: ROWS[name].username })
    expect(copy.note).toBe('users.disableMFAPolicyNote')
  })
})

describe('確認框內容渲染（實際文案）', () => {
  it('已綁外部身分的刪除框：主句、兩點後果、改用停用 MFA 的提示', () => {
    const vnode = renderDeleteConfirm(ROWS.localBound, t, 'zh-TW')
    const wrapper = mount({ render: () => vnode })
    expect(wrapper.find('.account-action-main').text()).toContain('一併解除綁定')
    expect(wrapper.find('.account-action-main').text()).toContain('Azure AD、Okta')
    expect(wrapper.findAll('.account-action-impact li')).toHaveLength(2)
    expect(wrapper.find('.account-action-tip').text()).toContain('「停用 MFA」')
    expect(wrapper.find('.account-action-tip').text()).toContain('身分提供者端移除此人')
  })

  it('本地帳號的刪除框沒有後果段，只有主句與提示', () => {
    const wrapper = mount({ render: () => renderDeleteConfirm(ROWS.local, t, 'zh-TW') })
    expect(wrapper.find('.account-action-impact').exists()).toBe(false)
    expect(wrapper.text()).toContain('刪除後無法復原')
    expect(wrapper.text()).not.toContain('解除綁定')
  })

  it('目錄帳號的刪除框講重建與目錄服務端停用', () => {
    const text = renderText(renderDeleteConfirm(ROWS.ldap, t, 'zh-TW'))
    expect(text).toContain('經目錄服務登入')
    expect(text).toContain('系統會建立一個新帳號')
    expect(text).toContain('目錄服務端停用此人')
  })

  it('僅外部身分的停用 MFA 框不說「只需密碼」，並附政策提醒', () => {
    const text = renderText(renderDisableMFAConfirm(ROWS.oidcBound, t))
    expect(text).toContain('身分提供者端的驗證不受影響')
    expect(text).not.toContain('只需密碼')
    expect(text).toContain('下次登入時會要求重新綁定驗證器')
  })

  it('英文介面渲染英文文案', () => {
    setLanguage('en-US')
    const text = renderText(renderDeleteConfirm(ROWS.oidcBound, t, 'en-US'))
    expect(text).toContain('deleting it also unlinks them')
    expect(text).toContain('Disable MFA')
  })
})
