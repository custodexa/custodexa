// 憑證庫的枚舉值域與三語完備性。
//
// 值域硬拷後端：
//   internal/model/credential.go（範圍、協定族、輪替模式與狀態、成員狀態）
//   internal/modules/asset/credential_rotation.go（聚合態五值）
//   internal/modules/asset/credential_rotation_split.go（脫離來源）
//   internal/model/change_secret.go（密碼長度界線）
// 後端新增一個值而這裡沒跟上時，畫面會靜默顯示一個機器碼；本檔讓那件事變成紅燈。
import { describe, it, expect } from 'vitest'
import {
  CREDENTIAL_SCOPE_VALUES,
  CREDENTIAL_SECRET_TYPE_VALUES,
  CREDENTIAL_PROTOCOL_FAMILY_VALUES,
  CREDENTIAL_ROTATION_MODE_VALUES,
  CREDENTIAL_ROTATION_STATUS_VALUES,
  CREDENTIAL_MEMBER_STATE_VALUES,
  CREDENTIAL_AGGREGATE_STATE_VALUES,
  CREDENTIAL_DETACH_SOURCE_VALUES,
  MEMBER_STATE_TAG_TYPE,
  AGGREGATE_STATE_TAG_TYPE,
  RETRYABLE_MEMBER_STATES,
  PASSWORD_LENGTH_MIN,
  PASSWORD_LENGTH_MAX,
  PASSWORD_LENGTH_DEFAULT,
  credentialDisplayName,
} from '../credentials'
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

describe('值域（硬拷後端）', () => {
  it('範圍、秘密型別、協定族', () => {
    expect(CREDENTIAL_SCOPE_VALUES).toEqual(['dedicated', 'shared'])
    expect(CREDENTIAL_SECRET_TYPE_VALUES).toEqual(['password', 'ssh_key'])
    expect(CREDENTIAL_PROTOCOL_FAMILY_VALUES)
      .toEqual(['ssh', 'windows', 'vnc', 'database', 'k8s'])
  })

  it('輪替模式、輪替狀態、脫離來源', () => {
    expect(CREDENTIAL_ROTATION_MODE_VALUES).toEqual(['group', 'split'])
    expect(CREDENTIAL_ROTATION_STATUS_VALUES).toEqual(['running', 'completed', 'abandoned'])
    expect(CREDENTIAL_DETACH_SOURCE_VALUES).toEqual(['random', 'custom'])
  })

  it('成員狀態七值、聚合態五值', () => {
    expect(CREDENTIAL_MEMBER_STATE_VALUES).toEqual([
      'queued', 'changing', 'changed_unverified', 'applied',
      'retry_wait', 'terminal_failed', 'abandoned',
    ])
    expect(CREDENTIAL_AGGREGATE_STATE_VALUES).toEqual([
      'idle', 'queued', 'changing', 'partial', 'out_of_sync',
    ])
  })

  it('密碼長度界線與改密計劃同一組', () => {
    expect([PASSWORD_LENGTH_MIN, PASSWORD_LENGTH_DEFAULT, PASSWORD_LENGTH_MAX])
      .toEqual([12, 16, 64])
  })
})

describe('顯示中繼資料涵蓋整個值域', () => {
  it('每個成員狀態與聚合態都有標籤色，沒有落到預設值的漏網之魚', () => {
    for (const state of CREDENTIAL_MEMBER_STATE_VALUES) {
      expect(MEMBER_STATE_TAG_TYPE[state], state).toBeTruthy()
    }
    for (const state of CREDENTIAL_AGGREGATE_STATE_VALUES) {
      expect(AGGREGATE_STATE_TAG_TYPE[state], state).toBeTruthy()
    }
  })

  it('可補跑的狀態是成員狀態的子集，且不含終態以外的值', () => {
    for (const state of RETRYABLE_MEMBER_STATES) {
      expect(CREDENTIAL_MEMBER_STATE_VALUES, state).toContain(state)
    }
    // 就位與改密中沒有「再試一次」可言：讓它們可補跑等於允許重複改密
    expect(RETRYABLE_MEMBER_STATES).not.toContain('applied')
    expect(RETRYABLE_MEMBER_STATES).not.toContain('changing')
  })
})

describe('三語完備性（值域 × locale）', () => {
  it.each([
    ['credentialScope', CREDENTIAL_SCOPE_VALUES],
    ['credentialSecretType', CREDENTIAL_SECRET_TYPE_VALUES],
    ['credentialProtocolFamily', CREDENTIAL_PROTOCOL_FAMILY_VALUES],
    ['credentialRotationMode', CREDENTIAL_ROTATION_MODE_VALUES],
    ['credentialRotationStatus', CREDENTIAL_ROTATION_STATUS_VALUES],
    ['credentialMemberState', CREDENTIAL_MEMBER_STATE_VALUES],
    ['credentialAggregateState', CREDENTIAL_AGGREGATE_STATE_VALUES],
    ['credentialDetachSource', CREDENTIAL_DETACH_SOURCE_VALUES],
  ])('enum.%s 的每個值三語皆有非空文案', (node, values) => {
    for (const value of values) {
      expectKeyInAllLocales(`enum.${node}.${value}`)
    }
  })
})

describe('顯示名（專用憑證是計算值，兩個來源都可能缺席）', () => {
  it('共用憑證用落庫名稱', () => {
    expect(credentialDisplayName({ scope: 'shared', name: '正式區 root', username: 'root' }))
      .toBe('正式區 root')
  })

  it('專用憑證齊全時原樣呈現', () => {
    expect(credentialDisplayName({ scope: 'dedicated', name: 'web-01 / app', username: 'app' }))
      .toBe('web-01 / app')
  })

  // 掛載的資產被移除後投影退為帳號名本身；空白一列會讓人以為是資料壞了
  it('資產不存在時指名這件事，而不是留白', () => {
    expect(credentialDisplayName({ scope: 'dedicated', name: 'app', username: 'app' }))
      .toBe('（資產已移除） / app')
  })

  it('帳號名為空時指名這件事', () => {
    expect(credentialDisplayName({ scope: 'dedicated', name: 'vnc-test / ', username: '' }))
      .toBe('vnc-test / （未設定）')
  })

  it('兩者都缺時兩句話都出現，不會是一整列空白', () => {
    expect(credentialDisplayName({ scope: 'dedicated', name: '', username: '' }))
      .toBe('（資產已移除） / （未設定）')
  })

  it('資產名本身含分隔符時取最後一個分隔符切', () => {
    expect(credentialDisplayName({ scope: 'dedicated', name: 'a / b / ops', username: 'ops' }))
      .toBe('a / b / ops')
  })
})
