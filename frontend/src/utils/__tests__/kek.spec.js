import { describe, it, expect } from 'vitest'
import {
  KEK_ALPHABET,
  KEK_LENGTH,
  decodeKEKMaterial,
  generateKEKMaterial,
  kekFingerprint,
  validateKEKMaterialFormat,
} from '@/utils/kek'

// kek-provider-modularization D8 路 2：本地生成與前端格式檢查。
// 字元集／長度須與伺服端 crypto.KEKAlphabet／KEKMaterialLength 一致——
// 兩端漂移的後果是「前端生成的材料被伺服端拒收」，故此處直接釘住常數本身。

describe('KEK 常數與伺服端一致', () => {
  it('字元集恰為 A-Z a-z 0-9（62 字元）、長度 32', () => {
    expect(KEK_ALPHABET).toBe(
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    )
    expect(KEK_ALPHABET).toHaveLength(62)
    expect(KEK_LENGTH).toBe(32)
  })
})

describe('generateKEKMaterial', () => {
  it('產出長度 32 且全數落在字元集內', () => {
    for (let i = 0; i < 20; i += 1) {
      const material = generateKEKMaterial()
      expect(material).toHaveLength(KEK_LENGTH)
      expect(validateKEKMaterialFormat(material)).toBe('')
      for (const ch of material) expect(KEK_ALPHABET).toContain(ch)
    }
  })

  it('連續生成不重複（CSPRNG 而非固定值）', () => {
    const set = new Set(Array.from({ length: 20 }, () => generateKEKMaterial()))
    expect(set.size).toBe(20)
  })
})

describe('validateKEKMaterialFormat', () => {
  const valid = 'NEWKEK1234567890abcdefABCDEF0000'

  it('合格材料回空字串', () => {
    expect(validateKEKMaterialFormat(valid)).toBe('')
  })

  it('空值／全空白回 empty', () => {
    expect(validateKEKMaterialFormat('')).toBe('empty')
    expect(validateKEKMaterialFormat('   ')).toBe('empty')
    // 恰 32 個空白：長度合法但 trim 後為空，仍是無效材料（與伺服端同判定）
    expect(validateKEKMaterialFormat(' '.repeat(32))).toBe('empty')
  })

  it('無法解為 32 位元組金鑰回 format', () => {
    expect(validateKEKMaterialFormat(valid.slice(0, 31))).toBe('format')
    expect(validateKEKMaterialFormat(`${valid}A`)).toBe('format')
    // 64 個字元但非十六進位：長度不在 base64 的 43/44，hex 讀法又不合法
    expect(validateKEKMaterialFormat('Zz'.repeat(32))).toBe('format')
    // 43 個字元但含非 base64 字元
    expect(validateKEKMaterialFormat('!'.repeat(43))).toBe('format')
    // 混用標準與 URL-safe 兩套字母表：不是任何一種編碼的輸出
    expect(validateKEKMaterialFormat(`A+B_${'C'.repeat(39)}=`)).toBe('format')
  })

  it('字元集外字元回 charset（僅約束原字元形態；含出廠預設值的連字號）', () => {
    expect(validateKEKMaterialFormat('dev-key-for-testing-only-ok32bts')).toBe('charset')
    expect(validateKEKMaterialFormat(`${valid.slice(0, 31)}+`)).toBe('charset')
  })
})

// kek-encoding-and-unseal-entry：三種輸入編碼。判定規則逐條對齊伺服端
// pkg/crypto/kek_material.go——兩端漂移的後果是「前端擋下伺服端會接受的材料」
// 或反之，兩者都會讓合法管理員解不開自己的部署。
describe('三種輸入編碼', () => {
  // 一把含 A-Za-z0-9 以外位元組的 32 位元組金鑰
  const key = Uint8Array.from([
    0x00, 0x01, 0x02, 0x7f, 0x80, 0xfe, 0xff, 0x2b, 0x2f, 0x3d, 0x5f, 0x2d, 0x41, 0x61, 0x30, 0x39,
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
  ])
  const hex = Array.from(key, (b) => b.toString(16).padStart(2, '0')).join('')
  const b64 = btoa(String.fromCharCode(...key))
  const b64url = b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')

  const sameKey = (material) => {
    const { key: got } = decodeKEKMaterial(material)
    expect(got).not.toBeNull()
    expect(Array.from(got)).toEqual(Array.from(key))
  }

  it('十六進位（大小寫、帶結尾換行）解出同一把金鑰', () => {
    sameKey(hex)
    sameKey(hex.toUpperCase())
    // `openssl rand -hex 32` 的輸出帶結尾換行；貼上時常一併帶入
    sameKey(`${hex}\n`)
    expect(decodeKEKMaterial(hex).form).toBe('hex')
  })

  it('base64 標準／URL-safe、有無 padding 皆解出同一把金鑰', () => {
    sameKey(b64)
    sameKey(b64.replace(/=+$/, ''))
    sameKey(b64url)
    sameKey(`  ${b64} \n`)
    expect(decodeKEKMaterial(b64).form).toBe('base64')
  })

  it('恰 32 位元組的輸入一律視為原字元形態（不論是否全屬 hex／base64 字元集）', () => {
    for (const input of ['abcdef01'.repeat(4), 'A'.repeat(32), 'NEWKEK1234567890abcdefABCDEF0000']) {
      const { key: got, form } = decodeKEKMaterial(input)
      expect(form).toBe('raw')
      expect(got).toHaveLength(32)
      expect(String.fromCharCode(...got)).toBe(input)
    }
  })

  it('恰 32 位元組含前後空白時原樣採用（不修剪，與伺服端零回歸保證一致）', () => {
    const withSpaces = ' abcdefghijklmnopqrstuvwxyzABCD '
    expect(withSpaces).toHaveLength(32)
    const { key: got, form } = decodeKEKMaterial(withSpaces)
    expect(form).toBe('raw')
    expect(String.fromCharCode(...got)).toBe(withSpaces)
  })

  it('非規範 base64（多餘位元非零）被拒', () => {
    const raw = b64.replace(/=+$/, '')
    const tampered = `${raw.slice(0, -1)}B`
    expect(decodeKEKMaterial(tampered).reason).toBe('format')
  })

  it('三種寫法算出同一個指紋（伺服端以解碼後金鑰算 kek_id）', async () => {
    // 原字元形態的輸入以 UTF-8 送到伺服端，故只有 ASCII 材料的「32 個字元」
    // 才等於「32 個位元組」——非 ASCII 位元組的金鑰只能以 hex／base64 輸入。
    // 此處用 ASCII 金鑰驗三種寫法同指紋，另用高位元組金鑰驗 hex 與 base64 同指紋。
    const ascii = 'NEWKEK1234567890abcdefABCDEF0000'
    const asciiBytes = Uint8Array.from(ascii, (c) => c.charCodeAt(0))
    const asciiHex = Array.from(asciiBytes, (b) => b.toString(16).padStart(2, '0')).join('')
    const asciiB64 = btoa(ascii)
    const fromRaw = await kekFingerprint(ascii)
    expect(fromRaw).toBe('ee3ba87dabea0ae6')
    expect(await kekFingerprint(asciiHex)).toBe(fromRaw)
    expect(await kekFingerprint(asciiB64)).toBe(fromRaw)

    const fromHex = await kekFingerprint(hex)
    expect(await kekFingerprint(b64)).toBe(fromHex)
    expect(await kekFingerprint(b64url)).toBe(fromHex)
  })
})

describe('kekFingerprint', () => {
  it('與伺服端 crypto.Fingerprint 同演算法（SHA-256 前 8 bytes 的小寫 hex）', async () => {
    // 期望值以 Go 的同一演算法離線算出：sha256(material)[:8]
    expect(await kekFingerprint('NEWKEK1234567890abcdefABCDEF0000')).toBe('ee3ba87dabea0ae6')
  })

  it('空材料回 null（本端無法判定即不宣稱）', async () => {
    expect(await kekFingerprint('')).toBeNull()
  })
})
