/**
 * 角色顯示中繼資料唯一事實源。
 * 後端 roles 表為角色存在性事實源；此處只管前端顯示的值域與非譯 metadata（tag 色），
 * label／description 譯文住 locale 檔（enum.role.*），以 getter 回 t()——render 期
 * 取值會被依賴追蹤，切語言自動重繪。roles 為開放集：僅鎖 seeded 四角色，
 * 未知角色 graceful fallback（raw name＋info tag＋後端 description）。
 * 新增後端角色時：此處補 META＋三語 locale 補 key（完備性單測釘住）；
 * 可指派清單一律由 getRoleList() API 拉取，勿硬編碼。
 */
import { t } from '@/i18n'

const meta = (name, tagType) => ({
  tagType,
  get label() {
    return t(`enum.role.${name}.label`)
  },
  get description() {
    return t(`enum.role.${name}.description`)
  },
})

export const ROLE_META = {
  admin: meta('admin', 'danger'),
  auditor: meta('auditor', 'warning'),
  approver: meta('approver', 'primary'),
  user: meta('user', 'info'),
}

export const roleLabel = (name) => ROLE_META[name]?.label || name

export const roleTagType = (name) => ROLE_META[name]?.tagType || 'info'

export const roleDescription = (name) => ROLE_META[name]?.description || ''
