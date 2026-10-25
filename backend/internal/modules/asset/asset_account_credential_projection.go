package asset

// AssetAccountOutOfScopeDTO 範圍化檢視者讀到「引用的憑證歸屬在其範圍外（含全域）」的帳號列。
//
// 由完整版收窄：移除憑證識別、名稱與掛載台數，加 credential_out_of_scope。帳號自身的欄位
// （名稱、預設、是否有秘密、就位版本）隨所屬資產照舊；範圍外憑證的身分不經帳號列外露。
type AssetAccountOutOfScopeDTO struct {
	ID                 uint   `json:"id"`
	AssetID            uint   `json:"asset_id"`
	Username           string `json:"username"`
	IsDefault          bool   `json:"is_default"`
	Privileged         bool   `json:"privileged"`
	AuthMethod         string `json:"auth_method"`
	Note               string `json:"note"`
	HasPassword        bool   `json:"has_password"`
	HasPrivateKey      bool   `json:"has_private_key"`
	SharedCredential   bool   `json:"shared_credential"`
	CredentialScope    string `json:"credential_scope"`
	EffectiveVersionNo int    `json:"effective_version_no"`
	// CredentialOutOfScope 恆為 true：本列引用的憑證不在檢視者的範圍內
	CredentialOutOfScope bool   `json:"credential_out_of_scope"`
	CreatedAt            string `json:"created_at"`
	UpdatedAt            string `json:"updated_at"`
	// Actions 帳號列動作旗標（rebind、remove、secret_fix、detach）；判定來源未注入時不出現
	Actions map[string]CredentialAction `json:"actions,omitempty"`
}

// OutOfScopeAssetAccountDTO 由完整版收窄為範圍外憑證的帳號列。
func OutOfScopeAssetAccountDTO(d *AssetAccountDTO) *AssetAccountOutOfScopeDTO {
	if d == nil {
		return nil
	}
	return &AssetAccountOutOfScopeDTO{
		ID:                   d.ID,
		AssetID:              d.AssetID,
		Username:             d.Username,
		IsDefault:            d.IsDefault,
		Privileged:           d.Privileged,
		AuthMethod:           d.AuthMethod,
		Note:                 d.Note,
		HasPassword:          d.HasPassword,
		HasPrivateKey:        d.HasPrivateKey,
		SharedCredential:     d.SharedCredential,
		CredentialScope:      d.CredentialScope,
		EffectiveVersionNo:   d.EffectiveVersionNo,
		CredentialOutOfScope: true,
		CreatedAt:            d.CreatedAt,
		UpdatedAt:            d.UpdatedAt,
	}
}
