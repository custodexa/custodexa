package database

// 身分與認證——baseline schema 的「identity」域（migration-baseline-compression D1）。
//
// 使用者、角色、群組、憑證與外部身分來源。
//
// **DDL 一律無條件**（不使用任何條件式建立語法）：baseline 是全新安裝的唯一 schema 事實源，
// 在非空 schema 上跑必須立刻炸而不是靜默 no-op——後者正是 2026-08-12 索引事故的成因。
//
// 本檔為機器可讀的最終形狀宣告，不描述任何歷史演進；欄位語義見對應的
// internal/model 檔與 docs/DB_SCHEMA.md。

// baselineIdentityTables 本域的建表 DDL（依「被參照者先建」排列）。
var baselineIdentityTables = []string{
	`CREATE TABLE users (
		id bigserial,
		created_at timestamp with time zone,
		updated_at timestamp with time zone,
		deleted_at timestamp with time zone,
		username character varying(50) NOT NULL,
		email character varying(100),
		password text NOT NULL,
		full_name character varying(100),
		active boolean DEFAULT true,
		local_display_name character varying(100),
		is_ldap boolean DEFAULT false,
		provisioning_origin character varying(16) DEFAULT 'local'::character varying NOT NULL,
		external_credential boolean DEFAULT false,
		credential_epoch bigint DEFAULT 0 NOT NULL,
		totp_secret_enc character varying(512),
		totp_enabled boolean DEFAULT false,
		totp_last_step bigint,
		failed_login_attempts bigint DEFAULT 0,
		locked_until timestamp with time zone,
		must_change_password boolean DEFAULT false,
		password_changed_at timestamp with time zone,
		last_login_at timestamp with time zone,
		inactivity_exempt boolean DEFAULT false,
		CONSTRAINT users_pkey PRIMARY KEY (id)
	)`,
	`CREATE TABLE roles (
		id bigserial,
		created_at timestamp with time zone,
		updated_at timestamp with time zone,
		deleted_at timestamp with time zone,
		name character varying(50) NOT NULL,
		description character varying(200),
		CONSTRAINT roles_pkey PRIMARY KEY (id)
	)`,
	`CREATE TABLE user_roles (
		role_id bigint NOT NULL,
		user_id bigint NOT NULL,
		CONSTRAINT user_roles_pkey PRIMARY KEY (role_id, user_id)
	)`,
	`CREATE TABLE user_groups (
		id bigserial,
		created_at timestamp with time zone,
		updated_at timestamp with time zone,
		deleted_at timestamp with time zone,
		name character varying(100) NOT NULL,
		description character varying(500),
		CONSTRAINT user_groups_pkey PRIMARY KEY (id)
	)`,
	`CREATE TABLE user_group_members (
		user_group_id bigint NOT NULL,
		user_id bigint NOT NULL,
		CONSTRAINT user_group_members_pkey PRIMARY KEY (user_group_id, user_id)
	)`,
	`CREATE TABLE refresh_tokens (
		id bigserial,
		user_id bigint NOT NULL,
		token_hash character varying(64) NOT NULL,
		session_started_at timestamp with time zone NOT NULL,
		expires_at timestamp with time zone NOT NULL,
		last_used_at timestamp with time zone NOT NULL,
		auth_method character varying(32),
		provider_id bigint,
		auth_epoch bigint DEFAULT 0 NOT NULL,
		cred_epoch bigint DEFAULT 0 NOT NULL,
		revoked_at timestamp with time zone,
		revoked_reason character varying(32),
		created_at timestamp with time zone,
		CONSTRAINT refresh_tokens_pkey PRIMARY KEY (id)
	)`,
	`CREATE TABLE password_histories (
		id bigserial,
		user_id bigint NOT NULL,
		password_hash text NOT NULL,
		created_at timestamp with time zone,
		CONSTRAINT password_histories_pkey PRIMARY KEY (id)
	)`,
	`CREATE TABLE security_policies (
		key character varying(64) NOT NULL,
		value character varying(128) NOT NULL,
		updated_by character varying(100),
		updated_at timestamp with time zone,
		CONSTRAINT security_policies_pkey PRIMARY KEY (key)
	)`,
	`CREATE TABLE oidc_providers (
		id bigserial,
		created_at timestamp with time zone,
		updated_at timestamp with time zone,
		deleted_at timestamp with time zone,
		name character varying(100) NOT NULL,
		issuer character varying(500) NOT NULL,
		client_id character varying(255) NOT NULL,
		client_secret_enc text,
		scopes character varying(255) DEFAULT 'openid profile email'::character varying NOT NULL,
		admission_mode character varying(32) DEFAULT 'prebound_only'::character varying NOT NULL,
		admission_rules text,
		force_shared boolean,
		auth_epoch bigint DEFAULT 0 NOT NULL,
		enabled boolean DEFAULT false NOT NULL,
		CONSTRAINT oidc_providers_pkey PRIMARY KEY (id)
	)`,
	`CREATE TABLE user_external_identities (
		id bigserial,
		created_at timestamp with time zone,
		updated_at timestamp with time zone,
		deleted_at timestamp with time zone,
		user_id bigint NOT NULL,
		provider_id bigint,
		issuer character varying(500) NOT NULL,
		client_id character varying(255) NOT NULL,
		subject character varying(255) NOT NULL,
		claim_username character varying(255),
		claim_email character varying(255),
		last_login_at timestamp with time zone,
		CONSTRAINT user_external_identities_pkey PRIMARY KEY (id)
	)`,
	`CREATE TABLE oidc_flow_states (
		state character varying(64) NOT NULL,
		nonce character varying(64) NOT NULL,
		pkce_verifier character varying(128) NOT NULL,
		provider_id bigint NOT NULL,
		auth_epoch bigint DEFAULT 0 NOT NULL,
		binding_hash character varying(64) NOT NULL,
		redirect_next character varying(255),
		expires_at timestamp with time zone NOT NULL,
		created_at timestamp with time zone,
		CONSTRAINT oidc_flow_states_pkey PRIMARY KEY (state)
	)`,
	`CREATE TABLE oidc_login_tickets (
		token_hash character varying(64) NOT NULL,
		user_id bigint NOT NULL,
		provider_id bigint NOT NULL,
		auth_epoch bigint DEFAULT 0 NOT NULL,
		cred_epoch bigint DEFAULT 0 NOT NULL,
		auth_method character varying(32) NOT NULL,
		flow_binding_hash character varying(64) NOT NULL,
		redirect_next character varying(255),
		binding_failures bigint DEFAULT 0 NOT NULL,
		expires_at timestamp with time zone NOT NULL,
		created_at timestamp with time zone,
		CONSTRAINT oidc_login_tickets_pkey PRIMARY KEY (token_hash)
	)`,
	`CREATE TABLE ldap_directories (
		id bigserial,
		created_at timestamp with time zone,
		updated_at timestamp with time zone,
		deleted_at timestamp with time zone,
		singleton integer DEFAULT 1 NOT NULL,
		name character varying(100) DEFAULT ''::character varying NOT NULL,
		url character varying(500) DEFAULT ''::character varying NOT NULL,
		bind_dn character varying(500) DEFAULT ''::character varying NOT NULL,
		bind_password_enc text DEFAULT ''::text NOT NULL,
		base_dn character varying(500) DEFAULT ''::character varying NOT NULL,
		user_filter character varying(500) DEFAULT ''::character varying NOT NULL,
		attr_email character varying(100) DEFAULT ''::character varying NOT NULL,
		attr_fullname character varying(100) DEFAULT ''::character varying NOT NULL,
		skip_tls_verify boolean DEFAULT false NOT NULL,
		enabled boolean DEFAULT false NOT NULL,
		CONSTRAINT ldap_directories_singleton_check CHECK ((singleton = 1)),
		CONSTRAINT ldap_directories_pkey PRIMARY KEY (id)
	)`,
}

// baselineIdentityForeignKeys 本域的外鍵約束（於全部建表之後統一套用，故不受建表順序限制）。
var baselineIdentityForeignKeys = []string{
	`ALTER TABLE user_external_identities ADD CONSTRAINT fk_user_external_identities_user FOREIGN KEY (user_id) REFERENCES users(id)`,
	`ALTER TABLE user_group_members ADD CONSTRAINT fk_user_group_members_user FOREIGN KEY (user_id) REFERENCES users(id)`,
	`ALTER TABLE user_group_members ADD CONSTRAINT fk_user_group_members_user_group FOREIGN KEY (user_group_id) REFERENCES user_groups(id)`,
	`ALTER TABLE user_roles ADD CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES roles(id)`,
	`ALTER TABLE user_roles ADD CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users(id)`,
}

// baselineIdentityIndexes 本域的索引。
var baselineIdentityIndexes = []string{
	`CREATE INDEX idx_users_deleted_at ON users USING btree (deleted_at)`,
	`CREATE UNIQUE INDEX idx_users_email ON users USING btree (email) WHERE ((email IS NOT NULL) AND (deleted_at IS NULL))`,
	`CREATE UNIQUE INDEX idx_users_username ON users USING btree (username) WHERE (deleted_at IS NULL)`,
	`CREATE INDEX idx_roles_deleted_at ON roles USING btree (deleted_at)`,
	`CREATE UNIQUE INDEX idx_roles_name ON roles USING btree (name)`,
	`CREATE INDEX idx_user_groups_deleted_at ON user_groups USING btree (deleted_at)`,
	`CREATE UNIQUE INDEX idx_user_groups_name ON user_groups USING btree (name)`,
	`CREATE INDEX idx_refresh_tokens_provider_id ON refresh_tokens USING btree (provider_id)`,
	`CREATE INDEX idx_refresh_tokens_revoked_at ON refresh_tokens USING btree (revoked_at)`,
	`CREATE UNIQUE INDEX idx_refresh_tokens_token_hash ON refresh_tokens USING btree (token_hash)`,
	`CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens USING btree (user_id)`,
	`CREATE INDEX idx_password_histories_user_id ON password_histories USING btree (user_id)`,
	`CREATE INDEX idx_oidc_providers_deleted_at ON oidc_providers USING btree (deleted_at)`,
	`CREATE UNIQUE INDEX idx_oidc_providers_identity_domain ON oidc_providers USING btree (issuer, client_id) WHERE (deleted_at IS NULL)`,
	`CREATE INDEX idx_user_external_identities_deleted_at ON user_external_identities USING btree (deleted_at)`,
	`CREATE UNIQUE INDEX idx_user_external_identities_domain ON user_external_identities USING btree (issuer, client_id, subject) WHERE (deleted_at IS NULL)`,
	`CREATE INDEX idx_user_external_identities_provider_id ON user_external_identities USING btree (provider_id)`,
	`CREATE INDEX idx_user_external_identities_user_id ON user_external_identities USING btree (user_id)`,
	`CREATE INDEX idx_oidc_flow_states_expires_at ON oidc_flow_states USING btree (expires_at)`,
	`CREATE INDEX idx_oidc_flow_states_provider_id ON oidc_flow_states USING btree (provider_id)`,
	`CREATE INDEX idx_oidc_login_tickets_expires_at ON oidc_login_tickets USING btree (expires_at)`,
	`CREATE INDEX idx_oidc_login_tickets_provider_id ON oidc_login_tickets USING btree (provider_id)`,
	`CREATE INDEX idx_oidc_login_tickets_user_id ON oidc_login_tickets USING btree (user_id)`,
	`CREATE INDEX idx_ldap_directories_deleted_at ON ldap_directories USING btree (deleted_at)`,
	`CREATE UNIQUE INDEX idx_ldap_directories_singleton ON ldap_directories USING btree (singleton) WHERE (deleted_at IS NULL)`,
}
