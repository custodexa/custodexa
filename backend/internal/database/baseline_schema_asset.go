package database

// 資產與憑證——baseline schema 的「asset」域。
//
// 資產本體、分組、節點樹、帳號與改密工作流。
//
// **DDL 一律無條件**（不使用任何條件式建立語法）：baseline 是全新安裝的唯一 schema 事實源，
// 在非空 schema 上跑必須立刻炸而不是靜默 no-op——後者正是 2026-08-12 索引事故的成因。
//
// 本檔為機器可讀的最終形狀宣告，不描述任何歷史演進；欄位語義見對應的
// internal/model 檔與 docs/DB_SCHEMA.md。

// baselineAssetTables 本域的建表 DDL（依「被參照者先建」排列）。
var baselineAssetTables = []string{
	`CREATE TABLE asset_groups (
		id bigserial,
		created_at timestamp with time zone,
		updated_at timestamp with time zone,
		deleted_at timestamp with time zone,
		name character varying(100) NOT NULL,
		description character varying(500),
		parent_id bigint,
		CONSTRAINT asset_groups_pkey PRIMARY KEY (id)
	)`,
	`CREATE TABLE assets (
		id bigserial,
		created_at timestamp with time zone,
		updated_at timestamp with time zone,
		deleted_at timestamp with time zone,
		name character varying(100) NOT NULL,
		protocol character varying(10) NOT NULL,
		host character varying(255) NOT NULL,
		port bigint NOT NULL,
		description character varying(500),
		active boolean DEFAULT true,
		created_by bigint NOT NULL,
		username character varying(100),
		password_enc text,
		private_key_enc text,
		has_password boolean,
		has_private_key boolean,
		access_policy character varying(20),
		tags character varying(500),
		last_test_status character varying(20) DEFAULT ''::character varying,
		last_test_at timestamp with time zone,
		last_test_latency_ms bigint DEFAULT 0,
		rdp_security character varying(10),
		rdp_verify_cert boolean DEFAULT false,
		db_name character varying(128),
		db_tls_mode character varying(20),
		dbca_cert text,
		k8s_namespace character varying(63),
		k8s_pod character varying(253),
		k8s_container character varying(63),
		k8s_ca_cert text,
		k8s_insecure_skip_tls boolean DEFAULT false,
		sftp_enabled boolean DEFAULT false,
		sftp_port bigint DEFAULT 22,
		sftp_username character varying(100),
		sftp_password_enc text,
		has_sftp_password boolean,
		CONSTRAINT assets_pkey PRIMARY KEY (id)
	)`,
	`CREATE TABLE asset_nodes (
		id bigserial,
		created_at timestamp with time zone,
		asset_id bigint NOT NULL,
		node_id bigint NOT NULL,
		CONSTRAINT asset_nodes_pkey PRIMARY KEY (id)
	)`,
	`CREATE TABLE asset_accounts (
		id bigserial,
		created_at timestamp with time zone,
		updated_at timestamp with time zone,
		deleted_at timestamp with time zone,
		asset_id bigint NOT NULL,
		username character varying(100),
		password_enc text,
		private_key_enc text,
		is_default boolean DEFAULT false,
		privileged boolean DEFAULT false,
		auth_method character varying(20) DEFAULT 'sql'::character varying,
		note character varying(255),
		CONSTRAINT asset_accounts_pkey PRIMARY KEY (id)
	)`,
	`CREATE TABLE asset_host_keys (
		id bigserial,
		asset_id bigint NOT NULL,
		algorithm character varying(64) NOT NULL,
		fingerprint character varying(128) NOT NULL,
		public_key text NOT NULL,
		created_at timestamp with time zone,
		updated_at timestamp with time zone,
		CONSTRAINT asset_host_keys_pkey PRIMARY KEY (id)
	)`,
	`CREATE TABLE snippets (
		id bigserial,
		user_id bigint NOT NULL,
		name character varying(128) NOT NULL,
		content character varying(4096) NOT NULL,
		created_at timestamp with time zone,
		updated_at timestamp with time zone,
		CONSTRAINT snippets_pkey PRIMARY KEY (id)
	)`,
	`CREATE TABLE change_secret_plans (
		id bigserial,
		name character varying(128) NOT NULL,
		asset_ids text NOT NULL,
		accounts text,
		cron character varying(64),
		enabled boolean DEFAULT true,
		secret_type character varying(16) DEFAULT 'password'::character varying,
		key_strategy character varying(16) DEFAULT 'append_replace'::character varying,
		password_length bigint DEFAULT 16,
		password_include_symbol boolean DEFAULT true,
		password_exclude_ambiguous boolean DEFAULT true,
		created_at timestamp with time zone,
		updated_at timestamp with time zone,
		CONSTRAINT change_secret_plans_pkey PRIMARY KEY (id)
	)`,
	`CREATE TABLE change_secret_records (
		id bigserial,
		plan_id bigint NOT NULL,
		asset_id bigint NOT NULL,
		account_id bigint,
		account_username character varying(100),
		secret_type character varying(16),
		status character varying(16) NOT NULL,
		error character varying(512),
		executed_at timestamp with time zone,
		CONSTRAINT change_secret_records_pkey PRIMARY KEY (id)
	)`,
	`CREATE TABLE change_secret_candidates (
		id bigserial,
		account_id bigint NOT NULL,
		asset_id bigint NOT NULL,
		plan_id bigint,
		account_username character varying(100),
		secret_type character varying(16) NOT NULL,
		password_enc text,
		private_key_enc text,
		public_key text,
		previous_public_key text,
		applied boolean DEFAULT false,
		abandoned boolean DEFAULT false,
		attempt_count bigint DEFAULT 0,
		last_attempt_at timestamp with time zone,
		next_attempt_at timestamp with time zone,
		last_error character varying(512),
		created_at timestamp with time zone,
		updated_at timestamp with time zone,
		CONSTRAINT change_secret_candidates_pkey PRIMARY KEY (id)
	)`,
}

// baselineAssetForeignKeys 本域的外鍵約束（於全部建表之後統一套用，故不受建表順序限制）。
var baselineAssetForeignKeys = []string{}

// baselineAssetIndexes 本域的索引。
var baselineAssetIndexes = []string{
	`CREATE INDEX idx_asset_groups_deleted_at ON asset_groups USING btree (deleted_at)`,
	`CREATE INDEX idx_asset_groups_parent_id ON asset_groups USING btree (parent_id)`,
	`CREATE UNIQUE INDEX idx_asset_groups_sibling_name ON asset_groups USING btree (COALESCE(parent_id, (0)::bigint), name) WHERE (deleted_at IS NULL)`,
	`CREATE INDEX idx_assets_active ON assets USING btree (active)`,
	`CREATE INDEX idx_assets_created_by ON assets USING btree (created_by)`,
	`CREATE INDEX idx_assets_deleted_at ON assets USING btree (deleted_at)`,
	`CREATE UNIQUE INDEX idx_assets_name ON assets USING btree (name) WHERE (deleted_at IS NULL)`,
	`CREATE INDEX idx_assets_protocol ON assets USING btree (protocol)`,
	`CREATE INDEX idx_asset_nodes_asset_id ON asset_nodes USING btree (asset_id)`,
	`CREATE UNIQUE INDEX idx_asset_nodes_asset_node ON asset_nodes USING btree (asset_id, node_id)`,
	`CREATE INDEX idx_asset_nodes_node_id ON asset_nodes USING btree (node_id)`,
	`CREATE INDEX idx_asset_accounts_asset_id ON asset_accounts USING btree (asset_id)`,
	`CREATE UNIQUE INDEX idx_asset_accounts_default ON asset_accounts USING btree (asset_id) WHERE ((is_default = true) AND (deleted_at IS NULL))`,
	`CREATE INDEX idx_asset_accounts_deleted_at ON asset_accounts USING btree (deleted_at)`,
	`CREATE INDEX idx_asset_accounts_is_default ON asset_accounts USING btree (is_default)`,
	`CREATE UNIQUE INDEX idx_asset_accounts_username ON asset_accounts USING btree (asset_id, username) WHERE (deleted_at IS NULL)`,
	`CREATE UNIQUE INDEX idx_asset_host_keys_asset_id ON asset_host_keys USING btree (asset_id)`,
	`CREATE INDEX idx_snippets_user_id ON snippets USING btree (user_id)`,
	`CREATE UNIQUE INDEX idx_change_secret_plans_name ON change_secret_plans USING btree (name)`,
	`CREATE INDEX idx_change_secret_records_account_id ON change_secret_records USING btree (account_id)`,
	`CREATE INDEX idx_change_secret_records_asset_id ON change_secret_records USING btree (asset_id)`,
	`CREATE INDEX idx_change_secret_records_plan_id ON change_secret_records USING btree (plan_id)`,
	`CREATE INDEX idx_change_secret_candidates_abandoned ON change_secret_candidates USING btree (abandoned)`,
	`CREATE UNIQUE INDEX idx_change_secret_candidates_account_id ON change_secret_candidates USING btree (account_id)`,
	`CREATE INDEX idx_change_secret_candidates_asset_id ON change_secret_candidates USING btree (asset_id)`,
	`CREATE INDEX idx_change_secret_candidates_next_attempt_at ON change_secret_candidates USING btree (next_attempt_at)`,
}
