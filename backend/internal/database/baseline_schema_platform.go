package database

// 平台服務——baseline schema 的「platform」域。
//
// 金鑰信封、簽章鑰與外送通道設定。
//
// **DDL 一律無條件**（不使用任何條件式建立語法）：baseline 是全新安裝的唯一 schema 事實源，
// 在非空 schema 上跑必須立刻炸而不是靜默 no-op——後者正是 2026-08-12 索引事故的成因。
//
// 本檔為機器可讀的最終形狀宣告，不描述任何歷史演進；欄位語義見對應的
// internal/model 檔與 docs/DB_SCHEMA.md。

// baselinePlatformTables 本域的建表 DDL（依「被參照者先建」排列）。
var baselinePlatformTables = []string{
	`CREATE TABLE data_keys (
		id bigserial,
		purpose character varying(32) NOT NULL,
		version bigint NOT NULL,
		wrapped_key text NOT NULL,
		kek_id character varying(255) NOT NULL,
		status character varying(16) NOT NULL,
		created_at timestamp with time zone,
		retired_at timestamp with time zone,
		kek_pending boolean DEFAULT false NOT NULL,
		kek_retired_at timestamp with time zone,
		kek_retired_by character varying(255) DEFAULT ''::character varying NOT NULL,
		kek_retired_reason character varying(16) DEFAULT ''::character varying NOT NULL,
		CONSTRAINT data_keys_pkey PRIMARY KEY (id)
	)`,
	`CREATE TABLE checkpoint_signing_keys (
		id bigserial,
		version bigint NOT NULL,
		active boolean DEFAULT false NOT NULL,
		public_key character varying(64) NOT NULL,
		private_key_enc text NOT NULL,
		created_at timestamp with time zone,
		CONSTRAINT checkpoint_signing_keys_pkey PRIMARY KEY (id)
	)`,
	`CREATE TABLE export_signing_keys (
		id bigserial,
		private_key_enc text NOT NULL,
		public_key character varying(64) NOT NULL,
		created_at timestamp with time zone,
		CONSTRAINT export_signing_keys_pkey PRIMARY KEY (id)
	)`,
	`CREATE TABLE notification_channels (
		id bigserial,
		name character varying(100) NOT NULL,
		type character varying(20) DEFAULT 'webhook'::character varying NOT NULL,
		url text NOT NULL,
		secret text,
		enabled boolean DEFAULT true NOT NULL,
		created_at timestamp with time zone DEFAULT now() NOT NULL,
		updated_at timestamp with time zone DEFAULT now() NOT NULL,
		language character varying(8) DEFAULT 'zh-TW'::character varying NOT NULL,
		CONSTRAINT notification_channels_language_check CHECK (language IN ('zh-TW','en-US','ja-JP')),
		CONSTRAINT notification_channels_type_check CHECK (type IN ('webhook','slack')),
		CONSTRAINT notification_channels_pkey PRIMARY KEY (id)
	)`,
	`CREATE TABLE syslog_settings (
		id bigserial,
		enabled boolean DEFAULT false NOT NULL,
		host character varying(255) DEFAULT ''::character varying NOT NULL,
		port bigint DEFAULT 514 NOT NULL,
		protocol character varying(10) DEFAULT 'udp'::character varying NOT NULL,
		tls_ca text DEFAULT ''::text NOT NULL,
		updated_by character varying(100),
		updated_at timestamp with time zone,
		CONSTRAINT syslog_settings_pkey PRIMARY KEY (id)
	)`,
}

// baselinePlatformForeignKeys 本域的外鍵約束（於全部建表之後統一套用，故不受建表順序限制）。
var baselinePlatformForeignKeys = []string{}

// baselinePlatformIndexes 本域的索引。
var baselinePlatformIndexes = []string{
	`CREATE INDEX idx_data_keys_kek_retired_at ON data_keys USING btree (kek_retired_at)`,
	`CREATE UNIQUE INDEX idx_data_keys_purpose_version_kek ON data_keys USING btree (purpose, version, kek_id) WHERE (kek_retired_at IS NULL)`,
	`CREATE UNIQUE INDEX idx_checkpoint_signing_keys_version ON checkpoint_signing_keys USING btree (version)`,
}
