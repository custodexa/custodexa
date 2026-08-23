package database

// 授權與申請流程——baseline schema 的「authz」域。
//
// 資產授權、臨時存取申請、簽核路由與週期性複審。
//
// **DDL 一律無條件**（不使用任何條件式建立語法）：baseline 是全新安裝的唯一 schema 事實源，
// 在非空 schema 上跑必須立刻炸而不是靜默 no-op——後者正是 2026-08-12 索引事故的成因。
//
// 本檔為機器可讀的最終形狀宣告，不描述任何歷史演進；欄位語義見對應的
// internal/model 檔與 docs/DB_SCHEMA.md。

// baselineAuthzTables 本域的建表 DDL（依「被參照者先建」排列）。
var baselineAuthzTables = []string{
	`CREATE TABLE asset_authorizations (
		id bigserial,
		created_at timestamp with time zone,
		updated_at timestamp with time zone,
		deleted_at timestamp with time zone,
		user_id bigint,
		user_group_id bigint,
		asset_id bigint,
		asset_group_id bigint,
		permission character varying(20) NOT NULL,
		date_start timestamp with time zone,
		date_expired timestamp with time zone,
		source character varying(20),
		accounts text DEFAULT '["@ALL"]'::text NOT NULL,
		granted_by bigint NOT NULL,
		CONSTRAINT chk_auth_target CHECK ((((asset_id IS NOT NULL) AND (asset_group_id IS NULL)) OR ((asset_id IS NULL) AND (asset_group_id IS NOT NULL)))),
		CONSTRAINT chk_authz_subject_xor CHECK (((((user_id IS NOT NULL))::integer + ((user_group_id IS NOT NULL))::integer) = 1)),
		CONSTRAINT asset_authorizations_pkey PRIMARY KEY (id)
	)`,
	`CREATE TABLE access_requests (
		id bigserial,
		created_at timestamp with time zone,
		updated_at timestamp with time zone,
		deleted_at timestamp with time zone,
		requester_id bigint NOT NULL,
		asset_id bigint NOT NULL,
		reason character varying(1000) NOT NULL,
		requested_duration_minutes bigint NOT NULL,
		requested_date_start timestamp with time zone,
		accounts text DEFAULT '["@ALL"]'::text NOT NULL,
		status character varying(20) NOT NULL,
		approver_id bigint,
		decided_at timestamp with time zone,
		decision_note character varying(1000),
		approved_duration_minutes bigint,
		approved_date_start timestamp with time zone,
		auto_approved boolean,
		authorization_id bigint,
		pending_expires_at timestamp with time zone NOT NULL,
		kind character varying(20),
		review_status character varying(20),
		reviewed_by bigint,
		reviewed_at timestamp with time zone,
		review_disposition character varying(20),
		review_note character varying(1000),
		review_overdue_notified_at timestamp with time zone,
		revoked_at timestamp with time zone,
		revoked_by bigint,
		revoke_note character varying(1000),
		CONSTRAINT access_requests_pkey PRIMARY KEY (id)
	)`,
	`CREATE TABLE access_request_approvals (
		id bigserial,
		created_at timestamp with time zone,
		request_id bigint NOT NULL,
		approver_id bigint NOT NULL,
		note character varying(1000),
		CONSTRAINT access_request_approvals_pkey PRIMARY KEY (id)
	)`,
	`CREATE TABLE approver_scopes (
		id bigserial,
		created_at timestamp with time zone,
		updated_at timestamp with time zone,
		deleted_at timestamp with time zone,
		approver_id bigint,
		approver_group_id bigint,
		asset_id bigint,
		asset_group_id bigint,
		subject_user_id bigint,
		subject_group_id bigint,
		granted_by bigint NOT NULL,
		CONSTRAINT chk_approver_scope_actor CHECK (((((approver_id IS NOT NULL))::integer + ((approver_group_id IS NOT NULL))::integer) = 1)),
		CONSTRAINT chk_approver_scope_target CHECK (((((((asset_id IS NOT NULL))::integer + ((asset_group_id IS NOT NULL))::integer) + ((subject_user_id IS NOT NULL))::integer) + ((subject_group_id IS NOT NULL))::integer) = 1)),
		CONSTRAINT approver_scopes_pkey PRIMARY KEY (id)
	)`,
	`CREATE TABLE access_reviews (
		id bigserial,
		reviewed_by bigint NOT NULL,
		reviewer_name character varying(50),
		reviewed_at timestamp with time zone NOT NULL,
		scope character varying(200) NOT NULL,
		note text NOT NULL,
		authorization_count bigint NOT NULL,
		matrix_snapshot text NOT NULL,
		created_at timestamp with time zone,
		CONSTRAINT access_reviews_pkey PRIMARY KEY (id)
	)`,
}

// baselineAuthzForeignKeys 本域的外鍵約束（於全部建表之後統一套用，故不受建表順序限制）。
var baselineAuthzForeignKeys = []string{
	`ALTER TABLE access_request_approvals ADD CONSTRAINT fk_access_request_approvals_approver FOREIGN KEY (approver_id) REFERENCES users(id)`,
	`ALTER TABLE access_request_approvals ADD CONSTRAINT fk_access_request_approvals_request FOREIGN KEY (request_id) REFERENCES access_requests(id)`,
	`ALTER TABLE access_request_approvals ADD CONSTRAINT fk_access_requests_approvals FOREIGN KEY (request_id) REFERENCES access_requests(id)`,
	`ALTER TABLE access_requests ADD CONSTRAINT fk_access_requests_approver FOREIGN KEY (approver_id) REFERENCES users(id)`,
	`ALTER TABLE access_requests ADD CONSTRAINT fk_access_requests_asset FOREIGN KEY (asset_id) REFERENCES assets(id)`,
	`ALTER TABLE access_requests ADD CONSTRAINT fk_access_requests_authorization FOREIGN KEY (authorization_id) REFERENCES asset_authorizations(id)`,
	`ALTER TABLE access_requests ADD CONSTRAINT fk_access_requests_requester FOREIGN KEY (requester_id) REFERENCES users(id)`,
	`ALTER TABLE approver_scopes ADD CONSTRAINT fk_approver_scopes_approver FOREIGN KEY (approver_id) REFERENCES users(id)`,
	`ALTER TABLE approver_scopes ADD CONSTRAINT fk_approver_scopes_approver_group FOREIGN KEY (approver_group_id) REFERENCES user_groups(id)`,
	`ALTER TABLE approver_scopes ADD CONSTRAINT fk_approver_scopes_asset FOREIGN KEY (asset_id) REFERENCES assets(id)`,
	`ALTER TABLE approver_scopes ADD CONSTRAINT fk_approver_scopes_asset_group FOREIGN KEY (asset_group_id) REFERENCES asset_groups(id)`,
	`ALTER TABLE approver_scopes ADD CONSTRAINT fk_approver_scopes_granted_by_user FOREIGN KEY (granted_by) REFERENCES users(id)`,
	`ALTER TABLE approver_scopes ADD CONSTRAINT fk_approver_scopes_subject_group FOREIGN KEY (subject_group_id) REFERENCES user_groups(id)`,
	`ALTER TABLE approver_scopes ADD CONSTRAINT fk_approver_scopes_subject_user FOREIGN KEY (subject_user_id) REFERENCES users(id)`,
	`ALTER TABLE asset_authorizations ADD CONSTRAINT fk_asset_authorizations_asset FOREIGN KEY (asset_id) REFERENCES assets(id)`,
	`ALTER TABLE asset_authorizations ADD CONSTRAINT fk_asset_authorizations_asset_group FOREIGN KEY (asset_group_id) REFERENCES asset_groups(id)`,
	`ALTER TABLE asset_authorizations ADD CONSTRAINT fk_asset_authorizations_granted_by_user FOREIGN KEY (granted_by) REFERENCES users(id)`,
	`ALTER TABLE asset_authorizations ADD CONSTRAINT fk_asset_authorizations_user FOREIGN KEY (user_id) REFERENCES users(id)`,
	`ALTER TABLE asset_authorizations ADD CONSTRAINT fk_asset_authorizations_user_group FOREIGN KEY (user_group_id) REFERENCES user_groups(id)`,
}

// baselineAuthzIndexes 本域的索引。
var baselineAuthzIndexes = []string{
	`CREATE INDEX idx_asset ON asset_authorizations USING btree (asset_id)`,
	`CREATE INDEX idx_asset_authorizations_deleted_at ON asset_authorizations USING btree (deleted_at)`,
	`CREATE UNIQUE INDEX idx_ugroup_agroup_permission ON asset_authorizations USING btree (user_group_id, asset_group_id, permission) WHERE ((deleted_at IS NULL) AND ((source)::text <> 'ticket'::text))`,
	`CREATE UNIQUE INDEX idx_ugroup_asset_permission ON asset_authorizations USING btree (user_group_id, asset_id, permission) WHERE ((deleted_at IS NULL) AND ((source)::text <> 'ticket'::text))`,
	`CREATE INDEX idx_user_asset ON asset_authorizations USING btree (user_id, asset_id) WHERE (asset_id IS NOT NULL)`,
	`CREATE UNIQUE INDEX idx_user_asset_permission ON asset_authorizations USING btree (user_id, asset_id, permission) WHERE ((deleted_at IS NULL) AND ((source)::text <> 'ticket'::text))`,
	`CREATE INDEX idx_user_group ON asset_authorizations USING btree (user_id, asset_group_id) WHERE (asset_group_id IS NOT NULL)`,
	`CREATE UNIQUE INDEX idx_user_group_permission ON asset_authorizations USING btree (user_id, asset_group_id, permission) WHERE ((deleted_at IS NULL) AND ((source)::text <> 'ticket'::text))`,
	`CREATE INDEX idx_access_request_asset ON access_requests USING btree (asset_id)`,
	`CREATE UNIQUE INDEX idx_access_request_pending_dedup ON access_requests USING btree (requester_id, asset_id) WHERE (((status)::text = 'pending'::text) AND (deleted_at IS NULL) AND ((kind)::text = 'normal'::text))`,
	`CREATE INDEX idx_access_request_requester ON access_requests USING btree (requester_id)`,
	`CREATE INDEX idx_access_request_review_status ON access_requests USING btree (review_status) WHERE (((review_status)::text = 'pending_review'::text) AND (deleted_at IS NULL))`,
	`CREATE INDEX idx_access_request_status ON access_requests USING btree (status)`,
	`CREATE INDEX idx_access_requests_deleted_at ON access_requests USING btree (deleted_at)`,
	`CREATE INDEX idx_access_requests_pending_expires_at ON access_requests USING btree (pending_expires_at)`,
	`CREATE INDEX idx_access_requests_review_status ON access_requests USING btree (review_status)`,
	`CREATE INDEX idx_access_request_approvals_request_id ON access_request_approvals USING btree (request_id)`,
	`CREATE UNIQUE INDEX idx_request_approval_once ON access_request_approvals USING btree (request_id, approver_id)`,
	`CREATE UNIQUE INDEX idx_approver_scope_agroup ON approver_scopes USING btree (approver_id, asset_group_id) WHERE (deleted_at IS NULL)`,
	`CREATE UNIQUE INDEX idx_approver_scope_asset ON approver_scopes USING btree (approver_id, asset_id) WHERE (deleted_at IS NULL)`,
	`CREATE UNIQUE INDEX idx_approver_scope_g_agroup ON approver_scopes USING btree (approver_group_id, asset_group_id) WHERE (deleted_at IS NULL)`,
	`CREATE UNIQUE INDEX idx_approver_scope_g_asset ON approver_scopes USING btree (approver_group_id, asset_id) WHERE (deleted_at IS NULL)`,
	`CREATE UNIQUE INDEX idx_approver_scope_g_sgroup ON approver_scopes USING btree (approver_group_id, subject_group_id) WHERE (deleted_at IS NULL)`,
	`CREATE UNIQUE INDEX idx_approver_scope_g_suser ON approver_scopes USING btree (approver_group_id, subject_user_id) WHERE (deleted_at IS NULL)`,
	`CREATE UNIQUE INDEX idx_approver_scope_sgroup ON approver_scopes USING btree (approver_id, subject_group_id) WHERE (deleted_at IS NULL)`,
	`CREATE UNIQUE INDEX idx_approver_scope_suser ON approver_scopes USING btree (approver_id, subject_user_id) WHERE (deleted_at IS NULL)`,
	`CREATE INDEX idx_approver_scopes_deleted_at ON approver_scopes USING btree (deleted_at)`,
}
