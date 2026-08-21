# Changelog

All notable changes to Custodexa will be documented in this file.

## 1.0.2 — session cookie and audit query hardening (2026-08-22)

Browsers now hold the session refresh credential in an httpOnly cookie rather than
in local storage. Sessions do not carry across the upgrade: everyone signs in once
after you deploy this.

If you serve Custodexa over HTTPS, set `PUBLIC_BASE_URL` to the public https
address, or set `AUTH_REFRESH_COOKIE_SECURE=true` when TLS terminates further out
and that variable cannot carry the public address. The startup log states which
value is in effect and where it came from.

### Security

- The session refresh credential is issued as an httpOnly, `SameSite=Strict`
  cookie scoped to `/api/v1/auth/`. It no longer appears in response bodies and
  the browser no longer stores it; the frontend clears any value left over from
  an earlier version at startup. Access tokens continue to travel in the
  `Authorization` header and are not read from cookies.
- Audit log queries check the `sort_by` and `sort_order` parameters against a
  fixed column list before building the query.
- Integer parsing in configuration, pagination cursors and local user lookup
  rejects out-of-range input at the parse step rather than after conversion.
- A malformed `SEAL_UNSEAL_COOLDOWN_THRESHOLD` refuses startup instead of falling
  back to the default.

### Changed

- The version reported by `/health` is injected at build time from the `VERSION`
  file, which a test keeps in step with this changelog.

### Documentation

- The environment template is written in English, with Traditional Chinese and
  Japanese reference translations under `docs/`. The template remains the one file
  you copy to `.env`.
- QUICKSTART covers the refresh cookie's `Secure` derivation alongside the TLS
  reverse-proxy walkthrough.

## 1.0.1 — dependency security updates (2026-08-21)

No product code changes. Rebuild your images to pick these up.

### Security

- Frontend dependencies updated to resolve all open advisories: lodash and
  lodash-es 4.18.1, axios 1.18.0, flatted 3.4.4, minimatch 3.1.5, ajv 6.15.0,
  nanoid, postcss, form-data, js-yaml, and the Vite toolchain (Vite 8,
  plugin-vue 6). `npm audit` and GitHub dependency alerts are clean after
  this release.
- Backend: `github.com/Azure/go-ntlmssp` updated to v0.1.1.
- Verified against the full backend and frontend test suites and the
  production image build.

### Documentation

- QUICKSTART now walks through a minimal TLS reverse-proxy setup step by step
  (nginx container, certificate mounts, WebSocket upgrade verification).
- Public-facing prose reworked to read naturally; commands, procedures, and
  capability claims unchanged.

## 1.0.0 — initial public release (2026-08-21)

First public release under AGPL-3.0.

### What's in 1.0.0

- Browser-based access to SSH (native web terminal), RDP / VNC, database web CLIs
  (MySQL / PostgreSQL / Redis / SQL Server), and Kubernetes exec, plus SFTP file
  management, all funneled through one gateway with one-time connect tokens:
  the frontend never touches plaintext credentials.
- Full-session recording with variable-speed playback; command-level audit via an
  in-house terminal screen parser that reconstructs commands accurately inside
  full-screen programs (vim, top, pagers); clipboard and file-transfer auditing;
  no recording quotas, and recordings are never dropped to save space.
- Tamper-evident audit chain: row-level HMAC seals plus Ed25519-signed checkpoints
  anchored off-host via syslog; offline-verifiable evidence bundle export; an
  auditor workbench; alert rules with real-time command blocking and
  webhook / Slack delivery.
- Access governance: three-tier access policies, approval flows, break-glass
  emergency access (ships disabled), user groups, asset-tree authorization,
  periodic access reviews, and daily sign-off.
- Identity: local accounts, LDAP / AD directory login, OIDC SSO (multiple
  providers side by side), and TOTP MFA; envelope encryption for stored secrets
  with pluggable KEK providers (env / in-memory UI unseal / cloud KMS);
  in-memory unseal is the default mode.
- Credential rotation for the SSH domain (account-level passwords and SSH keys);
  session watermarking, live read-only monitoring, and session sharing.
- Full UI internationalization: Traditional Chinese, English, Japanese.
- docker compose deployment with a quickstart script, hardened fail-close startup
  checks, Prometheus metrics, RFC 5424 syslog forwarding, retention policies with
  audited deletion, and four operations runbooks.

### Known limitations at release

- Single-instance deployment only.
- Text-based command audit has principled limits; session recording replay is the
  source of truth (see "Design boundaries" in the README).
