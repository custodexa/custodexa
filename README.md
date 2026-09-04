<div align="center">
  <img src="docs/assets/brand/logo.png" alt="Custodexa — Guard Access. Preserve Evidence." width="440">
</div>

<p align="center"><b>English</b> | <a href="docs/zh-TW/README.md">繁體中文</a> | <a href="docs/ja/README.md">日本語</a> | <a href="docs/README.md">More languages →</a></p>
<p align="center"><a href="https://custodexa.org/en/">Website</a> · <a href="https://custodexa.org/en/docs/quickstart/">Documentation</a></p>
<p align="center">
  <a href="https://sonarcloud.io/summary/new_code?id=custodexa_custodexa"><img src="https://sonarcloud.io/api/project_badges/measure?project=custodexa_custodexa&metric=alert_status" alt="Quality Gate"></a>
  <a href="https://sonarcloud.io/summary/new_code?id=custodexa_custodexa"><img src="https://sonarcloud.io/api/project_badges/measure?project=custodexa_custodexa&metric=security_rating" alt="Security Rating"></a>
  <a href="https://sonarcloud.io/summary/new_code?id=custodexa_custodexa"><img src="https://sonarcloud.io/api/project_badges/measure?project=custodexa_custodexa&metric=sqale_rating" alt="Maintainability Rating"></a>
  <a href="https://sonarcloud.io/summary/new_code?id=custodexa_custodexa"><img src="https://sonarcloud.io/api/project_badges/measure?project=custodexa_custodexa&metric=reliability_rating" alt="Reliability Rating"></a>
  <a href="https://github.com/custodexa/custodexa/releases"><img src="https://img.shields.io/github/v/release/custodexa/custodexa" alt="Latest release"></a>
  <a href="https://github.com/custodexa/custodexa/commits"><img src="https://img.shields.io/github/last-commit/custodexa/custodexa" alt="Last commit"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue" alt="License: AGPL-3.0"></a>
</p>

**Who connected to what, and what they did. The recording decides.**

An open-source privileged access gateway. The browser is the entrance, target hosts
install nothing, and every connection passes policy before it opens. What comes back is
a recording and a trail of commands, packaged with a signature an auditor can verify
offline.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/architecture-dark.svg">
    <img alt="Architecture: operators connect from a browser through the Custodexa gateway (auth gate, policy engine, protocol proxy, audit, evidence export) to SSH, RDP/VNC, database, and Kubernetes targets with zero agents installed; every session leaves a recording, a command log, and an Ed25519-sealed audit chain." src="docs/assets/architecture-light.svg" width="920">
  </picture>
</p>

## Why Custodexa

Any team managing a fleet of servers and databases eventually runs into the same
problems:

- **No answers after an incident.** Who connected to which machine, when, and what
  did they do? All you have is shell history and guesswork.
- **Credentials everywhere.** Root passwords and database credentials get passed
  around in note apps and chat windows; one departure forces a company-wide rotation.
- **Auditors want evidence.** "We have controls" doesn't pass an audit. You need
  complete operation logs and session recordings you can actually produce.

## One connection, five gates

Every session takes the same path, and the evidence is made along the way.

| | What it does |
|---|---|
| **01 Authentication gate** | Local accounts, LDAP and Active Directory, OIDC single sign-on, MFA by TOTP, and a break-glass path for the day the directory is down. |
| **02 Policy engine** | Each asset is set to direct connection, reason required, or approval required. An approval and the time-limited authorization it grants land together, so "why was this person allowed in" always has an answer. Role-based access control goes down to which account on which machine a person may use. |
| **03 Protocol proxy** | SSH, RDP, VNC, MySQL, PostgreSQL, SQL Server, Redis and Kubernetes exec, each a browser tab away. Credentials terminate here and never reach the browser, with one-time connect tokens and host key verification. Dangerous commands and database statements can alert or be stopped where they stand, and clipboard and file transfer content is captured. |
| **04 Credential rotation** | Scheduled password changes for Linux and Windows local accounts, verified on the target and rolled back there on failure. The rotation evidence report says, per account, how long it has gone without a change. |
| **05 Recording and audit** | Full-session recording with replay (seek, speed control) for every protocol, a command and statement trail that handles full-screen programs like vim correctly, webhook alerts, a checkpoint chain that seals intervals, and evidence bundles carrying a manifest and a signature, with offsite copies to object storage. |

**Truly open source, single edition.** No enterprise tier and no paywalled features.
What you see is all there is, under AGPL-3.0.

**Simple to deploy.** One docker compose command, four containers in production, https
served out of the box, and no outbound network needed once running.

## How this compares

Approaches, not brands. Each column describes a common shape and your environment may
differ. The reading criteria and the verification date for every cell are on the
[comparison page](https://custodexa.org/en/docs/compare/).

| | SSH jump host | VPN | Open source bastion | Commercial PAM | Custodexa |
|---|---|---|---|---|---|
| **Access boundary** | Usually the whole login host | Usually a whole network segment | Mostly per single target | Mostly per target or account | Per asset: direct, reason required, or approval required |
| **Approval before connecting** | Usually none | Authorized once, when the tunnel is built | Mostly none per connection | Mostly a request and approval flow | Approval and time-limited authorization land together |
| **Database statement auditing** | Mostly out of reach | No parsing above the network layer | Mostly some protocols | Depends on the edition | Recorded before execution, dangerous ones blocked live |
| **Evidence packaging** | Assembled from logs by hand | Connection logs by hand | Mostly record and recording export | Mostly reports and exports | One ZIP with a manifest and a signature, verifiable offline |
| **Credential rotation** | Mostly by hand | Mostly a directory service | Mostly by hand | Mostly scheduled rotation | Scheduled for Linux and Windows, with a rotation report |
| **License** | Follows the operating system components | Open source and commercial both exist | Mostly open source | Commercial subscription or perpetual | AGPL-3.0, source you can review yourself |

## Screenshots

| | |
|---|---|
| ![Dashboard](screenshots/dashboard-overview.png) | ![Web terminal in the workspace](screenshots/workspace-terminal.png) |
| ![Session replay with command log](screenshots/session-playback.png) | ![Command audit](screenshots/command-audit.png) |

Top-left to bottom-right: dashboard overview, workspace web terminal (with user
watermark), session replay with per-session command log, cross-session command audit.

## Quick Start

```bash
git clone https://github.com/custodexa/custodexa.git
cd custodexa
bash scripts/quickstart.sh --up
```

The script checks `.env` (creating it from the template on first run), generates any
missing secrets with a CSPRNG, starts the stack, waits for the backend to become
healthy, and finishes with the URL and admin login info. Values you have already set
are never touched.

By default the platform's own master key never touches disk. Your first visit opens
the **master-key initialization page**; the key is generated locally in your browser.
Save it — every restart stays sealed until it is entered again. Unattended deployments
can switch to the `env` or KMS key mode in `.env`. Prefer doing it by hand? Copy
`.env.example` to `.env`, follow its inline notes, then `docker compose up -d`.
On Windows, run the script inside WSL.

The stack serves https on port 443, with 80 redirecting to it, so the address carries no
port number; a host already running something there takes a different pair through
`TLS_HTTPS_PORT` and `TLS_HTTP_PORT` in `.env`. Out of the box it uses
a certificate it generated itself, so the address the script prints opens with a browser
warning until you install the accompanying certificate authority: download it from
`/custodexa-ca.crt` and hand it to the machines that connect. Bringing your own
certificate, or leaving TLS to a load balancer you already run, takes one setting each
and is covered in [docs/QUICKSTART.md](docs/QUICKSTART.md).

Log in as `admin` with the initial password you set. The first login walks you through a
mandatory password change, after which you can start adding assets and opening
connections.

There are no factory-default passwords; all four secrets must be set by you. This is
deliberate: a bastion host should never go live with default credentials.
Full configuration options, development mode, and troubleshooting are covered in
[docs/QUICKSTART.md](docs/QUICKSTART.md).

**Want to hack on it?** Uncomment `COMPOSE_FILE=docker-compose.dev.yml` in `.env` to
switch to the development stack (hot reload for both frontend and backend, plus test
target machines for every protocol). Start with [CONTRIBUTING.md](CONTRIBUTING.md).

## Architecture

**Backend** Go · Gin · GORM · PostgreSQL 16　**Frontend** Vue 3 · Element Plus · Vite
**Text terminals** xterm.js + native backend proxying　**Graphical protocols**
Apache Guacamole (guacd; RDP/VNC only)

Two decisions that shape the whole system:

- **All protocol handshakes happen in the backend**; the browser is just a display and a
  keyboard. This is what makes "the frontend never sees plaintext credentials" true.
  See `backend/internal/proxy/`.
- **SSH, database CLIs, and Kubernetes exec share a single text-terminal pipeline**:
  recording, command audit, blocking, and live monitoring are implemented once and apply
  uniformly across all eight protocols.

## Documentation

The quick start, the operations guides, and the security and contributing notes are
available in English, Traditional Chinese, and Japanese; the API and database references
are kept in one language. The index of all documents is [docs/README.md](docs/README.md).

| What you want to do | Read this |
|------|------|
| Deploy and operate | [docs/QUICKSTART.md](docs/QUICKSTART.md) (setup, configuration, troubleshooting); [docs/ops/](docs/ops/) (backup & restore, upgrades, deployment topology, platform credential rotation) |
| Contribute | [CONTRIBUTING.md](CONTRIBUTING.md) (DCO, workflow); [docs/dev/](docs/dev/) (architecture and testing discipline); [openspec/specs/](openspec/specs/) (behavioral specs, the source of truth for details) |
| Look up the API or schema | [docs/API_SPEC.md](docs/API_SPEC.md), [docs/DB_SCHEMA.md](docs/DB_SCHEMA.md) |
| Report a security issue | [SECURITY.md](SECURITY.md) (private reporting channel and handling policy) |

## Design boundaries

Worth knowing before you deploy:

- **It governs the connections that pass through it.** Traffic that connects directly to
  a target host is outside its view. Use your network layer (firewalls / security
  groups) to close off direct access and make the bastion the only entrance.
- **Text-based command audit has inherent limits** (edge behaviors of some full-screen
  programs, input without echo). When in doubt, the **session recording replay** is the
  source of truth: it captures the actual screen, with no reconstruction or inference.
- **A failed audit write never kills your connection**, but the UI clearly signals the
  degraded state instead of pretending everything is fine.

## Related Projects

- [Apache Guacamole](https://guacamole.apache.org/) - clientless remote desktop gateway

## License

This project is released under the **GNU Affero General Public License v3.0
(AGPL-3.0)**; see [LICENSE](LICENSE) for the full text.

The network clause of AGPL-3.0 (Section 13) requires that if you modify this software
and offer it as a network service, you must also offer the complete corresponding source
of your modified version to the users of that service.

**Single edition, no tiers.** There is no enterprise version, no paid feature unlocks,
and no separately licensed modules. Contributions are
accepted under the DCO rather than a CLA (see [CONTRIBUTING.md](CONTRIBUTING.md));
the project does not ask for, and does not hold, the right to re-license external
contributions under a closed-source license.

### Third-Party Components

The distribution also contains 218 third-party components, each retaining its original
license; see [THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md) for the inventory,
[NOTICE](NOTICE) for Apache License 2.0 attribution notices, and [`licenses/`](licenses/)
for copies of the license texts.

Container images are based on Alpine Linux and contain GPL/LGPL components running as
separate processes. The version table and how to obtain their corresponding source are in Section 3 of
[THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md); open a repository issue if a
source cannot be reached.

