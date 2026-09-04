# Quickstart Guide

**English** | [繁體中文](zh-TW/QUICKSTART.md) | [日本語](ja/QUICKSTART.md) | [More languages →](README.md)

> Related documents: the API reference is [API_SPEC.md](API_SPEC.md), the database reference is [DB_SCHEMA.md](DB_SCHEMA.md), the project overview is [README.md](../README.md) (Traditional Chinese in [zh-TW/README.md](zh-TW/README.md)), and contribution and development workflow is [CONTRIBUTING.md](../CONTRIBUTING.md).

## Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- Git

Verify the installation:
```bash
docker --version
docker compose version
```

## Startup steps

Deploying for your own use and joining development follow the **same path**; the default
`docker-compose.yml` is the production stack (nginx serves the compiled frontend, the backend
is a slim binary, no test targets). Developers take one extra step: uncomment
`COMPOSE_FILE=docker-compose.dev.yml` in `.env`, and every later `docker compose` command
targets the development stack (Vite HMR for the frontend, Air hot reload for the backend, plus
test targets for each protocol) without `-f`.

### 1. Get the source

```bash
git clone https://github.com/custodexa/custodexa.git
cd custodexa
```

### 2. Set environment variables (required)

> **Fast path**: `bash scripts/quickstart.sh` does this whole section for you. It checks for
> `.env` (creating it from the template when absent) and generates the missing secrets with a
> CSPRNG; values you already filled in are never touched, so re-running is safe. Add `--up` to
> start the stack as well: it reports progress by stage, waits for the backend to become
> healthy, and prints the address to open along with the admin sign-in details.
> On Windows, run it inside WSL.
> To understand what each value means, or to set them by hand, read on.

Copy the template first, then edit it for your environment.

```bash
cp .env.example .env
# Every fresh (empty database) deployment: set ADMIN_INITIAL_PASSWORD (the initial admin password; there is no published default)
# Production: change JWT_SECRET (release refuses to start while it is unchanged) and DB_PASSWORD, and set DB_SSLMODE / LDAP / DATA_PATH as needed
#   (ENCRYPTION_KEY is only for KEK_PROVIDER=env; the shipped default is ui, meaning the key never lands on disk -- see the KEK section of the template)
# Development: uncomment COMPOSE_FILE=docker-compose.dev.yml, and set KEK_PROVIDER=env with
#   an ENCRYPTION_KEY -- hot reload restarts the process on every rebuild, and ui asks you to unseal each time
```

> **Initial administrator password (`ADMIN_INITIAL_PASSWORD`)**: there is no factory default.
> Every fresh (empty database) deployment has to set an acceptable value of its own: at least
> 12 characters, no leading or trailing whitespace, and not the placeholder string copied from
> the template. Anything else and the service refuses to start and says why in the log.
> Generate one with `openssl rand -base64 24` (drop the trailing newline).
> The value is used once: the first sign-in forces a password change, after which you should
> remove it from `.env` or rotate it. An existing (non-empty) database does not need this value.

> **Off-site evidence storage (`OFFSITE_*`) is first-run setup only**: these keys are written to
> the database **at the first startup**, and from then on the administration page
> (System Settings → Offsite storage) manages them; editing `.env` has no further effect
> (the `LDAP_*` keys for directory integration work the same way). Automated deployment loses
> nothing: fill in `.env` and the first startup applies it.
> Left empty (the default) the feature stays off and system behavior is unchanged.

`.env.example` is the **only environment template** (both the dev and prod compose files consume
it through `env_file`). Its completeness against what the backend consumes is guarded by
`backend/config/env_drift_test.go`: it scans the variables the code actually consumes and compares
them with this template plus the topology variables compose supplies, and drift fails the test.
Topology and mode constants (`DB_HOST=postgres`, `GUACD_HOST=guacd`, `GIN_MODE` and so on) come
from the compose files and are not in the template.

> **Note**: `env_file` does not strip an inline `#` comment from an empty value (the line
> `KEY=  # note` yields the literal value `# note`), and most knobs in the template default to
> empty. So every explanation in `.env` (and in the template) sits on its own line and no value
> line carries a trailing comment; otherwise the value picks up the comment and the service
> fails to start.

**Where data lives (`DATA_PATH`)**: the main application data (audit logs, recordings, database)
sits under a single root folder chosen by `DATA_PATH`, which defaults to `./data` inside the
project (easy to inspect during development). Production deployments can point it at a dedicated
folder or disk:

```bash
# Production: put the data on a dedicated path
DATA_PATH=/opt/custodexa/data
```

> **Persistence and reset**: data lands in the `${DATA_PATH}` directory as a bind mount, and
> `docker compose down -v` does **not** clear it (`-v` only removes named volumes). To reset the
> data completely, stop the services and delete the contents of the directory `DATA_PATH` points
> at (`./data` by default, or your own path; `DATA_PATH` from `.env` is not carried into a manual
> shell command): `rm -rf ./data/*`. `./data/` is listed in `.gitignore` and will not slip into
> version control.

### 3. Start the services

```bash
# In the background (with no existing images it builds first -- building the production images is step one of deployment)
docker compose up -d

# In the foreground (logs on screen)
docker compose up
```

The first startup builds the images and downloads dependencies, which takes about 5-10 minutes.

### 4. Verify the services

**Check container status**:
```bash
docker compose ps
# Production (default): backend, frontend, postgres, guacd, tls-proxy
#   (tls-init exits once the certificates are ready; a status of exited(0) is normal)
# Development (COMPOSE_FILE enabled) also brings up test targets:
#   ssh-test, ssh-multi-test, mssql-test, mysql-test, rdp-test, vnc-test, k3s-test
#   (plus ldap-test / dex / localstack for the LDAP, OIDC and S3 features)
```

**Entry points (they differ between the two stacks)**:

| | Production (default) | Development |
|---|---|---|
| Frontend | https://localhost (TLS proxy; http://localhost returns a 301 to it) | http://localhost:3000 (Vite dev server) |
| Backend | No published port (the proxy and nginx forward `/api`) | http://localhost:8080 |

The production stack publishes only the two ports of the TLS proxy, `443` (https) and `80`
(http, redirect only), so the address people type carries no port number. A host that already
runs something on those ports needs a different pair -- set `TLS_HTTPS_PORT=8443` and
`TLS_HTTP_PORT=8088` in `.env` -- and the address then carries the port, as in
`https://localhost:8443`. Everything below uses the default ports.
The certificate comes from a local CA the product generates itself by default
(`TLS_MODE=selfsigned`), so browsers show a warning until you distribute the CA to the machines
that connect; bringing your own certificate and distributing the CA are covered in
"Transport encryption for external traffic (TLS)".

**Test the backend API**:
```bash
# Production: the backend publishes no port, and /health is not on the nginx proxy path, so go through the container
docker compose exec backend wget -qO- http://localhost:8080/health
# Development: connect directly
curl http://localhost:8080/health
# {"status":"ok","service":"custodexa-backend"}
```

**Seal state (the shipped default is `KEK_PROVIDER=ui`)**: after a fresh installation starts, the
system is **sealed and awaiting initialization**. `/health` answers normally but the business
endpoints are not open yet, and the first visit to the frontend lands on the initialization
unseal page. To query the state:

```bash
curl -k https://localhost/api/v1/seal/status
```

- Initial account: `admin`; the initial password is the `ADMIN_INITIAL_PASSWORD` you set in `.env`

> **The first sign-in requires a password change**: after the initial admin signs in, the system
> sends them to a forced password change page. Set a new password (following the policy shown on
> screen: length, letters plus digits, no reuse of the last few) and you go straight into the
> system, with no second sign-in. Once changed, `ADMIN_INITIAL_PASSWORD` is retired; remove it
> from `.env` or rotate it.

Creating your first asset and starting your first connection are covered in "First use" below.
The settings production deployments must get right are collected in "Production deployment
notes"; external TLS, time synchronization, the limits of audit integrity and log retention --
the deployer's responsibilities and the behavior that goes with them -- are in "Deployer
responsibilities and behavioral limits in production". Offline recovery for a lost admin
password, a startup blocked by the weak-credential scan, or an administrator locked out by
source restrictions is in "Troubleshooting".

### 5. Read the logs

```bash
# All services
docker compose logs -f

# One service
docker compose logs -f backend
docker compose logs -f frontend
```

## First use: from sign-in to the first connection

The following applies to both stacks. The development stack has built-in test targets you can
connect to (see "Testing the connection features"); on production, use the hosts you actually
want to manage.

### 1. Initialization unseal, sign-in and password change

Open `https://localhost/` (`http://localhost:3000` on the development stack).

**With the shipped default (`KEK_PROVIDER=ui`) the first stop is the initialization unseal
page**: the master key is generated **locally in your browser and lives only in the server's
memory**, and the page asks you to confirm you have stored it safely (every later process
restart stops at the sealed state and needs that key to unseal). Authorize the initialization
with `admin` and `ADMIN_INITIAL_PASSWORD`.
(The env and kms modes have no such step and go straight to the sign-in page.)

Then sign in: account `admin`, password the `ADMIN_INITIAL_PASSWORD` from `.env`. The first
sign-in goes to the forced password change page; set a new password and you land on the
dashboard.

### 2. Create your first asset

Assets → New Asset. The fields:

| Field | Meaning |
|---|---|
| Name, Protocol, Host, Port | Required. Host takes an IP or a host name (a containerized deployment reaching a service on the Docker host can use `host.docker.internal`) |
| Username, Password, SSH Private Key | The credentials used to connect; they may be left empty when saving. On an actual connection the **private key wins over the password**; an asset with neither can be saved, but starting a connection fails ("the asset has no usable credentials") |
| Attach to Nodes | Where the asset sits in the asset tree; several may be picked (one asset can hang under several nodes). Left empty it is listed under "Ungrouped" |
| Connection Policy | Per-asset connection control. It defaults to following the global setting and shows the current global value; change it only when this asset needs to be looser or tighter |
| Description | Optional, to help identify the asset in the list |

The "Status" column in the asset list carries reachability probe information (an asset that has
not been probed yet shows "-"). The probe currently only tests password authentication, so it
fails for an asset that has only a private key, which does not mean the real connection is
unavailable; whether it connects is settled by "Connect" in the next step.

### 3. Start a connection

Find the asset in the list and click **Connect** on its row, which opens a workspace tab. The
remote host's prompt appearing in the web terminal means you are connected. Run a couple of
commands (`whoami`, `ls`); typing `exit` or closing the tab ends the session.

### 4. Look back at the audit trail

Once the session ends, Sessions shows the historical session, and opening its detail gives you
the **recording playback** (with a scrubber and speed control) along with the **command log**
for that session. To search commands across sessions, use the Command Audit page.
This "every operation leaves a trail" chain is the core of the product, and a first deployment
should walk through it once to confirm that recordings play back.

## Production deployment notes

The production stack is the default compose file (see the startup steps above); this section adds
the settings release mode requires and the deployment verification that goes with it.
What the production stack does: no published DB or guacd ports, `restart: always`, a compiled
binary for the backend (no source mount, `GIN_MODE=release`), and only the TLS proxy's `443`
(https) and `80` (http redirect) exposed.

### 1. Settings release mode requires in `.env`

Release mode is **fail-close** on these values: it refuses to start rather than warning.

| Variable | Requirement |
|---|---|
| `JWT_SECRET` | Must be changed from the shipped default (PCI 2.2.2) |
| `ENCRYPTION_KEY` | Only for `KEK_PROVIDER=env`; under the shipped default `ui` (where the key never lands on disk) it must stay commented out, and a value there is a contradictory configuration that refuses startup |
| `DB_PASSWORD` | Required -- the prod compose file supplies no default |
| `ADMIN_INITIAL_PASSWORD` | Required for a fresh empty database (>=12 bytes, not the placeholder, no leading or trailing whitespace or newline); an existing database does not need it |
| `CORS_ALLOWED_ORIGINS` | Required for a cross-origin deployment; while unset, only same-origin is allowed |
| `DATA_PATH` | Best pointed at a dedicated folder or disk (`./data` by default) |
| `TLS_DOMAIN` | The external host name, written into the certificate; empty is the same as `localhost` |
| `PUBLIC_BASE_URL` | The external https address (the OIDC `redirect_uri` is built from it), on the same domain as `TLS_DOMAIN` |

### 2. Start

```bash
# With no existing images, up builds the production images first (building is step one of deployment).
docker compose up -d
```

> The production and development images have separate names (`custodexa/*:latest` and
> `custodexa/*:dev`), so one machine can hold both and building either never overwrites the other.

### 3. Deployment verification (run this on every production deployment)

```bash
# (1) All services up and postgres healthy
docker compose ps

# (2) Backend health check -- the backend publishes no port and /health is not on the nginx proxy path, so go through the container
docker compose exec backend wget -qO- http://localhost:8080/health

# (3) The frontend is reachable and http redirects to https (add -k to curl for a self-signed certificate)
curl -skI https://localhost/
curl -sI http://localhost/ | head -1     # 301

# (4) The sign-in chain works (account admin, password the ADMIN_INITIAL_PASSWORD from .env)
curl -sk -X POST https://localhost/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<ADMIN_INITIAL_PASSWORD>"}'

# (5) No fatal in the startup log (release fail-close messages all show up here)
docker compose logs backend | tail -30
```

> Verifying the production stack from a development machine means adding an explicit
> `-f docker-compose.yml` to every command above (which overrides `COMPOSE_FILE` from `.env`).

Under the shipped `ui` mode, (4) is stopped by the seal gate **until the initialization unseal is
done**; complete the initialization in the browser first (see "First use"), or check the state
with `curl -k https://localhost/api/v1/seal/status`.

On a **fresh deployment**, (4) returns
`{"change_token": "...", "password_change_required": true, "policy_hint": {...}}` rather than a
normal token; that is the forced password change on first sign-in (PCI 8.3.5), and receiving it
means the authentication chain is working. A real session is issued after the change.

If any step fails, start with the log from (5): a release refusing to start always says which
variable is at fault and why.

> **External connections are TLS by default**: the production stack ships a reverse proxy,
> `443` serves https and `80` always redirects to it. The certificate is signed by the product
> itself (a local CA) by default; distribute the CA to the machines that connect and browsers
> show the site as trusted. Deployments with an institutional certificate or their own ingress
> take one of two other paths, all three of which are in "Transport encryption for external
> traffic (TLS)" below.

### 4. OIDC / SSO deployment notes

The provider's own settings (issuer, client_id, secret, admission rules) are stored in the
database from the administration pages; the deployment layer decides only the three environment
variables below, plus one **operational prerequisite you have to settle before enabling SSO**.

| Variable | Meaning |
|---|---|
| `PUBLIC_BASE_URL` | The external base address, used to build the `redirect_uri` handed to the IdP (`${PUBLIC_BASE_URL}/api/v1/auth/oidc/callback`) and the callback return address. **It is not derived from the request Host**: derivation is bound to be wrong behind several layers of reverse proxy, and the value goes into the `redirect_uri`, so getting it wrong sends users to the wrong host. While it is unset, an enabled provider is marked "incompletely configured" and hidden from the sign-in page (fail-close). It must be https in production. |
| `OIDC_DEDICATED_ISSUERS` | A declaration of dedicated issuers (comma-separated). The system treats an unknown issuer as a **shared identity domain** fail-close and requires its admission rules to include an organizational condition (a tenant identifier or a hosted domain); but Okta, self-hosted IdPs and the like **do not issue** such a claim, and without this declaration their automatic provisioning cannot be configured. The declaration means "this issuer serves only our organization", a judgment only the deployer can make, which is why it sits at the deployment layer rather than in an administration API (an admin account must not be able to loosen a security rule for itself). The built-in shared list (Google, Microsoft multi-tenant endpoints and so on) takes precedence and cannot be overruled here. **A change takes effect only after every replica has been restarted** (the declaration is loaded at startup; restarting one replica leaves the replicas disagreeing, and the provider detail page in the administration UI shows the decision source of **this** replica). |
| `OIDC_ALLOWED_INTERNAL_HOSTS` | Internal host names allowed for outbound requests (comma-separated). Outbound requests to an IdP refuse by default to resolve to loopback, link-local (including cloud metadata addresses) or private ranges, so an **internal IdP has to be listed here explicitly**; there is no boolean switch that turns the address check off. Outside release mode, host names listed here are also allowed over http (for the dev IdP target). An internal IdP with a self-signed certificate needs its CA added to the container's trust store; the system offers **no switch to skip TLS verification**. |

**At least one local admin account has to remain** (confirm this before enabling SSO):

- The system maintains the invariant that the number of local admins never falls from one or more
  to zero: turning the last local admin into external-login-only, disabling it, removing its admin
  role or deleting it are all rejected.
- The reason is not just "you cannot get in when the IdP is down": **unsealing
  (`KEK_PROVIDER=ui`) and initial-administrator verification only accept local credentials**,
  because that path runs while the system is not fully started and cannot possibly go through an
  external IdP. Externalizing every admin means nobody can unseal once the system is sealed.
- That local admin should have a strong password and MFA, and serve as the break-glass account.

**Deactivation at the IdP does not terminate protocol connections already in progress**:

- When a user is deactivated or deleted at the IdP, this system **is not** told in real time
  (OIDC has no reverse notification unless back-channel logout is wired up, which this version
  does not implement). An established SSH, RDP or VNC connection no longer uses the credentials,
  so it **stays alive**, governed by the idle timeout (`SSH_IDLE_TIMEOUT_MINUTES`) and the maximum
  session lifetime; an access token already issued also lives until it expires (a fixed 15
  minutes). What deactivation at the IdP actually does is reject the next sign-in.

**Known limits of a multi-replica deployment** (single-instance deployments are unaffected):

- From this version on, a second application instance started against the same database is
  **stopped by a guard that asks for confirmation**. The guard is aimed at unknowing coexistence,
  not coexistence itself: a confirmed run leaves audit evidence, and its data consequences are
  the confirmer's to carry (see [Deployment topology limits](ops/deployment-topology-limits.md)).
- Authorization for a recording playback token is **per-process**: only the backend replica that
  issued a token can redeem or revoke it. Across replicas, if a request to disable an account or
  a provider lands on a different replica, the tokens already issued on the issuing replica live
  until their TTL expires; the residual window is **120 seconds or less and read-only** (it can
  fetch already recorded content, not open a new connection). This limit belongs to the gaps that
  precede multi-replica deployment (see
  [Deployment topology limits](ops/deployment-topology-limits.md)) and has to be closed together
  with a cross-replica notification mechanism before going HA.
- **Anyone who needs an immediate cutoff has to act in this system's administration pages**:
  disable the user account (which advances that user's credential generation) or disable the whole
  provider (which advances the provider generation). Either revokes refresh tokens, rejects access
  tokens already issued, terminates protocol connections in that scope and drops session
  monitoring and sharing subscriptions.
- **The upload worker for off-site evidence storage has no cross-replica mutual exclusion**:
  across replicas the same recording or evidence bundle is picked up more than once and
  **re-uploaded under the same key**. The content is identical, the overwrite is harmless and the
  accounting comes out the same, so this is not a correctness problem; the cost is wasted bandwidth
  and a racing re-upload. It does not happen on a single instance.
- **Rotating or deleting a provider secret follows the same full invalidation flow as disabling
  it**; `auth_epoch` only ever increases, so "disable and re-enable shortly after" does not revive
  credentials already in an attacker's hands. The side effect is that every user of that provider
  is forced to sign in again, which is a deliberate trade-off (the reason to rotate is usually that
  the old secret may have leaked).

**Why trusted proxy settings matter**: the SSO callback and exchange endpoints are public and
carry per-IP rate limiting. While `TRUSTED_PROXIES` is unset, the rate-limit key is always the
socket peer IP and forwarding headers are ignored (with no agreed chain of trusted proxies the
headers can be forged at will, and losing some availability beats offering a defense that can be
walked around). Behind a reverse proxy, set `TRUSTED_PROXIES` correctly or every request looks
like it comes from the proxy's single IP.

### 5. LDAP directory settings

The LDAP directory settings (address, bind credentials, search parameters, attribute mapping) are
stored in the database from the administration pages, maintained under
Identity & Access → Directory (LDAP); **the database is the single source of truth**, and the nine
`LDAP_*` keys in `.env` are only a **seed source for the first startup**.

| Situation | Behavior |
|---|---|
| `.env` has `LDAP_ENABLED=true` at the first startup | After unsealing, the env values are written to the database once, and the database governs from then on |
| Not enabled at the first startup (the template default is `LDAP_ENABLED=false`) | Nothing is seeded and the table stays empty; create the settings in the administration UI |
| `LDAP_*` in `.env` is edited after seeding | **No effect** -- change settings in the UI |
| The settings are deleted in the UI and the service restarts | They are not re-seeded from env (the system records an "evaluation complete" marker and does not re-run because a row disappeared) |

Outbound restrictions: a connection to the directory always refuses to resolve to loopback,
link-local (including cloud metadata addresses), the unspecified address or multicast;
**private ranges are allowed by default** (a directory service normally lives on the internal
network, the opposite of the public-IdP assumption behind OIDC).
For the special case of connecting over a loopback address, list exact `host:port` entries in
`LDAP_ALLOWED_LOOPBACK_ENDPOINTS`; wildcards are not supported, and there is no switch to turn the
check off.

**`.env` is never written back**: nothing changed in the administration pages after seeding is
reflected in `.env`, because the product does not modify files the deployer manages. So the
`LDAP_*` values in `.env` are only a snapshot of the first startup and are not a reference for the
current settings; open the administration page to see those.

### 6. Capacity and storage planning

Capacity planning turns on **recording storage growth**; the backend process itself is not the
resource that saturates first (see the end of this section).
The numbers below are reference observations from a development environment, not commitments, and
they predict nothing about your hardware; what transfers across environments is the **conversion
method**.

#### Recording storage growth rate (text and graphical differ by about two orders of magnitude and must not be averaged)

| Protocol | Observed | Kind |
|---|---|---|
| Text terminal SSH (`.cast`) | About 30 B/s idle, roughly 105 KB per session-hour; a full-load multiplier of about 1.32x | Text |
| Graphical RDP / VNC (`.guac`) | From about 10.4 MB per session-hour for a static desktop | Graphical |

> Both are **idle lower bounds** (measured on a terminal with no input and a static desktop with
> no screen change). Real work -- scrolling output, dragging windows, switching screens -- runs
> several times to an order of magnitude higher. A lower bound only establishes "you need at least
> this much" and must not be used as a planning figure.

**The conversion method (the part that transfers across hardware)**

- **Text**: recording disk usage is roughly terminal output bytes x 1.32 (the JSON framing and
  timestamp overhead of asciicast); substitute the terminal output per person per day from your
  own environment.
- **Graphical**: start from 10.4 MB per session-hour and multiply up by how heavy the real work is.
  Disk demand is roughly concurrent graphical sessions x average session length x growth rate x
  retention days, plus headroom.
- The retention window is managed on the security policy page (see "Deployer responsibilities and
  behavioral limits in production → Log and recording retention" below), and disk demand is roughly
  daily growth x retention days.

#### Concurrency capacity

**Custodexa sets no cap on concurrent sessions and never refuses a connection because of the
session count.** The resources that saturate first, in the order you should check them:

1. **The guacd container (graphical protocols)**: every RDP/VNC session maps to one guacd
   connection, which carries both the CPU and the memory, and it is the real ceiling in graphical
   scenarios. Load-test it separately against your own share of graphical sessions.
2. **Write bandwidth and capacity of the recording disk**: estimate from the graphical growth rate
   above x concurrent graphical sessions.
3. **The database connection pool limit.**
4. **Limits on the target hosts themselves**: sshd's `MaxSessions` and `MaxStartups`, for example,
   which have nothing to do with this system but will stop you first.

The backend Go process is not the bottleneck: about +16 goroutines per session, and a memory
increment below the noise floor of the measurement (an upper bound of about 148 KB per session),
so 1 GB of available memory is worth several thousand text sessions.
**Text session capacity is limited almost entirely by disk, and graphical session capacity is
decided by guacd.**

#### Storage monitoring

- Recording usage is visible in the product (the "Recording Storage Used" card on the dashboard,
  for anyone with audit view permission); collectors can read
  `custodexa_recording_storage_bytes` (on `/metrics`, refreshed every 30 seconds, so the value
  lags by at most one refresh period).
- **The system sets no storage cap**: the availability of an audit system should not be held
  hostage by storage volume, and "keep connecting but stop recording" would produce unrecorded
  privileged sessions, neither of which is acceptable. Total disk capacity and the risk of running
  out are therefore carried by your infrastructure monitoring; set a growth-rate or capacity
  threshold alert on `custodexa_recording_storage_bytes`.
- To reduce usage, use the **retention window** (System Settings → Security Policies) and delete
  expired recordings by age.

## Deployer responsibilities and behavioral limits in production

Before serving external traffic, the items below are **the deployer's responsibility**. The
product deliberately does not do them for you and does not pretend it does. Two behavioral notes
are collected here as well; go through the whole section before going live.

### Transport encryption for external traffic (TLS)

External connections to the production stack terminate TLS at the built-in reverse proxy: `443`
serves https, `80` always returns a 301 to it, and neither the frontend nor the backend
publishes a host port. The proxy provides TLS 1.2+, HSTS and **WebSocket upgrade forwarding
(wss)**, and its configuration file needs no editing -- the domain comes from `TLS_DOMAIN` in
`.env` and is substituted into the configuration at startup. `bash scripts/quickstart.sh` also
fills in `TRUSTED_PROXIES` with the Docker subnet this stack runs on, which is what lets the
backend read the client address the proxy forwards instead of attributing every request to the
proxy itself.

Where the certificate comes from is decided by `TLS_MODE` in `.env`, whose two values match the
first two subsections below: `selfsigned` (the default, a local CA the product signs itself) and
`provided` (your own certificate). Deployments that already have an ingress of their own take a
third path and switch the built-in proxy off with an overlay.

Whichever path you take, two things hold. The external edge has to provide TLS 1.2+, an
HTTP-to-HTTPS redirect, HSTS and WebSocket upgrade forwarding; and if the hop from the edge to
this host crosses an untrusted segment, that hop has to be encrypted too (re-encrypt).
The application itself is TLS-ready: the frontend switches `ws` and `wss` with the page protocol
and the access token travels in the Authorization header. The one thing to line up is
`PUBLIC_BASE_URL` (see "The Secure flag on the session refresh cookie").

**The Secure flag on the session refresh cookie**: the web session refresh credential is issued as
an `HttpOnly` cookie (`custodexa_refresh`), and its `Secure` flag is decided by the security
policy **"keep sign-in state only over https"** (System Settings → Security Policies → Sessions
and Accounts). Change the value on that page and save, and the next cookie issued uses the new
value; no restart needed.

At the first startup, the initial value of this policy comes from `.env`:

| Setting at the first startup | Seeded value |
|---|---|
| `AUTH_REFRESH_COOKIE_SECURE=true` or `false` | Used as given (highest precedence) |
| Unset, `PUBLIC_BASE_URL` is `https://…` | On |
| Unset, `PUBLIC_BASE_URL` is `http://…` | Off |
| Unset, `PUBLIC_BASE_URL` also empty | On (factory default) |

These two environment variables act only while the policy has no value. Once it has one (seeded at
the first startup, or saved by someone on the security policy page), editing `.env` has no effect
at all; go back to that page to adjust it.

**An HTTPS deployment should set `PUBLIC_BASE_URL` to the https address** (even without OIDC).
When TLS terminates further out and `PUBLIC_BASE_URL` cannot reflect the external address, seed
with `AUTH_REFRESH_COOKIE_SECURE=true`.

**A deployment served over plain HTTP** should set `AUTH_REFRESH_COOKIE_SECURE` to `false` before
the first startup, or turn the policy off on the security policy page afterwards. With the policy
on, the system still works; the cost is that browsers do not keep the cookie, so everyone signs in
again about every 15 minutes (the lifetime of the access token). Users see this: the sign-in page
explains the situation when they are signed out and asks them to contact an administrator, and an
administrator signing in over the same http address sees a matching notice at the top of the
security policy page with two ways to resolve it. **The system never changes this setting on its
own.**

Local development on `http://localhost` is unaffected: Chromium 145 and Firefox 146 both accept a
Secure cookie from that address in our testing; WebKit in the Safari family drops it, so turn the
policy off when developing with Safari.

The startup log always prints the value in effect and where it came from (the security policy page,
env seeding, or the factory default). **Take a look at it after going live**:

```bash
docker compose logs backend | grep "refresh cookie"
```

When the value is off, the log points out that the refresh credential will travel over plain HTTP
-- and if this site does in fact serve https, that setting wants tightening, so go to the security
policy page and turn it on.

#### The default: a local CA the product signs itself (`TLS_MODE=selfsigned`)

You get https in one command without an institutional PKI. At the first startup the system
generates a local CA and a server certificate in `tls/` (825 days for the certificate, 10 years
for the CA) and reuses them on every later start. The connection is encrypted end to end, and the
chain of trust is established by you distributing the CA to the machines that connect.

1. Set the external host name and base address in `.env` (`bash scripts/quickstart.sh` fills these
   in from the machine's host name and addresses):

   ```bash
   TLS_DOMAIN=jumper.example.internal
   TLS_IP_SAN=10.0.0.5            # Fill in when connecting by IP has to work too, comma-separated; leave empty if not
   PUBLIC_BASE_URL=https://jumper.example.internal
   ```

2. `docker compose up -d`. The certificates are generated on the first start.

3. Download the CA certificate and distribute it to the machines that will connect:

   ```bash
   curl -sk https://jumper.example.internal/custodexa-ca.crt -o custodexa-ca.crt
   ```

   In a Windows domain, distribute it through group policy (Computer Configuration → Windows
   Settings → Security Settings → Public Key Policies → Trusted Root Certification Authorities);
   on macOS and mobile devices use an MDM configuration profile; on a standalone machine, import
   it into the system's trusted root store by hand. Once distributed, browsers show the connection
   as trusted. The CA certificate is public data; the CA private key stays on the host under
   `tls/ca-private/` and never enters the proxy container.

4. To move to a certificate from an institutional or public CA later: delete the files in `tls/`,
   set `TLS_MODE=provided`, put the new certificate in place (see the next subsection) and restart.

Until the CA is distributed, browsers show a certificate warning and an external identity provider
used for OIDC refuses the callback -- a self-signed leaf certificate at that point suits testing
only.

#### Internal domains and an institutional CA

`TLS_DOMAIN` is just this system's external host name. Being resolvable by internal DNS or a hosts
file on the client is enough; it does not have to be a publicly registered domain (something like
`jumper.bnc.prod` is fine), and `PUBLIC_BASE_URL` is the https address of that same host name.

When the organization has its own CA, generate the private key and a certificate signing request
locally (the SAN has to include that host name) and submit it for signing:

```bash
openssl req -newkey rsa:2048 -nodes -keyout tls/privkey.pem \
  -out custodexa.csr -subj "/CN=jumper.bnc.prod" \
  -addext "subjectAltName=DNS:jumper.bnc.prod"
```

Once it comes back, concatenate the server certificate and the intermediates in order into
`tls/fullchain.pem` (leaf first), keep the private key at `tls/privkey.pem`, set `TLS_MODE` to
`provided` and restart. Clients have to trust that CA, which is usually handled by AD group policy
or MDM. If the identity provider used for SSO is also internal, served over https and signed by the
same CA, add the CA certificate to the backend container's trust store (see the
`OIDC_ALLOWED_INTERNAL_HOSTS` part of "OIDC / SSO deployment notes").

#### Bring your own certificate (`TLS_MODE=provided`)

When you already have a certificate from a public or institutional CA:

1. Put the certificate chain and the private key at `tls/fullchain.pem` and `tls/privkey.pem`.
2. Set `TLS_MODE=provided`, `TLS_DOMAIN` (matching the host name on the certificate) and
   `PUBLIC_BASE_URL=https://<host name>` in `.env`.
3. `docker compose up -d`.

With any file missing, the start stops at the certificate preparation step and names the missing
one; the proxy does not come up with half a configuration:

```bash
docker compose logs tls-init
```

#### Leaving it to your own ingress (external ingress overlay)

When a cloud load balancer or an existing nginx or Traefik ingress already sits in front, use the
overlay to switch the built-in proxy off and let the frontend publish an HTTP port for your ingress
to reach:

```bash
docker compose -f docker-compose.yml -f docker-compose.external-ingress.yml up -d
```

Once you uncomment `COMPOSE_FILE=docker-compose.yml:docker-compose.external-ingress.yml` in
`.env`, the everyday `docker compose up -d`, `ps` and `down` no longer need `-f`.
In this shape the frontend publishes `80` (changeable through `HTTP_PORT` in `.env`), external
TLS is carried by your ingress under the contract listed at the start of this section, and
`PUBLIC_BASE_URL` takes the https address your users actually see.

Two settings belong to your ingress rather than to this stack. **Forward the Host header with the
port people actually connect to** -- add the port whenever it is not `443`: the backend compares
`Origin` against `Host` to recognise a same-origin request, so a `Host` that has lost the port
makes an authenticated request look cross-origin and it is answered with a 403 and an empty body
(sign-in and unseal are where this shows up first). In nginx that is `proxy_set_header Host
$http_host;` over HTTP/1.1, and a value assembled from `$host` and the public port when the
listener speaks HTTP/2, which has no Host header at all. **Set `TRUSTED_PROXIES` in `.env` to your
ingress address or its subnet** as well; it decides which address every request is attributed to,
and therefore what the audit log records and what the sign-in rate limit counts against.

#### Customizing the reverse proxy configuration

The bundled template covers ordinary needs. To change it, copy the file, point at the copy, and
leave the original alone:

```bash
cp docker/reverse-proxy/nginx-tls.conf.template tls/custodexa.conf.template
# .env
TLS_NGINX_TEMPLATE=./tls/custodexa.conf.template
```

What that file has to change: `server_name` (filled from `TLS_DOMAIN` by default), the certificate
paths, extra headers (the HSTS `max-age` and `includeSubDomains` / `preload` according to your
domain strategy), and the upstream (the service name `frontend:80` on the same docker network).
Apply the change with `docker compose up -d tls-proxy`.

#### The variant with nginx installed on the host

To skip the proxy container and use the nginx already on the host: use the external ingress overlay
so the frontend publishes an HTTP port (binding it to loopback is a good idea, changing the mapping
in the overlay to `127.0.0.1:8088:80`), reuse the same template for the configuration, point the
upstream at `127.0.0.1:8088`, and replace `server_name` and the certificate paths with yours.
nginx below 1.25.1 does not support the `http2 on;` directive; write it as `listen 443 ssl http2;`
instead. Any other reverse proxy (Caddy, Traefik, a cloud load balancer) works as long as it meets
the contract at the start of this section, and `docker/reverse-proxy/Caddyfile.example` is the
equivalent Caddy version.

#### Verifying that TLS works

```bash
docker compose ps                                  # tls-proxy is Up (tls-init is exited(0))
curl -sI http://localhost/ | head -1          # 301, redirecting to https
curl -skI https://localhost/ | head -1        # 200
curl --cacert tls/ca-public/custodexa-ca.crt -sI https://<TLS_DOMAIN>/ | head -1   # self-signed mode: 200
```

Then sign in and open an SSH connection: the Network tab of the browser's DevTools should show a
`wss://` stream. A terminal that will not open while the page itself is fine usually means the
WebSocket upgrade forwarding is not in effect.

### Time synchronization (PCI 10.6)

Container clocks inherit the host's, and the product ships no NTP client. A production host has to
have time synchronization enabled (chrony, systemd-timesyncd, or the cloud platform's default NTP),
with the time source in UTC and pointed at a time server the industry accepts (10.6.2); access
control and auditing for changes to the host's system time belong to the OS layer (10.6.3).
Whether audit log timestamps can be compared depends entirely on the host clock being right.

### The limits of audit integrity (PCI 10.3.4)

A per-row HMAC on audit_logs, an Ed25519 signature over the export manifest, and real-time
off-site forwarding to syslog together form a compensating control that can detect "an existing row
was modified" and "a row was tampered with after the baseline time and its HMAC cleared" (the first
startup records the baseline for the control, after which every path that **enters storage** is
stamped through `BeforeCreate`, and an empty HMAC after the baseline is judged non-compliant;
events lost to file degradation or a full queue never enter storage and are never stamped, hence
"paths that enter storage" rather than "write paths"). "A whole row deleted along with its HMAC"
is **detected by the checkpoint chain** (interval aggregation, chaining and an Ed25519 signature,
with a legitimate purge distinguished from theft by a signed tombstone), and the limits of what it
proves, R0-R6, are on the verification page and in the checkpoint chain specification.
The integrity stamping key is a versioned key the system generates (KEK-wrapped in storage since
v1); it is not derived from `JWT_SECRET` and needs no environment variable at all.

### The login notice

The sign-in page can show an access statement before the user types a username and password
(System Settings → Security Policies → Login Notice).
**It ships empty, and an empty one is not shown** -- the wording of such a statement is the
deployer's legal business, and the product presumes no content.
When delivering a new installation, set it according to
[Deployment and Upgrade SOP §1.7](ops/upgrade-sop.md), which spells out how to do it and what
happens if you do not.

### Log and recording retention

The retention period in days is managed on the security policy page, where `0 = keep forever`.
`RECORDING_RETENTION_DAYS` seeds it only at the **first startup** (while the policy table has no
such row); editing env and restarting afterwards has no effect, and the policy page governs.
Expiry deletion is a hard delete at 02:00 daily and cannot be undone, and the UI asks for
confirmation before a retention period is shortened.
A single run deletes at most 100,000 rows per table by default; a high-volume deployment can raise
`RETENTION_MAX_PER_RUN` so that daily expiry does not fall behind.

## Common commands

### Restart a service
```bash
docker compose restart backend
```

### Rebuild (after changing a Dockerfile or dependencies)
```bash
docker compose up --build
```

### Stop the services
```bash
# Stop the services (application data stays in ${DATA_PATH:-./data})
docker compose down

# Stop and remove named volumes (go_modules / k3s and so on)
# Note: audit / recordings / postgres are bind mounts, unaffected by -v, and stay in ${DATA_PATH:-./data}
docker compose down -v

# Erase the application data completely (audit / recordings / database): stop, then delete the contents of DATA_PATH by hand
# ./data by default; with a custom DATA_PATH, delete that path instead (the value in .env is not carried into this manual command)
docker compose down && rm -rf ./data/*
```

## Development workflow

> This section and the test sections below need the **development stack** (`.env` with
> `COMPOSE_FILE=docker-compose.dev.yml` enabled): hot reload, the direct 8080/3000 ports and the
> test targets are all development-stack features.

### Backend development
1. Change the code under `backend/`
2. Air recompiles automatically (hot reload)
3. Check the logs to confirm the change took effect

### Frontend development
1. Change the code under `frontend/`
2. Vite reloads automatically (HMR)
3. The browser updates itself

### Database administration
```bash
# Connect to PostgreSQL
docker compose exec postgres psql -U postgres -d custodexa

# Common SQL commands
\dt          # List all tables
\d users     # Show the structure of the users table
SELECT * FROM users;
\q           # Quit
```

## Troubleshooting

### A port is already in use
```bash
lsof -i :443   # production https (TLS proxy)
lsof -i :80    # production http redirect
lsof -i :3000  # development frontend
lsof -i :8080  # development backend
# Stop the process holding it, or set TLS_HTTPS_PORT and TLS_HTTP_PORT in .env to a free pair
# (8443 and 8088 are the usual choice); `bash scripts/quickstart.sh --up` names the program in
# the way before it starts anything
```

### A container will not start
```bash
# Read the error
docker compose logs backend

# Rebuild
docker compose up --build
```

### Lost admin password, a startup blocked by the weak-credential scan, or an administrator locked out by source restrictions (offline reset)

All three take the same offline reset path, because they share one thing: the person can no longer
get into the system and can only work from the database.

- **The only admin has not signed in yet and the initial password is lost** (no way in).
- **The startup is blocked by the weak-credential scan**: at release startup the system scans every
  account holding the admin role, and if any of them still uses a publicly known weak credential
  (`admin123`, for example), the service **refuses to start** and asks for a reset first.
- **An administrator locked themselves out of the allowed source ranges**: once an account has
  allowed source ranges set (`users.allowed_cidrs`), signing in, renewing and starting connections
  from an address outside the list are all blocked. **Do not take this path while another
  administrator exists** -- have them change the list back in the UI, since that path leaves a
  field-level audit difference. Use the offline clearing below only when the system has no other
  administrator.

For the lost password and the weak-credential scan, what has to change is the password. The way to
do it is a direct database connection that updates the password hash, `must_change_password=true`
and a row in `password_histories` **in a single transaction** (all three together, so no
inconsistent state is left behind).
Example (PostgreSQL, where `$1` is the new bcrypt hash and `$2` is the admin user id).
**`$1` and `$2` are placeholders -- pasting this straight into `psql` returns
`ERROR: there is no parameter $1`, so substitute the real values by hand first**:

```sql
BEGIN;
UPDATE users SET password = $1, must_change_password = true, password_changed_at = now() WHERE id = $2;
INSERT INTO password_histories (user_id, password_hash, created_at) VALUES ($2, $1, now());
COMMIT;
```

The bcrypt hash has to be produced with an **external tool**, for example:

```bash
htpasswd -bnBC 10 "" 'your-new-password' | tr -d ':\n'
```

Or a bcrypt library in any language (use cost 10, matching the product default).

**The production image contains no tool for generating a hash and no Go toolchain**, so generate it
on your own machine and paste it into the SQL.
(`backend/scripts/generate_hash.go` carries `//go:build ignore`, is compiled into no binary, and
can only be run with `go run` on a development machine that has Go.)

**In the third case (locked out by source restrictions) leave the password alone**: there is nothing
wrong with the password, and replacing it only puts you through a forced change, with no need to
write `password_histories` either. All you have to do is clear that account's allowed source ranges
to an empty string -- an empty string means no source restriction. Example (PostgreSQL):

```sql
-- Confirm which row to clear first (an empty allowed_cidrs means no source restriction)
SELECT id, username, allowed_cidrs FROM users WHERE username = 'admin';
-- Clear the allowed source ranges for that account ($1 is the id found above)
UPDATE users SET allowed_cidrs = '' WHERE id = $1;
```

No restart is needed afterwards: signing in, renewing and starting connections read this column
fresh every time, so the next sign-in is no longer subject to the source restriction.
Set the list back to the range you want in the UI immediately after signing in -- leaving it
cleared means this account can get in from anywhere.

The product offers **no** online recovery API (anyone with database write access can already reset
this, and there is no reason to open a remote privilege surface for it).

The offline reset in all three cases **is not audited by the product**: the path goes around the
application, and `audit_logs` gets no row for it. The change is on the deployer's own change
management to record (who connected to the database, when, and why). What the product can show
afterwards is the sign-in audit row from the recovery (including the source address) and the
field-level difference from setting the list again in the UI.

### Wipe and start over
```bash
docker compose down -v
rm -rf ./data/*          # down -v does not clear bind-mounted data, so delete it by hand (./data by default; with a custom DATA_PATH, that path)
docker image prune -a
docker compose up --build
```

### macOS: the frontend does not update after a change (HMR did not fire)
fsnotify on a macOS Docker volume is unreliable, and Vite may not notice the file change.
Do not use `docker compose restart frontend` (it hits a bind-mount race and crashes with ENOENT).
Use this instead:
```bash
docker compose up -d --force-recreate frontend
```

### A backend change seems to have no effect (Air hot reload is running the old binary)
A half-finished state in the middle of editing several files makes the Air build fail while the old
binary keeps running. After the edits:
```bash
docker compose restart backend
# Confirm the running binary contains the new symbol
docker compose exec -T backend sh -c "strings /app/tmp/main | grep <new function name>"
```

## Testing the connection features

> The flow is the same as "First use" above; the test targets in this section exist only on the
> **development stack** (on production, point at your own target hosts).

### SSH connection test

1. Sign in (account admin; the first time with ADMIN_INITIAL_PASSWORD from .env, changing the password, and with the new one after that)
2. Go to Assets and create an SSH asset with New Asset (the fields are explained under "First use")
3. Click Connect on that row in the asset list
4. The workspace opens a web terminal, and the remote host's prompt means success
5. Run some commands: `ls`, `pwd`, `whoami`

**Test container details**:
- Host: ssh-test
- Port: 2222
- Account: testuser / testpass123

### RDP connection test

1. Sign in (account admin; the first time with ADMIN_INITIAL_PASSWORD from .env, changing the password, and with the new one after that)
2. Go to Assets
3. Create an RDP asset
4. Click the Connect button
5. You should see an Xfce desktop

**Test container details**:
- Host: rdp-test
- Port: 3389
- Account: testuser / testpass123

### SSO (OIDC) sign-in test -- the dex target (development stack only)

The development stack ships dex (a lightweight CNCF OIDC provider) as an IdP target, configured in
`docker/dex/config.yaml`.

**Target details**:
- issuer: `http://dex.localhost:5556/dex` (**the same string inside the backend container and in the
  browser**, as explained below)
- client_id / client_secret: `custodexa-dev` / `custodexa-dev-secret`
- redirect URI: `http://localhost:3000/api/v1/auth/oidc/callback`
- Test accounts: `oidcuser@dex.localhost` / `oidcpass123` (an ordinary user);
  `conflict@dex.localhost` / `conflictpass123` (whose `preferred_username` is deliberately `admin`,
  to test rejection on a name conflict)

**Setup steps**:
1. Set `PUBLIC_BASE_URL=http://localhost:3000` and
   `OIDC_ALLOWED_INTERNAL_HOSTS=dex.localhost` in `.env` (outside release mode, host names listed
   there are also allowed over http), and add `http://dex.localhost:5556/dex` to
   `OIDC_DEDICATED_ISSUERS` if you need to (otherwise it counts as a shared identity domain and its
   admission rules have to carry an organizational condition). Then run
   `docker compose up -d --force-recreate backend`.
2. Sign in as admin and create the provider on the OIDC provider administration page (issuer,
   client_id and secret as above).
3. Sign out, and the sign-in page should show an SSO button for that provider.

**Verify discovery (do this before configuring the provider; it saves a lot of misdiagnosis)**:
```bash
# Inside the backend container (the path go-oidc actually takes) -- the issuer in the response has to match the configured value character for character
docker compose exec backend wget -qO- http://dex.localhost:5556/dex/.well-known/openid-configuration
# From the browser's side (the host)
curl -s http://dex.localhost:5556/dex/.well-known/openid-configuration
```

> **Why the host name has to be `dex.localhost`**: go-oidc compares the issuer in the discovery
> response as a **complete string**, so the backend (resolving inside the container) and the
> browser (resolving on the host) have to use the same string. An IP literal will not do: inside
> the backend container `127.0.0.1` points at the backend itself, and `extra_hosts` can only change
> host name resolution, not the loopback meaning of an IP literal.
> `dex.localhost` is reachable from both: a compose network alias makes DNS inside the containers
> resolve it to the dex container, and the browser resolves it to loopback per RFC 6761 and reaches
> the same dex through the `127.0.0.1:5556` port mapping.
> Changing the alias, the port or the issuer in `docker/dex/config.yaml` means changing all three.

> dex exists only in `docker-compose.dev.yml` and is not part of the production stack; its port is
> bound to `127.0.0.1` and not exposed to the LAN.

## Testing recording and playback

### SSH recording playback

1. Open an SSH connection and run some commands
2. Disconnect
3. Go to the session history list under Sessions
4. Click that session to see its detail
5. You should see the asciinema player, which replays the terminal work

### RDP recording playback

1. Open an RDP connection and work on the desktop
2. Disconnect
3. Go to the session history list under Sessions
4. Click that session to see its detail
5. You should see the Guacamole player, which replays the graphical work

## Operating procedures

This document covers **getting the system running**. The procedures real operation needs are in
`docs/ops/`:

| Document | When you need it |
|---|---|
| [Backup and restore](ops/backup-and-restore.md) | Set up backups as soon as the deployment is done; **read the custody prerequisites for the KEK material before deploying**, since in some modes losing the material makes the data permanently unreadable |
| [Deployment and upgrade SOP](ops/upgrade-sop.md) | Before every version upgrade. **This version provides no migration rollback**, so the only way back from a failed upgrade is restoring a backup, which means deciding the backup point first |
| [Deployment topology limits](ops/deployment-topology-limits.md) | While planning the architecture. 1.0 is a single-instance deployment; multiple replicas and rolling updates are not supported |
| [Platform privileged credential rotation](ops/privileged-credential-rotation.md) | For scheduled rotation, or when staff change. Covers the LDAP bind, notification channel secrets, the KEK and DEK, and the env-side key |

## Next steps

- Read [README.md](../README.md) (English) or [zh-TW/README.md](zh-TW/README.md) (Traditional Chinese) for the project architecture and the documentation map
- The development workflow (OpenSpec, commit conventions, verification practice) is in [CONTRIBUTING.md](../CONTRIBUTING.md)
- Architectural invariants and testing discipline are in [dev/conventions.md](dev/conventions.md) and [dev/testing.md](dev/testing.md)

## API documentation

The single source of truth for the API is [API_SPEC.md](API_SPEC.md); this project keeps no second
API artifact generated from comments.

Its **endpoint index** is generated by a test from the routes actually registered, and `TestAPIIndex`
guards equality in both directions: a route missing from the index and a phantom entry in it both
turn the test red. Regenerate it after touching the routes (on the **development stack**; with
`COMPOSE_FILE=docker-compose.dev.yml` enabled in `.env` no `-f` is needed):

```bash
docker compose run --rm --no-deps -v ./docs:/app/cmd/server/testdata/docs-rw backend \
  go test ./cmd/server -run '^TestAPIIndex$' -update
```

The container that runs the tests normally mounts `docs/` read-only (a guard must not be able to
alter what it verifies), which is why regeneration takes the one-off container above with a
writable mount added. The prose sections outside the index are still maintained by hand.

The routes themselves have a golden baseline as well (`cmd/server/testdata/route-golden`). A
deliberate route change means regenerating it too, and **its diff has to be reviewed line by line in
the commit**:

```bash
docker compose exec backend go test ./cmd/server -run '^TestRoutesMatchGolden$' -update
```
