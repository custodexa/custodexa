# Application Host Standby Takeover

**English** | [繁體中文](../zh-TW/ops/standby-takeover.md) | [日本語](../ja/ops/standby-takeover.md) | [More languages →](../README.md)

> Applies to: Custodexa 1.12.0.
>
> **Verification status of this procedure**: the project rehearsed it once on a single machine, with two compose projects standing in for the two application hosts and a third one for the database; the guard behaviour, the confirmation path and the sign-in on the standby were exercised in that rehearsal. It has not been rehearsed across two physical hosts. Rehearse it in your own environment before relying on it, and keep the record.
>
> Related documents: [Deployment Topology Limits](./deployment-topology-limits.md), [Backup and Restore](./backup-and-restore.md),
> [Deployment and Upgrade SOP](./upgrade-sop.md) (§2.6b for the guard message, §3.4 for the runtime lock states).
>
> Every `docker compose` command in this document runs on an application host in the external database shape, so it needs both files (`-f docker-compose.yml -f docker-compose.external-database.yml`) or a `COMPOSE_FILE` in `.env` that lists them; with your own ingress in front, that list has three files. The commands below write only `docker compose` for brevity.

---

## 1. What this procedure covers

**The shape**: PostgreSQL runs outside the application host. Two application hosts exist, the **primary** and the **standby**, both prepared from the same files and both pointed at that database. Only the primary runs. When the primary is down, whether on purpose or because it failed, the standby is started against the same database and takes over.

**What it is and what it is not**:

| It is | It is not |
|---|---|
| A cold standby: the standby is started only after the primary has stopped | A second running instance. Two instances against one database is the topology [Deployment Topology Limits](./deployment-topology-limits.md) excludes; here too, the single-instance guard stops the second one at startup and asks for a confirmation, and once someone has confirmed it does not keep the two from running |
| A procedure that a person or a script starts | Automatic failover. Nothing in the product watches the primary or starts the standby |
| Recovery from the loss of the application host | Recovery from the loss of the database. The database is the single copy of the data in this shape; when it is gone, the way back is [backup and restore](./backup-and-restore.md), on whichever host |
| A way to shorten the time to service after a host failure | A way to prevent the loss of what only the failed host held (§7) |

Everything the two hosts share lives in the database. What each host keeps for itself, recordings first of all, is listed in §2.3 and again in §7; read both before deciding that this procedure meets your recovery objectives.

---

## 2. Building the standby before you need it

### 2.1 Put the database outside the application host

The stack's bundled postgres lives on the application host, so with the default shape the host and the data go down together. The external database overlay leaves the bundled postgres out and points the backend at a server you name:

```env
# .env on every application host (the same values on the primary and the standby)
COMPOSE_FILE=docker-compose.yml:docker-compose.external-database.yml
EXTERNAL_DB_HOST=db.example.internal
EXTERNAL_DB_PORT=5432
DB_NAME=custodexa
DB_USER=custodexa
DB_PASSWORD=<the account's password on that server>
DB_SSLMODE=verify-full
```

Where that server runs is your decision: a PostgreSQL server the institution already operates, a managed service, or a second machine of your own. The takeover procedure is the same in every case. What the server has to provide:

- **PostgreSQL 16**, the database and the account created before the first start (the backend creates the schema on its first start against an empty database).
- **Access from both application hosts.** Whatever limits client addresses on the server (`pg_hba.conf`, a firewall, a security group) has to admit the standby's address as well as the primary's, before the day you need it. A standby that cannot reach the database is found out at the worst moment.
- **TLS on the connection.** The database is now reached across a network; `DB_SSLMODE=require` at least, `verify-full` when the server certificate can be verified (PCI DSS Requirement 4). The bundled shape uses `disable` because that connection never leaves the host; do not carry that value into this shape.
- **A direct connection, or a pool in session mode.** The single-instance guard holds a session-level lock; a pool in transaction mode breaks it (see [Deployment Topology Limits](./deployment-topology-limits.md)).
- **Backups now target this server.** The database row of the backup procedure's table is no longer under `DATA_PATH` on the application host: `pg_dump` runs against this server, by whoever operates it, and the recordings and audit directories are still backed up from the application host (§8).
- **TCP keepalive.** When an application host crashes, its database session stays open on the server until the server's TCP keepalive gives up on it; while it lingers, it still holds the single-instance lock and the standby has to go through the confirmation step in §4.3. PostgreSQL decides that with `tcp_keepalives_idle`, `tcp_keepalives_interval` and `tcp_keepalives_count`; at the shipped defaults it follows the operating system (about 2 hours on Linux). A server that sets `tcp_keepalives_idle=300`, `tcp_keepalives_interval=10`, `tcp_keepalives_count=3` gives up on a dead client about five and a half minutes after its last packet; in the project's rehearsal with these values the standby, started with the confirmation code, took the lock on its own 5 minutes 46 seconds after the crash (the server's 5.5 minutes, plus part of one 15-second retry interval on the standby). The confirmation step is the same either way; the setting only shortens how long the standby shows the banner afterwards.

If you run the database yourself on a separate machine, the shipped image is enough. A minimal compose file for a database-only host, including the keepalive setting and TLS:

```yaml
# docker-compose.yml on the database host
services:
  postgres:
    image: postgres:16.15-alpine3.24
    command:
      - postgres
      - -c
      - ssl=on
      - -c
      - ssl_cert_file=/certs/server.crt
      - -c
      - ssl_key_file=/certs/server.key
      - -c
      - tcp_keepalives_idle=300
      - -c
      - tcp_keepalives_interval=10
      - -c
      - tcp_keepalives_count=3
    environment:
      POSTGRES_DB: custodexa
      POSTGRES_USER: custodexa
      POSTGRES_PASSWORD: <the same value as DB_PASSWORD on the application hosts>
    ports:
      - "5432:5432"
    volumes:
      - /opt/custodexa-db/postgres:/var/lib/postgresql/data
      # server.crt and server.key issued for this host's name; the key file mode 0600 and owned by the postgres user inside the container (uid 70 in the shipped image), or the server refuses to load it
      - /opt/custodexa-db/certs:/certs:ro
    restart: always
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U custodexa"]
      interval: 10s
      timeout: 5s
      retries: 5
```

The certificate's name has to match `EXTERNAL_DB_HOST` for `verify-full` to pass, and the application hosts have to trust the issuing CA (`DB_SSLMODE=require` skips the name check and the trust check, and still encrypts). Restricting the listening address and the client addresses is done with the host's firewall or `pg_hba.conf`, as for any database server.

### 2.2 Prepare the standby host

The standby is a second application host prepared from the same files, kept **down** until it is needed. Prepare it at the same time as the primary and repeat the preparation after every change to the primary, because a standby that lags behind takes over with the wrong version or the wrong settings.

1. **The same images, at the same version.** Build or load the production images on the standby exactly as on the primary (Deployment and Upgrade SOP §2.2). Every upgrade of the primary is an upgrade of the standby too (§8): a standby left on the previous version starts against a newer schema and refuses to start (SOP §2.6), and a standby on a newer version would migrate the schema under the primary's feet.
2. **The same compose files and the same `.env`.** Copy `docker-compose.yml`, `docker-compose.external-database.yml` (and the ingress overlay if you use it), `docker/`, and `.env` from the primary. The values that differ between the two hosts are the few in the table below; everything else, secrets included, has to be identical, or the standby cannot read what the primary wrote.

   | Key | On the standby |
   |---|---|
   | `DATA_PATH` | This host's own data root; create `${DATA_PATH}/recordings` and `${DATA_PATH}/audit` with the permissions in SOP §1.3 |
   | `TLS_DOMAIN`, `TLS_IP_SAN`, `PUBLIC_BASE_URL` | Unchanged when users reach the service through a name or a virtual address that you re-point at takeover (the arrangement this procedure assumes); this host's own values when users will reach it under a different address |
   | `TRUSTED_PROXIES` | The built-in proxy's subnet is the same on both hosts; with your own ingress, its address as seen from this host |
   | `INSTANCE_GUARD_ACK` | Absent. A takeover after a failure is confirmed on the halt page (§4.3); this variable is the scripted alternative, set only for that takeover and removed afterwards |

   ```bash
   # on the primary: the deployment files the standby needs, .env and tls/ included
   rsync -a --relative \
     docker-compose.yml docker-compose.external-database.yml docker/ .env tls/ \
     standby:/opt/custodexa/
   ```

   `.env` carries the database password and, in `KEK_PROVIDER=env` mode, the KEK material; `tls/ca-private/` carries the local CA's private key. Move them the way you move secrets, and keep the `0600` permission on the standby.
3. **The same TLS material.** With `TLS_MODE=selfsigned`, copy `tls/` so the standby serves the same CA and certificate; a standby that generates its own CA at first start is a new, untrusted site to every browser and every SSO callback. With `TLS_MODE=provided`, put the same certificate files in place.
4. **The KEK material has to be available on the standby**, or the standby starts and stays sealed with nothing readable:

   | `KEK_PROVIDER` | What the standby needs |
   |---|---|
   | `env` | The same `ENCRYPTION_KEY` in its `.env` (it comes with the copy above) |
   | `ui` | Nothing on disk; **someone has to enter the unseal material on the standby's unseal page after it starts.** Takeover time includes that person |
   | `kms` | The custodian reachable from this host, and **someone to unseal the standby after it starts**: they sign in on its unseal page with a local administrator's username and password, check the custodian shown there, and supply that provider's credentials again. Takeover time includes that person. The custodian settings come from the shared database and need no preparation on this host; the credentials are held only in memory and are never copied with `.env`, so whoever takes over has to be able to obtain them at that moment |

   **A delegated standby does not come up ready.** In `kms` mode the credentials exist only in the memory of the unseal generation that was running on the primary, so the standby has no way to obtain them by itself; it starts sealed and waits. Put the person who holds those credentials, and how they are reached out of hours, into the takeover plan alongside the person for `ui` mode. While sealed, the standby serves only the health check and the seal endpoints, so §5's checks below the first three cannot be run until the unseal is done.
5. **Offsite evidence storage, enabled and verified on the primary** (System Settings → Offsite storage). It is the only way the standby can play recordings the primary made; without it the standby has none of them (§2.3). The settings live in the database, so the standby uses them as soon as it starts; the standby's own host still needs network access to the storage endpoint.
6. **The address users connect to.** Decide now how users reach the standby after a takeover: re-pointing a DNS name or a virtual address to the standby keeps `PUBLIC_BASE_URL`, the certificate and every SSO redirect URI unchanged, which is the arrangement this document assumes. Any other arrangement changes those values on the standby, and the IdP-side redirect URIs with them.
7. **Start it once, then take it down.** Bring the standby up while the primary is **stopped** (a planned switchover, §3), verify it (§5), switch back, and leave the standby down. Two things to make sure of before you walk away: `docker compose ps` on the standby shows nothing, and nothing on that host starts the stack on boot (the `restart: always` policy only acts on containers that exist; a `down` removes them).

### 2.3 What the standby does not have

The database is shared; the host's file system is not. After a takeover, whatever the primary kept on its own disk is not on the standby:

| Kept only on the primary's host | Consequence on the standby | What reduces it |
|---|---|---|
| Recording files under `${DATA_PATH}/recordings` | The session records are in the database, but playback needs the file. A recording whose file the standby does not have plays only if a copy was uploaded to offsite storage (it is retrieved on first playback) | Offsite evidence storage; copying the directory from the primary's disk when it is recoverable (§4.4) |
| Audit fallback files and the seal-period journal under `${DATA_PATH}/audit` | Audit rows that could not reach the database at the time stay in those files; the seal journal of `KEK_PROVIDER=ui` mode too | Copying the directory when the disk is recoverable; low volume under normal conditions, since rows go to the database first |
| Export artifacts (evidence packages, rotation evidence reports) in the container's `/var/lib/custodexa/exports` | Their downloads stop working. The job rows are in the database; export again on the standby | Offsite storage keeps copies of completed artifacts within their retention period; otherwise nothing, the directory is container-local on every host |
| The offsite retrieval cache (`OFFSITE_SPOOL_PATH`) | Recordings are retrieved again on first playback | Nothing needed; it is a cache |
| Sessions in progress and their recordings' unwritten tail | Every protocol session ends when the host fails, and the recording of a session that ends this way is not uploaded (offsite storage uploads only recordings that ended normally). On the standby's first start those sessions are closed out with `end_reason=backend_restart` | Nothing; see §7 |

---

## 3. Planned switchover (the primary is healthy)

Use this for maintenance of the primary host, for the rehearsal in §2.2 step 7, and for returning to the primary afterwards (§6). No confirmation code is involved: a primary that stops normally releases the single-instance lock, and the standby takes it at once.

1. **Announce the downtime.** Every protocol session in progress ends when the primary stops; users see their terminals close. Choose the time as for an upgrade.
2. **Let the primary drain.** The same checks as before stopping for an upgrade: the audit queue empty (SOP §2.4) and, with offsite storage enabled, the upload queue empty (SOP §3.2b). A recording still in the upload queue when the primary stops stays on the primary's disk until the primary comes back.
3. **Stop the primary.**

   ```bash
   # on the primary
   docker compose down
   docker compose ps          # must show nothing
   ```

   `down` removes the containers, so the stack cannot come back on its own at the next reboot; `stop` would leave containers that `restart: always` brings back. The lock is released when the backend container stops.
4. **Start the standby.**

   ```bash
   # on the standby
   docker compose up -d
   docker compose logs backend | grep -E 'InstanceGuard|資料庫連線成功|Listening|監聽'
   ```

   The log shows the database connection, then the normal startup without any `[InstanceGuard]` warning; the lock was free. With `KEK_PROVIDER=ui` or `kms`, the backend now waits for the unseal, and so does everything else.
5. **Re-point the address** users connect to (DNS or virtual address) at the standby, and verify (§5).

Switching back is the same steps with the hosts exchanged.

---

## 4. Takeover after the primary has failed

### 4.1 Decide, then make sure the primary stays down

Before starting the standby, establish two things and record how you did:

- **The primary is not serving.** A host that lost its network towards users but still reaches the database is still a running instance; starting the standby next to it is the excluded topology, and the guard's confirmation step (§4.3) is where you would be asked to take responsibility for that. Confirm the failure on the host itself (console, power state, the hypervisor) when the network view is ambiguous.
- **The primary cannot come back by itself while the standby is taking over.** The primary's containers have `restart: always`: a host that reboots after a crash brings the stack back with it. Make that impossible before starting the standby, in one of these ways: keep the host powered off; on the database server, reject the primary's address (`pg_hba.conf` or the firewall) until you have decided which host stays; or, if the host is reachable, `docker compose down` there. Why this matters is in §4.4.

### 4.2 Start the standby and read the guard's answer

```bash
# on the standby
docker compose up -d
docker compose logs -f backend
```

Two outcomes:

- **The backend starts normally**, with the database connection line and no `[InstanceGuard]` warning. The primary's database session was already gone (the host was stopped cleanly, or the database's keepalive had already reclaimed it). Go to §5.
- **The backend reports that the lock is held by another database session and does not open the service.** The process stays up in the guard's halted mode instead of exiting: it keeps retrying the lock every 15 seconds and opens one page for you to act on. The passage looks like this (`pid`, the times and `code` differ every time):

  ```
  CRITICAL：單實例鎖由另一個資料庫工作階段持有。本版不支援多實例部署，本實例未啟動服務。
    持鎖者：application_name=custodexa-instance-guard pid=268 backend_start=2026-09-05T13:50:58.116184Z code=2936aed7c309
    風險：兩個實例同時執行會造成金鑰快取、匯出工作、錄影落地與封存期留痕的資料問題（見 docs/ops/deployment-topology-limits.md）。
    處置 (a)：若確認另一實例仍在執行：先停止它，再重啟本實例（無需任何設定）。
    處置 (b)：若確認無其他實例在執行（例如持鎖者是主機當機後殘留的工作階段）：開啟本實例的守衛攔下頁 /instance-guard，以管理員帳密重打確認碼 2936aed7c309 後確認，不需重啟；腳本化替代路徑為設定環境變數 INSTANCE_GUARD_ACK=2936aed7c309 後重啟。兩者都會寫入稽核事件並在管理介面顯示橫幅，直到鎖由本實例取得。
    澄清：這不是資料庫損毀；本次啟動未由本實例執行 migration 或任何資料寫入；INSTANCE_GUARD_ACK 綁定上列指紋，持鎖者變更後失效；確認後兩實例並存造成的資料問題由確認者承擔，守衛只保證此事被記錄。
  ```

  followed by a line saying that the halted mode is open on the backend's port, that it serves only the health check, the seal status and the halt confirmation, and that it has run no migration and written nothing to the database.

**Open the halt page**: `https://<address>/instance-guard` on the standby, where `<address>` is the standby's own address (the address users connect to may still point at the primary). It needs no sign-in, and it is reachable under the same source restriction as the unseal page, that is the network ranges in `SEAL_UNSEAL_ALLOWED_CIDRS` when that variable is set. Every other path on a halted instance answers 503.

The page shows the same facts as the log: the holder's `application_name`, `pid` and `backend_start`, the confirmation code for this conflict, that two instances running at once damage data, and that this instance has written nothing, so this is not database corruption. It re-reads the guard's state every retry interval, so it follows the situation without being reloaded.

The holder is the failed primary's database session, kept open on the server until its TCP keepalive gives up on it (§2.1). The standby has run no migration and has written nothing; the only listener it has open is the one serving that page. `backend_start` is when that session was created, that is, roughly when the primary last started; a value that matches your primary's last start, with the primary confirmed down, is the picture of a leftover session. How to read every field, and the optional diagnostic query that joins `pg_locks` with `pg_stat_activity`, is in SOP §2.6b. Do not terminate the session on the database server; the guard's recovery does not need it, and the procedure below is the one this document rehearsed.

**If the other instance turns out to be running**, stop it and do nothing else: the standby acquires the lock at its next retry and starts on its own, with no confirmation and no restart, and the page turns to "started".

### 4.3 Confirm with the code and let the standby take over

Only after §4.1 is settled. On the halt page:

1. **Tick the confirmation** that you have checked on the host itself that the other instance is not running and will not restart by itself.
2. **Retype the confirmation code** shown next to the holder's fingerprint.
3. **Enter an administrator's account and password**, and submit.

All three are required; a submission missing any of them is refused. The code is checked against the holder **at the moment you submit**, not against the one the page displayed: if the holder changed while you were filling the form, the submission is refused and the page shows the new fingerprint and the new code for you to retype. Wrong administrator credentials are refused too, and the confirmation is not accepted; after five credential failures the page stops accepting submissions for five minutes. That waiting period is kept inside the halted process and is gone when the process ends, and no part of it is written to the database, because a halted instance writes nothing there. It is there to stop automated guessing, not someone with access to the host. If the page answers that the credentials cannot be verified here, the instance could not read the user table (a schema from a different version, or a database problem); take the scripted path at the end of this section instead.

Once the submission is accepted the page shows **starting**: the instance closes the halt-page listener, runs the migrations and the rest of its startup, and opens the service port again. **The port does not answer during that window, which is expected**; the page keeps asking until it does, then turns to "started" and offers the way to sign in. Nothing has to be restarted and nothing has to be edited in `.env`.

From here the standby serves fully: sign-in, connections, audit, schedules. What you see until the leftover session is gone:

- A persistent banner for every signed-in user, "this instance started with an acknowledgement code; another database session still holds the single-instance lock"; administrators additionally see the confirming account, the holder fingerprint and the code in it.
- `GET /api/v1/seal/status` reports `instance_guard.state = overridden`, `reason = ack_page`; the metric `custodexa_instance_guard_overridden` is 1.
- An `audit_logs` row, `resource=instance_guard`, `event=overridden`, whose `actor` is the administrator account that confirmed, with the source recorded as the page and the number of credential failures that preceded the accepted submission. The account is what the product records; **why** the confirmation was made is not, so put the evidence from §4.1 on your incident ticket.

When the database reclaims the leftover session, the standby takes the lock on its own at its next retry (every 15 seconds): the log prints `[InstanceGuard] 已重新取得單實例鎖（自 overridden 起未持鎖 … ms，reason=…）；告知解除`, the banner disappears at the interface's next poll, `state` becomes `held`, and `audit_logs` gains an `event=regained` row. **No restart is needed.** How long that takes is the keepalive setting on the database server (§2.1), about 2 hours at the operating system default.

What confirming means, in full, is in SOP §2.6b; the one sentence that matters here: **if the primary was in fact alive, two instances are now writing the same database, and the data problems that causes are not prevented by the guard; they belong to whoever confirmed.** §4.1 is what stands between you and that.

**The scripted alternative**: `INSTANCE_GUARD_ACK`. The same confirmation can be given without the page, for a takeover driven by a script or on a host where the page is not reachable. Put the code from the most recent message into the standby's `.env` and start the backend again:

```bash
# on the standby: the value is code= from the most recent message, valid for this conflict only
printf 'INSTANCE_GUARD_ACK=%s\n' 2936aed7c309 >> .env
docker compose up -d backend
docker compose logs backend | grep InstanceGuard
```

The log then shows `CRITICAL：以 INSTANCE_GUARD_ACK 啟動：單實例鎖仍由 … 持有；本實例將照常執行 migration 與服務；此確認已記錄（actor=operator via env）`, followed by the normal startup, and `reason` is `ack_startup` instead of `ack_page`. **This path cannot record who confirmed**: the audit row's `actor` is `operator via env`, an environment variable cannot identify a person, so the person belongs on your ticket. Afterwards remove the `INSTANCE_GUARD_ACK` line from `.env`, without restarting anything: the value is bound to that one leftover session and is inert once the holder changed, but a stale line in `.env` invites the next operator to reuse it.

### 4.4 When the failed host comes back

The primary's host may come back later, repaired or rebooted. Its stack is still in `.env` and, unless you took it down, in the container list with `restart: always`. Three situations:

- **The standby holds the lock (`state = held`)**: the primary's backend is halted by the guard at startup and prints the same passage as in §4.2, with the standby as the holder, and offers the same halt page. That is the guard working as intended, and it is why §4.1 does not rely on it: it only holds once the standby actually has the lock. Confirming on the primary's halt page while the standby is serving would be the excluded topology; leave it halted, or take it down.
- **The standby is still in `overridden`** (the leftover session has not been reclaimed yet): the primary's new backend is halted by the leftover session too. When the leftover is reclaimed, **both are retrying and whichever gets there first wins the lock**. If that is the primary, it starts normally, with no `[InstanceGuard]` warning in its log, and both serve; the standby stays in `overridden` with `reason` still the one recorded at acknowledgement (`ack_page` from the guard page, `ack_startup` from the environment variable), so its state alone does not show what happened. What shows it is the holder: in `GET /api/v1/instance-guard`, and in the administrators' banner once its detail is refreshed, the holder's `backend_start` is no longer the failed primary's last start but the time its new backend came up (the standby's log prints the new holder too, at most once every 10 minutes). This is the window §4.1 closes by keeping the primary from starting until the standby reports `held`.
- **The primary's disk is recoverable**: the recordings and audit files it holds (§2.3) can be moved to the standby. The database refers to a recording by its path inside the container, which is the same on both hosts, so files copied under the standby's `${DATA_PATH}` with the same relative layout are found by playback.

  ```bash
  # from the recovered primary disk to the standby's data root; keep the relative layout and the ownership
  rsync -a /mnt/primary-disk/custodexa/data/recordings/ standby:${DATA_PATH}/recordings/
  rsync -a /mnt/primary-disk/custodexa/data/audit/      standby:${DATA_PATH}/audit/
  ```

  Recordings of sessions that were in progress at the crash come across as files but were never confirmed written; whether they play depends on how far the file got. Audit fallback files are replayed by the existing procedure ([Backup and Restore §7.3](./backup-and-restore.md#73-recovering-audit-fallback-files-after-a-restore)).

Once the standby is `held` and you have decided the primary is to return to service, going back is a planned switchover (§6). The primary's `.env` may still contain an old `INSTANCE_GUARD_ACK` line from an earlier takeover; it is inert (the holder has changed), and should be removed anyway.

---

## 5. Verifying the takeover

Run on the standby after §3 or §4; every row has to hold before the takeover is declared complete.

| # | Check | How | Expected |
|---|---|---|---|
| 1 | Services up | `docker compose ps` | backend, frontend, guacd, tls-proxy running; no postgres (it is not part of this shape) |
| 2 | Backend healthy | `docker compose exec backend wget -qO- http://localhost:8080/health` | A normal response |
| 3 | Lock state | `curl -sk https://<address>/api/v1/seal/status`; while `overridden`, also `GET /api/v1/instance-guard` as an administrator, or the holder in the banner | `instance_guard.state` is `held` after §3; after §4.3, `held`, or `overridden` with the holder's `backend_start` unchanged from the §4.2 message. `reason` is `ack_page` when the confirmation was made on the halt page and `ack_startup` when it came from `INSTANCE_GUARD_ACK`; the `overridden` audit row carries the confirming account for the first and `operator via env` for the second. A holder with a newer `backend_start` means another backend took the lock (§4.4) |
| 4 | Sign-in works | Sign in with an account whose password you know | The sign-in succeeds; users' accounts, roles and assets are all there, since they are in the database |
| 5 | The data is the primary's | Open the asset list and the audit page | Assets created on the primary are listed; the last audit rows written on the primary are there, followed by the sign-in you just made on the standby |
| 6 | Unsealed | With `KEK_PROVIDER=ui` or `kms`: the unseal page | Completed. In `kms` mode the page first asks for a local administrator's username and password, then shows the custodian for you to check against the deployment record, and then takes that provider's credentials; `seal/status` reports the unsealed state afterwards. With `env`, the backend log shows no seal-related refusal |
| 7 | Recordings | Play a recording made on the primary that was uploaded offsite | It plays after the retrieval wait (first playback of an offsite recording downloads it) |
| 8 | The address | Open the service under the address users use | It lands on the standby (compare the container names in `docker compose ps` against the certificate and the response) |
| 9 | Source attribution | The audit row of your sign-in | Shows your client address, not the proxy's; otherwise `TRUSTED_PROXIES` is wrong for this host |

```bash
# on the standby, checks 1 to 3
docker compose ps
docker compose exec backend wget -qO- http://localhost:8080/health
curl -sk https://<address>/api/v1/seal/status
```

A takeover after a failure is complete when the incident ticket carries the §4.1 evidence, the confirmation code if one was used, and the time the standby reported `held`.

---

## 6. Returning to the primary

A repaired primary comes back through a planned switchover in the other direction (§3): announce, drain the standby, `docker compose down` on the standby, `docker compose up -d` on the primary, re-point the address, verify. Before the primary starts, make sure it has everything the standby changed meanwhile: the same version, any `.env` change, and the recordings the standby made if you want them playable on the primary (§4.4 in reverse; or leave them to offsite storage).

---

## 7. What an unplanned takeover does not preserve

This is the boundary of the procedure, stated so that it can go into a recovery plan as it is. After a takeover following a host failure:

- **Every session that was in progress ends**, on every protocol, and the users have to connect again. There is no session migration.
- **The recordings of those sessions are cut at the failure.** The file, up to the moment of the crash, is on the failed host's disk; it is not uploaded to offsite storage (uploads cover recordings that ended normally), and it is not on the standby. On the standby, those session records show `end_reason=backend_restart` and no playable recording. If the disk is recovered, the files can be copied over (§4.4), and play as far as they were written.
- **Recordings that ended normally but had not finished uploading** exist only on the failed host's disk until it is recovered. The exposure window is the upload queue at the moment of failure (text recordings queue within seconds of the session end, graphical ones after at least a minute; anything waiting for an unreachable storage endpoint waits longer).
- **With offsite storage not enabled, no recording made on the primary is playable on the standby** until the primary's disk is recovered and copied over.
- **Audit rows that had fallen back to files** on the failed host (written while the database was unreachable) are not in the database and not on the standby until the files are recovered and replayed.
- **Export artifacts** that were being produced or had not been downloaded are gone from their download links; they are re-exportable on the standby, and completed ones may still be retrievable from offsite storage within their retention period.
- **Browser sign-ins are kept, not lost**: the two hosts share `JWT_SECRET`, so in the project's rehearsal an access token issued by the primary was accepted by the standby as it was. What users lose is the protocol session, not the sign-in.
- **The confirmation, when it was made on the halt page, is attributed to the administrator account that made it; when it came from `INSTANCE_GUARD_ACK`, it is attributed to `operator via env`**, not to a person. Either way, what led to the decision is on your ticket, not in the product.

Nothing in the list above is recovered by the product on its own. What the database holds, that is accounts, assets, credentials, policies, audit rows, session records, schedules and the offsite custody ledger, is intact, because it was never on the host.

---

## 8. Effect on backup, upgrade and the topology limits

- **Backup** ([Backup and Restore](./backup-and-restore.md)): the database is backed up on the database server, with `pg_dump` against it instead of `docker compose exec postgres`; the recordings and audit directories are backed up from **every application host that has files**, which after a takeover means both; `.env` and `tls/` from both hosts. The restore procedure's step of starting postgres and loading the dump happens on the database server. The consistency requirement (database and file locations from the same point in time) is unchanged and harder to meet across machines; stop the active application host for the backup window.
- **Upgrade** ([Deployment and Upgrade SOP](./upgrade-sop.md)): an upgrade is performed with the active host stopped, as before; then **both** hosts get the new images and files, and only one is started. A standby that is not upgraded in step is a standby that cannot take over (§2.2 step 1). The rolling update the SOP excludes is also excluded here: never start the standby to "cover" the upgrade of the primary.
- **Topology** ([Deployment Topology Limits](./deployment-topology-limits.md)): this procedure adds no topology. At every moment exactly one application instance runs against the database, which is what the single-instance guard requires, and the guard is what tells you when that is not the case.

## Sensitive output detection: scope and operational checks

Detection scans only parsed text output from SSH, K8s and database consoles. RDP/VNC graphics, encrypted, compressed or encoded content (including Base64) are outside its coverage. Terminal control sequences are not rendered or removed. Encoding can bypass matching; a match means the output **may contain** sensitive data, and no match does not establish absence. This mechanism raises alerts and does not block or alter delivered bytes.

Output rule additions, disabling and edits take effect for **new sessions**. Sessions already in progress retain the rule set captured at startup. After an upgrade, restore or takeover, check rule direction, enabled state and protocols, then open a new text session to verify the applicable rule set. The installed seed set has 16 rules: 12 original input rules, two agent input/block rules, plus card-number and private-key-header output rules. The builtin card pattern additionally uses Luhn validation; editing that pattern makes it an ordinary regular expression without card validation.

Hits for the same rule and session are aggregated over five seconds; session close flushes the remaining window. Alert records and forwarding retain identifiers, rule, count and time, with an empty command and no matching text or byte offsets. The count is encoded as `o1:<base36 count>` in `reason_code`; webhook payloads also expose `possible_sensitive_output.count`. These are indications of possible sensitive output, not evidence that all output was scanned.

A bounded queue overflow disables scanning for that session without interrupting output. Query the existing audit records for action `output_scan_disabled`, resource `session` and the session's resource ID; `details` contains `session_id` and `reason=queue_overflow`, with no output text. A server log alone is not the audit record. Treat that session's subsequent output as unscanned; inspect the existing evidence under the usual permissions and open a new session after checking load. Scanner failures also leave server logs; absence of alerts is not a successful-scan guarantee.

The shared redaction primitive returns fully replaced text and a replacement count; it is **not connected to a product response path in this release**. Recordings, command records and other evidence are not redacted. Existing retention, access controls and backup/restore procedures continue to apply to their original contents.


### Principal and credential integrity coverage

The verification page reports role assignments, principal kind/owner, and agent credential state separately. After upgrade, the two new rows remain “Not covered” until the first checkpoint containing their snapshots. Detection is not immediate: reconciliation runs during verification, checkpoint sealing, and before token issuance. A mismatch raises one `principal_state_integrity` / `principal_state_mismatch` event per projection, with identifier-only differences and a notification. Issuance continues on mismatch or reconciliation error; errors are logged as unknown and do not change business state. Service-layer projection state rows record actor `system`; the existing HTTP audit rows identify the operator.

Compatibility is one-way: this release verifies old checkpoints, but old releases cannot fully verify the new snapshot keys. Do not remove snapshot keys, re-sign checkpoints, or restore the old single-mechanism failure index. Rollback requires a consistent pre-upgrade backup and the documented restore procedure. The payload version remains the current latest version (v3).

## Agent MCP operations

Create an agent principal with an active human owner. As that owner or an administrator, create a named, expiring agent token; save the one-time plaintext in the operator's secret store. The agent has only the user role and explicitly scoped asset/account grants. Install the `custodexa-mcp` stdio client on the agent's machine from https://github.com/custodexa/custodexa-mcp, either with `go install github.com/custodexa/custodexa-mcp@latest` or as a release binary verified against the `checksums.txt` published with that release. Supply `CUSTODEXA_AGENT_TOKEN` to `custodexa-mcp` through its environment and set `CUSTODEXA_MCP_URL` to the HTTPS `/api/v1/mcp` endpoint. Human JWTs and cookies cannot authenticate this endpoint. The stdio client forwards tool calls; all decisions and evidence writes happen in the service. Never put the token in command arguments or reports.

Whether a task the agent submits waits for a person is decided by the access policy segment of each requested asset, taken from the asset's own `access_policy` when set and otherwise from the `access_policy_default` security policy. An item in the `approval` segment stays pending until an approver whose scope covers that asset decides it. Items in the `open` and `reason` segments are approved at submission, are recorded with `auto_approved: true` and a policy snapshot, and carry no approval votes. Under the shipped defaults most assets fall outside `approval`, so a deployment that changes nothing will see agent tasks approve themselves. To require a human decision, set `access_policy` to `approval` on the assets concerned, or set `access_policy_default` to `approval` for the whole deployment; `access_request_min_approvals` then sets how many approvals such a request needs. Decide this before granting an agent its first asset, and state the choice in the runbook: automatic approval is still fully recorded, but it is not a human control.

Rotate by issuing a new named token, updating the operator's secret, starting a new MCP connection and verifying asset visibility, then revoking the old token. There is no in-place token secret rotation or automatic token recovery from backup. Revocation closes sessions created with the old token; a session handle cannot move to a new token or MCP connection. After restore or standby takeover, create new MCP connections and tasks as needed; old in-memory handles and the 60-second idempotency cache do not survive restart. Inspect retained token state and task state before resuming work.

To contain an incident, revoke or suspend the affected token, disable the agent if necessary, and inspect its task, tool-call and HTTP request records. A probe breaker suspends tokens and records an incident. An owner or administrator releases it with a reason; release does not reactivate suspended tokens, so issue a new token afterward. Its count covers one class of reference only: assets that exist and have never been exposed to that agent. A reference to an asset id that does not exist, or to a deleted one, is classified as retired, and a reference to an asset previously exposed to that agent is classified as revoked; both are recorded as events but neither counts toward the trip threshold. Enumerating identifiers at random therefore mostly produces uncounted events, and the breaker should not be presented as general scanning detection. It is a control against repeated reach for real assets outside the agent's scope; cover broader enumeration with alert rules and request rate policy, and read the `class` field on the breaker event list before judging how much a denied reference means. Existing webhook/Slack notifications include `owner_id`; they are not a private inbox or proof of delivery. Visibility exposure history begins at its migration and cannot reconstruct older visibility; verify that boundary before attributing a denied reference to abuse.

Token expiry, the bound task item's expiry and task closure terminate existing sessions and in-flight tools without waiting for the current command to finish. Expiry checks sample current state every 250 ms; that interval is not a completion SLA. Revocation uses the existing termination path (target at most three seconds, with late termination evidence). Termination controls only sessions created by this system, not detached processes or changes already made on the target. During an in-flight request, cancellation closes its session. Between POST requests, client departure cannot be detected immediately: the server closes abandoned handles when its five-minute idle lease expires. Do not describe this as immediate disconnect detection.

`completed` means a prompt was observed again; it guarantees neither command termination nor success. Prompts can be forged and background output can interleave. `timed_out` means the outcome is unknown: inspect subsequent output before retrying. Same-handle idempotency keys suppress repeat writes for 60 seconds; calls without a key can execute again. `needs_input` requires an explicit `send_keys` reset; the service never sends an interrupt automatically. `read_screen` is a line buffer, not a virtual screen. Agent-visible text is masked while recordings and command records retain the original. Masking is rule-driven and enumerated, not a general sensitive-data filter: it applies the enabled alert rules with `direction=output` whose subject kind covers agents and whose protocol list covers the session, and replaces each matched span with a placeholder. Anything no enabled rule matches reaches the agent in full, and the shipped rule set covers two categories, a card-number pattern and a private-key header pattern. Treat the rule list as the definition of what this deployment considers sensitive on the agent channel, review it against the data actually reachable on the granted assets, and add rules for the categories that matter there. Masking never applies to human terminals, recordings or command records.

For evidence, preserve the database, recordings, checkpoints and matching versioned integrity keys. A pending tool row proves recorded intent, not delivery or completion. An unattributable task/handle is rejected before the tool ledger and recorded in that MCP HTTP request's audit row with principal, tool, reason code and time. Command integrity coverage is available only through the Investigation Workbench and batch export; a single-session export has no coverage axis. Zero degraded rows does not prove that no commands were lost. Keep report versions and closed-task timestamps; do not manufacture results for pending calls.

Takeover does not migrate active MCP sessions; inspect unknown outcomes before starting replacement work.
