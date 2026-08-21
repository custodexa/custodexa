# Reporting Security Issues

**English** | [繁體中文](docs/zh-TW/SECURITY.md)

> If the two language versions ever diverge, this English text governs.

## Please do not open a public issue

If you find a security problem, use GitHub's **private vulnerability reporting**:

**[Submit a private report](https://github.com/custodexa/custodexa/security/advisories/new)**
(the repo's Security tab → Report a vulnerability)

Only the maintainer can see reports sent through this channel; nothing becomes
public before an advisory is published. This project is a privileged-access
management product — a public issue hands the attack method straight to the
attackers of every deployment out there.

## What to include if you can

All of these are **nice to have**, none are **required** — a report is never
rejected for missing items:

1. Affected version or commit
2. Component and protocol involved (SSH / RDP / VNC / database CLI / K8s exec /
   web admin UI / API)
3. Reproduction steps, ideally with a minimal environment
4. Impact: what an attacker gains, and what privileges they need first
5. How you would like to be credited (or that you prefer to stay anonymous)

**Never include real credentials, personal data, or customer data.**
If reproduction depends on specific data, describe its shape — do not paste it.

## Ground rules for testing

- Only test deployments **you own, or are authorised in writing to test**.
  There is no public test instance, and this project cannot authorise you to
  test anyone else's deployment.
- No data destruction, no access to non-test data, no denial-of-service load testing.

## What you can expect

**This project makes no response-time (SLA) promises.** That is deliberate:
it is maintained by an individual, and numbers like "response within 24 hours"
or "patch within 7 days" would have no one to stand behind them — writing them
down would just be an unkeepable sentence.

What you get instead is an explicit **handling order**:

| Severity | Handling |
|---|---|
| **Critical** | Interrupts all current work; takes priority over any feature development |
| **High** | Scheduled ahead of the next batch of work; never competes with feature items |
| **Medium / Low** | Enters the backlog, scheduled together with other security items |

Anything already exploited in the wild, or with a public PoC, is escalated one level.

### How severity is decided

CVSS scores are not used as the criterion. This product is a connection-funneling
system: the real-world consequence of the same technical flaw depends heavily on
"is the attacker already inside the management plane?" and "is the path reachable
from an unauthenticated entry point?" — exactly what CVSS base scores capture
worst. If you provide a CVSS vector we will record it, but severity is decided
on three axes:

- **Reachability**: triggerable unauthenticated? as a regular user? as an admin?
  only from the host itself?
- **Preconditions**: does it require a specific configuration or deployment
  topology? does the default configuration hit it?
- **Consequence**: credential exposure / bypass of connection funneling / bypass
  of audit or recording / privilege escalation / denial of service / information
  disclosure

**Severity is never lowered because a fix is hard.** The response to a hard fix
is disclosing mitigations, not adjusting the rating.

### "Won't fix" is a legitimate conclusion

Deciding not to fix is a valid outcome, but it always comes with the reasoning.
Typical legitimate reasons: the premise does not hold (the report is based on a
misreading of the behavior); it falls outside the threat model (for example,
"an administrator holding the signing key can re-sign" — an honest boundary
already stated in the specifications); or an equivalent compensating control
exists and is documented in the operations guides.

## Disclosure

**Please hold the details until a fix ships.**

If no fix has shipped within **90 days** of your report, you may publish on your
own — no further permission needed. This is **your right, not a deadline promise
from this project**: there is no guarantee a fix will exist within 90 days, but
a known issue will also never be held over your head indefinitely just because
it is not fixed yet.

When a fix ships, it is announced as a **GitHub Security Advisory**, covering
the impact, affected versions, mitigations, and credit to the reporter (unless
you prefer to stay anonymous). CVE IDs are requested through GitHub when needed.

## What this project does not have

Listed honestly so you do not waste your time:

- **Bug bounty**: none, and none planned.
- **Formal legal safe harbor**: none. This project is maintained by an
  individual and cannot offer legally binding guarantees. The maintainer will
  not take action against good-faith reporters who follow the rules above —
  but that is a statement of intent, not a legal commitment.
- **Public test instance**: none. Please test on your own deployment.

## Known dependency situation

**The `sqlcmd` binary used for MSSQL connections embeds outdated library
versions.** This project builds that binary from the upstream (Microsoft
go-sqlcmd) **source** (`sqlcmd-builder` stage in `docker/backend/Dockerfile`,
pinned to `v1.10.0`), and v1.10.0 is its latest release — **its dependency tree
is decided by upstream's `go.mod`, and this project does not override it**:
bumping versions unilaterally would diverge from the combination upstream has
validated, which amounts to maintaining a fork. The stance is therefore "follow
upstream releases", pending an upstream update.

**What can be determined**: most advisories fall on functional paths this
project does not use (SSH connections, container-management subcommands).

**What cannot be determined**: there is no reliable way to do reachability
analysis on that binary — scanners compare package versions rather than actual
call paths, and the build strips symbol tables with `-w -s`.
**This project therefore does not claim these advisories are harmless.**

**Structural constraints that do exist** (mechanically asserted on every build,
not promised): the binary runs as an unprivileged user, with no writable paths,
no setuid, and the production image contains no shell.

Deployments that do not use the MSSQL connection feature are unaffected.

For guacd (used by RDP/VNC), whose base system no longer receives security
updates, see [deployment topology limits](docs/ops/deployment-topology-limits.md)
for the situation and its deployment implications.

## Supported versions

After 1.0, security fixes ship only for the **latest minor version**. There are
no backports to older minors — this project does not have the capacity to
maintain multiple branches, and promising otherwise would not survive contact
with reality.
