# Contributing

<p><b>English</b> | <a href="docs/zh-TW/CONTRIBUTING.md">繁體中文</a></p>

Thanks for contributing to Custodexa. This document tells you how to get a
contribution in; for environment setup, see [`docs/QUICKSTART.md`](docs/QUICKSTART.md).

## I want to…

- **Report a bug or suggest an idea**: open a GitHub issue with reproduction
  steps or your motivation.
- **Fix docs, typos, or an obvious small bug**: open a PR directly, no prior
  discussion needed. Remember to commit with `-s` (see DCO below).
- **Change behavior or add a feature**: open an issue first to discuss the
  motivation and approach, then follow the behavioral-change workflow once
  there is agreement, so you do not build something that turns out not to fit.

## Development environment and tests

```bash
bash scripts/quickstart.sh --up                # bring up the full stack
docker compose exec backend go test ./...      # backend tests
docker compose exec frontend npm run test      # frontend tests
```

All verification runs inside docker compose. For more commands, environment
pitfalls, and guard-test discipline, see [`docs/dev/testing.md`](docs/dev/testing.md).

## DCO sign-off (required)

The project is licensed under **AGPL-3.0** and accepts contributions under the
**DCO**. There is no agreement to sign, just one line per commit:

```bash
git commit -s -m "fix: describe your change"
```

The line states that you wrote the code, or have the right to submit it under
the project's license. **It does not transfer your copyright** (full text in
[`DCO.md`](DCO.md)). The sign-off is taken from your git config
(`user.name` / `user.email`) and stays in public history permanently, so use
details you are comfortable publishing.

- Forgot to sign: `git commit --amend -s` for the last commit, or
  `git rebase --signoff <base>` for several, then force-push.
- Unsigned PRs will not be merged, but review proceeds as usual and a
  maintainer will remind you how to fix it.
- Why not a CLA: a CLA exists so a project can relicense your contribution
  under non-AGPL terms. This project does not do that, so it does not need one.

## PR checklist

- Every commit carries `Signed-off-by`.
- Commit messages follow Conventional Commits
  (`feat:` / `fix:` / `refactor:` / `docs:` / `test:` / `chore:`).
- Tests are green; behavioral changes come with tests.
- Behavioral changes and refactors live in separate commits, each
  independently revertable.
- User-visible text goes through i18n (machine codes plus three languages;
  hardcoded single-language strings fail the guard tests; see
  [`docs/dev/conventions.md`](docs/dev/conventions.md)).
- No hardcoded secrets; external input is validated.
- Commit messages and docs may be in English or Traditional Chinese; technical
  terms stay in their original form.

## Behavioral-change workflow (OpenSpec)

[`openspec/specs/`](openspec/specs/) describes what the system does **today**
and is the source of truth. Every behavioral change follows the same path:

```
evidence → proposal (openspec/changes/<id>/) → implementation → archive (merge into specs/)
```

A change folder under `openspec/changes/` exists only while the change is in
flight; archiving merges its spec delta into `openspec/specs/` and retires the
folder.

Key points:

1. **Designs need evidence**: code inventory with file:line references, actual
   runtime behavior, or screenshots, never recollection. Other open-source
   bastion projects may be studied but never copied: they are mostly GPL-family
   licensed, and copied code would contaminate this project.
2. **Guard-protected machine artifacts** (route goldens, the API endpoint
   index) are regenerated via the process in
   [`docs/dev/testing.md`](docs/dev/testing.md), never hand-edited.
3. **Touched routes?** Update the prose sections of
   [`docs/API_SPEC.md`](docs/API_SPEC.md). **Touched models/migrations?**
   Update [`docs/DB_SCHEMA.md`](docs/DB_SCHEMA.md).
4. **Archived specs may only describe what the system actually does.**
   Explain unfinished parts in the PR and a maintainer will track them in an
   issue; do not write them into the spec.

### Change codes in the source

Markers like `（asset-multi-account D5）` in comments flag branches that encode
a recorded decision, so double-check before changing them. The authoritative
description of the behavior is always `openspec/specs/`; if the reasoning is
unclear, ask in an issue and a maintainer will add it to the docs.

## Design principles (read before proposing features)

- **Each role gets its own feature pages**: do not bolt another role's
  sections onto an existing page; decide which role's navigation a feature
  belongs to before designing it.
- **Users who get stuck need a product-level way out** (a UI action plus an
  API endpoint). If the answer is "ask an admin to edit the database", the
  feature is missing.
- **The single source of truth for visuals is
  [`docs/DESIGN_SPEC.md`](docs/DESIGN_SPEC.md)**; brand token changes require
  maintainer approval, and audit-relevant technical identifiers never change
  for visual reasons.

## Security red lines (non-negotiable)

A PR that crosses any of these will not be merged:

1. **Connection containment**: the frontend never touches plaintext
   credentials. They live only in the backend, and the frontend gets a
   one-time connect token.
2. **Full operation audit**: every connection and management operation leaves
   a trace; when the audit trail is unavailable, fail closed.
3. **Input validation**: all external input is validated before use.

Concrete architectural invariants live in
[`docs/dev/conventions.md`](docs/dev/conventions.md).

## Further reading

| Document | Contents |
|---|---|
| [`docs/dev/conventions.md`](docs/dev/conventions.md) | Architectural invariants, security red-line details, i18n rules, frontend UI conventions, code style |
| [`docs/dev/testing.md`](docs/dev/testing.md) | In-docker verification, machine-artifact regeneration, guard-test discipline, flakiness triage |
| [`docs/dev/architecture.md`](docs/dev/architecture.md) | The seven-module split and the invariants later changes must not break |
