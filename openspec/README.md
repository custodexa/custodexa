# openspec/ — Behavioral Specifications

This directory is the **source of truth for what the system does**. Each capability
has a `specs/<capability>/spec.md` describing its requirements and scenarios in
normative language (SHALL / MUST). When code and spec disagree, that is a bug in
one of them — see [CONTRIBUTING.md](../CONTRIBUTING.md) for how changes flow
through proposals into these specs.

- `specs/` — one directory per capability (the behavioral contract).
- `changes/` — proposal workspace. Work-in-progress and archived proposals are
  **not** part of the public tree, except two build manifests consumed by guard
  tests at `changes/archive/2026-08-11-modular-architecture/research/`.
- `config.yaml` — workflow configuration.

**Normative keywords**: requirements use RFC-2119-style keywords, kept in English
because the spec toolchain validates them literally. Reading key:
`SHALL` / `MUST` = 必須（強制要求）; `SHALL NOT` / `MUST NOT` = 不得（強制禁止）;
`SHOULD` = 應當（強烈建議，偏離須有理由）; `MAY` = 可以（允許）.
Everything outside these keywords is explanatory prose.

**Language**: the specifications are written and maintained in **Traditional
Chinese**, which is the normative text. Translations are welcome as contributions,
but until a translated copy is kept in sync by CI, the Chinese text governs.
Machine translation is generally adequate for reading; if a passage matters to
you and the translation is ambiguous, please open an issue and we will clarify.

---

# openspec/ — 行為規格

本目錄是**系統行為的事實源**：每個能力一份 `specs/<capability>/spec.md`，以規範語言
（SHALL／MUST）描述其要求與場景。程式碼與規格不一致時，其中之一就是缺陷——
變更如何經提案流入規格，見 [CONTRIBUTING.md](../CONTRIBUTING.md)。

**規範詞**：條文中的 `SHALL`／`MUST`＝必須、`SHALL NOT`／`MUST NOT`＝不得、
`SHOULD`＝應當、`MAY`＝可以——這些關鍵字因規格工具鏈按字面驗證而保留英文，
其餘文字皆為說明性中文。

**語言**：規格以繁體中文撰寫與維護，中文本文為規範文本；歡迎以貢獻形式提供譯本，
但在譯本具備同步機制之前，以中文為準。
