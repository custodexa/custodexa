# terminal-search

## Purpose

終端輸出緩衝的關鍵字搜尋與高亮。

## Requirements

### Requirement: Scrollback search
The SSH terminal SHALL provide scrollback search opened with Ctrl/Cmd+F, with next (Enter) and previous (Shift+Enter) navigation, closing with Escape and returning focus to the terminal. The browser's native find dialog MUST NOT open while the terminal has focus.

#### Scenario: Find text in scrollback
- **WHEN** the user presses Ctrl+F in an SSH session and types a term that exists in earlier output, then presses Enter
- **THEN** the terminal highlights and scrolls to the next match instead of opening the browser find dialog

#### Scenario: Close search returns focus
- **WHEN** the user presses Escape in the search bar
- **THEN** the search bar closes and keyboard input goes to the terminal again
