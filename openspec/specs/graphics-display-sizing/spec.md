# graphics-display-sizing

## Purpose

RDP/VNC 圖形會話的顯示尺寸協商與動態調整。

## Requirements

### Requirement: Graphics session initial size
RDP and VNC sessions SHALL be initiated with the actual measured container size. The client MUST wait for the first non-zero container measurement before connecting; hardcoded fallback resolutions (such as 1024x768) MUST NOT be used.

#### Scenario: RDP connects at container size
- **WHEN** a user opens an RDP session and the container measures, for example, 1680x950 after layout
- **THEN** the connection handshake uses that measured size and the desktop fills the container without letterboxing

#### Scenario: No fallback on slow layout
- **WHEN** the terminal container has not yet completed layout at mount time
- **THEN** the client defers connecting until a non-zero size is observed instead of falling back to a fixed resolution

### Requirement: Graphics session dynamic resize
All guacd-backed protocols SHALL observe container size changes (ResizeObserver with debounce) and send updated dimensions to the server during an active session.

#### Scenario: VNC view resizes with window
- **WHEN** the browser window is resized during an active VNC session
- **THEN** the client sends the new size and the remote display adjusts (or scales) to fill the container
