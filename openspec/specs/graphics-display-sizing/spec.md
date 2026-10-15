# graphics-display-sizing

## Purpose

RDP/VNC 圖形會話的顯示尺寸協商與動態調整，包含容器尺寸變動時的縮放計算，以及畫面貼齊容器邊緣時不得進入反覆縮放的穩定性要求。

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

### Requirement: Graphics display stability at container edges

The graphics display container for RDP and VNC sessions MUST NOT produce scrollbars, including when the remote cursor image extends past the container edge. Container measurement SHALL be rounded down to whole pixels, and the same measured values SHALL be used both for the size sent to the server and for scaling the display, so the scaled display never exceeds the container. A resize whose measured width and height equal the last applied size SHALL be ignored (no size update to the server, no rescale, no repaint). Synthetic input used to trigger a repaint SHALL be limited to the first frame after the connection is established, and the client MUST NOT synthesize modifier key presses (such as Shift) for repaint purposes.

#### Scenario: Cursor resting at the right edge does not cause rescaling

- **WHEN** during an active RDP session on a browser whose scrollbars take layout space, the user moves the cursor to within a few pixels of the display's right edge and keeps it there with small movements for 5 seconds
- **THEN** the container shows no scrollbar, the display scale stays constant, at most one resize is applied, and no edge of the remote desktop is clipped

#### Scenario: Unchanged size is not reapplied

- **WHEN** the container size observer reports a size equal to the last applied width and height
- **THEN** the client sends no size update, does not rescale, and does not trigger a repaint

#### Scenario: Resize does not inject synthetic keys

- **WHEN** the user resizes the browser window during an active RDP session
- **THEN** the client sends the new size and rescales once, and no synthetic mouse move or Shift key event is sent to the remote host
