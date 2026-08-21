# session-latency

## Purpose

終端會話的往返延遲量測與徽章呈現。

## Requirements

### Requirement: SSH session latency indicator
The SSH terminal SHALL measure round-trip latency using the existing keepalive ping/pong exchange and display a color-coded badge (green under 100ms, yellow under 300ms, red otherwise). The badge SHALL be hidden until the first measurement and after disconnect.

#### Scenario: Latency shown during session
- **WHEN** an SSH session is connected and a pong response arrives
- **THEN** the terminal shows a latency badge with the measured milliseconds and the corresponding color

#### Scenario: Hidden when unknown
- **WHEN** the session has not yet received a pong (or has disconnected)
- **THEN** no latency badge is displayed
