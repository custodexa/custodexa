/**
 * xterm.js theme constants mirroring the terminal design tokens in
 * tokens.css (--ot-terminal-*). xterm cannot consume CSS variables,
 * so keep the two in sync here as the single JS source.
 */
export const TERMINAL_BACKGROUND = '#0d1117'
export const TERMINAL_FOREGROUND = '#e6edf3'

export const xtermTheme = {
  background: TERMINAL_BACKGROUND,
  foreground: TERMINAL_FOREGROUND,
  cursor: '#3b9eff',
  cursorAccent: TERMINAL_BACKGROUND,
  selectionBackground: 'rgba(59, 158, 255, 0.3)',
  black: '#161b22',
  red: '#e5604f',
  green: '#4ec47a',
  yellow: '#d9a93e',
  blue: '#3b9eff',
  magenta: '#bc8cff',
  cyan: '#39c5cf',
  white: '#b1bac4',
  brightBlack: '#6e7781',
  brightRed: '#ff7b72',
  brightGreen: '#56d364',
  brightYellow: '#e3b341',
  brightBlue: '#79c0ff',
  brightMagenta: '#d2a8ff',
  brightCyan: '#56d4dd',
  brightWhite: '#e6edf3',
}
