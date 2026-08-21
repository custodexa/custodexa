# session-watermark

## Purpose

會話畫面浮水印覆蓋。

## Requirements

### Requirement: 會話浮水印
所有會話面板與分享觀看頁 SHALL 疊加半透明浮水印（使用者名＋日期，斜向平鋪）；浮水印 SHALL NOT 攔截滑鼠鍵盤輸入；canvas 不可用時 SHALL 靜默省略。

#### Scenario: 工作區會話
- **WHEN** 使用者開啟任一協議會話
- **THEN** 面板可見平鋪浮水印且終端輸入不受影響

#### Scenario: 分享觀看
- **WHEN** 觀看者開啟分享頁
- **THEN** 畫面含觀看者自己的使用者名浮水印
