# 使用官方 Guacamole guacd 映像
#
# **釘 1.6.0（2026-08-17 查證）**：1.6.0 是 Apache Guacamole 官方 releases 頁上的
# 最新正式版（無 1.6.1）。原本的 `:latest` 是 2026-02-25 的重建，但兩者的基底層
# 完全相同（皆為 `alpine-minirootfs-3.18.12`，該層自 2025-02-14 未動），故釘版
# **不會**倒退基底。附帶好處：`:latest` 只有 amd64 單架構 manifest，`:1.6.0` 是
# amd64＋arm64 多架構——arm64 主機自此跑原生映像而非 QEMU 模擬。
# 釘版理由（AGPL 對應源碼／離線包／漏洞公告需可指名版本）見 docker/backend/Dockerfile 檔首。
#
# **已知風險，未解決（不要當成已修）**：
# 1. 本映像基底為 **Alpine 3.18.12，該分支已 EOL**（3.18 於 2025-05-09 停止支援）。
#    上游沒有任何較新基底的 tag 可換——`:latest` 與 `:1.6.0` 是同一顆基底。
#    唯一的真正解法是上游出新版，或本專案改為自建 guacd 映像；兩者本次都未做。
# 2. trivy 對本映像回報 0 項 HIGH/CRITICAL，**那是「沒有資料」不是「沒有漏洞」**：
#    (a) EOL 分支不再有安全資料庫更新；(b) guacd 本體是 `/opt/guacamole` 下的 C
#    二進位（libguac.so.25 等），不在 apk 套件資料庫內，套件掃描器看不見它。
# 3. guacd 解析的是**目標主機送來的 RDP／VNC 協議資料**，而目標主機正是威脅模型裡
#    假設可能已被入侵的一方——這是本產品最不能靠掃描器代勞的暴露面。
#    人工追蹤點：https://guacamole.apache.org/security/ ，發版前比對 `guacd -v` 與上游最新版。
FROM guacamole/guacd:1.6.0

# guacd 預設監聽 4822 port
EXPOSE 4822

# 使用預設啟動命令（日誌級別通過 LOG_LEVEL 環境變數控制）
