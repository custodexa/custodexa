#!/bin/sh
set -e

VNC_PASSWORD="${VNC_PASSWORD:-vncpass123}"
DISPLAY_NUM="${DISPLAY_NUM:-:1}"

mkdir -p /root/.vnc
x11vnc -storepasswd "$VNC_PASSWORD" /root/.vnc/passwd

# SFTP 側車測試（vnc-file-transfer e2e）：同主機起 sshd 供 guacd SFTP 連入
SFTP_USER="${SFTP_USER:-sftpuser}"
SFTP_PASSWORD="${SFTP_PASSWORD:-testpass123}"
ssh-keygen -A
adduser -D -s /bin/sh "$SFTP_USER" 2>/dev/null || true
echo "$SFTP_USER:$SFTP_PASSWORD" | chpasswd
/usr/sbin/sshd

# 容器非正常停止會殘留 X lock/socket，Xvfb 誤判 display 已占用而退出（重啟循環）
rm -f "/tmp/.X${DISPLAY_NUM#:}-lock" "/tmp/.X11-unix/X${DISPLAY_NUM#:}"

Xvfb "$DISPLAY_NUM" -screen 0 1024x768x24 &
sleep 2

DISPLAY="$DISPLAY_NUM" fluxbox &
DISPLAY="$DISPLAY_NUM" xterm -e "echo 'Custodexa VNC test server'; sh" &

exec x11vnc -display "$DISPLAY_NUM" -rfbauth /root/.vnc/passwd -rfbport 5901 -forever -shared -noxdamage
