# VNC 測試容器：Xvfb + x11vnc + 輕量視窗管理器
FROM alpine:3.20

RUN apk add --no-cache \
    xvfb \
    x11vnc \
    fluxbox \
    xterm \
    netcat-openbsd \
    openssh-server

COPY docker/vnc-test/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 5901

HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=5 \
  CMD nc -z localhost 5901 || exit 1

ENTRYPOINT ["/entrypoint.sh"]
