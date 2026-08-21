# RDP 測試容器 Dockerfile
FROM ubuntu:22.04

# 設定非互動模式安裝
ENV DEBIAN_FRONTEND=noninteractive

# 更新套件並安裝 xrdp 和桌面環境
RUN apt-get update && \
    apt-get install -y \
    xrdp \
    xfce4 \
    xfce4-goodies \
    supervisor \
    sudo \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 配置 xrdp 使用 Xfce
RUN echo "xfce4-session" > /etc/skel/.xsession

# 創建啟動腳本
RUN mkdir -p /var/run/xrdp /var/run/sshd

# 創建 supervisor 配置
RUN mkdir -p /var/log/supervisor
COPY docker/rdp-test/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# 創建啟動腳本
COPY docker/rdp-test/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 3389

ENTRYPOINT ["/entrypoint.sh"]
