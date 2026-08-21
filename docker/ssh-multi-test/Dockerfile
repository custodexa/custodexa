# 多帳號 SSH 測試靶機（dev only）
# 與 ssh-test（linuxserver/openssh-server，rootless、單帳號）互補：
# sshd 以 root 執行才能 setuid 切換使用者，供 asset-multi-account 的
# 帳號切換與授權範圍驗證使用。
FROM alpine:3.20

RUN apk add --no-cache openssh && \
    ssh-keygen -A && \
    adduser -D -s /bin/sh testuser && \
    echo 'root:rootpass123' | chpasswd && \
    echo 'testuser:testpass123' | chpasswd && \
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]
