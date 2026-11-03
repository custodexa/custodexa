# 多帳號 SSH 測試靶機（dev only）
# 與 ssh-test（linuxserver/openssh-server，rootless、單帳號）互補：
# sshd 以 root 執行才能 setuid 切換使用者，供帳號切換與授權範圍驗證使用。
FROM alpine:3.20

RUN apk add --no-cache openssh && \
    ssh-keygen -A && \
    adduser -D -s /bin/sh testuser && \
    echo 'root:rootpass123' | chpasswd && \
    echo 'testuser:testpass123' | chpasswd && \
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

# 主機帳號盤點的特權判定情境：sudo 直接授權、群組授權、User_Alias 授權、
# 一列無法解析的 netgroup 規則，以及 gid 0 但不可登入的帳號。
# 既有帳號不加入任何 sudo 規則（保留「無 sudo 權限的帳號改密被拒」情境）。
RUN apk add --no-cache sudo && \
    addgroup invadmins && \
    adduser -D -s /bin/sh invuser1 && \
    addgroup invuser1 invadmins && \
    adduser -D -s /bin/sh invuser2 && \
    adduser -D -H -G root -s /bin/sync invsync && \
    (grep -Eq '^[@#]includedir /etc/sudoers\.d' /etc/sudoers || echo '@includedir /etc/sudoers.d' >> /etc/sudoers) && \
    printf '%s\n' \
      'invuser1 ALL=(ALL) ALL' \
      '%invadmins ALL=(ALL) ALL' \
      'User_Alias INVOPS = invuser2' \
      'INVOPS ALL=(ALL) ALL' \
      '+netops ALL=(ALL) ALL' \
      > /etc/sudoers.d/90-inventory && \
    chmod 0440 /etc/sudoers.d/90-inventory && \
    visudo -c

# 堡壘機專用帳號代改密碼的情境：三個被改者（沒有 sudo）與三種專用帳號。
# cxexec-key 密碼欄設為 `*`（不可用但非鎖定），金鑰由平台產生後另行寫入其 authorized_keys；
# cxexec-pw 以自己的密碼提權，也用來驗證只開 chpasswd 一條規則時仍能輪替自己；
# cxexec-nosudo 沒有任何 sudo 規則。root 沿用既有帳號，不在這裡動它。
RUN adduser -D -s /bin/sh rotuser1 && echo 'rotuser1:rotpass123' | chpasswd && \
    adduser -D -s /bin/sh rotuser2 && echo 'rotuser2:rotpass123' | chpasswd && \
    adduser -D -s /bin/sh rotuser3 && echo 'rotuser3:rotpass123' | chpasswd && \
    adduser -D -s /bin/sh cxexec-key && sed -i 's/^cxexec-key:[^:]*:/cxexec-key:*:/' /etc/shadow && \
    adduser -D -s /bin/sh cxexec-pw && echo 'cxexec-pw:execpass123' | chpasswd && \
    adduser -D -s /bin/sh cxexec-nosudo && echo 'cxexec-nosudo:nosudopass123' | chpasswd && \
    printf '%s\n' \
      'cxexec-key ALL=(root) NOPASSWD: /usr/sbin/chpasswd' \
      'cxexec-pw ALL=(root) /usr/sbin/chpasswd' \
      > /etc/sudoers.d/91-executor && \
    chmod 0440 /etc/sudoers.d/91-executor && \
    visudo -c

# 堡壘機專用帳號的測試登入與盤點提權讀取：cxexec-key-nosudo 只能以金鑰登入、沒有任何 sudo 規則
# （驗「需要免密碼規則」）；92-inventory-read 讓 cxexec-key 免密碼、cxexec-pw 以自己的密碼
# 讀取規則檔，cxexec-nosudo 與 cxexec-key-nosudo 不給（驗「提權被拒」）。
RUN adduser -D -s /bin/sh cxexec-key-nosudo && sed -i 's/^cxexec-key-nosudo:[^:]*:/cxexec-key-nosudo:*:/' /etc/shadow && \
    printf '%s\n' \
      'cxexec-key ALL=(root) NOPASSWD: /bin/tar -cf - -C /etc sudoers sudoers.d' \
      'cxexec-pw ALL=(root) /bin/tar -cf - -C /etc sudoers sudoers.d' \
      > /etc/sudoers.d/92-inventory-read && \
    chmod 0440 /etc/sudoers.d/92-inventory-read && \
    visudo -c

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]
