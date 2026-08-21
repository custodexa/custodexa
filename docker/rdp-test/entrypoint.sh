#!/bin/bash
set -e

# 從環境變數取得使用者名稱和密碼，或使用預設值
RDP_USER=${RDP_USER:-testuser}
RDP_PASSWORD=${RDP_PASSWORD:-testpass123}

echo "=========================================="
echo "RDP 測試伺服器啟動中..."
echo "=========================================="

# 建立 RDP 使用者
if ! id -u "$RDP_USER" >/dev/null 2>&1; then
    echo "建立使用者: $RDP_USER"
    useradd -m -s /bin/bash "$RDP_USER"
    echo "$RDP_USER:$RDP_PASSWORD" | chpasswd

    # 加入 sudo 群組
    usermod -aG sudo "$RDP_USER"

    # 設定 xsession
    echo "xfce4-session" > /home/$RDP_USER/.xsession
    chown $RDP_USER:$RDP_USER /home/$RDP_USER/.xsession

    echo "使用者建立完成"
else
    echo "使用者 $RDP_USER 已存在，更新密碼"
    echo "$RDP_USER:$RDP_PASSWORD" | chpasswd
fi

echo "=========================================="
echo "RDP 連線資訊："
echo "  主機: rdp-test (容器內) 或 localhost:3389 (主機)"
echo "  使用者: $RDP_USER"
echo "  密碼: $RDP_PASSWORD"
echo "=========================================="

# 啟動 supervisor
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
