#!/usr/bin/env bash

set -e

INSTALL_DIR="/usr/local/3proxy"
CONFIG_FILE="${INSTALL_DIR}/3proxy.cfg"

echo "=================================="
echo "3proxy Installer for Debian 12/13"
echo "=================================="

# 检查 root
if [ "$(id -u)" != "0" ]; then
    echo "请使用 root 用户运行"
    exit 1
fi

echo "[1/8] 安装依赖..."
apt update
DEBIAN_FRONTEND=noninteractive apt install -y \
git gcc g++ make build-essential libssl-dev zlib1g-dev curl wget

echo "[2/8] 下载源码..."
cd /tmp
rm -rf 3proxy*
git clone https://github.com/z3APA3A/3proxy.git

echo "[3/8] 编译..."
cd /tmp/3proxy
make -f Makefile.Linux

echo "[4/8] 安装..."
mkdir -p "${INSTALL_DIR}"
cp bin/3proxy "${INSTALL_DIR}/"
chmod +x "${INSTALL_DIR}/3proxy"

# 获取用户配置
echo
read -p "请输入 SOCKS5 端口 [默认1080]: " PORT
PORT=${PORT:-1080}

read -p "请输入用户名 [默认 admin]: " USERNAME
USERNAME=${USERNAME:-admin}

read -s -p "请输入密码 [默认 123456]: " PASSWORD
echo
PASSWORD=${PASSWORD:-123456}

echo "[5/8] 生成配置文件..."
cat > "${CONFIG_FILE}" <<EOF
# 3proxy 配置文件 - systemd 管理版本

# 不使用 daemon，由 systemd 管理
# daemon

# DNS
nserver 8.8.8.8
nserver 1.1.1.1

# 超时设置
timeouts 1 5 30 60 180 1800 15 60

# 用户认证
users ${USERNAME}:CL:${PASSWORD}
auth strong
allow ${USERNAME}

# SOCKS5
socks -p${PORT}

flush
EOF

echo "[6/8] 创建 systemd 服务..."
cat > /etc/systemd/system/3proxy.service <<EOF
[Unit]
Description=3proxy Proxy Server
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/3proxy ${CONFIG_FILE}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

echo "[7/8] 启动服务..."
systemctl daemon-reload
systemctl enable 3proxy
systemctl restart 3proxy

echo "[8/8] 放行防火墙端口..."
if command -v ufw >/dev/null 2>&1; then
    ufw allow ${PORT}/tcp || true
fi

if command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port=${PORT}/tcp || true
    firewall-cmd --reload || true
fi

echo
echo "=================================="
echo "3proxy 安装完成！"
echo "=================================="
echo "IP       : $(curl -4 -s ifconfig.me || echo VPS_IP)"
echo "端口     : ${PORT}"
echo "用户名   : ${USERNAME}"
echo "密码     : ${PASSWORD}"
echo
echo "服务状态:"
systemctl --no-pager status 3proxy | head -n 10
echo
echo "检查监听端口:"
ss -lntp | grep ${PORT} || echo "未发现监听，检查配置或防火墙"
