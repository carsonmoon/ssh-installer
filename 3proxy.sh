#!/usr/bin/env bash

set -e

INSTALL_DIR="/usr/local/3proxy"
CONFIG_FILE="${INSTALL_DIR}/3proxy.cfg"

echo "=================================="
echo "3proxy Installer for Debian 12/13"
echo "=================================="

if [ "$(id -u)" != "0" ]; then
    echo "请使用 root 运行"
    exit 1
fi

echo "[1/7] 安装依赖..."

apt update

DEBIAN_FRONTEND=noninteractive apt install -y \
git \
gcc \
g++ \
make \
build-essential \
libssl-dev \
zlib1g-dev \
curl \
wget

echo "[2/7] 下载源码..."

cd /tmp
rm -rf 3proxy 3proxy-master 3proxy.zip

git clone https://github.com/z3APA3A/3proxy.git

echo "[3/7] 编译..."

cd /tmp/3proxy

make -f Makefile.Linux

echo "[4/7] 安装..."

mkdir -p "${INSTALL_DIR}"

cp bin/3proxy "${INSTALL_DIR}/"

chmod +x "${INSTALL_DIR}/3proxy"

echo
read -p "SOCKS5端口 [默认1080]: " PORT
PORT=${PORT:-1080}

read -p "用户名 [默认admin]: " USERNAME
USERNAME=${USERNAME:-admin}

read -s -p "密码 [默认123456]: " PASSWORD
echo
PASSWORD=${PASSWORD:-123456}

echo "[5/7] 生成配置..."

cat > "${CONFIG_FILE}" <<EOF
daemon

nserver 8.8.8.8
nserver 1.1.1.1

timeouts 1 5 30 60 180 1800 15 60

users ${USERNAME}:CL:${PASSWORD}

auth strong

allow ${USERNAME}

socks -p${PORT}

flush
EOF

echo "[6/7] 创建systemd服务..."

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

systemctl daemon-reload
systemctl enable 3proxy
systemctl restart 3proxy

echo "[7/7] 放行防火墙..."

if command -v ufw >/dev/null 2>&1; then
    ufw allow ${PORT}/tcp || true
fi

if command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port=${PORT}/tcp || true
    firewall-cmd --reload || true
fi

echo
echo "=================================="
echo "安装完成"
echo "=================================="
echo "IP      : $(curl -4 -s ifconfig.me || echo VPS_IP)"
echo "端口    : ${PORT}"
echo "用户名  : ${USERNAME}"
echo "密码    : ${PASSWORD}"
echo
echo "服务状态:"
systemctl --no-pager status 3proxy | head -n 10
