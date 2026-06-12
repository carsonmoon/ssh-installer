#!/usr/bin/env bash
#=============================================================
# 3proxy Auto Installer for Debian 12/13
# Version: 1.0
#=============================================================

set -e

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
RESET="\033[0m"

echo -e "${GREEN}==> 更新系统并安装依赖...${RESET}"
apt update -y
apt upgrade -y
apt install -y build-essential git make gcc

echo -e "${GREEN}==> 下载 3proxy 源码...${RESET}"
cd /tmp
git clone https://github.com/z3APA3A/3proxy.git
cd 3proxy

echo -e "${GREEN}==> 编译 3proxy...${RESET}"
make -f Makefile.Linux

echo -e "${GREEN}==> 创建安装目录并复制文件...${RESET}"
mkdir -p /usr/local/3proxy
cp ./bin/3proxy /usr/local/3proxy/
cp ./bin/3proxy.cfg /usr/local/3proxy/ 2>/dev/null || true

echo -e "${GREEN}==> 设置权限...${RESET}"
chmod +x /usr/local/3proxy/3proxy

echo -e "${GREEN}==> 创建 systemd 服务文件...${RESET}"
cat >/etc/systemd/system/3proxy.service <<EOF
[Unit]
Description=3proxy Proxy Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/3proxy/3proxy /usr/local/3proxy/3proxy.cfg
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

echo -e "${GREEN}==> 重新加载 systemd 并启用服务...${RESET}"
systemctl daemon-reload
systemctl enable 3proxy
systemctl start 3proxy

echo -e "${GREEN}==> 3proxy 安装完成！${RESET}"
echo -e "${YELLOW}默认配置文件位置: /usr/local/3proxy/3proxy.cfg${RESET}"
echo -e "${YELLOW}使用 systemctl [start|stop|status] 3proxy 管理服务${RESET}"
