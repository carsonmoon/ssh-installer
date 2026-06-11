#!/bin/bash
set -e

echo "==== 3proxy 最小稳定安装（Debian12 / Ubuntu22）===="

# 1. 依赖（关键）
apt update
apt install -y \
    build-essential \
    gcc \
    g++ \
    make \
    wget \
    unzip \
    libssl-dev \
    zlib1g-dev \
    iproute2

# 2. 清理旧文件（防止 unzip 卡死 / 冲突）
rm -rf /tmp/3proxy*
cd /tmp

# 3. 下载源码（用官方codeload，比git zip稳定）
echo "下载 3proxy..."
wget -q https://codeload.github.com/3proxy/3proxy/zip/refs/heads/master -O 3proxy.zip

# 4. 解压（强制无交互）
unzip -o 3proxy.zip > /dev/null

cd 3proxy-master/src

# 5. 编译（关键步骤）
echo "编译 3proxy..."
make -f Makefile.Linux

# 6. 安装
cp 3proxy /usr/local/bin/
chmod +x /usr/local/bin/3proxy

echo "编译完成 ✔"

# 7. 创建配置
mkdir -p /etc/3proxy

cat > /etc/3proxy/3proxy.cfg <<EOF
auth none
socks -p1080
EOF

# 8. 启动测试
echo "启动测试 SOCKS5 (1080)..."
/usr/local/bin/3proxy /etc/3proxy/3proxy.cfg &
sleep 2

echo ""
echo "==== 完成 ===="
echo "SOCKS5: 127.0.0.1:1080"
