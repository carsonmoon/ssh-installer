#!/bin/bash
set -e

echo "==== SOCKS5 站群一键部署（稳定版）===="

# ===== 基础依赖 =====
apt update
apt install -y curl wget unzip make gcc g++ build-essential libssl-dev iproute2

# ===== 获取IP =====
IPS=($(ip -4 addr show | awk '/inet / {print $2}' | cut -d/ -f1 | grep -v '^127.0.0.1'))

echo "检测到IP："
for i in "${!IPS[@]}"; do
    echo "[$i] ${IPS[$i]}"
done

read -p "是否全部IP部署？(y/n): " all
if [[ "$all" == "y" ]]; then
    SELECTED_IPS=("${IPS[@]}")
else
    read -p "输入选择IP序号(空格分隔): " -a idxs
    SELECTED_IPS=()
    for i in "${idxs[@]}"; do
        SELECTED_IPS+=("${IPS[$i]}")
    done
fi

# ===== 端口 =====
read -p "端口模式 1统一 / 2递增: " pmode
read -p "起始端口: " base_port

# ===== 用户密码 =====
read -p "账号模式 1统一 / 2随机: " umode

if [[ "$umode" == "1" ]]; then
    read -p "用户名: " USERNAME
    read -p "密码: " PASSWORD
fi

# ===== 安装3proxy（避免重复）=====
if ! command -v 3proxy >/dev/null 2>&1; then
    echo "安装3proxy..."

    rm -rf /tmp/3proxy*
    cd /tmp

    wget -q https://codeload.github.com/3proxy/3proxy/zip/refs/heads/master -O 3proxy.zip
    unzip -o 3proxy.zip >/dev/null

    cd 3proxy-master/src
    make -f Makefile.Linux

    cp 3proxy /usr/local/bin/
else
    echo "3proxy已存在，跳过编译"
fi

mkdir -p /etc/3proxy

# ===== 写配置 =====
CFG=/etc/3proxy/3proxy.cfg
echo "" > $CFG

NODE_LIST=()

i=0
for ip in "${SELECTED_IPS[@]}"; do

    port=$base_port
    if [[ "$pmode" == "2" ]]; then
        port=$((base_port + i))
    fi

    if [[ "$umode" == "2" ]]; then
        USERNAME="u$(tr -dc a-z0-9 </dev/urandom | head -c5)"
        PASSWORD="p$(tr -dc a-z0-9 </dev/urandom | head -c8)"
    fi

    cat >> $CFG <<EOF
auth strong
users $USERNAME:CL:$PASSWORD
allow $USERNAME
socks -p$port -i$ip
EOF

    NODE_LIST+=("$ip:$port:$USERNAME:$PASSWORD")

    ((i++))
done

# ===== systemd =====
cat > /etc/systemd/system/3proxy.service <<EOF
[Unit]
Description=3proxy
After=network.target

[Service]
ExecStart=/usr/local/bin/3proxy /etc/3proxy/3proxy.cfg
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable 3proxy
systemctl restart 3proxy

# ===== 输出 =====
echo ""
echo "==== SOCKS5 节点 ===="

for n in "${NODE_LIST[@]}"; do
    echo "$n"
done

echo "${NODE_LIST[@]}" > /etc/3proxy/nodes.txt

# CSV
echo "ip,port,user,pass" > /etc/3proxy/nodes.csv
for n in "${NODE_LIST[@]}"; do
    IFS=":" read ip port user pass <<< "$n"
    echo "$ip,$port,$user,$pass" >> /etc/3proxy/nodes.csv
done

echo ""
echo "完成："
echo "/etc/3proxy/nodes.txt"
echo "/etc/3proxy/nodes.csv"
