#!/bin/bash
# 高级交互版 SOCKS5 一键搭建 (Debian12 / Ubuntu22.04+)
# Author: JsWorld
set -e

echo "==== 高级 SOCKS5 节点一键搭建 ===="

# 检查系统
if [[ ! -f /etc/debian_version ]]; then
    echo "不支持的系统，当前脚本仅适用于 Debian/Ubuntu 系列"
    exit 1
fi

# 安装依赖
echo "安装依赖..."
apt update
apt install -y wget unzip curl iproute2

# 获取服务器 IPv4
IPS=($(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '^127\.0\.0\.1$'))
echo "检测到以下 IPv4 地址："
for i in "${!IPS[@]}"; do
    echo "$i) ${IPS[$i]}"
done

# IP选择
read -p "是否为全部 IP 搭建 SOCKS5 节点？(y/n) " all_ip_choice
if [[ "$all_ip_choice" == "y" ]]; then
    SELECTED_IPS=("${IPS[@]}")
else
    echo "请输入需要搭建的 IP 编号，用空格分隔，例如 0 2 3："
    read -a indices
    SELECTED_IPS=()
    for idx in "${indices[@]}"; do
        SELECTED_IPS+=("${IPS[$idx]}")
    done
fi

# 端口策略
echo "端口设置方式："
echo "1) 所有节点相同"
echo "2) 随机递增"
echo "3) 自定义端口列表"
read -p "请选择(1/2/3): " port_choice
PORTS=()
case "$port_choice" in
1)
    read -p "请输入 SOCKS5 端口号（如1080）: " base_port
    for ((i=0;i<${#SELECTED_IPS[@]};i++)); do
        PORTS+=("$base_port")
    done
    ;;
2)
    read -p "请输入起始端口号（如1080）: " base_port
    for ((i=0;i<${#SELECTED_IPS[@]};i++)); do
        PORTS+=($((base_port + i)))
    done
    ;;
3)
    echo "请输入端口列表，用空格分隔（数量需与节点数量一致）:"
    read -a PORTS
    if [[ ${#PORTS[@]} -ne ${#SELECTED_IPS[@]} ]]; then
        echo "端口数量与节点数量不匹配！"
        exit 1
    fi
    ;;
*)
    echo "无效选择"
    exit 1
    ;;
esac

# 账号密码策略
echo "账号密码设置方式："
echo "1) 所有节点相同"
echo "2) 随机生成"
echo "3) 自定义列表"
read -p "请选择(1/2/3): " auth_choice
USERS=()
PASSWORDS=()
case "$auth_choice" in
1)
    read -p "请输入用户名: " username
    read -p "请输入密码: " password
    for ((i=0;i<${#SELECTED_IPS[@]};i++)); do
        USERS+=("$username")
        PASSWORDS+=("$password")
    done
    ;;
2)
    for ((i=0;i<${#SELECTED_IPS[@]};i++)); do
        USERS+=("u$(head /dev/urandom | tr -dc a-z0-9 | head -c4)")
        PASSWORDS+=("p$(head /dev/urandom | tr -dc a-z0-9 | head -c6)")
    done
    ;;
3)
    echo "请输入用户名列表，用空格分隔:"
    read -a USERS
    echo "请输入密码列表，用空格分隔:"
    read -a PASSWORDS
    if [[ ${#USERS[@]} -ne ${#SELECTED_IPS[@]} || ${#PASSWORDS[@]} -ne ${#SELECTED_IPS[@]} ]]; then
        echo "账号或密码数量与节点数量不匹配！"
        exit 1
    fi
    ;;
*)
    echo "无效选择"
    exit 1
    ;;
esac

# 安装 3proxy
if ! command -v 3proxy &> /dev/null; then
    echo "安装 3proxy..."
    wget -O /tmp/3proxy.zip https://github.com/z3APA3A/3proxy/archive/refs/heads/master.zip
    unzip /tmp/3proxy.zip -d /tmp/
    cd /tmp/3proxy-master
    make -f Makefile.Linux
    mkdir -p /usr/local/3proxy/bin
    cp src/3proxy /usr/local/3proxy/bin/
    mkdir -p /etc/3proxy
else
    echo "检测到 3proxy 已安装"
fi

# 生成 3proxy 配置
CONFIG_FILE="/etc/3proxy/3proxy.cfg"
echo "daemon
maxconn 2000
nserver 8.8.8.8
nserver 8.8.4.4
timeouts 1 5 30 60 180 1800 15 60
setgid 65535
setuid 65535
flush" > $CONFIG_FILE

NODE_LIST=()
for i in "${!SELECTED_IPS[@]}"; do
    ip=${SELECTED_IPS[$i]}
    port=${PORTS[$i]}
    user=${USERS[$i]}
    pass=${PASSWORDS[$i]}
    echo "auth strong" >> $CONFIG_FILE
    echo "users $user:CL:$pass" >> $CONFIG_FILE
    echo "socks -p$port -i$ip" >> $CONFIG_FILE
    NODE_LIST+=("$ip:$port:$user:$pass")
done

# 创建 systemd 服务
cat > /etc/systemd/system/3proxy.service <<EOF
[Unit]
Description=3Proxy Proxy Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/3proxy/bin/3proxy /etc/3proxy/3proxy.cfg
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable 3proxy
systemctl restart 3proxy

# 输出节点信息
echo "==== SOCKS5 节点搭建完成 ===="
echo "节点信息(host:port:user:pass)："
for node in "${NODE_LIST[@]}"; do
    echo "$node"
done

# 保存为文件
NODE_FILE="/etc/3proxy/nodes.txt"
CSV_FILE="/etc/3proxy/nodes.csv"
printf "%s\n" "${NODE_LIST[@]}" > $NODE_FILE
# 导出 CSV
echo "host,port,user,pass" > $CSV_FILE
for node in "${NODE_LIST[@]}"; do
    IFS=':' read -r h p u pw <<< "$node"
    echo "$h,$p,$u,$pw" >> $CSV_FILE
done

echo "节点信息已保存到:"
echo "$NODE_FILE"
echo "$CSV_FILE"
