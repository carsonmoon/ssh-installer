#!/bin/bash

CADDYFILE="/etc/caddy/Caddyfile"

get_server_ip(){

IPV4=$(curl -4 -s --max-time 3 https://api.ipify.org)
IPV6=$(curl -6 -s --max-time 3 https://api64.ipify.org)

echo "服务器IP信息:"
echo "IPv4: ${IPV4:-无}"
echo "IPv6: ${IPV6:-无}"

}

check_dns(){

read -p "输入域名: " DOMAIN

A_RECORD=$(dig +short A $DOMAIN | head -n1)
AAAA_RECORD=$(dig +short AAAA $DOMAIN | head -n1)

echo ""
echo "DNS解析结果:"
echo "A记录: ${A_RECORD:-无}"
echo "AAAA记录: ${AAAA_RECORD:-无}"
echo ""

}

check_ipv6_connect(){

echo "检测 IPv6 外网连通性..."

IPV6=$(curl -6 -s https://api64.ipify.org)

if [ -z "$IPV6" ]; then
echo "未检测到 IPv6"
return
fi

echo "IPv6地址: $IPV6"

PING_RESULT=$(ping6 -c 2 ipv6.google.com 2>/dev/null)

if [ $? -eq 0 ]; then
echo "IPv6 网络正常"
else
echo "IPv6 可能被屏蔽"
fi

}

open_firewall(){

echo "开放 80 / 443 端口"

if command -v ufw >/dev/null 2>&1; then

ufw allow 80/tcp
ufw allow 443/tcp
ufw reload

elif systemctl is-active firewalld >/dev/null 2>&1; then

firewall-cmd --permanent --add-port=80/tcp
firewall-cmd --permanent --add-port=443/tcp
firewall-cmd --reload

else

iptables -I INPUT -p tcp --dport 80 -j ACCEPT
iptables -I INPUT -p tcp --dport 443 -j ACCEPT

fi

}

install_caddy(){

echo "安装 Caddy..."

apt update
apt install -y debian-keyring debian-archive-keyring apt-transport-https curl gnupg dnsutils

curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
| gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg

curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
| tee /etc/apt/sources.list.d/caddy-stable.list

apt update
apt install -y caddy

systemctl enable caddy
systemctl start caddy

open_firewall

echo "Caddy 安装完成"

}

add_reverse_proxy(){

read -p "输入域名: " DOMAIN
read -p "输入反代端口: " PORT

cat >> $CADDYFILE <<EOF

$DOMAIN {

    encode gzip
    reverse_proxy localhost:$PORT

}
EOF

systemctl reload caddy

echo ""
echo "反代创建成功"
echo "访问: https://$DOMAIN"

}

add_static_site(){

read -p "输入域名: " DOMAIN

SITE_DIR="/var/www/$DOMAIN"

mkdir -p $SITE_DIR

echo "<h1>$DOMAIN</h1>" > $SITE_DIR/index.html

cat >> $CADDYFILE <<EOF

$DOMAIN {

    root * $SITE_DIR
    file_server

}
EOF

systemctl reload caddy

echo "网站目录:"
echo $SITE_DIR

}

delete_site(){

read -p "输入要删除的域名: " DOMAIN

sed -i "/$DOMAIN {/,/}/d" $CADDYFILE

systemctl reload caddy

echo "站点删除完成"

}

show_sites(){

echo ""
echo "当前 Caddy 配置:"
echo "----------------"
cat $CADDYFILE
echo "----------------"

}

reload_caddy(){

systemctl reload caddy
echo "Caddy 已重载"

}

menu(){

echo ""
echo "====== Caddy IPv6 管理工具 ======"
echo "1 查看服务器IP"
echo "2 检测域名解析"
echo "3 检测IPv6网络"
echo "4 安装 Caddy"
echo "5 添加反向代理"
echo "6 部署静态网站"
echo "7 删除站点"
echo "8 查看配置"
echo "9 重载 Caddy"
echo "0 退出"
echo ""

read -p "选择: " NUM

case $NUM in

1) get_server_ip ;;
2) check_dns ;;
3) check_ipv6_connect ;;
4) install_caddy ;;
5) add_reverse_proxy ;;
6) add_static_site ;;
7) delete_site ;;
8) show_sites ;;
9) reload_caddy ;;
0) exit ;;
*) echo "输入错误" ;;

esac

}

while true
do
menu
done
