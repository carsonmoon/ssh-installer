#!/usr/bin/env bash

# 解决 curl | bash 没有交互输入的问题
if [ ! -t 0 ]; then
exec < /dev/tty
fi

CADDYFILE="/etc/caddy/Caddyfile"

check_root(){
if [ "$EUID" -ne 0 ]; then
echo "请使用 root 运行"
exit
fi
}

get_server_ip(){

echo "服务器IP信息："

IPV4=$(curl -4 -s https://api.ipify.org)
IPV6=$(curl -6 -s https://api64.ipify.org)

echo "IPv4: ${IPV4:-无}"
echo "IPv6: ${IPV6:-无}"

}

check_domain(){

read -p "输入要检测的域名: " DOMAIN

echo "检测 DNS 解析..."

dig +short $DOMAIN

}

check_ipv6(){

echo "检测 IPv6 网络..."

curl -6 ip.sb

}

install_caddy(){

echo "开始安装 Caddy..."

apt update
apt install -y curl gnupg

curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
| gpg --dearmor -o /usr/share/keyrings/caddy.gpg

curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
| tee /etc/apt/sources.list.d/caddy.list

apt update
apt install -y caddy

systemctl enable caddy
systemctl start caddy

echo "Caddy 安装完成"

}

add_reverse_proxy(){

read -p "输入域名: " DOMAIN
read -p "输入反代端口: " PORT

cat >> $CADDYFILE <<EOF

$DOMAIN {

reverse_proxy localhost:$PORT

}
EOF

systemctl reload caddy

echo "反向代理创建完成"

}

deploy_static(){

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

echo "静态站点部署完成"

}

create_reality(){

read -p "输入伪装域名: " DOMAIN

SITE_DIR="/var/www/$DOMAIN"

mkdir -p $SITE_DIR

cat > $SITE_DIR/index.html <<EOF
<h1>$DOMAIN</h1>
<p>Service running</p>
EOF

cat >> $CADDYFILE <<EOF

$DOMAIN {

root * $SITE_DIR
file_server

}
EOF

systemctl reload caddy

echo "Reality 伪装站创建完成"

}

delete_site(){

read -p "输入要删除的域名: " DOMAIN

sed -i "/$DOMAIN {/,/}/d" $CADDYFILE

systemctl reload caddy

echo "站点删除完成"

}

show_config(){

cat $CADDYFILE

}

reload_caddy(){

systemctl reload caddy
echo "Caddy 已重载"

}

menu(){

echo ""
echo "====== Caddy 管理工具 ======"
echo "1 查看服务器IP"
echo "2 检测域名解析"
echo "3 检测IPv6网络"
echo "4 安装 Caddy"
echo "5 添加反向代理"
echo "6 部署静态网站"
echo "7 创建 Reality 伪装站"
echo "8 删除站点"
echo "9 查看配置"
echo "10 重载 Caddy"
echo "0 退出"
echo ""

}

main(){

check_root

while true
do

menu

read -p "选择: " NUM

case $NUM in

1) get_server_ip ;;
2) check_domain ;;
3) check_ipv6 ;;
4) install_caddy ;;
5) add_reverse_proxy ;;
6) deploy_static ;;
7) create_reality ;;
8) delete_site ;;
9) show_config ;;
10) reload_caddy ;;
0) exit ;;
*) echo "输入错误" ;;

esac

done

}

main
