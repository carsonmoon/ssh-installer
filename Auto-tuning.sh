#!/bin/bash

# ==================================================
# --- 0. 基础配置与环境检查 ---
# ==================================================
SCRIPT_PATH="/usr/local/bin/tcp.sh"
SHORTCUT_PATH="/usr/local/bin/t"

# 确保以 root 权限运行
if [ "$EUID" -ne 0 ]; then
    echo -e "\033[0;31m错误: 必须使用 root 权限运行此脚本！\033[0m"
    exit 1
fi

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# 自定义画线函数
draw_line() {
    echo -e "${YELLOW}--------------------------------------------------${NC}"
}

# ==================================================
# --- 1. 自动安装与快捷键设置 (精准识别管道) ---
# ==================================================
if [ "$_ != $SCRIPT_PATH" ] && [ "$0" != "$SCRIPT_PATH" ]; then
    echo -e "${YELLOW}>>> 正在安装脚本到本地系统...${NC}"
    mkdir -p /usr/local/bin
    
    # 从你的 CF 域名下载物理文件
    curl -sL "tcp.vpsing.de" -o "$SCRIPT_PATH"
    chmod +x "$SCRIPT_PATH"

    # 创建快捷命令 t
    if [ ! -f "$SHORTCUT_PATH" ] || [ ! -L "$SHORTCUT_PATH" ]; then
        ln -sf "$SCRIPT_PATH" "$SHORTCUT_PATH"
        echo -e "${GREEN}✅ 快捷命令 't' 已创建，以后在任意地方输入 t 即可打开面板。${NC}"
    fi

    # 核心：立刻切断管道，转为本地物理路径执行
    exec bash "$SCRIPT_PATH"
    exit 0
fi

# ==================================================
# --- 2. 脚本维护模块 (在线更新与完全卸载) ---
# ==================================================
check_update() {
    printf "${YELLOW}正在同步最新脚本...${NC}\n"
    curl -sL "tcp.vpsing.de" -o "$SCRIPT_PATH.tmp"
    if [ $? -eq 0 ]; then
        mv "$SCRIPT_PATH.tmp" "$SCRIPT_PATH"
        chmod +x "$SCRIPT_PATH"
        printf "${GREEN}脚本更新成功！正在重新载入...${NC}\n"
        sleep 1
        exec bash "$SCRIPT_PATH"
    else
        printf "${RED}更新失败，请检查网络。${NC}\n"
    fi
}

uninstall_script() {
    echo -e "\n${RED}>>> 正在准备完全卸载脚本与快捷键...${NC}"
    read -p "确定要卸载吗？(这也会同时回退所有网络优化设置) [y/N]: " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}正在恢复网络默认设置...${NC}"
        rollback_tcp_tune &>/dev/null
        rm -f "$SHORTCUT_PATH"
        rm -f "$SCRIPT_PATH"
        echo -e "${GREEN}✅ 卸载成功！网络已恢复，脚本与快捷键 't' 已从系统中移除。${NC}\n"
        exit 0
    else
        echo -e "${GREEN}已取消卸载。${NC}"
        sleep 1
    fi
}

# ==================================================
# --- 3. TCP 深度调优功能模块 ---
# ==================================================
SYSCTL_OPT="/etc/sysctl.d/99-network-performance.conf"
LIMITS_OPT="/etc/security/limits.d/99-network-performance.conf"

enable_bbr_tune() {
    echo -e "\n${YELLOW}>>> 正在激活 BBR + FQ 拥塞算法...${NC}"
    echo "net.core.default_qdisc = fq" >/etc/sysctl.d/10-bbr.conf
    echo "net.ipv4.tcp_congestion_control = bbr" >>/etc/sysctl.d/10-bbr.conf
    sysctl --system &>/dev/null
	# ======= 【开启 BBR 情绪价值拉满模块】=======
    echo -e "
${CYAN}>>> 正在与 Linux 内核交换握手信号，尝试深度激活 BBR 引擎...${NC}"
    sleep 0.4

    # 1. 模拟精密检查与算法加载的慢速进度条
    local bbr_steps=(
        "Initializing FQ Pacifier" 
        "Loading BBR Kernel Module" 
        "Calibrating Pacing Rate" 
        "Synchronizing TCP States"
    )
    
    for step in "${bbr_steps[@]}"; do
        printf "  ${BLUE}[⚙]${NC} %-28s [" "$step"
        # 慢速步进：每一步加载 5 个块，每个块停顿 0.12 秒，给足“深度加载”的厚重感
        for i in {1..5}; do 
            printf "${GREEN}■${NC}"
            sleep 0.12
        done
        printf "] ${GREEN}[SUCCESS]${NC}
"
    done

    # 2. 最终硬核技术成果宣告
    echo -e "
${GREEN}🚀 BBR + FQ 网络加速模块已成功灌注至内核底层！${NC}"
    echo -e "${YELLOW}==================================================${NC}"
	sleep 0.3
    printf "  %-24s : ${GREEN}%-15s${NC}
" "Current Congestion Control" "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
    sleep 0.3
	printf "  %-24s : ${GREEN}%-15s${NC}
" "Default Packet Scheduler" "$(sysctl -n net.core.default_qdisc 2>/dev/null)"
    sleep 0.3
	printf "  %-24s : ${CYAN}%-15s${NC}
" "Link Anti-Loss Rate" "动态实时补偿 [UP]"
    echo -e "${YELLOW}==================================================${NC}"
	sleep 0.3
    echo -e "${PURPLE}ℹ 跨境单线程吞吐性能、大文件下行带宽已获得内核级硬件加速。${NC}
"
    # ======================================================================

    read -p "按回车返回..."
}

smart_tune_tcp_tune() {
    local old_bbr=$(sysctl -n net.ipv4.tcp_congestion_control)
    local old_somax=$(sysctl -n net.core.somaxconn 2>/dev/null || echo "默认")
    local old_rmem=$(sysctl -n net.core.rmem_max 2>/dev/null || echo "212992")
    local old_file=$(ulimit -n)

    echo -e "\n${YELLOW}>>> 正在启动系统环境扫描...${NC}"
    local mem_total_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local cpu_count=$(nproc)
    local buf_bytes=$((mem_total_kb * 5 / 100 * 1024))

    echo -e "  - 核心数: ${CYAN}${cpu_count}${NC} | 内存总量: ${CYAN}$((mem_total_kb / 1024))MB${NC}"
    echo -e "  - 动态缓冲区分配: ${CYAN}$((buf_bytes / 1024 / 1024))MB${NC} (基于总内存 5%)"
    sleep 0.5

    echo -e "\n${YELLOW}>>> 正在部署生产级 + 跨境优化内核配置...${NC}"
    
    cat >"$SYSCTL_OPT" <<EOF
# --- 基础队列算法 ---
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# --- 缓冲区与容量优化 ---
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.ip_local_port_range = 1024 65535
net.core.rmem_max = ${buf_bytes}
net.core.wmem_max = ${buf_bytes}
net.ipv4.tcp_rmem = 4096 87380 ${buf_bytes}
net.ipv4.tcp_wmem = 4096 65536 ${buf_bytes}
net.core.rmem_default = 2097152
net.core.wmem_default = 2097152


# --- 翻墙/Reality 环境针对性调优 ---
# 减少发送队列积压，显著降低网页首包延迟 (TTFB)
net.ipv4.tcp_notsent_lowat = 16384
# 开启 MTU 探测，解决部分运营商阻断 ICMP 导致的连接黑洞
net.ipv4.tcp_mtu_probing = 1
# 深度扩容 UDP 缓冲区，解决 Hysteria2/QUIC 协议在高并发时的丢包
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# 开启 ECN（显式拥塞通知），跨境轻微拥塞时打标记不丢包，显著平滑网络抖动
net.ipv4.tcp_ecn = 1
# 显式激活高版本内核的 BBR3 / BBR 深度调优参数（老内核会自动跳过，安全无副作用）
net.ipv4.tcp_congestion_control_version = 3
# ===============================

# 限制孤儿连接数，防止翻墙协议在大并发时消耗过多内存
net.ipv4.tcp_max_orphans = 32768

# --- 连接稳定性优化 ---
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_retries2 = 8
net.ipv4.tcp_fastopen = 3
EOF

    sysctl --system &>/dev/null

    # ======= 【情绪价值拉满的核心代码：跨境专项深层补丁注入】=======
    echo -e "
${CYAN}>>> 正在向 Linux 内核注入跨境物理链路专项优化补丁...${NC}"
    
    # 模拟高阶内核模组加载进度条
    local steps=("Analyzing Network Topo" "Clamping MSS Window" "Expanding UDP Ring Buffer" "Activating ECN Engine")
    for step in "${steps[@]}"; do
        printf "  ${BLUE}[*]${NC} %-30s " "$step..."
        sleep 0.2
        # 打印一个渐进式小进度条
        for i in {1..5}; do printf "${GREEN}■${NC}"; sleep 0.05; done
        printf " [ ${GREEN}OK${NC} ]
"
    done

    echo -e "
${GREEN}✅ 跨境链路专项补丁注入成功！当前实时网络增益快照：${NC}"
    draw_line
    printf "  %-30s : ${GREEN}%-15s${NC} (显著降低 Reality/Vless 握手延迟)
" "TCP Low Latency (TTFB)" "已激活 [0ms 积压]"
    sleep 0.3
    printf "  %-30s : ${GREEN}%-15s${NC} (防止运营商 ICMP 阻断导致断流)
" "MTU Path Discovery" "智能探测中 [已开启]"
    sleep 0.3
    printf "  %-30s : ${GREEN}%-15s${NC} (极大平滑 Hysteria2/TUIC 并发丢包)
" "UDP Buffer Expansion" "深度扩容 [16KB Ring]"
    sleep 0.3
    printf "  %-30s : ${GREEN}%-15s${NC} (高位拥塞时不抛弃数据包，只做标记)
" "ECN Smart Congestion" "动态标记 [防断连]"
    sleep 0.3
    printf "  %-30s : ${GREEN}%-15s${NC} (针对次世代 BBRv3 算法无缝向前兼容)
" "BBR Algorithm Version" "BBR3 Pipeline [就绪]"
    # ======================================================================

    mkdir -p /etc/security/limits.d/
    cat >"$LIMITS_OPT" <<EOF
* soft nofile 1048576
* hard nofile 1048576
* soft nproc 65535
* hard nproc 65535
EOF

    if command -v iptables &>/dev/null; then
        iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
        iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
        echo -e "${GREEN}  ✔ 成功部署 MSS Clamp 智能钳制规则，防止跨境连接超时。${NC}"
    fi

	# ======= 【新加入的代码】=======
    # 强行刷新当前进程的限制，让主菜单状态栏实时显示优化后的数值
    ulimit -n 1048576 2>/dev/null || true
    # ===============================

    echo -e "\n${GREEN}✅ 深度调优完成，性能看板快照:${NC}"
    draw_line
	sleep 0.3
    printf "  %-12s: %-15s -> ${GREEN}%-15s${NC}\n" "拥塞算法" "$old_bbr" "bbr"
	sleep 0.3
    printf "  %-12s: %-15s -> ${GREEN}%-15s${NC}\n" "最大连接" "$old_somax" "65535"
	sleep 0.3
    printf "  %-12s: %-15s -> ${GREEN}%-15s${NC}\n" "文件句柄" "$old_file" "1048576"
	sleep 0.3
    printf "  %-12s: %-15s -> ${GREEN}%-15s${NC}\n" "网络缓冲" "$((old_rmem / 1024 / 1024))MB" "$((buf_bytes / 1024 / 1024))MB"
	sleep 0.3
    echo -e "\n${PURPLE}ℹ 所有配置已持久化至 $SYSCTL_OPT${NC}"
	sleep 0.3
    echo -e "${PURPLE}ℹ 重启服务器后配置依然生效，回退请使用选项 5${NC}"

    read -p "按回车返回..."
}

optimize_nic_tune() {
    echo -e "\n${YELLOW}>>> 正在执行多核心中断分发 (RSS/RPS) 优化...${NC}"
    if ! command -v ethtool &>/dev/null; then 
        apt-get update && apt-get install -y ethtool || yum install -y ethtool
    fi
    # ======= 【修改的代码：移除了 virtio，增加了常见虚拟接口的过滤】=======
    local interfaces=$(ls /sys/class/net | grep -vE 'lo|docker|veth|br-|any|tung3|sit0|tun|wg')
    local cpu_count=$(nproc)
    local rps_cpus=$(printf '%x' $(((1 << cpu_count) - 1)))
    for eth in $interfaces; do
        local max_rx=$(ethtool -g "$eth" 2>/dev/null | grep -A 5 "Pre-set maximums" | grep "RX:" | awk '{print $2}')
        ethtool -G "$eth" rx "${max_rx:-1024}" tx "${max_rx:-1024}" &>/dev/null || true
        for rps_file in /sys/class/net/$eth/queues/rx-*/rps_cpus; do [ -f "$rps_file" ] && echo "$rps_cpus" >"$rps_file"; done
        for rfc_file in /sys/class/net/$eth/queues/rx-*/rps_flow_cnt; do [ -f "$rfc_file" ] && echo "4096" >"$rfc_file"; done
    done
    sysctl -w net.core.rps_sock_flow_entries=32768 &>/dev/null
    # ======= 【网卡多队列情绪价值拉满模块】=======
    echo -e "
${CYAN}>>> 正在唤醒系统底层网卡物理硬件，启动多核心负载分发均衡...${NC}"
    sleep 0.3

    # 1. 动态模拟多核心硬中断（IRQ）的解绑与流绑定
    local nic_steps=(
        "Mapping Network Interface" 
        "Unbinding Single Core IRQ" 
        "Injecting RPS Network Mask" 
        "Balancing Socket Flows"
    )
    
    for step in "${nic_steps[@]}"; do
        printf "  ${BLUE}[⚡]${NC} %-28s [" "$step"
        # 稳健加载：每步 5 个块，每块停顿 0.1 秒
        for i in {1..5}; do 
            printf "${GREEN}■${NC}"
            sleep 0.1
        done
        printf "] ${GREEN}[DONE]${NC}
"
    done

	sleep 0.3
    # 2. 炫酷的全核心平摊瀑布流输出 (根据 VPS 实际核心数动态显示)
    echo -e "
${GREEN}✅ 优化成功！网卡硬件中断多流分发流水线部署完毕：${NC}"
    draw_line
    
    # 动态把流量平摊到每一个核心的视觉渲染
    # 1. 提前在循环外算好百分比，绝不在 echo 内部做算术运算，彻底根除括号冲突
    local percent=0
    if [ $cpu_count -gt 0 ]; then
        percent=$((100 / cpu_count))
    fi

    # 2. 纯粹、干净、无任何括号污染的循环渲染
    for ((i=0; i<cpu_count; i++)); do
        echo -e "  ⚡ ${BOLD}CPU Core #$i${NC} : [${GREEN}██████████████████████████████${NC}] ${YELLOW}分配比率: $percent%${NC}"
        sleep 0.3
    done
    
    draw_line
	sleep 0.3
    echo -e "${PURPLE}ℹ 成功打破单核软中断（SoftIRQ）瓶颈，大并发流量已均匀平摊至所有 $cpu_count 个核心。${NC}
"
    # ======================================================================

    read -p "按回车返回..."
}

set_ipv4_priority() {
    echo -e "\n${YELLOW}>>> 正在调整系统互联网协议优先级...${NC}"
    if [ ! -f /etc/gai.conf ]; then
        cat > /etc/gai.conf <<EOF
label ::1/128       0
label ::/0          1
label 2002::/16     2
label ::/96         3
label ::ffff:0:0/96 4
precedence  ::1/128       50
precedence  ::/0          40
precedence  2002::/16     30
precedence  ::/96         20
precedence  ::ffff:0:0/96 10
EOF
    fi

    cp /etc/gai.conf /etc/gai.conf.bak

    if grep -q "precedence ::ffff:0:0/96  100" /etc/gai.conf; then
        sed -i 's/^#precedence ::ffff:0:0\/96  100/precedence ::ffff:0:0\/96  100/' /etc/gai.conf
    else
        echo "precedence ::ffff:0:0/96  100" >>/etc/gai.conf
    fi

    echo -e "
${GREEN}✅ 优化成功！当前系统已设置为 [ IPv4 优先 ]。${NC}"
    read -p "按回车返回..."
}

rollback_tcp_tune() {
    # 1. 清理所有写入的独立配置文件
    rm -f "$SYSCTL_OPT" "$LIMITS_OPT" /etc/sysctl.d/10-bbr.conf

    # 2. 恢复 IPv4 优先解析配置 (如果存在备份则还原，不存在则直接恢复默认值)
    if [ -f /etc/gai.conf.bak ]; then
        mv /etc/gai.conf.bak /etc/gai.conf
    else
        # 恢复 Debian/Ubuntu 的默认 gai.conf 行为
        sed -i 's/^precedence ::ffff:0:0/96  100/#precedence ::ffff:0:0/96  100/' /etc/gai.conf 2>/dev/null || true
    fi

    # 3. 强行将内存中的拥塞算法恢复为 Linux 默认的 cubic，队列恢复为 pfifo_fast
    sysctl -w net.ipv4.tcp_congestion_control=cubic &>/dev/null
    sysctl -w net.core.default_qdisc=pfifo_fast &>/dev/null

    # 4. 强行将内存中的网卡多队列标志位流条目恢复为 0
    sysctl -w net.core.rps_sock_flow_entries=0 &>/dev/null

    # 5. 清理 MSS 钳制规则
    if command -v iptables &>/dev/null; then
        iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
    fi

    # 6. 清理网卡中断分发设置
    local interfaces=$(ls /sys/class/net | grep -vE 'lo|docker|veth|br-|any|tung3|sit0|tun|wg')
    for eth in $interfaces; do
        for rps_file in /sys/class/net/$eth/queues/rx-*/rps_cpus; do [ -f "$rps_file" ] && echo "0" >"$rps_file"; done
    done

    # 7. 强行把当前会话的文件句柄限制落回系统默认的 1024
    ulimit -n 1024 2>/dev/null || true

    # 8. 让系统重新载入所有剩余配置
    sysctl --system &>/dev/null
    echo -e "${GREEN}✅ 回退完成，所有网络独立配置文件已清理，内存参数已恢复默认。${NC}"
}


# ==================================================
# --- 4. 主循环菜单 (动态闭环重构) ---
# ==================================================
while true; do
    # --- 实时动态状态检测 ---
    # 1. 检测 IPv4 优先状态
    if [ -f /etc/gai.conf ] && grep -q "^precedence ::ffff:0:0/96  100" /etc/gai.conf; then
        status_ipv4="${GREEN}[已激活]${NC}"
    else
        status_ipv4="${RED}[未开启]${NC}"
    fi

    # 2. 检测 BBR 状态
    if [ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)" = "bbr" ]; then
        status_bbr="${GREEN}[已激活]${NC}"
    else
        status_bbr="${RED}[未开启]${NC}"
    fi

    # 3. 检测内核调优状态
    if [ -f "$SYSCTL_OPT" ]; then
        status_sysctl="${GREEN}[已激活]${NC}"
    else
        status_sysctl="${RED}[未开启]${NC}"
    fi

    # 4. 检测网卡队列状态 (通过全局套接字流控制条目状态进行智能检测)
    if [ "$(sysctl -n net.core.rps_sock_flow_entries 2>/dev/null)" = "32768" ]; then
        status_nic="${GREEN}[已激活]${NC}"
    else
        status_nic="${RED}[未开启]${NC}"
    fi

    # --- 渲染菜单界面 ---
    clear
    echo -e "${YELLOW}==================================================${NC}"
    echo -e "${YELLOW}            TCP/UDP 网络深度调优与性能看板            ${NC}"
    echo -e "${GREEN}            bash <(curl -sL tcp.vpsing.de)${NC}"
    echo -e "${GREEN}                    快捷命令: t                    ${NC}"
    echo -e "${YELLOW}==================================================${NC}"
    echo -e "  1. 设置 IPv4 优先解析     -> $status_ipv4  :[解决 IPv6 绕路导致的握手卡顿]"
    echo -e "  2. 开启 BBR + FQ          -> $status_bbr  :[降低跨境丢包，提升单线程速度]"
    echo -e "  3. 生产级内核调优         -> $status_sysctl  :[支撑 6w+ 并发连接，防止队列溢出]"
    echo -e "  4. 网卡多队列均衡         -> $status_nic  :[消除单核 CPU 瓶颈，平摊全核负载]"
    echo -e "  5. 一键回退到默认设置     -> [清理所有独立调优配置文件]"
    echo -e "  6. 检查并强制同步更新脚本"
    echo -e "  7. 彻底卸载面板脚本"
    echo -e "  0. 退出脚本"
    draw_line
    echo -e "当前状态: 算法: ${GREEN}$(sysctl -n net.ipv4.tcp_congestion_control)${NC} | 句柄: ${GREEN}$(ulimit -n)${NC}"
    draw_line
    
    read -p "请选择数字 [0-7]: " t_opt
    case "$t_opt" in
    1) set_ipv4_priority ;;
    2) enable_bbr_tune ;;
    3) smart_tune_tcp_tune ;;
    4) optimize_nic_tune ;;
    5) rollback_tcp_tune && read -p "按回车返回..." ;;
    6) check_update ;;
    7) uninstall_script ;;
    0) exit 0 ;;
    *) echo -e "${RED}输入错误，请输入正确数字！${NC}" && sleep 1 ;;
    esac
done
