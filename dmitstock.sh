#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_NAME="dmitbox.sh"
AD_TEXT="欢迎加入DMIT交流群 https://t.me/DmitChat"

# managed files
TUNE_SYSCTL_FILE="/etc/sysctl.d/99-dmit-tcp-tune.conf"
DMIT_TCP_DEFAULT_FILE="/etc/sysctl.d/99-dmit-tcp-dmitdefault.conf"
IPV6_SYSCTL_FILE="/etc/sysctl.d/99-dmit-ipv6.conf"
GAI_CONF="/etc/gai.conf"
BACKUP_BASE="/root/dmit-backup"

# MTU persistent via systemd
MTU_SERVICE="/etc/systemd/system/dmit-mtu.service"
MTU_VALUE_FILE="/etc/dmit-mtu.conf"

# DNS backup
RESOLV_BACKUP="${BACKUP_BASE}/resolv.conf.orig"

# SSH backup & drop-in
SSH_ORIG_TGZ="${BACKUP_BASE}/ssh-orig.tgz"
SSH_DROPIN_DIR="/etc/ssh/sshd_config.d"
SSH_DROPIN_FILE="${SSH_DROPIN_DIR}/99-dmitbox.conf"

RUN_MODE="${RUN_MODE:-menu}" # menu | cli

# colors (no red)
c_reset="\033[0m"
c_dim="\033[2m"
c_bold="\033[1m"
c_green="\033[32m"
c_yellow="\033[33m"
c_cyan="\033[36m"
c_white="\033[37m"

ok()   { echo -e "${c_green}✔${c_reset} $*"; }
info() { echo -e "${c_cyan}➜${c_reset} $*"; }
warn() { echo -e "${c_yellow}⚠${c_reset} $*"; }

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    warn "请用 root 运行：sudo bash ${SCRIPT_NAME}"
    exit 1
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }
ts_now() { date +"%Y%m%d-%H%M%S"; }
ensure_dir() { mkdir -p "$1"; }

has_tty() { [[ -r /dev/tty ]]; }

read_tty() {
  # read_tty VAR "prompt" "default"
  local __var="$1" __prompt="$2" __default="${3:-}"
  local __val=""
  if has_tty; then
    read -r -p "$__prompt" __val </dev/tty || true
  else
    read -r -p "$__prompt" __val || true
  fi
  __val="${__val:-$__default}"
  printf -v "$__var" "%s" "$__val"
}

read_tty_secret() {
  # read_tty_secret VAR "prompt"
  local __var="$1" __prompt="$2"
  local __val=""
  if has_tty; then
    read -r -s -p "$__prompt" __val </dev/tty || true
    echo >&2 || true
  else
    read -r -s -p "$__prompt" __val || true
    echo >&2 || true
  fi
  printf -v "$__var" "%s" "$__val"
}

soft_clear() {
  # 先“全清屏”，再光标归位，兼容性更好
  # - 清空回滚：尽力（部分终端不支持 3J）
  # - 无 clear 命令也能工作
  printf "\033[2J\033[H" 2>/dev/null || true
  printf "\033[3J" 2>/dev/null || true
  if have_cmd clear; then clear >/dev/null 2>&1 || true; fi
}

pause_if_menu() {
  if [[ "$RUN_MODE" == "menu" ]]; then
    echo
    if has_tty; then
      read -r -p "↩ 回车返回工具箱..." _ </dev/tty || true
    else
      read -r -p "↩ 回车返回工具箱..." _ || true
    fi
    # 按回车后：先清屏，再回到主菜单
    soft_clear
  fi
}

write_file() {
  local path="$1"
  local content="$2"
  umask 022
  mkdir -p "$(dirname "$path")"
  printf "%s\n" "$content" > "$path"
}

sysctl_apply_all() { sysctl --system >/dev/null 2>&1 || true; }

# ---------------- pkg helper ----------------
pkg_install() {
  local pkgs=("$@")
  [[ "${#pkgs[@]}" -eq 0 ]] && return 0

  if have_cmd apt-get; then
    DEBIAN_FRONTEND=noninteractive apt-get -qq update >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get -y install "${pkgs[@]}" >/dev/null 2>&1 || true
    return 0
  fi
  if have_cmd dnf; then dnf -y install "${pkgs[@]}" >/dev/null 2>&1 || true; return 0; fi
  if have_cmd yum; then yum -y install "${pkgs[@]}" >/dev/null 2>&1 || true; return 0; fi
  if have_cmd apk; then apk add --no-cache "${pkgs[@]}" >/dev/null 2>&1 || true; return 0; fi

  warn "未识别包管理器：请手动安装 ${pkgs[*]}"
}

# ---------------- helpers ----------------
default_iface() {
  local ifc=""
  ifc="$(ip -4 route 2>/dev/null | awk '/^default/{print $5; exit}' || true)"
  [[ -n "$ifc" ]] && { echo "$ifc"; return 0; }
  ifc="$(ip -6 route 2>/dev/null | awk '/^default/{print $5; exit}' || true)"
  [[ -n "$ifc" ]] && { echo "$ifc"; return 0; }
  echo "eth0"
}

ipv6_status() {
  local a d
  a="$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo "N/A")"
  d="$(sysctl -n net.ipv6.conf.default.disable_ipv6 2>/dev/null || echo "N/A")"
  echo "all=$a default=$d"
}

has_ipv6_global_addr() { ip -6 addr show scope global 2>/dev/null | grep -q "inet6 "; }
has_ipv6_default_route() { ip -6 route show default 2>/dev/null | grep -q "^default "; }

libc_kind() {
  if have_cmd getconf && getconf GNU_LIBC_VERSION >/dev/null 2>&1; then echo "glibc"; return 0; fi
  if have_cmd ldd && ldd --version 2>&1 | head -n 1 | grep -qi musl; then echo "musl"; return 0; fi
  if have_cmd ldd && ldd --version 2>&1 | grep -qi "glibc"; then echo "glibc"; return 0; fi
  echo "unknown"
}

is_systemd() { have_cmd systemctl; }
is_resolved_active() { is_systemd && systemctl is-active --quiet systemd-resolved 2>/dev/null; }

curl4_ok() { have_cmd curl && curl -4 -sS --max-time 5 https://ip.sb >/dev/null 2>&1; }
curl6_ok() { have_cmd curl && curl -6 -sS --max-time 5 https://ip.sb >/dev/null 2>&1; }

dns_resolve_ok() {
  if have_cmd getent; then getent hosts ip.sb >/dev/null 2>&1 && return 0; fi
  have_cmd curl && curl -sS --max-time 5 https://ip.sb >/dev/null 2>&1
}

# ---------------- banner ----------------
banner() {
  soft_clear
  echo -e "${c_bold}${c_white}DMIT 工具箱${c_reset}  ${c_dim}(${SCRIPT_NAME})${c_reset}"
  echo -e "${c_green}${AD_TEXT}${c_reset}"
  echo -e "${c_dim}----------------------------------------------${c_reset}"
}

# ---------------- 环境快照 ----------------
env_snapshot() {
  ensure_dir "$BACKUP_BASE"
  local bdir="${BACKUP_BASE}/snapshot-$(ts_now)"
  ensure_dir "$bdir"
  info "环境快照 → ${bdir}"

  for p in /etc/sysctl.conf /etc/sysctl.d /etc/gai.conf /etc/modprobe.d /etc/default/grub /etc/network /etc/netplan /etc/systemd/network /etc/resolv.conf /etc/ssh/sshd_config /etc/ssh/sshd_config.d; do
    if [[ -e "$p" ]]; then
      mkdir -p "${bdir}$(dirname "$p")"
      cp -a "$p" "${bdir}${p}" 2>/dev/null || true
    fi
  done

  {
    echo "time=$(date)"
    echo "uname=$(uname -a)"
    echo "libc=$(libc_kind)"
    echo "iface=$(default_iface)"
    echo "timezone=$( (timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || true) )"
    echo "ipv6_sysctl=$(ipv6_status)"
    echo
    echo "== ip -br a =="; ip -br a 2>/dev/null || true
    echo
    echo "== ip -4 route =="; ip -4 route 2>/dev/null || true
    echo
    echo "== ip -6 addr =="; ip -6 addr show 2>/dev/null || true
    echo
    echo "== ip -6 route =="; ip -6 route show 2>/dev/null || true
    echo
    echo "== resolv.conf =="; sed -n '1,80p' /etc/resolv.conf 2>/dev/null || true
    echo
    echo "== qdisc =="; tc qdisc show 2>/dev/null || true
    echo
    echo "== bbr =="; cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null || true
    echo
    echo "== sshd -T (if available) =="; (sshd -T 2>/dev/null | sed -n '1,180p' || true)
  } > "${bdir}/state.txt"

  ok "已保存：${bdir}"
  echo "查看：less -S ${bdir}/state.txt"
}

# ---------------- 时区：中国 ----------------
set_timezone_china() {
  info "时区：设置为中国（Asia/Shanghai）"
  pkg_install tzdata

  if have_cmd timedatectl; then
    timedatectl set-timezone Asia/Shanghai >/dev/null 2>&1 || true
  fi

  if [[ -e /usr/share/zoneinfo/Asia/Shanghai ]]; then
    ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime || true
    echo "Asia/Shanghai" > /etc/timezone 2>/dev/null || true
  fi

  local tz
  tz="$( (timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo "unknown") )"
  ok "当前时区：$tz"
}

# ---------------- 重启网络服务 ----------------
restart_network_services_best_effort() {
  if ! is_systemd; then
    warn "无 systemd：跳过网络服务重启"
    return 0
  fi

  local restarted=0
  if systemctl is-active --quiet systemd-networkd 2>/dev/null; then
    info "重启：systemd-networkd"
    systemctl restart systemd-networkd >/dev/null 2>&1 || true
    restarted=1
  fi
  if systemctl is-active --quiet NetworkManager 2>/dev/null; then
    info "重启：NetworkManager"
    systemctl restart NetworkManager >/dev/null 2>&1 || true
    restarted=1
  fi
  if systemctl is-active --quiet networking 2>/dev/null; then
    info "重启：networking"
    systemctl restart networking >/dev/null 2>&1 || true
    restarted=1
  fi

  if [[ "$restarted" -eq 0 ]]; then
    info "尝试重启常见网络服务（忽略错误）"
    systemctl restart networking >/dev/null 2>&1 || true
    systemctl restart systemd-networkd >/dev/null 2>&1 || true
    systemctl restart NetworkManager >/dev/null 2>&1 || true
  fi
}

# ---------------- IPv6 开关 ----------------
ipv6_disable() {
  info "IPv6：关闭（系统级禁用）"
  write_file "$IPV6_SYSCTL_FILE" \
"net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1"
  sysctl_apply_all
  ok "IPv6 已关闭（sysctl: $(ipv6_status)）"
}

_ipv6_enable_runtime_all_ifaces() {
  for f in /proc/sys/net/ipv6/conf/*/disable_ipv6; do
    [[ -e "$f" ]] || continue
    echo 0 > "$f" 2>/dev/null || true
  done
}

_ipv6_find_disable_sources() {
  echo -e "${c_yellow}${c_bold}--- IPv6 开启失败排查 ---${c_reset}"
  echo -e "${c_dim}[启动参数]${c_reset} $(cat /proc/cmdline 2>/dev/null || true)"
  if grep -qw "ipv6.disable=1" /proc/cmdline 2>/dev/null; then
    warn "发现 ipv6.disable=1：必须改 GRUB/引导并重启"
  fi
  echo
  echo -e "${c_dim}[sysctl 覆盖]${c_reset}"
  (grep -RIn --line-number -E 'net\.ipv6\.conf\.(all|default|lo)\.disable_ipv6\s*=\s*1' \
    /etc/sysctl.conf /etc/sysctl.d 2>/dev/null || true) | sed -n '1,140p'
  echo
  echo -e "${c_dim}[模块黑名单]${c_reset}"
  (grep -RIn --line-number -E '^\s*blacklist\s+ipv6|^\s*install\s+ipv6\s+/bin/true' \
    /etc/modprobe.d 2>/dev/null || true) | sed -n '1,140p'
  echo -e "${c_yellow}${c_bold}------------------------${c_reset}"
}

ipv6_enable() {
  info "IPv6：开启（自动重拉地址/默认路由）"

  rm -f "$IPV6_SYSCTL_FILE" || true

  if have_cmd modprobe; then
    modprobe ipv6 >/dev/null 2>&1 || true
  fi

  sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true
  sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null 2>&1 || true
  sysctl -w net.ipv6.conf.lo.disable_ipv6=0 >/dev/null 2>&1 || true
  _ipv6_enable_runtime_all_ifaces
  sysctl_apply_all

  restart_network_services_best_effort
  sleep 2
  _ipv6_enable_runtime_all_ifaces

  local st; st="$(ipv6_status)"

  echo -e "${c_dim}--- IPv6 状态快照 ---${c_reset}"
  echo -e "${c_dim}sysctl:${c_reset} $st"
  echo -e "${c_dim}地址:${c_reset}"
  ip -6 addr show 2>/dev/null || true
  echo -e "${c_dim}路由:${c_reset}"
  ip -6 route show 2>/dev/null || true
  echo -e "${c_dim}---------------------${c_reset}"

  if echo "$st" | grep -q "all=0" && echo "$st" | grep -q "default=0" \
     && has_ipv6_global_addr && has_ipv6_default_route; then
    ok "IPv6 已可用（有公网 IPv6 + 默认路由）"
  else
    warn "IPv6 未完整（缺公网 IPv6 或默认路由）"
    warn "如果 DMIT 面板未分配 IPv6，本机不会凭空生成公网 IPv6"
    _ipv6_find_disable_sources
  fi
}

# ---------------- IPv4/IPv6 优先级（glibc） ----------------
gai_backup_once() {
  ensure_dir "$BACKUP_BASE"
  if [[ -f "$GAI_CONF" ]] && [[ ! -f "${BACKUP_BASE}/gai.conf.orig" ]]; then
    cp -a "$GAI_CONF" "${BACKUP_BASE}/gai.conf.orig" || true
    ok "已备份 gai.conf.orig"
  fi
}

prefer_ipv4() {
  info "网络：优先 IPv4（系统解析优先级）"
  local kind; kind="$(libc_kind)"
  if [[ "$kind" != "glibc" ]]; then
    warn "非 glibc：此方式无效（Alpine/musl 常见），可用：关闭 IPv6 或应用层 -4"
    return 0
  fi
  gai_backup_once
  touch "$GAI_CONF"
  sed -i '/^\s*precedence\s\+::ffff:0:0\/96\s\+[0-9]\+\s*$/d' "$GAI_CONF"
  printf "\n# %s managed: prefer IPv4\nprecedence ::ffff:0:0/96  100\n" "$SCRIPT_NAME" >> "$GAI_CONF"
  ok "已设置：IPv4 优先"
}

prefer_ipv6() {
  info "网络：优先 IPv6（恢复默认倾向）"
  local kind; kind="$(libc_kind)"
  if [[ "$kind" != "glibc" ]]; then
    warn "非 glibc：此方式无效；要更强制 IPv6：确保 IPv6 可用，并应用层 -6"
    return 0
  fi
  gai_backup_once
  touch "$GAI_CONF"
  sed -i '/^\s*#\s*'"${SCRIPT_NAME}"'\s*managed: prefer IPv4\s*$/d' "$GAI_CONF" || true
  sed -i '/^\s*precedence\s\+::ffff:0:0\/96\s\+[0-9]\+\s*$/d' "$GAI_CONF" || true
  ok "已恢复：IPv6 倾向（默认）"
}

restore_gai_default() {
  info "网络：恢复 gai.conf（回到备份状态）"
  if [[ -f "${BACKUP_BASE}/gai.conf.orig" ]]; then
    cp -a "${BACKUP_BASE}/gai.conf.orig" "$GAI_CONF" || true
    ok "已恢复 gai.conf.orig"
  else
    warn "未找到 gai.conf.orig：改为移除脚本写入规则"
    prefer_ipv6 || true
  fi
}

# ---------------- BBR / TCP ----------------
bbr_check() {
  echo "================ BBR 检测 ================"
  echo "kernel=$(uname -r)"
  local avail cur
  avail="$(cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null || echo "")"
  cur="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "N/A")"
  echo "当前=${cur}"
  echo "可用=${avail:-N/A}"
  if echo " $avail " | grep -q " bbr "; then
    ok "支持 bbr（实现取决于内核）"
  else
    warn "未看到 bbr（可能内核不含/模块不可用）"
  fi
  echo "=========================================="
}

tcp_tune_apply() {
  info "TCP：通用调优（BBR + FQ + 常用参数）"
  have_cmd modprobe && modprobe tcp_bbr >/dev/null 2>&1 || true

  rm -f "$DMIT_TCP_DEFAULT_FILE" >/dev/null 2>&1 || true

  write_file "$TUNE_SYSCTL_FILE" \
"net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr

net.core.netdev_max_backlog=16384
net.core.somaxconn=8192
net.ipv4.tcp_max_syn_backlog=8192

net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864

net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_syncookies=1"
  sysctl_apply_all
  ok "已应用 TCP 通用调优"
  bbr_check
}

tcp_restore_default() {
  info "TCP：恢复 Linux 默认（CUBIC + pfifo_fast）"
  rm -f "$TUNE_SYSCTL_FILE" "$DMIT_TCP_DEFAULT_FILE" >/dev/null 2>&1 || true
  sysctl -w net.core.default_qdisc=pfifo_fast >/dev/null 2>&1 || true
  sysctl -w net.ipv4.tcp_congestion_control=cubic >/dev/null 2>&1 || true
  sysctl_apply_all
  ok "已恢复 TCP 默认"
}

tcp_restore_dmit_default() {
  info "TCP：恢复 DMIT 默认 TCP"
  rm -f "$TUNE_SYSCTL_FILE" >/dev/null 2>&1 || true

  write_file "$DMIT_TCP_DEFAULT_FILE" \
"net.core.rmem_max = 67108848
net.core.wmem_max = 67108848
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_rmem = 16384 16777216 536870912
net.ipv4.tcp_wmem = 16384 16777216 536870912
net.ipv4.tcp_adv_win_scale = -2
net.ipv4.tcp_sack = 1
net.ipv4.tcp_timestamps = 1
kernel.panic = -1
vm.swappiness = 0"
  sysctl_apply_all
  ok "已应用 DMIT 默认 TCP 参数"
  bbr_check
}

os_id_like() {
  if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    echo "${ID:-unknown}|${ID_LIKE:-}"
  else
    echo "unknown|"
  fi
}

bbrv3_install_xanmod() {
  local arch; arch="$(uname -m)"
  if [[ "$arch" != "x86_64" ]]; then
    warn "BBRv3（XanMod）仅建议 x86_64 使用。当前：$arch"
    return 1
  fi

  local ids; ids="$(os_id_like)"
  if ! echo "$ids" | grep -Eqi 'debian|ubuntu|kali'; then
    warn "当前系统不像 Debian/Ubuntu/Kali：此安装方式不适用"
    return 1
  fi

  warn "将安装 XanMod 内核（包含 BBRv3），需要重启生效"
  warn "有 DKMS/驱动的机器请谨慎"

  local ans=""
  read_tty ans "确认继续请输入 YES > " ""
  if [[ "$ans" != "YES" ]]; then
    warn "已取消"
    return 0
  fi

  pkg_install wget gpg ca-certificates lsb-release apt-transport-https

  local psabi="x86-64-v3"
  local out=""
  out="$(wget -qO- https://dl.xanmod.org/check_x86-64_psabi.sh | bash 2>/dev/null || true)"
  if echo "$out" | grep -q "x86-64-v1"; then psabi="x86-64-v1"; fi
  if echo "$out" | grep -q "x86-64-v2"; then psabi="x86-64-v2"; fi
  if echo "$out" | grep -q "x86-64-v3"; then psabi="x86-64-v3"; fi
  info "CPU 指令集等级：${psabi}"

  wget -qO /tmp/xanmod.gpg https://dl.xanmod.org/gpg.key
  gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg /tmp/xanmod.gpg >/dev/null 2>&1 || true

  local codename=""
  codename="$(lsb_release -sc 2>/dev/null || true)"
  if [[ -z "$codename" && -r /etc/os-release ]]; then
    . /etc/os-release
    codename="${VERSION_CODENAME:-}"
  fi
  [[ -z "$codename" ]] && codename="stable"

  write_file /etc/apt/sources.list.d/xanmod-release.list \
"deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org ${codename} main"

  apt-get -qq update >/dev/null 2>&1 || true

  local pkg="linux-xanmod-x64v3"
  case "$psabi" in
    x86-64-v1) pkg="linux-xanmod-x64v1" ;;
    x86-64-v2) pkg="linux-xanmod-x64v2" ;;
    x86-64-v3) pkg="linux-xanmod-x64v3" ;;
  esac

  info "安装内核包：${pkg}"
  apt-get -y install "${pkg}" >/dev/null 2>&1 || true

  ok "XanMod 内核已安装（需重启生效）"
  local rb=""
  read_tty rb "现在重启？(y/N) > " "N"
  if [[ "$rb" == "y" || "$rb" == "Y" ]]; then
    warn "即将重启..."
    reboot || true
  else
    info "稍后手动重启：reboot"
  fi
}

# ---------------- DNS 切换/恢复 ----------------
dns_backup_once() {
  ensure_dir "$BACKUP_BASE"
  if [[ -e /etc/resolv.conf ]] && [[ ! -e "$RESOLV_BACKUP" ]]; then
    cp -a /etc/resolv.conf "$RESOLV_BACKUP" 2>/dev/null || true
    ok "已备份 resolv.conf.orig"
  fi
}

dns_apply_resolved() {
  local ifc="$1"; shift
  local dns_list=("$@")
  resolvectl dns "$ifc" "${dns_list[@]}" >/dev/null 2>&1 || true
  resolvectl flush-caches >/dev/null 2>&1 || true
}

dns_apply_resolvconf() {
  local dns_list=("$@")
  dns_backup_once
  {
    echo "# managed by ${SCRIPT_NAME}"
    for d in "${dns_list[@]}"; do echo "nameserver $d"; done
    echo "options timeout:2 attempts:2"
  } > /etc/resolv.conf
}

dns_set() {
  local which="$1"; local ifc="$2"
  local dns1 dns2
  case "$which" in
    cloudflare) dns1="1.1.1.1"; dns2="1.0.0.1" ;;
    google) dns1="8.8.8.8"; dns2="8.8.4.4" ;;
    quad9) dns1="9.9.9.9"; dns2="149.112.112.112" ;;
    *) warn "未知 DNS 方案"; return 1 ;;
  esac

  info "DNS：切换到 ${which}"
  if is_resolved_active && have_cmd resolvectl; then
    dns_apply_resolved "$ifc" "$dns1" "$dns2"
    ok "已通过 systemd-resolved 应用（$ifc）"
  else
    dns_apply_resolvconf "$dns1" "$dns2"
    ok "已写入 /etc/resolv.conf"
  fi

  if dns_resolve_ok; then ok "DNS 解析：正常"; else warn "DNS 解析：仍异常（可试另一组 DNS）"; fi
}

dns_switch_menu() {
  local ifc; ifc="$(default_iface)"
  local c=""
  echo
  echo -e "${c_bold}${c_white}DNS 切换（更换解析服务器）${c_reset}  ${c_dim}(接口: $ifc)${c_reset}"
  echo "  1) Cloudflare  (1.1.1.1 / 1.0.0.1)"
  echo "  2) Google      (8.8.8.8 / 8.8.4.4)"
  echo "  3) Quad9       (9.9.9.9 / 149.112.112.112)"
  echo "  0) 返回"
  read_tty c "选择> " ""
  case "$c" in
    1) dns_set "cloudflare" "$ifc" ;;
    2) dns_set "google" "$ifc" ;;
    3) dns_set "quad9" "$ifc" ;;
    0) return 0 ;;
    *) warn "无效选项" ;;
  esac
}

dns_restore() {
  local ifc; ifc="$(default_iface)"
  info "DNS：恢复到脚本运行前的状态"
  if is_resolved_active && have_cmd resolvectl; then
    resolvectl revert "$ifc" >/dev/null 2>&1 || true
    resolvectl flush-caches >/dev/null 2>&1 || true
    ok "已对 $ifc 执行 resolvectl revert"
  fi

  if [[ -e "$RESOLV_BACKUP" ]]; then
    cp -a "$RESOLV_BACKUP" /etc/resolv.conf 2>/dev/null 2>&1 || true
    ok "已恢复 /etc/resolv.conf（来自备份）"
  else
    warn "未找到备份：$RESOLV_BACKUP"
  fi

  if dns_resolve_ok; then ok "DNS 解析：正常"; else warn "DNS 解析：仍异常（检查上游/防火墙）"; fi
}

# ---------------- MTU 自动探测/设置 ----------------
mtu_current() {
  local ifc; ifc="$(default_iface)"
  ip link show "$ifc" 2>/dev/null | awk '/mtu/{for(i=1;i<=NF;i++) if($i=="mtu"){print $(i+1); exit}}' || true
}

ping_payload_ok_v4() {
  local host="$1" payload="$2"
  ping -4 -c 1 -W 1 -M do -s "$payload" "$host" >/dev/null 2>&1
}

mtu_probe_v4_value() {
  local host="1.1.1.1"
  if ! ping -4 -c 1 -W 1 "$host" >/dev/null 2>&1; then host="8.8.8.8"; fi
  if ! ping -4 -c 1 -W 1 "$host" >/dev/null 2>&1; then
    echo -e "${c_yellow}⚠ IPv4 ping 不通，无法探测 MTU（先检查网络）${c_reset}" >&2
    return 1
  fi

  echo -e "${c_cyan}➜${c_reset} MTU 探测：对 ${host} 做 DF 探测" >&2
  local lo=1200 hi=1472 mid best=0
  while [[ $lo -le $hi ]]; do
    mid=$(( (lo + hi) / 2 ))
    if ping_payload_ok_v4 "$host" "$mid"; then
      best="$mid"; lo=$((mid + 1))
    else
      hi=$((mid - 1))
    fi
  done

  if [[ "$best" -le 0 ]]; then
    echo -e "${c_yellow}⚠ 未探测到可用值${c_reset}" >&2
    return 1
  fi

  local mtu=$((best + 28))
  echo -e "${c_green}✔${c_reset} 推荐 MTU=${mtu}" >&2
  echo "$mtu"
}

mtu_apply_runtime() {
  local mtu="$1"
  local ifc; ifc="$(default_iface)"
  info "MTU：临时设置（$ifc → $mtu）"
  if ! ip link set dev "$ifc" mtu "$mtu" >/dev/null 2>&1; then
    warn "设置失败：请确认网卡名/权限/MTU 值是否合理"
    return 1
  fi
  ok "已临时生效（当前 MTU=$(mtu_current || echo N/A)）"
}

mtu_enable_persist_systemd() {
  local mtu="$1"
  local ifc; ifc="$(default_iface)"
  if ! is_systemd; then
    warn "无 systemd：无法用 service 持久化"
    return 1
  fi

  write_file "$MTU_VALUE_FILE" "IFACE=${ifc}
MTU=${mtu}
"
  write_file "$MTU_SERVICE" \
"[Unit]
Description=DMIT MTU Apply
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c '. ${MTU_VALUE_FILE} 2>/dev/null || exit 0; ip link set dev \"${ifc}\" mtu \"${mtu}\"'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable dmit-mtu.service >/dev/null 2>&1 || true
  systemctl restart dmit-mtu.service >/dev/null 2>&1 || true
  ok "已持久化（systemd）：dmit-mtu.service"
}

mtu_disable_persist() {
  info "MTU：移除持久化设置（恢复由系统接管）"
  if is_systemd; then
    systemctl disable dmit-mtu.service >/dev/null 2>&1 || true
    systemctl stop dmit-mtu.service >/dev/null 2>&1 || true
    rm -f "$MTU_SERVICE" "$MTU_VALUE_FILE" || true
    systemctl daemon-reload >/dev/null 2>&1 || true
    ok "已移除 dmit-mtu.service"
  else
    warn "无 systemd：无需移除 service"
  fi
  warn "运行时 MTU 不会自动回到 1500，如需可执行：ip link set dev $(default_iface) mtu 1500"
}

mtu_menu() {
  local cur; cur="$(mtu_current || echo "")"
  local c=""
  echo
  echo -e "${c_bold}${c_white}MTU 工具（探测/设置/持久化）${c_reset}  ${c_dim}(接口: $(default_iface)，当前: ${cur:-N/A})${c_reset}"
  echo "  1) 自动探测 MTU（只显示推荐值）"
  echo "  2) 手动设置 MTU（临时生效）"
  echo "  3) 探测并设置 MTU（临时生效）"
  echo "  4) 探测并设置 MTU（开机自动生效）"
  echo "  5) 移除 MTU 开机自动设置"
  echo "  0) 返回"
  read_tty c "选择> " ""

  case "$c" in
    1)
      local mtu=""
      mtu="$(mtu_probe_v4_value || true)"
      [[ -n "${mtu:-}" ]] && ok "推荐 MTU：$mtu" || true
      ;;
    2)
      local mtu=""
      read_tty mtu "输入 MTU（如 1500/1480/1460/1450）> " ""
      [[ "$mtu" =~ ^[0-9]+$ ]] || { warn "输入无效"; return 0; }
      mtu_apply_runtime "$mtu" || true
      ;;
    3)
      local mtu=""
      mtu="$(mtu_probe_v4_value || true)"
      if [[ -n "${mtu:-}" ]]; then
        mtu_apply_runtime "$mtu" || true
      else
        warn "探测失败：未设置"
      fi
      ;;
    4)
      local mtu=""
      mtu="$(mtu_probe_v4_value || true)"
      if [[ -n "${mtu:-}" ]]; then
        mtu_apply_runtime "$mtu" || true
        mtu_enable_persist_systemd "$mtu" || true
      else
        warn "探测失败：未设置"
      fi
      ;;
    5) mtu_disable_persist || true ;;
    0) return 0 ;;
    *) warn "无效选项" ;;
  esac
}

# ---------------- 一键网络体检 / 体检+自动修复 ----------------
print_kv() { printf "%-20s %s\n" "$1" "$2"; }

health_check_core() {
  local ifc; ifc="$(default_iface)"
  local ipv6_sysctl; ipv6_sysctl="$(ipv6_status)"
  local v6_addr="NO" v6_route="NO" v4_net="NO" v6_net="NO" dns_ok="NO"

  has_ipv6_global_addr && v6_addr="YES"
  has_ipv6_default_route && v6_route="YES"
  curl4_ok && v4_net="YES"
  curl6_ok && v6_net="YES"
  dns_resolve_ok && dns_ok="YES"

  echo -e "${c_bold}${c_white}网络体检${c_reset}  ${c_dim}(接口: $ifc)${c_reset}"
  echo -e "${c_green}${AD_TEXT}${c_reset}"
  echo -e "${c_dim}----------------------------------------------${c_reset}"

  print_kv "IPv4 出网"       "$( [[ "$v4_net" == "YES" ]] && echo -e "${c_green}正常${c_reset}" || echo -e "${c_yellow}异常${c_reset}" )"
  print_kv "DNS 解析"        "$( [[ "$dns_ok" == "YES" ]] && echo -e "${c_green}正常${c_reset}" || echo -e "${c_yellow}异常${c_reset}" )"
  print_kv "IPv6 sysctl 开关" "$ipv6_sysctl"
  print_kv "IPv6 公网地址"   "$( [[ "$v6_addr" == "YES" ]] && echo -e "${c_green}有${c_reset}" || echo -e "${c_yellow}无${c_reset}" )"
  print_kv "IPv6 默认路由"   "$( [[ "$v6_route" == "YES" ]] && echo -e "${c_green}有${c_reset}" || echo -e "${c_yellow}无${c_reset}" )"
  print_kv "IPv6 出网"       "$( [[ "$v6_net" == "YES" ]] && echo -e "${c_green}正常${c_reset}" || echo -e "${c_yellow}异常${c_reset}" )"
  print_kv "当前 MTU"        "$(mtu_current || echo N/A)"
  echo -e "${c_dim}----------------------------------------------${c_reset}"

  if [[ "$dns_ok" != "YES" && "$v4_net" == "YES" ]]; then
    warn "像 DNS 问题：试试【DNS 切换】"
  fi
  if [[ "$v6_addr" == "NO" || "$v6_route" == "NO" ]]; then
    warn "IPv6 缺地址/路由：试试【体检+自动修复】或【开启 IPv6】"
  fi
}

health_check_only() {
  health_check_core
  ok "体检完成（未改动任何配置）"
}

health_check_autofix() {
  local fixed=0
  health_check_core
  echo
  info "自动修复：尝试重拉 IPv6 / 刷新 DNS（不做高风险改动）"

  if ! has_ipv6_global_addr || ! has_ipv6_default_route; then
    info "IPv6 不完整：执行“开启 IPv6（重拉地址/路由）”"
    ipv6_enable || true
    fixed=1
  fi

  if is_resolved_active && have_cmd resolvectl; then
    info "刷新 systemd-resolved DNS 缓存"
    resolvectl flush-caches >/dev/null 2>&1 || true
    fixed=1
  fi

  echo
  health_check_core
  [[ "$fixed" -eq 1 ]] && ok "已执行自动修复动作" || ok "无需修复"
}

# ---------------- SSH（安全优先 + 换端口） ----------------
ssh_backup_once() {
  ensure_dir "$BACKUP_BASE"
  if [[ ! -f "$SSH_ORIG_TGZ" ]]; then
    info "SSH：备份原始配置 → $SSH_ORIG_TGZ"
    tar -czf "$SSH_ORIG_TGZ" /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null || \
      tar -czf "$SSH_ORIG_TGZ" /etc/ssh/sshd_config 2>/dev/null || true
    ok "SSH 原始配置已备份"
  fi
}

sshd_restart() {
  if is_systemd; then
    systemctl restart ssh >/dev/null 2>&1 || true
    systemctl restart sshd >/dev/null 2>&1 || true
  else
    service ssh restart >/dev/null 2>&1 || true
    service sshd restart >/dev/null 2>&1 || true
  fi
}

sshd_status_hint() {
  echo -e "${c_dim}--- SSH 当前生效配置（节选）---${c_reset}"
  if have_cmd sshd; then
    sshd -T 2>/dev/null | egrep -i 'port|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|challengeresponseauthentication|usepam|permitrootlogin|maxauthtries|logingracetime|clientaliveinterval|clientalivecountmax' || true
  else
    warn "未找到 sshd 命令，改为简单 grep："
    egrep -i 'Port|PasswordAuthentication|PubkeyAuthentication|KbdInteractiveAuthentication|ChallengeResponseAuthentication|UsePAM|PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null || true
  fi
  echo -e "${c_dim}--------------------------------${c_reset}"
}

sshd_set_kv_in_main() {
  local key="$1" val="$2"
  local f="/etc/ssh/sshd_config"
  [[ -f "$f" ]] || return 0
  if grep -qiE "^\s*${key}\b" "$f"; then
    sed -i -E "s/^\s*${key}\b.*/${key} ${val}/I" "$f"
  else
    printf "\n# %s managed\n%s %s\n" "$SCRIPT_NAME" "$key" "$val" >> "$f"
  fi
}

sshd_set_port_in_main() {
  local val="$1"
  local f="/etc/ssh/sshd_config"
  [[ -f "$f" ]] || return 0
  sed -i -E '/^\s*Port\s+[0-9]+\s*$/Id' "$f" || true
  printf "\n# %s managed\nPort %s\n" "$SCRIPT_NAME" "$val" >> "$f"
}

ssh_dropin_ensure() {
  ensure_dir "$SSH_DROPIN_DIR"
  if [[ ! -f "$SSH_DROPIN_FILE" ]]; then
    write_file "$SSH_DROPIN_FILE" "# managed by ${SCRIPT_NAME}"
  fi
}

ssh_dropin_set_line() {
  local key="$1" val="$2"
  ssh_dropin_ensure
  sed -i -E "/^\s*${key}\b.*/Id" "$SSH_DROPIN_FILE" || true
  printf "%s %s\n" "$key" "$val" >> "$SSH_DROPIN_FILE"
}

ssh_common_hardening_dropin() {
  ssh_dropin_set_line "KbdInteractiveAuthentication" "no"
  ssh_dropin_set_line "ChallengeResponseAuthentication" "no"
  ssh_dropin_set_line "PermitEmptyPasswords" "no"
  ssh_dropin_set_line "UsePAM" "yes"
  ssh_dropin_set_line "MaxAuthTries" "3"
  ssh_dropin_set_line "LoginGraceTime" "20"
  ssh_dropin_set_line "ClientAliveInterval" "60"
  ssh_dropin_set_line "ClientAliveCountMax" "2"

  sshd_set_kv_in_main "KbdInteractiveAuthentication" "no"
  sshd_set_kv_in_main "ChallengeResponseAuthentication" "no"
  sshd_set_kv_in_main "PermitEmptyPasswords" "no"
  sshd_set_kv_in_main "UsePAM" "yes"
  sshd_set_kv_in_main "MaxAuthTries" "3"
  sshd_set_kv_in_main "LoginGraceTime" "20"
  sshd_set_kv_in_main "ClientAliveInterval" "60"
  sshd_set_kv_in_main "ClientAliveCountMax" "2"
}

ssh_random_pass() { tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 18 || true; }

ssh_create_user_with_password() {
  local user="$1"
  local passwd="$2"

  if ! id "$user" >/dev/null 2>&1; then
    info "创建用户：$user"
    if have_cmd useradd; then
      useradd -m -s /bin/bash "$user" >/dev/null 2>&1 || true
    elif have_cmd adduser; then
      adduser -D "$user" >/dev/null 2>&1 || adduser --disabled-password --gecos "" "$user" >/dev/null 2>&1 || true
    else
      warn "没有 useradd/adduser，无法创建用户"
      return 1
    fi
  fi

  echo "${user}:${passwd}" | chpasswd
  ok "已设置 ${user} 密码"
  echo -e "${c_green}${user} 密码：${passwd}${c_reset}"

  if getent group sudo >/dev/null 2>&1; then
    usermod -aG sudo "$user" >/dev/null 2>&1 || true
  elif getent group wheel >/dev/null 2>&1; then
    usermod -aG wheel "$user" >/dev/null 2>&1 || true
  fi
}

ssh_safe_enable_password_for_user_keep_root_key() {
  local user="${1:-dmit}"
  pkg_install openssh-server openssh-client
  ssh_backup_once

  warn "推荐模式：普通用户密码登录；root 禁止密码（仅密钥）"
  warn "建议保持当前 SSH 会话不要断开，确认新用户可登录后再退出"

  ssh_common_hardening_dropin
  ssh_dropin_set_line "PasswordAuthentication" "yes"
  ssh_dropin_set_line "PubkeyAuthentication" "yes"
  ssh_dropin_set_line "PermitRootLogin" "prohibit-password"

  sshd_set_kv_in_main "PasswordAuthentication" "yes"
  sshd_set_kv_in_main "PubkeyAuthentication" "yes"
  sshd_set_kv_in_main "PermitRootLogin" "prohibit-password"

  local p; p="$(ssh_random_pass)"
  [[ -z "${p:-}" ]] && { warn "生成随机密码失败"; return 1; }
  ssh_create_user_with_password "$user" "$p" || true

  sshd_restart
  ok "已重启 SSH（推荐模式已生效）"
  sshd_status_hint
}

ssh_enable_password_keep_key_for_user() {
  local user="${1:-root}"
  local mode="${2:-random}" # random|custom
  local passwd="${3:-}"

  pkg_install openssh-server openssh-client
  ssh_backup_once

  warn "中等模式：开启密码登录（保留密钥登录）"
  warn "建议保持当前 SSH 会话不要断开，确认密码可登录后再退出"

  ssh_common_hardening_dropin
  ssh_dropin_set_line "PasswordAuthentication" "yes"
  ssh_dropin_set_line "PubkeyAuthentication" "yes"

  sshd_set_kv_in_main "PasswordAuthentication" "yes"
  sshd_set_kv_in_main "PubkeyAuthentication" "yes"

  if [[ "$mode" == "random" ]]; then passwd="$(ssh_random_pass)"; fi
  [[ -z "${passwd:-}" ]] && { warn "密码为空：取消"; return 1; }

  if id "$user" >/dev/null 2>&1; then
    echo "${user}:${passwd}" | chpasswd
    ok "已设置用户密码：${user}"
    echo -e "${c_green}新密码：${passwd}${c_reset}"
  else
    warn "用户不存在：$user（未设置密码）"
  fi

  sshd_restart
  ok "已重启 SSH（密码+密钥均可）"
  sshd_status_hint
}

ssh_password_only_disable_key_risky() {
  local user="${1:-root}"
  local mode="${2:-random}" # random|custom
  local passwd="${3:-}"

  pkg_install openssh-server openssh-client
  ssh_backup_once

  warn "高风险模式：仅密码登录（禁用密钥）"
  warn "有锁门风险：务必保持当前 SSH 会话不断开"
  local ans=""
  read_tty ans "确认继续请输入 YES > " ""
  if [[ "${ans}" != "YES" ]]; then
    warn "已取消"
    return 0
  fi

  ssh_common_hardening_dropin
  ssh_dropin_set_line "PasswordAuthentication" "yes"
  ssh_dropin_set_line "PubkeyAuthentication" "no"

  sshd_set_kv_in_main "PasswordAuthentication" "yes"
  sshd_set_kv_in_main "PubkeyAuthentication" "no"

  if [[ "$mode" == "random" ]]; then passwd="$(ssh_random_pass)"; fi
  [[ -z "${passwd:-}" ]] && { warn "密码为空：取消"; return 1; }

  if id "$user" >/dev/null 2>&1; then
    echo "${user}:${passwd}" | chpasswd
    ok "已设置用户密码：${user}"
    echo -e "${c_green}新密码：${passwd}${c_reset}"
  else
    warn "用户不存在：$user（未设置密码）"
  fi

  sshd_restart
  ok "已重启 SSH（仅密码登录）"
  sshd_status_hint
}

ssh_restore_key_login() {
  ssh_backup_once
  info "SSH：恢复原来的配置（从备份还原）"
  if [[ -f "$SSH_ORIG_TGZ" ]]; then
    tar -xzf "$SSH_ORIG_TGZ" -C / 2>/dev/null || true
    rm -f "$SSH_DROPIN_FILE" 2>/dev/null || true
    sshd_restart
    ok "已恢复 SSH 原始配置并重启"
    sshd_status_hint
  else
    warn "未找到备份：$SSH_ORIG_TGZ"
  fi
}

ssh_current_ports() {
  if have_cmd sshd; then
    sshd -T 2>/dev/null | awk '$1=="port"{print $2}' | tr '\n' ' ' | sed 's/[[:space:]]*$//'
    return 0
  fi
  local ports=""
  ports="$(grep -RihE '^\s*Port\s+' /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null | awk '{print $2}' | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
  echo "${ports:-22}"
}

port_in_use() {
  local p="$1"
  if have_cmd ss; then
    ss -lntp 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${p}$" && return 0
  elif have_cmd netstat; then
    netstat -lntp 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${p}$" && return 0
  fi
  return 1
}

firewall_open_port_best_effort() {
  local p="$1"

  if have_cmd ufw; then
    if ufw status 2>/dev/null | grep -qi "Status: active"; then
      ufw allow "${p}/tcp" >/dev/null 2>&1 || true
      ok "已尝试放行 ufw：${p}/tcp"
      return 0
    fi
  fi

  if have_cmd firewall-cmd; then
    if firewall-cmd --state >/dev/null 2>&1; then
      firewall-cmd --permanent --add-port="${p}/tcp" >/dev/null 2>&1 || true
      firewall-cmd --reload >/dev/null 2>&1 || true
      ok "已尝试放行 firewalld：${p}/tcp"
      return 0
    fi
  fi

  if have_cmd iptables; then
    iptables -C INPUT -p tcp --dport "$p" -j ACCEPT >/dev/null 2>&1 || \
      iptables -I INPUT -p tcp --dport "$p" -j ACCEPT >/dev/null 2>&1 || true
    ok "已尝试放行 iptables：${p}/tcp（可能不持久）"
    return 0
  fi

  warn "未检测到可用防火墙工具：请自行放行 ${p}/tcp"
  return 0
}

ssh_set_port() {
  local newp="$1"

  [[ "$newp" =~ ^[0-9]+$ ]] || { warn "端口必须是数字"; return 1; }
  if (( newp < 1 || newp > 65535 )); then warn "端口范围 1-65535"; return 1; fi
  if (( newp < 1024 )); then warn "不建议使用 1024 以下端口"; fi

  local cur_ports; cur_ports="$(ssh_current_ports || echo "22")"
  if echo " $cur_ports " | grep -q " ${newp} "; then
    warn "端口 ${newp} 已在 SSH 当前配置中"
    return 0
  fi

  if port_in_use "$newp"; then
    warn "端口 ${newp} 似乎已被占用（请换一个）"
    return 1
  fi

  pkg_install openssh-server openssh-client
  ssh_backup_once

  warn "更换 SSH 端口会影响新连接"
  warn "强烈建议保持当前 SSH 会话不要断开"
  warn "请先测试：ssh -p ${newp} user@你的IP"

  ssh_dropin_set_line "Port" "$newp"
  sshd_set_port_in_main "$newp"
  firewall_open_port_best_effort "$newp"

  if have_cmd sshd; then
    if ! sshd -t >/dev/null 2>&1; then
      warn "sshd 配置校验失败：将恢复备份"
      ssh_restore_key_login || true
      return 1
    fi
  fi

  sshd_restart
  ok "已尝试切换 SSH 端口 → ${newp}"
  echo -e "${c_green}提示：请用新端口测试登录成功后，再退出当前会话${c_reset}"
  echo -e "${c_dim}当前端口：$(ssh_current_ports)${c_reset}"
}

ssh_menu() {
  local c=""
  echo
  echo -e "${c_bold}${c_white}SSH 工具（安全优先）${c_reset}"
  echo "  1) 创建新用户 + 密码登录（root 仅密钥，更安全）"
  echo "  2) 开启密码登录（保留密钥）"
  echo "  3) 仅密码登录（禁用密钥，高风险）"
  echo "  4) 更换 SSH 端口（并尝试放行防火墙）"
  echo "  5) 恢复 SSH 原始配置（用备份还原）"
  echo "  6) 查看 SSH 当前生效状态（含端口）"
  echo "  0) 返回"
  read_tty c "选择> " ""
  case "$c" in
    1)
      local u=""
      read_tty u "新用户名（默认 dmit）> " "dmit"
      ssh_safe_enable_password_for_user_keep_root_key "$u" || true
      ;;
    2)
      local u="" m="" p=""
      read_tty u "用户名（默认 root）> " "root"
      echo "  1) 随机密码"
      echo "  2) 自定义密码"
      read_tty m "选择> " ""
      if [[ "$m" == "1" ]]; then
        ssh_enable_password_keep_key_for_user "$u" "random" "" || true
      elif [[ "$m" == "2" ]]; then
        read_tty_secret p "设置密码（输入不回显）> "
        ssh_enable_password_keep_key_for_user "$u" "custom" "$p" || true
      else
        warn "无效选项"
      fi
      ;;
    3)
      local u="" m="" p=""
      read_tty u "用户名（默认 root）> " "root"
      echo "  1) 随机密码"
      echo "  2) 自定义密码"
      read_tty m "选择> " ""
      if [[ "$m" == "1" ]]; then
        ssh_password_only_disable_key_risky "$u" "random" "" || true
      elif [[ "$m" == "2" ]]; then
        read_tty_secret p "设置密码（输入不回显）> "
        ssh_password_only_disable_key_risky "$u" "custom" "$p" || true
      else
        warn "无效选项"
      fi
      ;;
    4)
      echo -e "${c_dim}当前 SSH 端口：$(ssh_current_ports)${c_reset}"
      local p=""
      read_tty p "输入新端口（建议 20000-59999）> " ""
      ssh_set_port "$p" || true
      ;;
    5) ssh_restore_key_login || true ;;
    6)
      sshd_status_hint
      echo -e "${c_dim}当前端口：$(ssh_current_ports)${c_reset}"
      ;;
    0) return 0 ;;
    *) warn "无效选项" ;;
  esac
}

# ---------------- 测试：运行外部脚本 ----------------
run_remote_script() {
  local title="$1"
  local cmd="$2"
  local note="${3:-}"

  echo
  echo -e "${c_bold}${c_white}${title}${c_reset}"
  [[ -n "$note" ]] && echo -e "${c_yellow}${note}${c_reset}"
  echo -e "${c_dim}将执行：${cmd}${c_reset}"
  warn "注意：这会从网络拉取并运行脚本（请自行确认来源可信）"

  if ! has_tty; then
    warn "当前无可交互 TTY（可能是 curl|bash 场景），为安全起见：已取消执行"
    return 0
  fi
  read_tty _ "回车执行（Ctrl+C 取消）..." ""

  if echo "$cmd" | grep -q "curl"; then pkg_install curl; fi
  if echo "$cmd" | grep -q "wget"; then pkg_install wget; fi
  pkg_install bash

  bash -lc "$cmd" || true
}

tests_menu() {
  local c=""
  echo
  echo -e "${c_bold}${c_white}一键测试脚本${c_reset}"
  echo "  1) GB5 性能测试（Geekbench 5）"
  echo "  2) Bench 综合测试（bench.sh）"
  echo "  3) 三网回程测试（仅参考）"
  echo "  4) IP 质量检测（IP.Check.Place）"
  echo "  5) NodeQuality 测试"
  echo "  6) Telegram 延迟测试"
  echo "  7) 流媒体解锁检测（check.unlock.media）"
  echo "  0) 返回"
  read_tty c "选择> " ""
  case "$c" in
    1) run_remote_script "GB5 性能测试"  "bash <(wget -qO- https://raw.githubusercontent.com/i-abc/GB5/main/gb5-test.sh)" ;;
    2) run_remote_script "Bench 综合测试" "curl -Lso- bench.sh | bash" ;;
    3) run_remote_script "三网回程测试" "curl https://raw.githubusercontent.com/ludashi2020/backtrace/main/install.sh -sSf | sh" "备注：仅参考" ;;
    4) run_remote_script "IP 质量检测" "bash <(curl -sL IP.Check.Place)" ;;
    5) run_remote_script "NodeQuality 测试" "bash <(curl -sL https://run.NodeQuality.com)" ;;
    6) run_remote_script "Telegram 延迟测试" "bash <(curl -fsSL https://sub.777337.xyz/tgdc.sh)" ;;
    7) run_remote_script "流媒体解锁检测" "bash <(curl -L -s check.unlock.media)" ;;
    0) return 0 ;;
    *) warn "无效选项" ;;
  esac
}

# ---------------- 一键DD重装系统 ----------------
dd_reinstall() {
  warn "一键 DD 重装系统：会清空系统盘数据，风险极高！"
  warn "建议先准备好：VNC/救援模式/面板控制台"
  warn "开始后 SSH 可能中断，请勿慌"

  if ! has_tty; then
    warn "当前无可交互 TTY（可能是 curl|bash 场景），为安全起见：已取消"
    return 0
  fi

  local c="" flag="" ver="" port="" mode="" pwd=""
  echo
  echo -e "${c_bold}${c_white}DD 重装系统（InstallNET.sh）${c_reset}"
  echo "  1) Debian 11"
  echo "  2) Debian 12"
  echo "  3) Debian 13"
  echo "  4) Ubuntu 22.04"
  echo "  5) Ubuntu 24.04"
  echo "  6) CentOS 7"
  echo "  7) CentOS 8"
  echo "  8) RockyLinux 9"
  echo "  9) AlmaLinux 9"
  echo "  10) Alpine edge"
  echo "  0) 返回"
  read_tty c "选择> " ""
  case "$c" in
    1)  flag="-debian";     ver="11" ;;
    2)  flag="-debian";     ver="12" ;;
    3)  flag="-debian";     ver="13" ;;
    4)  flag="-ubuntu";     ver="22.04" ;;
    5)  flag="-ubuntu";     ver="24.04" ;;
    6)  flag="-centos";     ver="7" ;;
    7)  flag="-centos";     ver="8" ;;
    8)  flag="-rockylinux"; ver="9" ;;
    9)  flag="-almalinux";  ver="9" ;;
    10) flag="-alpine";     ver="edge" ;;
    0) return 0 ;;
    *) warn "无效选项"; return 0 ;;
  esac

  local cur_port
  cur_port="$(ssh_current_ports | awk '{print $1}' || true)"
  cur_port="${cur_port:-22}"
  read_tty port "SSH 端口（默认 ${cur_port}）> " "$cur_port"
  [[ "$port" =~ ^[0-9]+$ ]] || { warn "端口必须是数字"; return 0; }

  echo
  echo "  1) 随机密码"
  echo "  2) 自定义密码"
  read_tty mode "选择> " "1"
  if [[ "$mode" == "1" ]]; then
    pwd="K$(ssh_random_pass)"
  elif [[ "$mode" == "2" ]]; then
    read_tty_secret pwd "设置密码（输入不回显）> "
    [[ -n "${pwd:-}" ]] || { warn "密码不能为空"; return 0; }
  else
    warn "无效选项"
    return 0
  fi

  echo
  echo -e "${c_bold}${c_white}即将执行（确认信息）${c_reset}"
  echo -e "系统：${flag} ${ver}"
  echo -e "SSH端口：${port}"
  echo -e "root密码：${c_green}${pwd}${c_reset}"
  echo -e "${c_yellow}⚠ 数据将被清空！${c_reset}"
  echo
  local ans=""
  read_tty ans "确认继续请输入 DD > " ""
  if [[ "$ans" != "DD" ]]; then
    warn "已取消"
    return 0
  fi

  if have_cmd apt-get; then
    apt-get -y update >/dev/null 2>&1 || true
    apt-get -y install wget >/dev/null 2>&1 || true
  elif have_cmd yum; then
    yum -y install wget >/dev/null 2>&1 || true
  elif have_cmd dnf; then
    dnf -y install wget >/dev/null 2>&1 || true
  elif have_cmd apk; then
    apk update >/dev/null 2>&1 || true
    apk add bash wget >/dev/null 2>&1 || true
    sed -i 's/root:\/bin\/ash/root:\/bin\/bash/g' /etc/passwd 2>/dev/null || true
  fi

  info "下载 InstallNET.sh..."
  wget --no-check-certificate -qO /tmp/InstallNET.sh 'https://raw.githubusercontent.com/leitbogioro/Tools/master/Linux_reinstall/InstallNET.sh'
  chmod a+x /tmp/InstallNET.sh

  warn "开始执行重装脚本（可能会进入安装流程/重启）"
  bash /tmp/InstallNET.sh "${flag}" "${ver}" -port "${port}" -pwd "${pwd}" || true
}

# ---------------- 一键还原 ----------------
restore_all() {
  local ifc; ifc="$(default_iface)"
  info "一键还原：撤销本脚本改动（DNS/MTU/IPv6/TCP/优先级/SSH）"

  rm -f "$TUNE_SYSCTL_FILE" "$DMIT_TCP_DEFAULT_FILE" >/dev/null 2>&1 || true
  rm -f "$IPV6_SYSCTL_FILE" >/dev/null 2>&1 || true

  if [[ -f "${BACKUP_BASE}/gai.conf.orig" ]]; then
    cp -a "${BACKUP_BASE}/gai.conf.orig" "$GAI_CONF" 2>/dev/null || true
  else
    [[ -f "$GAI_CONF" ]] && sed -i '/^\s*precedence\s\+::ffff:0:0\/96\s\+[0-9]\+\s*$/d' "$GAI_CONF" || true
  fi

  if is_resolved_active && have_cmd resolvectl; then
    resolvectl revert "$ifc" >/dev/null 2>&1 || true
    resolvectl flush-caches >/dev/null 2>&1 || true
  fi
  if [[ -f "$RESOLV_BACKUP" ]]; then
    cp -a "$RESOLV_BACKUP" /etc/resolv.conf 2>/dev/null 2>&1 || true
  fi

  if is_systemd; then
    systemctl disable dmit-mtu.service >/dev/null 2>&1 || true
    systemctl stop dmit-mtu.service >/dev/null 2>&1 || true
    rm -f "$MTU_SERVICE" "$MTU_VALUE_FILE" || true
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  ip link set dev "$ifc" mtu 1500 >/dev/null 2>&1 || true

  if [[ -f "$SSH_ORIG_TGZ" ]]; then
    tar -xzf "$SSH_ORIG_TGZ" -C / 2>/dev/null || true
    rm -f "$SSH_DROPIN_FILE" 2>/dev/null || true
    sshd_restart || true
  fi

  sysctl_apply_all
  restart_network_services_best_effort
  sleep 1

  ok "已还原（建议再跑一次“网络体检”确认状态）"
}

# ---------------- 主菜单 ----------------
menu() {
  RUN_MODE="menu"
  while true; do
    banner

    echo -e "${c_bold}${c_white}【网络】${c_reset}"
    echo -e "  ${c_cyan}1${c_reset}) 网络体检（只看状态）"
    echo -e "  ${c_cyan}2${c_reset}) 体检 + 自动修复（重拉IPv6/刷新DNS）"
    echo -e "  ${c_cyan}3${c_reset}) 开启 IPv6（重拉地址/路由）"
    echo -e "  ${c_cyan}4${c_reset}) 关闭 IPv6（系统级禁用）"
    echo -e "  ${c_cyan}5${c_reset}) DNS 切换（CF/Google/Quad9）"
    echo -e "  ${c_cyan}6${c_reset}) DNS 恢复（回到备份）"
    echo -e "  ${c_cyan}7${c_reset}) MTU 工具（探测/设置/持久化）"
    echo -e "  ${c_cyan}8${c_reset}) IPv4 优先（解析优先）"
    echo -e "  ${c_cyan}9${c_reset}) IPv6 优先（恢复默认）"
    echo -e "  ${c_cyan}10${c_reset}) 恢复 IPv4/IPv6 优先级（用备份还原）"

    echo
    echo -e "${c_bold}${c_white}【TCP/BBR】${c_reset}"
    echo -e "  ${c_cyan}11${c_reset}) TCP 通用调优（BBR+FQ）"
    echo -e "  ${c_cyan}12${c_reset}) 恢复 Linux 默认 TCP（CUBIC）"
    echo -e "  ${c_cyan}13${c_reset}) 恢复 DMIT 默认 TCP"
    echo -e "  ${c_cyan}14${c_reset}) BBR 支持性检测"
    echo -e "  ${c_cyan}15${c_reset}) 安装 BBRv3（XanMod 内核，需要重启）"

    echo
    echo -e "${c_bold}${c_white}【系统/安全】${c_reset}"
    echo -e "  ${c_cyan}16${c_reset}) 设置时区为中国（Asia/Shanghai）"
    echo -e "  ${c_cyan}17${c_reset}) SSH 安全工具（密码/密钥/换端口）"
    echo -e "  ${c_cyan}18${c_reset}) 一键 DD 重装系统（高风险）"

    echo
    echo -e "${c_bold}${c_white}【测试】${c_reset}"
    echo -e "  ${c_cyan}19${c_reset}) 一键测试脚本（GB5/Bench/回程/IP质量/解锁）"

    echo
    echo -e "${c_bold}${c_white}【工具】${c_reset}"
    echo -e "  ${c_cyan}20${c_reset}) 一键还原（撤销本脚本改动）"
    echo -e "  ${c_cyan}21${c_reset}) 保存环境快照（发工单用）"

    echo
    echo -e "  ${c_cyan}0${c_reset}) 退出"
    echo -e "${c_dim}----------------------------------------------${c_reset}"

    local choice=""
    read_tty choice "选择> " ""

    case "$choice" in
      1) health_check_only; pause_if_menu ;;
      2) health_check_autofix; pause_if_menu ;;
      3) ipv6_enable; pause_if_menu ;;
      4) ipv6_disable; pause_if_menu ;;
      5) dns_switch_menu; pause_if_menu ;;
      6) dns_restore; pause_if_menu ;;
      7) mtu_menu; pause_if_menu ;;
      8) prefer_ipv4; pause_if_menu ;;
      9) prefer_ipv6; pause_if_menu ;;
      10) restore_gai_default; pause_if_menu ;;
      11) tcp_tune_apply; pause_if_menu ;;
      12) tcp_restore_default; pause_if_menu ;;
      13) tcp_restore_dmit_default; pause_if_menu ;;
      14) bbr_check; pause_if_menu ;;
      15) bbrv3_install_xanmod; pause_if_menu ;;
      16) set_timezone_china; pause_if_menu ;;
      17) ssh_menu; pause_if_menu ;;
      18) dd_reinstall; pause_if_menu ;;
      19) tests_menu; pause_if_menu ;;
      20) restore_all; pause_if_menu ;;
      21) env_snapshot; pause_if_menu ;;
      0) exit 0 ;;
      *) warn "无效选项"; pause_if_menu ;;
    esac
  done
}

main() {
  need_root
  menu
}
main "$@"
