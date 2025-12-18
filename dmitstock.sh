#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_NAME="dmitbox.sh"
AD_TEXT="娆㈣繋鍔犲叆DMIT浜ゆ祦缇� https://t.me/DmitChat"

# managed files
TUNE_SYSCTL_FILE="/etc/sysctl.d/99-dmit-tcp-tune.conf"
DMIT_TCP_SYSCTL_FILE="/etc/sysctl.d/99-dmit-tcp-dmit-default.conf"
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

ok()   { echo -e "${c_green}鉁�${c_reset} $*"; }
info() { echo -e "${c_cyan}鉃�${c_reset} $*"; }
warn() { echo -e "${c_yellow}鈿�${c_reset} $*"; }

# 浜や簰杈撳叆涓撶敤锛氫粠 /dev/tty 璇伙紙鍏煎 curl|bash / wget|bash 绠￠亾锛�
TTY_IN=""
if [[ -r /dev/tty ]]; then
  TTY_IN="/dev/tty"
fi

if [[ "$RUN_MODE" == "menu" ]] && [[ ! -t 0 ]] && [[ -z "$TTY_IN" ]]; then
  echo "褰撳墠鐜鏃� /dev/tty锛屾棤娉曚氦浜掕繍琛岃彍鍗曘€�"
  echo "璇锋敼鐢細curl -fsSL https://box.dmitstock.com -o dmitbox.sh && chmod +x dmitbox.sh && sudo ./dmitbox.sh"
  exit 1
fi

read_tty() {
  # read_tty "鎻愮ず> " varname [default]
  local prompt="$1"
  local __var="$2"
  local __default="${3:-}"
  local val=""

  if [[ -n "$TTY_IN" ]]; then
    IFS= read -r -p "$prompt" val <"$TTY_IN" || val=""
  else
    IFS= read -r -p "$prompt" val || val=""
  fi

  if [[ -z "$val" ]] && [[ -n "$__default" ]]; then
    val="$__default"
  fi
  printf -v "$__var" '%s' "$val"
}

press_enter() {
  local msg="${1:-鈫� 鍥炶溅缁х画...}"
  local _tmp=""
  if [[ -n "$TTY_IN" ]]; then
    IFS= read -r -p "$msg" _tmp <"$TTY_IN" || true
  else
    IFS= read -r -p "$msg" _tmp || true
  fi
}

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    warn "璇风敤 root 杩愯锛歴udo ./${SCRIPT_NAME}"
    exit 1
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }
ts_now() { date +"%Y%m%d-%H%M%S"; }
ensure_dir() { mkdir -p "$1"; }

pause_if_menu() {
  if [[ "$RUN_MODE" == "menu" ]]; then
    echo
    press_enter "鈫� 鍥炶溅杩斿洖宸ュ叿绠�..."
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

  warn "鏈瘑鍒寘绠＄悊鍣細璇锋墜鍔ㄥ畨瑁� ${pkgs[*]}"
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
  clear || true
  echo -e "${c_bold}${c_white}DMIT 宸ュ叿绠�${c_reset}  ${c_dim}(${SCRIPT_NAME})${c_reset}"
  echo -e "${c_green}${AD_TEXT}${c_reset}"
  echo -e "${c_dim}----------------------------------------------${c_reset}"
}

# ---------------- 鐜蹇収 ----------------
env_snapshot() {
  ensure_dir "$BACKUP_BASE"
  local bdir="${BACKUP_BASE}/snapshot-$(ts_now)"
  ensure_dir "$bdir"
  info "鐜蹇収 鈫� ${bdir}"

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

  ok "宸蹭繚瀛橈細${bdir}"
  echo "鏌ョ湅锛歭ess -S ${bdir}/state.txt"
}

# ---------------- 鏃跺尯锛氫腑鍥� ----------------
set_timezone_china() {
  info "鏃跺尯锛氳缃负涓浗锛圓sia/Shanghai锛�"
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
  ok "褰撳墠鏃跺尯锛�$tz"
}

# ---------------- 閲嶅惎缃戠粶鏈嶅姟 ----------------
restart_network_services_best_effort() {
  if ! is_systemd; then
    warn "鏃� systemd锛氳烦杩囩綉缁滄湇鍔￠噸鍚�"
    return 0
  fi

  local restarted=0
  if systemctl is-active --quiet systemd-networkd 2>/dev/null; then
    info "閲嶅惎锛歴ystemd-networkd"
    systemctl restart systemd-networkd >/dev/null 2>&1 || true
    restarted=1
  fi
  if systemctl is-active --quiet NetworkManager 2>/dev/null; then
    info "閲嶅惎锛歂etworkManager"
    systemctl restart NetworkManager >/dev/null 2>&1 || true
    restarted=1
  fi
  if systemctl is-active --quiet networking 2>/dev/null; then
    info "閲嶅惎锛歯etworking"
    systemctl restart networking >/dev/null 2>&1 || true
    restarted=1
  fi

  if [[ "$restarted" -eq 0 ]]; then
    info "灏濊瘯閲嶅惎甯歌缃戠粶鏈嶅姟锛堝拷鐣ラ敊璇級"
    systemctl restart networking >/dev/null 2>&1 || true
    systemctl restart systemd-networkd >/dev/null 2>&1 || true
    systemctl restart NetworkManager >/dev/null 2>&1 || true
  fi
}

# ---------------- IPv6 寮€鍏� ----------------
ipv6_disable() {
  info "IPv6锛氬叧闂紙绯荤粺绾х鐢級"
  write_file "$IPV6_SYSCTL_FILE" \
"net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1"
  sysctl_apply_all
  ok "IPv6 宸插叧闂紙sysctl: $(ipv6_status)锛�"
}

_ipv6_enable_runtime_all_ifaces() {
  for f in /proc/sys/net/ipv6/conf/*/disable_ipv6; do
    [[ -e "$f" ]] || continue
    echo 0 > "$f" 2>/dev/null || true
  done
}

_ipv6_find_disable_sources() {
  echo -e "${c_yellow}${c_bold}--- IPv6 寮€鍚け璐ユ帓鏌� ---${c_reset}"
  echo -e "${c_dim}[鍚姩鍙傛暟]${c_reset} $(cat /proc/cmdline 2>/dev/null || true)"
  if grep -qw "ipv6.disable=1" /proc/cmdline 2>/dev/null; then
    warn "鍙戠幇 ipv6.disable=1锛氬繀椤绘敼 GRUB/寮曞骞堕噸鍚�"
  fi
  echo
  echo -e "${c_dim}[sysctl 瑕嗙洊]${c_reset}"
  (grep -RIn --line-number -E 'net\.ipv6\.conf\.(all|default|lo)\.disable_ipv6\s*=\s*1' \
    /etc/sysctl.conf /etc/sysctl.d 2>/dev/null || true) | sed -n '1,120p'
  echo
  echo -e "${c_dim}[妯″潡榛戝悕鍗昡${c_reset}"
  (grep -RIn --line-number -E '^\s*blacklist\s+ipv6|^\s*install\s+ipv6\s+/bin/true' \
    /etc/modprobe.d 2>/dev/null || true) | sed -n '1,120p'
  echo -e "${c_yellow}${c_bold}------------------------${c_reset}"
}

ipv6_enable() {
  info "IPv6锛氬紑鍚紙鑷姩閲嶆媺鍦板潃/榛樿璺敱锛�"

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

  echo -e "${c_dim}--- IPv6 鐘舵€佸揩鐓� ---${c_reset}"
  echo -e "${c_dim}sysctl:${c_reset} $st"
  echo -e "${c_dim}鍦板潃:${c_reset}"
  ip -6 addr show 2>/dev/null || true
  echo -e "${c_dim}璺敱:${c_reset}"
  ip -6 route show 2>/dev/null || true
  echo -e "${c_dim}---------------------${c_reset}"

  if echo "$st" | grep -q "all=0" && echo "$st" | grep -q "default=0" \
     && has_ipv6_global_addr && has_ipv6_default_route; then
    ok "IPv6 宸插彲鐢紙鏈夊叕缃� IPv6 + 榛樿璺敱锛�"
  else
    warn "IPv6 鏈畬鏁达紙缂哄叕缃� IPv6 鎴栭粯璁よ矾鐢憋級"
    warn "濡傛灉 DMIT 闈㈡澘鏈垎閰� IPv6锛屾湰鏈轰笉浼氬嚟绌虹敓鎴愬叕缃� IPv6"
    _ipv6_find_disable_sources
  fi
}

# ---------------- IPv4/IPv6 浼樺厛绾э紙glibc锛� ----------------
gai_backup_once() {
  ensure_dir "$BACKUP_BASE"
  if [[ -f "$GAI_CONF" ]] && [[ ! -f "${BACKUP_BASE}/gai.conf.orig" ]]; then
    cp -a "$GAI_CONF" "${BACKUP_BASE}/gai.conf.orig" || true
    ok "宸插浠� gai.conf.orig"
  fi
}

prefer_ipv4() {
  info "缃戠粶锛氫紭鍏堜娇鐢� IPv4锛堢郴缁熻В鏋愪紭鍏堢骇锛�"
  local kind; kind="$(libc_kind)"
  if [[ "$kind" != "glibc" ]]; then
    warn "闈� glibc锛氭鏂瑰紡鏃犳晥锛圓lpine/musl 甯歌锛夛紝鍙敤鏇夸唬锛氬叧闂� IPv6 鎴栧簲鐢ㄥ眰 -4"
    return 0
  fi
  gai_backup_once
  touch "$GAI_CONF"
  sed -i '/^\s*precedence\s\+::ffff:0:0\/96\s\+[0-9]\+\s*$/d' "$GAI_CONF"
  printf "\n# %s managed: prefer IPv4\nprecedence ::ffff:0:0/96  100\n" "$SCRIPT_NAME" >> "$GAI_CONF"
  ok "宸茶缃細IPv4 浼樺厛"
}

prefer_ipv6() {
  info "缃戠粶锛氫紭鍏堜娇鐢� IPv6锛堟仮澶嶉粯璁ゅ€惧悜锛�"
  local kind; kind="$(libc_kind)"
  if [[ "$kind" != "glibc" ]]; then
    warn "闈� glibc锛氭鏂瑰紡鏃犳晥锛涜鏇村己鍒� IPv6锛氱‘淇� IPv6 鍙敤锛屽苟搴旂敤灞� -6"
    return 0
  fi
  gai_backup_once
  touch "$GAI_CONF"
  sed -i '/^\s*#\s*'"${SCRIPT_NAME}"'\s*managed: prefer IPv4\s*$/d' "$GAI_CONF" || true
  sed -i '/^\s*precedence\s\+::ffff:0:0\/96\s\+[0-9]\+\s*$/d' "$GAI_CONF" || true
  ok "宸叉仮澶嶏細IPv6 鍊惧悜锛堥粯璁わ級"
}

restore_gai_default() {
  info "缃戠粶锛氭仮澶� gai.conf锛堝洖鍒板浠界姸鎬侊級"
  if [[ -f "${BACKUP_BASE}/gai.conf.orig" ]]; then
    cp -a "${BACKUP_BASE}/gai.conf.orig" "$GAI_CONF" || true
    ok "宸叉仮澶� gai.conf.orig"
  else
    warn "鏈壘鍒� gai.conf.orig锛氭敼涓虹Щ闄よ剼鏈啓鍏ヨ鍒�"
    prefer_ipv6 || true
  fi
}

# ---------------- BBR / TCP 璋冧紭 ----------------
bbr_check() {
  echo "================ BBR 妫€娴� ================"
  echo "kernel=$(uname -r)"
  local avail cur
  avail="$(cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null || echo "")"
  cur="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "N/A")"
  echo "褰撳墠=${cur}"
  echo "鍙敤=${avail:-N/A}"
  if echo " $avail " | grep -q " bbr "; then
    ok "鏀寔 bbr"
  else
    warn "鏈湅鍒� bbr锛堝彲鑳藉唴鏍镐笉鍚�/妯″潡涓嶅彲鐢級"
  fi
  echo "=========================================="
}

tcp_tune_apply() {
  info "TCP锛氫竴閿皟浼橈紙BBR + FQ + 甯哥敤鍙傛暟锛�"
  have_cmd modprobe && modprobe tcp_bbr >/dev/null 2>&1 || true
  rm -f "$DMIT_TCP_SYSCTL_FILE" >/dev/null 2>&1 || true
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
  ok "宸插簲鐢� TCP 璋冧紭"
  bbr_check
}

tcp_restore_system_default() {
  info "TCP锛氭仮澶嶇郴缁熼粯璁わ紙CUBIC + pfifo_fast锛�"
  rm -f "$TUNE_SYSCTL_FILE" || true
  rm -f "$DMIT_TCP_SYSCTL_FILE" || true
  sysctl -w net.core.default_qdisc=pfifo_fast >/dev/null 2>&1 || true
  sysctl -w net.ipv4.tcp_congestion_control=cubic >/dev/null 2>&1 || true
  sysctl_apply_all
  ok "宸叉仮澶� TCP 绯荤粺榛樿"
}

tcp_restore_dmit_default() {
  info "TCP锛氭仮澶� DMIT 榛樿锛堜綘鎻愪緵鐨勫弬鏁帮級"
  rm -f "$TUNE_SYSCTL_FILE" >/dev/null 2>&1 || true
  write_file "$DMIT_TCP_SYSCTL_FILE" \
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
  have_cmd modprobe && modprobe tcp_bbr >/dev/null 2>&1 || true
  sysctl_apply_all
  ok "宸插簲鐢� DMIT 榛樿 TCP 鍙傛暟"
  bbr_check
}

tcp_restore_menu() {
  echo
  echo -e "${c_bold}${c_white}TCP 鎭㈠锛堥€夋嫨涓€绉嶆仮澶嶆柟妗堬級${c_reset}"
  echo "  1) 鎭㈠绯荤粺榛樿锛圕UBIC锛�"
  echo "  2) 鎭㈠ DMIT 榛樿锛圔BR 鍙傛暟锛�"
  echo "  0) 杩斿洖"
  local c=""
  read_tty "閫夋嫨> " c ""
  case "$c" in
    1) tcp_restore_system_default ;;
    2) tcp_restore_dmit_default ;;
    0) return 0 ;;
    *) warn "鏃犳晥閫夐」" ;;
  esac
}

# ---------------- DNS 鍒囨崲/鎭㈠ ----------------
dns_backup_once() {
  ensure_dir "$BACKUP_BASE"
  if [[ -e /etc/resolv.conf ]] && [[ ! -e "$RESOLV_BACKUP" ]]; then
    cp -a /etc/resolv.conf "$RESOLV_BACKUP" 2>/dev/null || true
    ok "宸插浠� resolv.conf.orig"
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
    *) warn "鏈煡 DNS 鏂规"; return 1 ;;
  esac

  info "DNS锛氬垏鎹㈠埌 ${which}"
  if is_resolved_active && have_cmd resolvectl; then
    dns_apply_resolved "$ifc" "$dns1" "$dns2"
    ok "宸查€氳繃 systemd-resolved 搴旂敤锛�$ifc锛�"
  else
    dns_apply_resolvconf "$dns1" "$dns2"
    ok "宸插啓鍏� /etc/resolv.conf"
  fi

  if dns_resolve_ok; then ok "DNS 瑙ｆ瀽锛氭甯�"; else warn "DNS 瑙ｆ瀽锛氫粛寮傚父锛堝彲璇曞彟涓€缁� DNS锛�"; fi
}

dns_switch_menu() {
  local ifc; ifc="$(default_iface)"
  echo
  echo -e "${c_bold}${c_white}DNS 鍒囨崲锛堟洿鎹㈣В鏋愭湇鍔″櫒锛�${c_reset}  ${c_dim}(鎺ュ彛: $ifc)${c_reset}"
  echo "  1) Cloudflare  (1.1.1.1 / 1.0.0.1)"
  echo "  2) Google      (8.8.8.8 / 8.8.4.4)"
  echo "  3) Quad9       (9.9.9.9 / 149.112.112.112)"
  echo "  0) 杩斿洖"
  local c=""
  read_tty "閫夋嫨> " c ""
  case "$c" in
    1) dns_set "cloudflare" "$ifc" ;;
    2) dns_set "google" "$ifc" ;;
    3) dns_set "quad9" "$ifc" ;;
    0) return 0 ;;
    *) warn "鏃犳晥閫夐」" ;;
  esac
}

dns_restore() {
  local ifc; ifc="$(default_iface)"
  info "DNS锛氭仮澶嶅埌鑴氭湰杩愯鍓嶇殑鐘舵€�"
  if is_resolved_active && have_cmd resolvectl; then
    resolvectl revert "$ifc" >/dev/null 2>&1 || true
    resolvectl flush-caches >/dev/null 2>&1 || true
    ok "宸插 $ifc 鎵ц resolvectl revert"
  fi

  if [[ -e "$RESOLV_BACKUP" ]]; then
    cp -a "$RESOLV_BACKUP" /etc/resolv.conf 2>/dev/null || true
    ok "宸叉仮澶� /etc/resolv.conf锛堟潵鑷浠斤級"
  else
    warn "鏈壘鍒板浠斤細$RESOLV_BACKUP"
  fi

  if dns_resolve_ok; then ok "DNS 瑙ｆ瀽锛氭甯�"; else warn "DNS 瑙ｆ瀽锛氫粛寮傚父锛堟鏌ヤ笂娓�/闃茬伀澧欙級"; fi
}

# ---------------- MTU 鑷姩鎺㈡祴/璁剧疆 ----------------
mtu_current() {
  local ifc; ifc="$(default_iface)"
  ip link show "$ifc" 2>/dev/null | awk '/mtu/{for(i=1;i<=NF;i++) if($i=="mtu"){print $(i+1); exit}}' || true
}

ping_payload_ok_v4() {
  local host="$1" payload="$2"
  ping -4 -c 1 -W 1 -M do -s "$payload" "$host" >/dev/null 2>&1
}

mtu_probe_v4() {
  local host="1.1.1.1"
  if ! ping -4 -c 1 -W 1 "$host" >/dev/null 2>&1; then host="8.8.8.8"; fi
  if ! ping -4 -c 1 -W 1 "$host" >/dev/null 2>&1; then
    warn "IPv4 ping 涓嶉€氾紝鏃犳硶鎺㈡祴 MTU锛堝厛妫€鏌ョ綉缁滐級"
    return 1
  fi

  info "MTU 鎺㈡祴锛氬 $host 鍋� DF 鎺㈡祴"
  local lo=1200 hi=1472 mid best=0
  while [[ $lo -le $hi ]]; do
    mid=$(( (lo + hi) / 2 ))
    if ping_payload_ok_v4 "$host" "$mid"; then
      best="$mid"; lo=$((mid + 1))
    else
      hi=$((mid - 1))
    fi
  done

  if [[ "$best" -le 0 ]]; then warn "鏈帰娴嬪埌鍙敤鍊�"; return 1; fi
  local mtu=$((best + 28))
  ok "鎺ㄨ崘 MTU=$mtu"
  echo "$mtu"
}

mtu_apply_runtime() {
  local mtu="$1"
  local ifc; ifc="$(default_iface)"
  info "MTU锛氫复鏃惰缃紙$ifc 鈫� $mtu锛�"
  ip link set dev "$ifc" mtu "$mtu" >/dev/null 2>&1 || { warn "璁剧疆澶辫触"; return 1; }
  ok "宸蹭复鏃剁敓鏁堬紙褰撳墠 MTU=$(mtu_current)锛�"
}

mtu_enable_persist_systemd() {
  local mtu="$1"
  local ifc; ifc="$(default_iface)"
  if ! is_systemd; then
    warn "鏃� systemd锛氭棤娉曠敤 service 鎸佷箙鍖�"
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
  ok "宸叉寔涔呭寲锛坰ystemd锛夛細dmit-mtu.service"
}

mtu_disable_persist() {
  info "MTU锛氱Щ闄ゆ寔涔呭寲璁剧疆锛堟仮澶嶇敱绯荤粺鎺ョ锛�"
  if is_systemd; then
    systemctl disable dmit-mtu.service >/dev/null 2>&1 || true
    systemctl stop dmit-mtu.service >/dev/null 2>&1 || true
    rm -f "$MTU_SERVICE" "$MTU_VALUE_FILE" || true
    systemctl daemon-reload >/dev/null 2>&1 || true
    ok "宸茬Щ闄� dmit-mtu.service"
  else
    warn "鏃� systemd锛氭棤闇€绉婚櫎 service"
  fi
  warn "杩愯鏃� MTU 涓嶄細鑷姩鍥炲埌 1500锛屽闇€鍙墽琛岋細ip link set dev $(default_iface) mtu 1500"
}

mtu_menu() {
  local cur; cur="$(mtu_current || echo "")"
  echo
  echo -e "${c_bold}${c_white}MTU 宸ュ叿锛堟帰娴� / 璁剧疆 / 鎸佷箙鍖栵級${c_reset}  ${c_dim}(鎺ュ彛: $(default_iface)锛屽綋鍓�: ${cur:-N/A})${c_reset}"
  echo "  1) 鑷姩鎺㈡祴 MTU锛堟帹鑽愬€硷級"
  echo "  2) 鎵嬪姩璁剧疆 MTU锛堜复鏃剁敓鏁堬級"
  echo "  3) 鎺㈡祴骞惰缃� MTU锛堜复鏃剁敓鏁堬級"
  echo "  4) 鎺㈡祴骞惰缃� MTU锛堝紑鏈鸿嚜鍔ㄧ敓鏁堬級"
  echo "  5) 绉婚櫎 MTU 寮€鏈鸿嚜鍔ㄨ缃�"
  echo "  0) 杩斿洖"
  local c=""
  read_tty "閫夋嫨> " c ""
  case "$c" in
    1) mtu_probe_v4 >/dev/null || true ;;
    2)
      local mtu=""
      read_tty "杈撳叆 MTU锛堝 1500/1480/1460/1450锛�> " mtu ""
      [[ "$mtu" =~ ^[0-9]+$ ]] || { warn "杈撳叆鏃犳晥"; return 0; }
      mtu_apply_runtime "$mtu" || true
      ;;
    3)
      local mtu; mtu="$(mtu_probe_v4 || true)"
      [[ -n "${mtu:-}" ]] && mtu_apply_runtime "$mtu" || true
      ;;
    4)
      local mtu; mtu="$(mtu_probe_v4 || true)"
      if [[ -n "${mtu:-}" ]]; then
        mtu_apply_runtime "$mtu" || true
        mtu_enable_persist_systemd "$mtu" || true
      fi
      ;;
    5) mtu_disable_persist || true ;;
    0) return 0 ;;
    *) warn "鏃犳晥閫夐」" ;;
  esac
}

# ---------------- 涓€閿綉缁滀綋妫€ / 浣撴+鑷姩淇 ----------------
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

  echo -e "${c_bold}${c_white}缃戠粶浣撴锛堟樉绀哄綋鍓嶇綉缁滃仴搴风姸鎬侊級${c_reset}  ${c_dim}(鎺ュ彛: $ifc)${c_reset}"
  echo -e "${c_green}${AD_TEXT}${c_reset}"
  echo -e "${c_dim}----------------------------------------------${c_reset}"

  print_kv "IPv4 鍑虹綉"       "$( [[ "$v4_net" == "YES" ]] && echo -e "${c_green}姝ｅ父${c_reset}" || echo -e "${c_yellow}寮傚父${c_reset}" )"
  print_kv "DNS 瑙ｆ瀽"        "$( [[ "$dns_ok" == "YES" ]] && echo -e "${c_green}姝ｅ父${c_reset}" || echo -e "${c_yellow}寮傚父${c_reset}" )"
  print_kv "IPv6 sysctl 寮€鍏�" "$ipv6_sysctl"
  print_kv "IPv6 鍏綉鍦板潃"   "$( [[ "$v6_addr" == "YES" ]] && echo -e "${c_green}鏈�${c_reset}" || echo -e "${c_yellow}鏃�${c_reset}" )"
  print_kv "IPv6 榛樿璺敱"   "$( [[ "$v6_route" == "YES" ]] && echo -e "${c_green}鏈�${c_reset}" || echo -e "${c_yellow}鏃�${c_reset}" )"
  print_kv "IPv6 鍑虹綉"       "$( [[ "$v6_net" == "YES" ]] && echo -e "${c_green}姝ｅ父${c_reset}" || echo -e "${c_yellow}寮傚父${c_reset}" )"
  print_kv "褰撳墠 MTU"        "$(mtu_current || echo N/A)"
  echo -e "${c_dim}----------------------------------------------${c_reset}"

  if [[ "$dns_ok" != "YES" && "$v4_net" == "YES" ]]; then
    warn "鍍� DNS 闂锛氳瘯璇曘€怐NS 鍒囨崲銆�"
  fi
  if [[ "$v6_addr" == "NO" || "$v6_route" == "NO" ]]; then
    warn "IPv6 缂哄湴鍧€/璺敱锛氳瘯璇曘€愪綋妫€+鑷姩淇銆戞垨銆愬紑鍚� IPv6銆�"
  fi
}

health_check_only() {
  health_check_core
  ok "浣撴瀹屾垚锛堟湭鏀瑰姩浠讳綍閰嶇疆锛�"
}

health_check_autofix() {
  local fixed=0
  health_check_core
  echo
  info "鑷姩淇锛氬皾璇曢噸鎷� IPv6 / 鍒锋柊 DNS锛堜笉鍋氶珮椋庨櫓鏀瑰姩锛�"

  if ! has_ipv6_global_addr || ! has_ipv6_default_route; then
    info "IPv6 涓嶅畬鏁达細鎵ц鈥滃紑鍚� IPv6锛堥噸鎷夊湴鍧€/璺敱锛夆€�"
    ipv6_enable || true
    fixed=1
  fi

  if is_resolved_active && have_cmd resolvectl; then
    info "鍒锋柊 systemd-resolved DNS 缂撳瓨"
    resolvectl flush-caches >/dev/null 2>&1 || true
    fixed=1
  fi

  echo
  health_check_core
  [[ "$fixed" -eq 1 ]] && ok "宸叉墽琛岃嚜鍔ㄤ慨澶嶅姩浣�" || ok "鏃犻渶淇"
}

# ---------------- SSH锛堝畨鍏ㄤ紭鍏� + 鎹㈢鍙ｏ級 ----------------
ssh_backup_once() {
  ensure_dir "$BACKUP_BASE"
  if [[ ! -f "$SSH_ORIG_TGZ" ]]; then
    info "SSH锛氬浠藉師濮嬮厤缃� 鈫� $SSH_ORIG_TGZ"
    tar -czf "$SSH_ORIG_TGZ" /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null || \
      tar -czf "$SSH_ORIG_TGZ" /etc/ssh/sshd_config 2>/dev/null || true
    ok "SSH 鍘熷閰嶇疆宸插浠�"
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
  echo -e "${c_dim}--- SSH 褰撳墠鐢熸晥閰嶇疆锛堣妭閫夛級---${c_reset}"
  if have_cmd sshd; then
    sshd -T 2>/dev/null | egrep -i 'port|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|challengeresponseauthentication|usepam|permitrootlogin|maxauthtries|logingracetime|clientaliveinterval|clientalivecountmax' || true
  else
    warn "鏈壘鍒� sshd 鍛戒护锛屾敼涓虹畝鍗� grep锛�"
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
    info "鍒涘缓鐢ㄦ埛锛�$user"
    if have_cmd useradd; then
      useradd -m -s /bin/bash "$user" >/dev/null 2>&1 || true
    elif have_cmd adduser; then
      adduser --disabled-password --gecos "" "$user" >/dev/null 2>&1 || true
    else
      warn "娌℃湁 useradd/adduser锛屾棤娉曞垱寤虹敤鎴�"
      return 1
    fi
  fi

  echo "${user}:${passwd}" | chpasswd
  ok "宸茶缃� ${user} 瀵嗙爜"
  echo -e "${c_green}${user} 瀵嗙爜锛�${passwd}${c_reset}"

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

  warn "鎺ㄨ崘妯″紡锛氭櫘閫氱敤鎴峰瘑鐮佺櫥褰曪紱root 绂佹瀵嗙爜锛堜粎瀵嗛挜锛�"
  warn "寤鸿淇濇寔褰撳墠 SSH 浼氳瘽涓嶈鏂紑锛岀‘璁ゆ柊鐢ㄦ埛鍙櫥褰曞悗鍐嶉€€鍑�"

  ssh_common_hardening_dropin
  ssh_dropin_set_line "PasswordAuthentication" "yes"
  ssh_dropin_set_line "PubkeyAuthentication" "yes"
  ssh_dropin_set_line "PermitRootLogin" "prohibit-password"

  sshd_set_kv_in_main "PasswordAuthentication" "yes"
  sshd_set_kv_in_main "PubkeyAuthentication" "yes"
  sshd_set_kv_in_main "PermitRootLogin" "prohibit-password"

  local p; p="$(ssh_random_pass)"
  [[ -z "${p:-}" ]] && { warn "鐢熸垚闅忔満瀵嗙爜澶辫触"; return 1; }
  ssh_create_user_with_password "$user" "$p" || true

  sshd_restart
  ok "宸查噸鍚� SSH锛堟帹鑽愭ā寮忓凡鐢熸晥锛�"
  sshd_status_hint
}

ssh_enable_password_keep_key_for_user() {
  local user="${1:-root}"
  local mode="${2:-random}" # random|custom
  local passwd="${3:-}"

  pkg_install openssh-server openssh-client
  ssh_backup_once

  warn "涓瓑妯″紡锛氬紑鍚瘑鐮佺櫥褰曪紙淇濈暀瀵嗛挜鐧诲綍锛�"
  warn "寤鸿淇濇寔褰撳墠 SSH 浼氳瘽涓嶈鏂紑锛岀‘璁ゅ瘑鐮佸彲鐧诲綍鍚庡啀閫€鍑�"

  ssh_common_hardening_dropin
  ssh_dropin_set_line "PasswordAuthentication" "yes"
  ssh_dropin_set_line "PubkeyAuthentication" "yes"

  sshd_set_kv_in_main "PasswordAuthentication" "yes"
  sshd_set_kv_in_main "PubkeyAuthentication" "yes"

  if [[ "$mode" == "random" ]]; then passwd="$(ssh_random_pass)"; fi
  [[ -z "${passwd:-}" ]] && { warn "瀵嗙爜涓虹┖锛氬彇娑�"; return 1; }

  if id "$user" >/dev/null 2>&1; then
    echo "${user}:${passwd}" | chpasswd
    ok "宸茶缃敤鎴峰瘑鐮侊細${user}"
    echo -e "${c_green}鏂板瘑鐮侊細${passwd}${c_reset}"
  else
    warn "鐢ㄦ埛涓嶅瓨鍦細$user锛堟湭璁剧疆瀵嗙爜锛�"
  fi

  sshd_restart
  ok "宸查噸鍚� SSH锛堝瘑鐮�+瀵嗛挜鍧囧彲锛�"
  sshd_status_hint
}

ssh_password_only_disable_key_risky() {
  local user="${1:-root}"
  local mode="${2:-random}" # random|custom
  local passwd="${3:-}"

  pkg_install openssh-server openssh-client
  ssh_backup_once

  warn "楂橀闄╂ā寮忥細浠呭瘑鐮佺櫥褰曪紙绂佺敤瀵嗛挜锛�"
  warn "鏈夐攣闂ㄩ闄╋細鍔″繀淇濇寔褰撳墠 SSH 浼氳瘽涓嶆柇寮€"
  local ans=""
  read_tty "纭缁х画璇疯緭鍏� YES > " ans ""
  if [[ "${ans}" != "YES" ]]; then
    warn "宸插彇娑�"
    return 0
  fi

  ssh_common_hardening_dropin
  ssh_dropin_set_line "PasswordAuthentication" "yes"
  ssh_dropin_set_line "PubkeyAuthentication" "no"

  sshd_set_kv_in_main "PasswordAuthentication" "yes"
  sshd_set_kv_in_main "PubkeyAuthentication" "no"

  if [[ "$mode" == "random" ]]; then passwd="$(ssh_random_pass)"; fi
  [[ -z "${passwd:-}" ]] && { warn "瀵嗙爜涓虹┖锛氬彇娑�"; return 1; }

  if id "$user" >/dev/null 2>&1; then
    echo "${user}:${passwd}" | chpasswd
    ok "宸茶缃敤鎴峰瘑鐮侊細${user}"
    echo -e "${c_green}鏂板瘑鐮侊細${passwd}${c_reset}"
  else
    warn "鐢ㄦ埛涓嶅瓨鍦細$user锛堟湭璁剧疆瀵嗙爜锛�"
  fi

  sshd_restart
  ok "宸查噸鍚� SSH锛堜粎瀵嗙爜鐧诲綍锛�"
  sshd_status_hint
}

ssh_restore_key_login() {
  ssh_backup_once
  info "SSH锛氭仮澶嶅師鏉ョ殑閰嶇疆锛堜粠澶囦唤杩樺師锛�"
  if [[ -f "$SSH_ORIG_TGZ" ]]; then
    tar -xzf "$SSH_ORIG_TGZ" -C / 2>/dev/null || true
    rm -f "$SSH_DROPIN_FILE" 2>/dev/null || true
    sshd_restart
    ok "宸叉仮澶� SSH 鍘熷閰嶇疆骞堕噸鍚�"
    sshd_status_hint
  else
    warn "鏈壘鍒板浠斤細$SSH_ORIG_TGZ"
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
      ok "宸插皾璇曟斁琛� ufw锛�${p}/tcp"
      return 0
    fi
  fi

  if have_cmd firewall-cmd; then
    if firewall-cmd --state >/dev/null 2>&1; then
      firewall-cmd --permanent --add-port="${p}/tcp" >/dev/null 2>&1 || true
      firewall-cmd --reload >/dev/null 2>&1 || true
      ok "宸插皾璇曟斁琛� firewalld锛�${p}/tcp"
      return 0
    fi
  fi

  if have_cmd iptables; then
    iptables -C INPUT -p tcp --dport "$p" -j ACCEPT >/dev/null 2>&1 || \
      iptables -I INPUT -p tcp --dport "$p" -j ACCEPT >/dev/null 2>&1 || true
    ok "宸插皾璇曟斁琛� iptables锛�${p}/tcp锛堝彲鑳戒笉鎸佷箙锛�"
    return 0
  fi

  warn "鏈娴嬪埌鍙敤闃茬伀澧欏伐鍏凤細璇疯嚜琛屾斁琛� ${p}/tcp"
  return 0
}

ssh_set_port() {
  local newp="$1"

  [[ "$newp" =~ ^[0-9]+$ ]] || { warn "绔彛蹇呴』鏄暟瀛�"; return 1; }
  if (( newp < 1 || newp > 65535 )); then warn "绔彛鑼冨洿 1-65535"; return 1; fi
  if (( newp < 1024 )); then warn "涓嶅缓璁娇鐢� 1024 浠ヤ笅绔彛"; fi

  local cur_ports; cur_ports="$(ssh_current_ports || echo "22")"
  if echo " $cur_ports " | grep -q " ${newp} "; then
    warn "绔彛 ${newp} 宸插湪 SSH 褰撳墠閰嶇疆涓�"
    return 0
  fi

  if port_in_use "$newp"; then
    warn "绔彛 ${newp} 浼间箮宸茶鍗犵敤锛堣鎹竴涓級"
    return 1
  fi

  pkg_install openssh-server openssh-client
  ssh_backup_once

  warn "鏇存崲 SSH 绔彛浼氬奖鍝嶆柊杩炴帴"
  warn "寮虹儓寤鸿淇濇寔褰撳墠 SSH 浼氳瘽涓嶈鏂紑"
  warn "璇峰厛娴嬭瘯锛歴sh -p ${newp} user@浣犵殑IP"

  ssh_dropin_set_line "Port" "$newp"
  sshd_set_port_in_main "$newp"
  firewall_open_port_best_effort "$newp"

  if have_cmd sshd; then
    if ! sshd -t >/dev/null 2>&1; then
      warn "sshd 閰嶇疆鏍￠獙澶辫触锛氬皢鎭㈠澶囦唤"
      ssh_restore_key_login || true
      return 1
    fi
  fi

  sshd_restart
  ok "宸插皾璇曞垏鎹� SSH 绔彛 鈫� ${newp}"
  echo -e "${c_green}鎻愮ず锛氳鐢ㄦ柊绔彛娴嬭瘯鐧诲綍鎴愬姛鍚庯紝鍐嶉€€鍑哄綋鍓嶄細璇�${c_reset}"
  echo -e "${c_dim}褰撳墠绔彛锛�$(ssh_current_ports)${c_reset}"
}

ssh_menu() {
  echo
  echo -e "${c_bold}${c_white}SSH 宸ュ叿锛堝畨鍏ㄤ紭鍏堬級${c_reset}"
  echo "  1) 鍒涘缓鏂扮敤鎴� + 寮€鍚瘑鐮佺櫥褰曪紙root 浠呭瘑閽ワ紝鏇村畨鍏級"
  echo "  2) 缁欑幇鏈夌敤鎴峰紑鍚瘑鐮佺櫥褰曪紙鍚屾椂淇濈暀瀵嗛挜锛�"
  echo "  3) 浠呭瘑鐮佺櫥褰曪紙绂佺敤瀵嗛挜锛岄珮椋庨櫓锛屽彲鑳介攣闂級"
  echo "  4) 鏇存崲 SSH 绔彛锛堝苟灏濊瘯鏀捐闃茬伀澧欙級"
  echo "  5) 鎭㈠ SSH 鍘熷閰嶇疆锛堢敤澶囦唤杩樺師锛�"
  echo "  6) 鏌ョ湅 SSH 褰撳墠鐢熸晥鐘舵€侊紙鍚鍙ｏ級"
  echo "  0) 杩斿洖"
  local c=""
  read_tty "閫夋嫨> " c ""
  case "$c" in
    1)
      local u=""
      read_tty "鏂扮敤鎴峰悕锛堥粯璁� dmit锛�> " u "dmit"
      ssh_safe_enable_password_for_user_keep_root_key "$u" || true
      ;;
    2)
      local u=""
      read_tty "鐢ㄦ埛鍚嶏紙榛樿 root锛�> " u "root"
      echo "  1) 闅忔満瀵嗙爜"
      echo "  2) 鑷畾涔夊瘑鐮�"
      local m=""
      read_tty "閫夋嫨> " m ""
      if [[ "$m" == "1" ]]; then
        ssh_enable_password_keep_key_for_user "$u" "random" "" || true
      elif [[ "$m" == "2" ]]; then
        local p=""
        read_tty "璁剧疆瀵嗙爜锛堟槑鏂囪緭鍏ワ級> " p ""
        ssh_enable_password_keep_key_for_user "$u" "custom" "$p" || true
      else
        warn "鏃犳晥閫夐」"
      fi
      ;;
    3)
      local u=""
      read_tty "鐢ㄦ埛鍚嶏紙榛樿 root锛�> " u "root"
      echo "  1) 闅忔満瀵嗙爜"
      echo "  2) 鑷畾涔夊瘑鐮�"
      local m=""
      read_tty "閫夋嫨> " m ""
      if [[ "$m" == "1" ]]; then
        ssh_password_only_disable_key_risky "$u" "random" "" || true
      elif [[ "$m" == "2" ]]; then
        local p=""
        read_tty "璁剧疆瀵嗙爜锛堟槑鏂囪緭鍏ワ級> " p ""
        ssh_password_only_disable_key_risky "$u" "custom" "$p" || true
      else
        warn "鏃犳晥閫夐」"
      fi
      ;;
    4)
      echo -e "${c_dim}褰撳墠 SSH 绔彛锛�$(ssh_current_ports)${c_reset}"
      local p=""
      read_tty "杈撳叆鏂扮鍙ｏ紙寤鸿 20000-59999锛�> " p ""
      ssh_set_port "$p" || true
      ;;
    5) ssh_restore_key_login || true ;;
    6)
      sshd_status_hint
      echo -e "${c_dim}褰撳墠绔彛锛�$(ssh_current_ports)${c_reset}"
      ;;
    0) return 0 ;;
    *) warn "鏃犳晥閫夐」" ;;
  esac
}

# ---------------- 娴嬭瘯锛氳繍琛屽閮ㄨ剼鏈� ----------------
run_remote_script() {
  local title="$1"
  local cmd="$2"
  local note="${3:-}"

  echo
  echo -e "${c_bold}${c_white}${title}${c_reset}"
  [[ -n "$note" ]] && echo -e "${c_yellow}${note}${c_reset}"
  echo -e "${c_dim}灏嗘墽琛岋細${cmd}${c_reset}"
  warn "娉ㄦ剰锛氳繖浼氫粠缃戠粶鎷夊彇骞惰繍琛岃剼鏈紙璇疯嚜琛岀‘璁ゆ潵婧愬彲淇★級"

  local ans=""
  read_tty "纭鎵ц锛熻緭鍏� y 鍥炶溅鎵ц锛屽叾瀹冭繑鍥� > " ans ""
  if [[ "${ans}" != "y" && "${ans}" != "Y" ]]; then
    warn "宸插彇娑�"
    return 0
  fi

  if echo "$cmd" | grep -q "curl"; then pkg_install curl; fi
  if echo "$cmd" | grep -q "wget"; then pkg_install wget; fi
  pkg_install bash

  bash -lc "$cmd" || true
  echo
  press_enter "鈫� 鍥炶溅杩斿洖娴嬭瘯鑿滃崟..."
}

tests_menu() {
  while true; do
    echo
    echo -e "${c_bold}${c_white}涓€閿祴璇曡剼鏈紙璺戞祴閫�/鍥炵▼/瑙ｉ攣鑴氭湰锛�${c_reset}"
    echo "  1) GB5 鎬ц兘娴嬭瘯锛圙eekbench 5锛�"
    echo "  2) Bench 缁煎悎娴嬭瘯锛坆ench.sh锛�"
    echo "  3) 涓夌綉鍥炵▼娴嬭瘯锛堜粎鍙傝€冿級"
    echo "  4) IP 璐ㄩ噺妫€娴嬶紙IP.Check.Place锛�"
    echo "  5) NodeQuality 娴嬭瘯"
    echo "  6) Telegram 寤惰繜娴嬭瘯"
    echo "  7) 娴佸獟浣撹В閿佹娴嬶紙check.unlock.media锛�"
    echo "  0) 杩斿洖"
    local c=""
    read_tty "閫夋嫨> " c ""
    case "$c" in
      1) run_remote_script "GB5 鎬ц兘娴嬭瘯"  "bash <(wget -qO- https://raw.githubusercontent.com/i-abc/GB5/main/gb5-test.sh)" ;;
      2) run_remote_script "Bench 缁煎悎娴嬭瘯" "curl -Lso- bench.sh | bash" ;;
      3) run_remote_script "涓夌綉鍥炵▼娴嬭瘯" "curl https://raw.githubusercontent.com/ludashi2020/backtrace/main/install.sh -sSf | sh" "澶囨敞锛氫粎鍙傝€�" ;;
      4) run_remote_script "IP 璐ㄩ噺妫€娴�" "bash <(curl -sL IP.Check.Place)" ;;
      5) run_remote_script "NodeQuality 娴嬭瘯" "bash <(curl -sL https://run.NodeQuality.com)" ;;
      6) run_remote_script "Telegram 寤惰繜娴嬭瘯" "bash <(curl -fsSL https://sub.777337.xyz/tgdc.sh)" ;;
      7) run_remote_script "娴佸獟浣撹В閿佹娴�" "bash <(curl -L -s check.unlock.media)" ;;
      0) return 0 ;;
      *) warn "鏃犳晥閫夐」" ;;
    esac
  done
}

# ---------------- 涓€閿繕鍘� ----------------
restore_all() {
  local ifc; ifc="$(default_iface)"
  info "涓€閿繕鍘燂細鎾ら攢鏈剼鏈敼鍔紙DNS/MTU/IPv6/TCP/浼樺厛绾�/SSH锛�"

  rm -f "$TUNE_SYSCTL_FILE" || true
  rm -f "$DMIT_TCP_SYSCTL_FILE" || true
  rm -f "$IPV6_SYSCTL_FILE" || true

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
    cp -a "$RESOLV_BACKUP" /etc/resolv.conf 2>/dev/null || true
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

  ok "宸茶繕鍘燂紙寤鸿鍐嶈窇涓€娆♀€滅綉缁滀綋妫€鈥濈‘璁ょ姸鎬侊級"
}

# ---------------- 涓昏彍鍗� ----------------
menu() {
  RUN_MODE="menu"
  while true; do
    banner

    echo -e "${c_bold}${c_white}銆愮綉缁滀慨澶嶃€�${c_reset}"
    echo -e "  ${c_cyan}1${c_reset}) 涓€閿綉缁滀綋妫€锛堝彧妫€鏌ワ紝涓嶆敼鍔級"
    echo -e "  ${c_cyan}2${c_reset}) 缃戠粶浣撴 + 鑷姩淇锛堥噸鎷塈Pv6/鍒锋柊DNS锛�"
    echo -e "  ${c_cyan}3${c_reset}) 寮€鍚� IPv6锛堥噸鎷夊叕缃慖Pv6/榛樿璺敱锛�"
    echo -e "  ${c_cyan}4${c_reset}) 鍏抽棴 IPv6锛堢郴缁熺骇绂佺敤锛�"
    echo -e "  ${c_cyan}5${c_reset}) DNS 涓€閿垏鎹紙Cloudflare/Google/Quad9锛�"
    echo -e "  ${c_cyan}6${c_reset}) DNS 涓€閿仮澶嶏紙鍥炲埌鑴氭湰杩愯鍓嶏級"
    echo -e "  ${c_cyan}7${c_reset}) MTU 鑷姩鎺㈡祴/璁剧疆锛堣В鍐虫柇娴�/涓㈠寘锛�"
    echo -e "  ${c_cyan}8${c_reset}) IPv4 浼樺厛锛堢郴缁熻В鏋愪紭鍏堣蛋IPv4锛�"
    echo -e "  ${c_cyan}9${c_reset}) IPv6 浼樺厛锛堟仮澶嶉粯璁ゅ€惧悜锛�"
    echo -e "  ${c_cyan}10${c_reset}) 鎭㈠ IPv4/IPv6 浼樺厛绾э紙鐢ㄥ浠借繕鍘燂級"

    echo
    echo -e "${c_bold}${c_white}銆怲CP/BBR銆�${c_reset}"
    echo -e "  ${c_cyan}11${c_reset}) 涓€閿� TCP 璋冧紭锛圔BR+FQ锛�"
    echo -e "  ${c_cyan}12${c_reset}) TCP 鎭㈠锛堢郴缁熼粯璁�/DMIT榛樿锛�"
    echo -e "  ${c_cyan}13${c_reset}) 妫€娴嬬郴缁熸槸鍚︽敮鎸� BBR"

    echo
    echo -e "${c_bold}${c_white}銆愮郴缁�/瀹夊叏銆�${c_reset}"
    echo -e "  ${c_cyan}14${c_reset}) 璁剧疆绯荤粺鏃跺尯涓轰腑鍥斤紙Asia/Shanghai锛�"
    echo -e "  ${c_cyan}15${c_reset}) SSH 瀹夊叏宸ュ叿锛堝瘑鐮�/瀵嗛挜/鎹㈢鍙ｏ級"

    echo
    echo -e "${c_bold}${c_white}銆愭祴璇曞伐鍏枫€�${c_reset}"
    echo -e "  ${c_cyan}16${c_reset}) 涓€閿祴璇曡剼鏈紙GB5/Bench/鍥炵▼/IP璐ㄩ噺/瑙ｉ攣锛�"

    echo
    echo -e "${c_bold}${c_white}銆愬伐鍏风銆�${c_reset}"
    echo -e "  ${c_cyan}17${c_reset}) 涓€閿繕鍘燂紙鎾ら攢鏈剼鏈墍鏈夋敼鍔級"
    echo -e "  ${c_cyan}18${c_reset}) 淇濆瓨鐜蹇収锛堢敤浜庢帓闅�/鍙戝伐鍗曪級"

    echo
    echo -e "  ${c_cyan}0${c_reset}) 閫€鍑�"
    echo -e "${c_dim}----------------------------------------------${c_reset}"

    local choice=""
    read_tty "閫夋嫨> " choice ""
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
      12) tcp_restore_menu; pause_if_menu ;;
      13) bbr_check; pause_if_menu ;;
      14) set_timezone_china; pause_if_menu ;;
      15) ssh_menu; pause_if_menu ;;
      16) tests_menu; pause_if_menu ;;
      17) restore_all; pause_if_menu ;;
      18) env_snapshot; pause_if_menu ;;
      0) exit 0 ;;
      *) warn "鏃犳晥閫夐」"; pause_if_menu ;;
    esac
  done
}

main() {
  need_root
  menu
}
main "$@"