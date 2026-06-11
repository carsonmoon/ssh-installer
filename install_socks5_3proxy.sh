#!/usr/bin/env bash
set -Eeuo pipefail

VERSION="1.0.0"
CONFIG_DIR="/etc/3proxy"
CONFIG_FILE="${CONFIG_DIR}/3proxy.cfg"
SERVICE_FILE="/etc/systemd/system/socks5-3proxy.service"
IP_BIND_SCRIPT="/usr/local/sbin/socks5-extra-ips.sh"
IP_BIND_SERVICE="/etc/systemd/system/socks5-extra-ips.service"
NODES_TXT="/root/socks5_nodes.txt"
NODES_CSV="/root/socks5_nodes.csv"

IPS_INPUT=""
SOCKS_USER=""
SOCKS_PASS=""
START_PORT="1080"
PORT_MODE="fixed"
PORT_STEP="1"
MAX_NODES="5000"
BIND_MISSING="ask"
IFACE=""
FORCE="no"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
die() { echo -e "${RED}[ERR]${NC} $*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
一键搭建 SOCKS5 节点，适配 Debian 12 / Ubuntu 22.04+

用法：
  bash install_socks5_3proxy.sh --ips "203.0.113.10-203.0.113.20" --user myuser --pass mypass

常用参数：
  --ips              IP 输入，支持单 IP、IP 段、CIDR、星号通配；多个用逗号或空格分隔
                     示例："1.2.3.4"、"1.2.3.4-1.2.3.20"、"1.2.3.0/28"、"1.2.3.*"
  --user             SOCKS5 用户名
  --pass             SOCKS5 密码
  --port             起始端口，默认 1080
  --port-mode        fixed 或 increment；默认 fixed
                     fixed：每个 IP 使用同一个端口，例如 ip:1080:user:pass
                     increment：端口递增，例如 ip1:1080、ip2:1081
  --port-step        递增步长，默认 1，仅 port-mode=increment 时生效
  --max-nodes        最大生成节点数量，默认 5000
  --bind-missing     ask / yes / no；是否把未绑定的 IP 添加到网卡，默认 ask
  --iface            绑定缺失 IP 时使用的网卡，例如 eth0、ens3；不填则自动检测默认出口网卡
  --force            非交互模式，覆盖旧配置并自动重启服务
  --help             查看帮助

生成文件：
  /etc/3proxy/3proxy.cfg
  /root/socks5_nodes.txt
  /root/socks5_nodes.csv

示例：
  bash install_socks5_3proxy.sh --ips "203.0.113.10-203.0.113.20" --user u1 --pass p1 --port 1080
  bash install_socks5_3proxy.sh --ips "203.0.113.0/28" --user u1 --pass p1 --port-mode increment --port 20000
  bash install_socks5_3proxy.sh --ips "203.0.113.*" --user u1 --pass p1 --bind-missing yes --iface eth0
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ips) IPS_INPUT="${2:-}"; shift 2 ;;
    --user) SOCKS_USER="${2:-}"; shift 2 ;;
    --pass) SOCKS_PASS="${2:-}"; shift 2 ;;
    --port) START_PORT="${2:-}"; shift 2 ;;
    --port-mode) PORT_MODE="${2:-}"; shift 2 ;;
    --port-step) PORT_STEP="${2:-}"; shift 2 ;;
    --max-nodes) MAX_NODES="${2:-}"; shift 2 ;;
    --bind-missing) BIND_MISSING="${2:-}"; shift 2 ;;
    --iface) IFACE="${2:-}"; shift 2 ;;
    --force) FORCE="yes"; shift ;;
    --help|-h) usage; exit 0 ;;
    *) die "未知参数：$1。使用 --help 查看帮助。" ;;
  esac
done

need_root() {
  [[ "$(id -u)" -eq 0 ]] || die "请使用 root 运行：sudo bash $0 ..."
}

detect_os() {
  [[ -r /etc/os-release ]] || die "无法识别系统版本。"
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID}" in
    debian)
      [[ "${VERSION_ID%%.*}" -ge 12 ]] || die "当前 Debian ${VERSION_ID} 不在支持范围内，需要 Debian 12 或更高。"
      ;;
    ubuntu)
      local major minor
      major="${VERSION_ID%%.*}"
      minor="${VERSION_ID#*.}"
      [[ "${major}" -gt 22 || ( "${major}" -eq 22 && "${minor%%.*}" -ge 04 ) ]] || die "当前 Ubuntu ${VERSION_ID} 不在支持范围内，需要 Ubuntu 22.04 或更高。"
      ;;
    *)
      die "当前系统 ${PRETTY_NAME:-unknown} 不在支持范围内，仅支持 Debian 12 / Ubuntu 22.04+。"
      ;;
  esac
  log "系统检查通过：${PRETTY_NAME}"
}

prompt_if_empty() {
  local var_name="$1" prompt="$2" default_value="${3:-}"
  local current="${!var_name}"
  if [[ -n "${current}" ]]; then
    return
  fi
  if [[ -n "${default_value}" ]]; then
    read -r -p "${prompt} [${default_value}]: " current
    current="${current:-${default_value}}"
  else
    read -r -p "${prompt}: " current
  fi
  printf -v "${var_name}" '%s' "${current}"
}

validate_number() {
  local name="$1" value="$2" min="$3" max="$4"
  [[ "${value}" =~ ^[0-9]+$ ]] || die "${name} 必须是数字。"
  (( value >= min && value <= max )) || die "${name} 必须在 ${min}-${max} 之间。"
}

validate_credentials() {
  [[ -n "${SOCKS_USER}" ]] || die "用户名不能为空。"
  [[ -n "${SOCKS_PASS}" ]] || die "密码不能为空。"
  [[ "${SOCKS_USER}" =~ ^[A-Za-z0-9_.@%+=,-]+$ ]] || die "用户名只能包含字母、数字和 . _ @ % + = , -"
  [[ "${SOCKS_PASS}" =~ ^[A-Za-z0-9_.@%+=,-]+$ ]] || die "密码只能包含字母、数字和 . _ @ % + = , -"
}

validate_options() {
  prompt_if_empty IPS_INPUT "请输入服务器 IP 段/CIDR/列表"
  prompt_if_empty SOCKS_USER "请输入 SOCKS5 用户名"
  prompt_if_empty SOCKS_PASS "请输入 SOCKS5 密码"
  validate_credentials
  validate_number "起始端口" "${START_PORT}" 1 65535
  validate_number "递增步长" "${PORT_STEP}" 0 65535
  validate_number "最大生成数量" "${MAX_NODES}" 1 100000
  [[ "${PORT_MODE}" == "fixed" || "${PORT_MODE}" == "increment" ]] || die "--port-mode 只能是 fixed 或 increment。"
  [[ "${BIND_MISSING}" == "ask" || "${BIND_MISSING}" == "yes" || "${BIND_MISSING}" == "no" ]] || die "--bind-missing 只能是 ask / yes / no。"
}

ip_to_int() {
  local ip="$1" a b c d
  IFS=. read -r a b c d <<<"${ip}"
  [[ "${a:-}" =~ ^[0-9]+$ && "${b:-}" =~ ^[0-9]+$ && "${c:-}" =~ ^[0-9]+$ && "${d:-}" =~ ^[0-9]+$ ]] || return 1
  (( a <= 255 && b <= 255 && c <= 255 && d <= 255 )) || return 1
  echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}

int_to_ip() {
  local n="$1"
  echo "$(( (n >> 24) & 255 )).$(( (n >> 16) & 255 )).$(( (n >> 8) & 255 )).$(( n & 255 ))"
}

append_ip() {
  local ip="$1"
  [[ "$(ip_to_int "${ip}" 2>/dev/null || true)" != "" ]] || die "无效 IP：${ip}"
  IPS+=("${ip}")
  (( ${#IPS[@]} <= MAX_NODES )) || die "节点数量超过上限 ${MAX_NODES}，请缩小 IP 范围或调高 --max-nodes。"
}

expand_range() {
  local start_ip="$1" end_ip="$2" start end n
  start="$(ip_to_int "${start_ip}")" || die "无效 IP：${start_ip}"
  end="$(ip_to_int "${end_ip}")" || die "无效 IP：${end_ip}"
  (( start <= end )) || die "IP 段起始值不能大于结束值：${start_ip}-${end_ip}"
  for (( n=start; n<=end; n++ )); do
    append_ip "$(int_to_ip "${n}")"
  done
}

expand_cidr() {
  local cidr="$1" base prefix base_int mask network size i
  base="${cidr%%/*}"
  prefix="${cidr##*/}"
  [[ "${prefix}" =~ ^[0-9]+$ && "${prefix}" -ge 0 && "${prefix}" -le 32 ]] || die "无效 CIDR：${cidr}"
  base_int="$(ip_to_int "${base}")" || die "无效 CIDR：${cidr}"
  size=$(( 1 << (32 - prefix) ))
  (( size <= MAX_NODES )) || die "CIDR ${cidr} 会生成 ${size} 个 IP，超过上限 ${MAX_NODES}。"
  if (( prefix == 0 )); then
    mask=0
  else
    mask=$(( (0xffffffff << (32 - prefix)) & 0xffffffff ))
  fi
  network=$(( base_int & mask ))
  for (( i=0; i<size; i++ )); do
    append_ip "$(int_to_ip $(( network + i )) )"
  done
}

expand_wildcard() {
  local pattern="$1" a b c d p1 p2 p3 p4
  IFS=. read -r p1 p2 p3 p4 <<<"${pattern}"
  [[ -n "${p1:-}" && -n "${p2:-}" && -n "${p3:-}" && -n "${p4:-}" ]] || die "无效通配 IP：${pattern}"
  for a in $(part_values "${p1}" "${pattern}"); do
    for b in $(part_values "${p2}" "${pattern}"); do
      for c in $(part_values "${p3}" "${pattern}"); do
        for d in $(part_values "${p4}" "${pattern}"); do
          append_ip "${a}.${b}.${c}.${d}"
        done
      done
    done
  done
}

part_values() {
  local part="$1" pattern="$2" n
  if [[ "${part}" == "*" ]]; then
    for (( n=0; n<=255; n++ )); do echo "${n}"; done
  else
    [[ "${part}" =~ ^[0-9]+$ && "${part}" -le 255 ]] || die "无效通配 IP：${pattern}"
    echo "${part}"
  fi
}

parse_ips() {
  IPS=()
  local normalized token start end
  normalized="${IPS_INPUT//,/ }"
  for token in ${normalized}; do
    if [[ "${token}" == */* ]]; then
      expand_cidr "${token}"
    elif [[ "${token}" == *"*"* ]]; then
      expand_wildcard "${token}"
    elif [[ "${token}" == *-* ]]; then
      start="${token%%-*}"
      end="${token##*-}"
      expand_range "${start}" "${end}"
    else
      append_ip "${token}"
    fi
  done
  (( ${#IPS[@]} > 0 )) || die "没有解析到任何 IP。"

  local deduped=() seen=" " ip
  for ip in "${IPS[@]}"; do
    if [[ "${seen}" != *" ${ip} "* ]]; then
      deduped+=("${ip}")
      seen+="${ip} "
    fi
  done
  IPS=("${deduped[@]}")
  log "解析到 ${#IPS[@]} 个唯一 IP。"
}

detect_default_iface() {
  if [[ -n "${IFACE}" ]]; then
    ip link show "${IFACE}" >/dev/null 2>&1 || die "网卡不存在：${IFACE}"
    return
  fi
  IFACE="$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
  [[ -n "${IFACE}" ]] || die "无法自动检测默认网卡，请使用 --iface 指定。"
}

local_ip_set() {
  ip -o -4 addr show scope global | awk '{split($4,a,"/"); print a[1]}'
}

find_missing_ips() {
  local current ip
  current=" $(local_ip_set | tr '\n' ' ') "
  MISSING_IPS=()
  for ip in "${IPS[@]}"; do
    if [[ "${current}" != *" ${ip} "* ]]; then
      MISSING_IPS+=("${ip}")
    fi
  done
}

bind_missing_ips() {
  find_missing_ips
  if (( ${#MISSING_IPS[@]} == 0 )); then
    log "所有目标 IP 已绑定到本机。"
    return
  fi

  warn "有 ${#MISSING_IPS[@]} 个 IP 当前没有绑定到本机网卡。"
  if [[ "${BIND_MISSING}" == "ask" && "${FORCE}" != "yes" ]]; then
    read -r -p "是否自动绑定这些 IP 并设置开机生效？[y/N]: " answer
    if [[ "${answer}" =~ ^[Yy]$ ]]; then
      BIND_MISSING="yes"
    else
      BIND_MISSING="no"
    fi
  fi

  if [[ "${BIND_MISSING}" != "yes" ]]; then
    warn "未绑定缺失 IP。3proxy 对这些 IP 的监听可能会启动失败；请先在服务商后台和系统网卡中确认 IP 已可用。"
    return
  fi

  detect_default_iface
  cat >"${IP_BIND_SCRIPT}" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
IFACE="${IFACE}"
IPS=(
$(printf '  "%s"\n' "${MISSING_IPS[@]}")
)
for ip in "\${IPS[@]}"; do
  /usr/sbin/ip addr replace "\${ip}/32" dev "\${IFACE}"
done
EOF
  chmod 700 "${IP_BIND_SCRIPT}"

  cat >"${IP_BIND_SERVICE}" <<EOF
[Unit]
Description=Bind extra IPv4 addresses for SOCKS5 service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${IP_BIND_SCRIPT}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now socks5-extra-ips.service
  log "已通过 ${IP_BIND_SERVICE} 绑定缺失 IP 到 ${IFACE}。"
}

install_3proxy() {
  if command -v 3proxy >/dev/null 2>&1; then
    log "3proxy 已安装：$(command -v 3proxy)"
    return
  fi

  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  if ! apt-get install -y 3proxy iproute2 ca-certificates; then
    if grep -qi '^ID=ubuntu' /etc/os-release; then
      warn "直接安装 3proxy 失败，尝试启用 Ubuntu universe 仓库后重试。"
      apt-get install -y software-properties-common
      add-apt-repository -y universe
      apt-get update
      apt-get install -y 3proxy iproute2 ca-certificates
    else
      die "安装 3proxy 失败，请检查 apt 源。"
    fi
  fi
  command -v 3proxy >/dev/null 2>&1 || die "3proxy 安装后仍不可用。"
  log "3proxy 安装完成。"
}

build_nodes() {
  NODES=()
  local idx=0 ip port
  for ip in "${IPS[@]}"; do
    if [[ "${PORT_MODE}" == "increment" ]]; then
      port=$(( START_PORT + idx * PORT_STEP ))
    else
      port="${START_PORT}"
    fi
    (( port >= 1 && port <= 65535 )) || die "端口超出 1-65535：${port}"
    NODES+=("${ip}:${port}:${SOCKS_USER}:${SOCKS_PASS}")
    idx=$(( idx + 1 ))
  done
}

write_3proxy_config() {
  mkdir -p "${CONFIG_DIR}" /var/log/3proxy
  if [[ -f "${CONFIG_FILE}" ]]; then
    local backup="${CONFIG_FILE}.bak.$(date +%Y%m%d%H%M%S)"
    if [[ "${FORCE}" != "yes" ]]; then
      read -r -p "检测到已有 ${CONFIG_FILE}，是否备份并覆盖？[y/N]: " answer
      [[ "${answer}" =~ ^[Yy]$ ]] || die "已取消。"
    fi
    cp -a "${CONFIG_FILE}" "${backup}"
    warn "旧配置已备份到 ${backup}"
  fi

  cat >"${CONFIG_FILE}" <<EOF
# Generated by install_socks5_3proxy.sh v${VERSION}
# Node format: host:port:user:pass
daemon
nscache 65536
maxconn 2000
timeouts 1 5 30 60 180 1800 15 60
log /var/log/3proxy/3proxy.log D
rotate 30
auth strong
users ${SOCKS_USER}:CL:${SOCKS_PASS}

EOF

  local node ip port idx=0
  for node in "${NODES[@]}"; do
    ip="${node%%:*}"
    port="${node#*:}"
    port="${port%%:*}"
    cat >>"${CONFIG_FILE}" <<EOF
# ${node}
allow ${SOCKS_USER}
socks -n -a -p${port} -i${ip} -e${ip}
flush

EOF
    idx=$(( idx + 1 ))
  done
  chmod 600 "${CONFIG_FILE}"
  log "已写入 3proxy 配置：${CONFIG_FILE}"
}

write_systemd_service() {
  local binary
  binary="$(command -v 3proxy)"
  cat >"${SERVICE_FILE}" <<EOF
[Unit]
Description=SOCKS5 nodes by 3proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
ExecStart=${binary} ${CONFIG_FILE}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl disable --now 3proxy.service >/dev/null 2>&1 || true
  systemctl enable --now socks5-3proxy.service
  systemctl restart socks5-3proxy.service
  if ! systemctl is-active --quiet socks5-3proxy.service; then
    systemctl status socks5-3proxy.service --no-pager || true
    die "socks5-3proxy.service 启动失败，请检查上方 systemd 输出和 ${CONFIG_FILE}。"
  fi
  log "systemd 服务已启动：socks5-3proxy.service"
}

verify_listening_ports() {
  local first_node first_ip first_port
  first_node="${NODES[0]}"
  first_ip="${first_node%%:*}"
  first_port="${first_node#*:}"
  first_port="${first_port%%:*}"
  if ss -lnt | awk '{print $4}' | grep -Eq "(^|:)${first_port}$"; then
    log "监听检查通过：至少检测到 TCP ${first_port} 已监听。"
  else
    warn "未在 ss 输出中检测到 ${first_ip}:${first_port}，请运行：ss -lntp | grep 3proxy"
  fi
}

write_exports() {
  printf '%s\n' "${NODES[@]}" >"${NODES_TXT}"
  {
    echo 'host,port,user,pass,line'
    local node ip rest port user pass
    for node in "${NODES[@]}"; do
      ip="${node%%:*}"
      rest="${node#*:}"
      port="${rest%%:*}"
      rest="${rest#*:}"
      user="${rest%%:*}"
      pass="${rest#*:}"
      printf '"%s","%s","%s","%s","%s"\n' "${ip}" "${port}" "${user}" "${pass}" "${node}"
    done
  } >"${NODES_CSV}"
  chmod 600 "${NODES_TXT}" "${NODES_CSV}"
  log "节点清单已生成：${NODES_TXT}"
  log "CSV 清单已生成：${NODES_CSV}"
}

print_summary() {
  echo
  echo "================ SOCKS5 节点信息 ================"
  echo "节点数量：${#NODES[@]}"
  echo "认证信息：${SOCKS_USER}:${SOCKS_PASS}"
  echo "节点文件：${NODES_TXT}"
  echo "配置文件：${CONFIG_FILE}"
  echo "服务状态：systemctl status socks5-3proxy.service"
  echo
  echo "前 10 条节点："
  local count=0 node
  for node in "${NODES[@]}"; do
    echo "${node}"
    count=$(( count + 1 ))
    (( count >= 10 )) && break
  done
  if (( ${#NODES[@]} > 10 )); then
    echo "... 其余见 ${NODES_TXT}"
  fi
  echo
  warn "如果服务器启用了防火墙/安全组，请放行对应 TCP 端口：${START_PORT}$([[ "${PORT_MODE}" == "increment" ]] && echo " 起及递增端口")"
}

main() {
  need_root
  detect_os
  validate_options
  parse_ips
  install_3proxy
  bind_missing_ips
  build_nodes
  write_3proxy_config
  write_systemd_service
  verify_listening_ports
  write_exports
  print_summary
}

main "$@"
