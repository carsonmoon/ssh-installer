#!/usr/bin/env bash
#=============================================================
# SSH 密钥安装器（Debian 10-13 / Ubuntu 22.04+）
# 中文增强版，增加自动放行防火墙端口
#=============================================================

set -o pipefail

VERSION=4.0

RED="\033[31m"
GREEN="\033[1;32m"
YELLOW="\033[33m"
RESET="\033[0m"

INFO="[信息]"
WARN="[警告]"
ERROR="[错误]"

SSHD_CONFIG=${SSHD_CONFIG:-/etc/ssh/sshd_config}
SSHD_DROPIN_DIR=${SSHD_DROPIN_DIR:-/etc/ssh/sshd_config.d}
SSHD_DROPIN=${SSHD_DROPIN:-${SSHD_DROPIN_DIR}/00-key-installer.conf}

PORT_BLOCK_BEGIN="# BEGIN key-installer 管理端口"
PORT_BLOCK_END="# END key-installer 管理端口"

OVERWRITE=0
DISABLE_PASSWORD=0
RESTART_SSHD=0
ACTION_COUNT=0
KEY_SOURCE=""
KEY_ARG=""
SSH_PORT=""

# sudo 自动检测
if [ "${EUID}" -ne 0 ] && [ -z "${SUDO+x}" ]; then
    SUDO=sudo
else
    SUDO=${SUDO-}
fi

log_info() { echo -e "${INFO} $*"; }
log_warn() { echo -e "${WARN} $*"; }
log_error() { echo -e "${ERROR} $*" >&2; }

#=============================================================
# 使用说明
#=============================================================
USAGE() {
cat <<EOF
SSH 密钥安装器 ${VERSION}

用法:
  bash key.sh [选项]

功能选项:
  -o   覆盖模式（清空原有 authorized_keys）
  -g   从 GitHub 获取公钥（参数：用户名）
  -u   从 URL 获取公钥（参数：链接）
  -f   从本地文件读取公钥（参数：文件路径）
  -p   修改 SSH 端口（参数：端口号）
  -d   禁用 SSH 密码登录
  -h   显示帮助

示例:
  bash key.sh -g username
  bash key.sh -o -f ~/.ssh/id_ed25519.pub
  bash key.sh -d -p 2222 -g username
EOF
}

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        log_error "缺少依赖命令：$1"
        exit 1
    fi
}

run_as_root() {
    if [ -n "${SUDO}" ]; then
        ${SUDO} "$@"
    else
        "$@"
    fi
}

#=============================================================
# 系统检测
#=============================================================
detect_os() {
    if [ ! -r /etc/os-release ]; then
        log_warn "无法读取系统信息文件 /etc/os-release"
        return
    fi

    . /etc/os-release

    case "${ID:-}" in
        debian)
            log_info "当前系统：Debian ${VERSION_ID:-未知}"
            ;;
        ubuntu)
            log_info "当前系统：Ubuntu ${VERSION_ID:-未知}"
            ;;
        *)
            log_warn "未知系统：${PRETTY_NAME:-未知}"
            ;;
    esac
}

#=============================================================
# SSHD 路径
#=============================================================
find_sshd() {
    if command -v sshd >/dev/null 2>&1; then
        command -v sshd
        return
    fi

    for bin in /usr/sbin/sshd /usr/local/sbin/sshd; do
        [ -x "$bin" ] && echo "$bin" && return
    done

    return 1
}

check_sshd_config() {
    if [ ! -f "${SSHD_CONFIG}" ]; then
        log_error "未找到 SSH 配置文件：${SSHD_CONFIG}"
        exit 1
    fi
}

#=============================================================
# 确保 Include 机制
#=============================================================
ensure_managed_include() {
    check_sshd_config

    run_as_root mkdir -p "${SSHD_DROPIN_DIR}"
    run_as_root touch "${SSHD_DROPIN}"
    run_as_root chmod 0644 "${SSHD_DROPIN}"

    include_line="Include ${SSHD_DROPIN}"
    tmp_file=$(mktemp)

    awk -v include_line="${include_line}" '
        BEGIN { print include_line }
        $0 == include_line { next }
        { print }
    ' "${SSHD_CONFIG}" >"${tmp_file}"

    if ! cmp -s "${tmp_file}" "${SSHD_CONFIG}"; then
        log_info "已写入 SSH drop-in 管理配置"
        run_as_root install -m 0644 "${tmp_file}" "${SSHD_CONFIG}"
        RESTART_SSHD=1
    fi

    rm -f "${tmp_file}"
}

set_dropin_option() {
    key=$1
    value=$2

    ensure_managed_include

    if run_as_root grep -Eq "^[[:space:]]*#?[[:space:]]*${key}[[:space:]]+" "${SSHD_DROPIN}"; then
        run_as_root sed -i -E "s@^[[:space:]]*#?[[:space:]]*${key}[[:space:]].*@${key} ${value}@" "${SSHD_DROPIN}"
    else
        echo "${key} ${value}" | run_as_root tee -a "${SSHD_DROPIN}" >/dev/null
    fi

    RESTART_SSHD=1
}

enable_pubkey_auth() {
    log_info "启用 SSH 公钥认证"
    set_dropin_option "PubkeyAuthentication" "yes"
}

disable_password_login() {
    log_info "关闭 SSH 密码登录"
    set_dropin_option "PasswordAuthentication" "no"
    set_dropin_option "KbdInteractiveAuthentication" "no"
    set_dropin_option "ChallengeResponseAuthentication" "no"
}

#=============================================================
# 自动放行防火墙端口
#=============================================================
auto_allow_firewall_port() {
    log_info "检测并放行防火墙端口 ${SSH_PORT}"

    # UFW
    if command -v ufw >/dev/null 2>&1; then
        if ufw status 2>/dev/null | grep -q "Status: active"; then
            log_info "UFW 已启用，放行 TCP ${SSH_PORT}"
            run_as_root ufw allow "${SSH_PORT}/tcp"
        fi
    fi

    # firewalld
    if command -v firewall-cmd >/dev/null 2>&1; then
        if systemctl is-active firewalld >/dev/null 2>&1; then
            log_info "firewalld 已启用，放行 TCP ${SSH_PORT}"
            run_as_root firewall-cmd --permanent --add-port="${SSH_PORT}/tcp"
            run_as_root firewall-cmd --reload
        fi
    fi

    # iptables/nftables 提示
    if command -v nft >/dev/null 2>&1; then
        log_warn "检测到 nftables，请确认规则已允许 TCP ${SSH_PORT}"
    fi
    if command -v iptables >/dev/null 2>&1; then
        log_warn "检测到 iptables，请确认规则已允许 TCP ${SSH_PORT}"
    fi
}

#=============================================================
# SSH 端口处理
#=============================================================
validate_port() {
    case "${SSH_PORT}" in
        ''|*[!0-9]*) log_error "端口不合法：${SSH_PORT}"; exit 1 ;;
    esac

    if [ "${SSH_PORT}" -lt 1 ] || [ "${SSH_PORT}" -gt 65535 ]; then
        log_error "端口范围必须为 1-65535"
        exit 1
    fi
}

rewrite_ports_in_file() {
    file=$1
    managed=$2

    [ ! -f "$file" ] && return

    tmp_file=$(mktemp)

    awk -v port="${SSH_PORT}" -v begin="${PORT_BLOCK_BEGIN}" -v end="${PORT_BLOCK_END}" -v managed="${managed}" '
    BEGIN { in_block=0; printed=0 }

    $0 == begin { in_block=1; next }
    $0 == end { in_block=0; next }
    in_block { next }

    /^[[:space:]]*Port[[:space:]]+/ {
        print "# 已被 key-installer 注释: " $0
        next
    }

    {
        print
    }

    END {
        if (managed == "1" && printed == 0) {
            print begin
            print "Port " port
            print end
        }
    }
    ' "$file" >"$tmp_file"

    if ! cmp -s "$tmp_file" "$file"; then
        run_as_root install -m 0644 "$tmp_file" "$file"
        RESTART_SSHD=1
    fi

    rm -f "$tmp_file"
}

set_managed_port() {
    check_sshd_config
    rewrite_ports_in_file "${SSHD_CONFIG}" 1

    for conf in "${SSHD_DROPIN_DIR}"/*.conf; do
        [ -e "$conf" ] && rewrite_ports_in_file "$conf" 0
    done
}

change_port() {
    validate_port
    log_info "修改 SSH 端口为 ${SSH_PORT}"
    auto_allow_firewall_port
    set_managed_port
    log_warn "请确认云平台安全组已放行端口 ${SSH_PORT}"
}

#=============================================================
# 获取公钥
#=============================================================
fetch_keys() {
    case "${KEY_SOURCE}" in
        github)
            need_cmd curl
            [ -z "$KEY_ARG" ] && read -rp "请输入 GitHub 用户名: " KEY_ARG
            PUB_KEY=$(curl -fsSL "https://github.com/${KEY_ARG}.keys")
            ;;
        url)
            need_cmd curl
            [ -z "$KEY_ARG" ] && read -rp "请输入公钥URL: " KEY_ARG
            PUB_KEY=$(curl -fsSL "${KEY_ARG}")
            ;;
        file)
            [ -z "$KEY_ARG" ] && read -rp "请输入本地文件路径: " KEY_ARG
            PUB_KEY=$(cat "$KEY_ARG")
            ;;
        '')
            return
            ;;
        *)
            log_error "未知来源"
            exit 1
            ;;
    esac

    [ -z "$PUB_KEY" ] && log_error "未获取到任何公钥" && exit 1
}

is_valid_public_key_line() {
    case "$1" in
        ssh-rsa*|ssh-ed25519*|ecdsa-sha2-*|sk-ssh-*|sk-ecdsa-*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

key_blob() {
    echo "$1" | awk '{print $2}'
}

install_keys() {
    [ -z "$KEY_SOURCE" ] && return

    fetch_keys

    SSH_DIR="$HOME/.ssh"
    AUTH_KEYS="$SSH_DIR/authorized_keys"

    mkdir -p "$SSH_DIR"
    chmod 700 "$SSH_DIR"
    touch "$AUTH_KEYS"
    chmod 600 "$AUTH_KEYS"

    tmp=$(mktemp)

    while read -r line; do
        [ -z "$line" ] && continue

        is_valid_public_key_line "$line" || continue

        blob=$(key_blob "$line")

        grep -q "$blob" "$tmp" 2>/dev/null && continue

        echo "$line" >>"$tmp"
    done <<< "$PUB_KEY"

    if [ "${OVERWRITE}" -eq 1 ]; then
        cp "$tmp" "$AUTH_KEYS"
    else
        cat "$tmp" >>"$AUTH_KEYS"
    fi

    rm -f "$tmp"

    log_info "SSH 公钥写入完成"
    enable_pubkey_auth
}

test_sshd_config() {
    sshd_bin=$(find_sshd)
    [ -z "$sshd_bin" ] && return

    log_info "检测 SSH 配置"
    run_as_root "$sshd_bin" -t || {
        log_error "SSH 配置错误，已阻止重启"
        exit 1
    }
}

restart_sshd() {
    [ "$RESTART_SSHD" -ne 1 ] && return

    test_sshd_config

    log_info "重启 SSH 服务"

    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || \
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || \
    service ssh restart 2>/dev/null || service sshd restart 2>/dev/null

    log_info "SSH 服务已更新"
}

verify_effective_config() {
    sshd_bin=$(find_sshd)
    [ -z "$sshd_bin" ] && return

    run_as_root "$sshd_bin" -T 2>/dev/null | awk '
        $1=="port"{print "当前端口: "$2}
        $1=="passwordauthentication"{print "密码登录: "$2}
        $1=="pubkeyauthentication"{print "密钥登录: "$2}
    '
}

#=============================================================
# 参数解析
#=============================================================
parse_options() {
    while getopts ":og:u:f:p:dh" opt; do
        case "$opt" in
            o) OVERWRITE=1 ;;
            g) KEY_SOURCE=github; KEY_ARG="$OPTARG"; ACTION_COUNT=$((ACTION_COUNT+1)) ;;
            u) KEY_SOURCE=url; KEY_ARG="$OPTARG"; ACTION_COUNT=$((ACTION_COUNT+1)) ;;
            f) KEY_SOURCE=file; KEY_ARG="$OPTARG"; ACTION_COUNT=$((ACTION_COUNT+1)) ;;
            p) SSH_PORT="$OPTARG"; ACTION_COUNT=$((ACTION_COUNT+1)) ;;
            d) DISABLE_PASSWORD=1 ;;
            h) USAGE; exit 0 ;;
        esac
    done
}

#=============================================================
# 主流程
#=============================================================
main() {
    parse_options "$@"
    detect_os

    install_keys

    [ -n "$SSH_PORT" ] && change_port
    [ "$DISABLE_PASSWORD" -eq 1 ] && disable_password_login

    restart_sshd
    verify_effective_config

    log_info "全部操作完成"
}

main "$@"
