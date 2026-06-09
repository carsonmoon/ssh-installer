#!/usr/bin/env bash
#=============================================================
# SSH Key Installer for Debian 10-13 / Ubuntu 22.04+
# Original Author: P3TERX
# Maintained compatibility update
# Version: 4.0
#=============================================================

set -o pipefail

VERSION=4.0

RED="\033[31m"
GREEN="\033[1;32m"
YELLOW="\033[33m"
RESET="\033[0m"
INFO="[${GREEN}INFO${RESET}]"
WARN="[${YELLOW}WARN${RESET}]"
ERROR="[${RED}ERROR${RESET}]"

SSHD_CONFIG=${SSHD_CONFIG:-/etc/ssh/sshd_config}
SSHD_DROPIN_DIR=${SSHD_DROPIN_DIR:-/etc/ssh/sshd_config.d}
SSHD_DROPIN=${SSHD_DROPIN:-${SSHD_DROPIN_DIR}/00-key-installer.conf}
PORT_BLOCK_BEGIN="# BEGIN key-installer managed port"
PORT_BLOCK_END="# END key-installer managed port"
OVERWRITE=0
DISABLE_PASSWORD=0
RESTART_SSHD=0
ACTION_COUNT=0
KEY_SOURCE=""
KEY_ARG=""
SSH_PORT=""

if [ "${EUID}" -ne 0 ] && [ -z "${SUDO+x}" ]; then
    SUDO=sudo
else
    SUDO=${SUDO-}
fi

log_info() { echo -e "${INFO} $*"; }
log_warn() { echo -e "${WARN} $*"; }
log_error() { echo -e "${ERROR} $*" >&2; }

USAGE() {
    cat <<EOF
SSH Key Installer ${VERSION}

Usage:
  bash key.sh [options...] <arg>

Options:
  -o    Overwrite mode (replace all keys)
  -g    Get public keys from GitHub (argument: GitHub username)
  -u    Get public keys from a URL (argument: URL)
  -f    Get public keys from a local file (argument: file path)
  -p    Change SSH port (argument: port number)
  -d    Disable SSH password login
  -h    Show help

Examples:
  bash key.sh -g username
  bash key.sh -o -f /path/to/id_ed25519.pub
  bash key.sh -d -p 2222 -g username
EOF
}

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        log_error "Required command not found: $1"
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

detect_os() {
    if [ ! -r /etc/os-release ]; then
        log_warn "Cannot read /etc/os-release; continuing without OS version checks."
        return 0
    fi

    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}" in
        debian)
            case "${VERSION_ID:-}" in
                10|11|12|13) log_info "Detected Debian ${VERSION_ID}." ;;
                *) log_warn "Detected Debian ${VERSION_ID:-unknown}; this script is tested for Debian 10-13." ;;
            esac
            ;;
        ubuntu)
            major=${VERSION_ID%%.*}
            if [ -n "${major}" ] && [ "${major}" -ge 22 ] 2>/dev/null; then
                log_info "Detected Ubuntu ${VERSION_ID}."
            else
                log_warn "Detected Ubuntu ${VERSION_ID:-unknown}; this script is tested for Ubuntu 22.04 and newer."
            fi
            ;;
        *)
            log_warn "Detected ${PRETTY_NAME:-an unsupported Linux distribution}; this script targets Debian and Ubuntu."
            ;;
    esac
}

find_sshd() {
    if [ -n "${SSHD_BIN:-}" ] && [ -x "${SSHD_BIN}" ]; then
        echo "${SSHD_BIN}"
        return 0
    fi

    if command -v sshd >/dev/null 2>&1; then
        command -v sshd
        return 0
    fi

    for bin in /usr/sbin/sshd /usr/local/sbin/sshd; do
        if [ -x "${bin}" ]; then
            echo "${bin}"
            return 0
        fi
    done

    return 1
}

check_sshd_config() {
    if [ ! -f "${SSHD_CONFIG}" ]; then
        log_error "sshd_config file not found: ${SSHD_CONFIG}"
        exit 1
    fi
}

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

    if cmp -s "${tmp_file}" "${SSHD_CONFIG}"; then
        rm -f "${tmp_file}"
    else
        log_info "Adding managed SSH include at the top of ${SSHD_CONFIG}."
        run_as_root install -m 0644 "${tmp_file}" "${SSHD_CONFIG}"
        rm -f "${tmp_file}"
        RESTART_SSHD=1
    fi
}

set_dropin_option() {
    key=$1
    value=$2
    ensure_managed_include

    if run_as_root grep -Eq "^[[:space:]]*#?[[:space:]]*${key}[[:space:]]+" "${SSHD_DROPIN}"; then
        run_as_root sed -i.bak -E "s@^[[:space:]]*#?[[:space:]]*${key}[[:space:]].*@${key} ${value}@" "${SSHD_DROPIN}"
    else
        printf '%s %s\n' "${key}" "${value}" | run_as_root tee -a "${SSHD_DROPIN}" >/dev/null
    fi
    RESTART_SSHD=1
}

enable_pubkey_auth() {
    log_info "Ensuring PubkeyAuthentication is enabled."
    set_dropin_option "PubkeyAuthentication" "yes"
}

disable_password_login() {
    log_info "Disabling password and keyboard-interactive SSH login."
    set_dropin_option "PasswordAuthentication" "no"
    set_dropin_option "KbdInteractiveAuthentication" "no"
    set_dropin_option "ChallengeResponseAuthentication" "no"
}

validate_port() {
    case "${SSH_PORT}" in
        ''|*[!0-9]*) log_error "Invalid SSH port: ${SSH_PORT}"; exit 1 ;;
    esac

    if [ "${SSH_PORT}" -lt 1 ] || [ "${SSH_PORT}" -gt 65535 ]; then
        log_error "SSH port must be between 1 and 65535."
        exit 1
    fi
}

change_port() {
    validate_port
    log_info "Changing SSH port to ${SSH_PORT}."
    set_managed_port
    log_warn "Make sure your firewall and cloud security group allow TCP port ${SSH_PORT}."
}

rewrite_ports_in_file() {
    file=$1
    managed=$2
    [ -f "${file}" ] || return 0

    tmp_file=$(mktemp)
    awk \
        -v port="${SSH_PORT}" \
        -v begin="${PORT_BLOCK_BEGIN}" \
        -v end="${PORT_BLOCK_END}" \
        -v include_line="Include ${SSHD_DROPIN}" \
        -v managed="${managed}" '
        BEGIN {
            in_block = 0
            printed_block = 0
        }
        managed == "1" && NR == 1 && $0 == include_line {
            print
            print begin
            print "Port " port
            print end
            printed_block = 1
            next
        }
        managed == "1" && NR == 1 && $0 != include_line {
            print begin
            print "Port " port
            print end
            printed_block = 1
        }
        END {
            if (managed == "1" && printed_block == 0) {
                print begin
                print "Port " port
                print end
            }
        }
        $0 == begin { in_block = 1; next }
        $0 == end { in_block = 0; next }
        in_block { next }
        /^[[:space:]]*Port[[:space:]]+/ {
            print "# key-installer disabled duplicate Port: " $0
            next
        }
        { print }
    ' "${file}" >"${tmp_file}"

    if cmp -s "${tmp_file}" "${file}"; then
        rm -f "${tmp_file}"
    else
        run_as_root install -m 0644 "${tmp_file}" "${file}"
        rm -f "${tmp_file}"
        RESTART_SSHD=1
    fi
}

set_managed_port() {
    check_sshd_config
    rewrite_ports_in_file "${SSHD_CONFIG}" 1

    if [ -d "${SSHD_DROPIN_DIR}" ]; then
        for conf in "${SSHD_DROPIN_DIR}"/*.conf; do
            [ -e "${conf}" ] || continue
            rewrite_ports_in_file "${conf}" 0
        done
    fi
}

fetch_keys() {
    case "${KEY_SOURCE}" in
        github)
            need_cmd curl
            [ -z "${KEY_ARG}" ] && read -rp "GitHub username: " KEY_ARG
            log_info "Getting public keys from GitHub user: ${KEY_ARG}"
            PUB_KEY=$(curl -fsSL "https://github.com/${KEY_ARG}.keys") || {
                log_error "Unable to fetch keys from GitHub."
                exit 1
            }
            ;;
        url)
            need_cmd curl
            [ -z "${KEY_ARG}" ] && read -rp "Public key URL: " KEY_ARG
            log_info "Fetching public keys from URL."
            PUB_KEY=$(curl -fsSL "${KEY_ARG}") || {
                log_error "Unable to fetch keys from URL."
                exit 1
            }
            ;;
        file)
            [ -z "${KEY_ARG}" ] && read -rp "Local key file path: " KEY_ARG
            [ ! -f "${KEY_ARG}" ] && log_error "File not found: ${KEY_ARG}" && exit 1
            log_info "Reading public keys from ${KEY_ARG}."
            PUB_KEY=$(cat "${KEY_ARG}")
            ;;
        '')
            return 0
            ;;
        *)
            log_error "Unknown key source: ${KEY_SOURCE}"
            exit 1
            ;;
    esac

    [ -z "${PUB_KEY}" ] && log_error "SSH key content is empty." && exit 1
}

is_valid_public_key_line() {
    line=$1
    case "${line}" in
        ssh-rsa\ *|ssh-ed25519\ *|ecdsa-sha2-nistp256\ *|ecdsa-sha2-nistp384\ *|ecdsa-sha2-nistp521\ *|sk-ssh-ed25519@openssh.com\ *|sk-ecdsa-sha2-nistp256@openssh.com\ *)
            if command -v ssh-keygen >/dev/null 2>&1; then
                tmp_key=$(mktemp)
                printf '%s\n' "${line}" >"${tmp_key}"
                ssh-keygen -l -f "${tmp_key}" >/dev/null 2>&1
                rc=$?
                rm -f "${tmp_key}"
                return "${rc}"
            fi
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

key_blob() {
    printf '%s\n' "$1" | awk '{print $2}'
}

install_keys() {
    [ -z "${KEY_SOURCE}" ] && return 0
    fetch_keys

    SSH_DIR="${HOME}/.ssh"
    AUTH_KEYS="${SSH_DIR}/authorized_keys"

    mkdir -p "${SSH_DIR}"
    touch "${AUTH_KEYS}"
    chmod 700 "${SSH_DIR}"
    chmod 600 "${AUTH_KEYS}"

    tmp_keys=$(mktemp)
    valid_count=0
    skipped_count=0

    while IFS= read -r line || [ -n "${line}" ]; do
        case "${line}" in
            ''|'#'*) continue ;;
        esac

        if ! is_valid_public_key_line "${line}"; then
            skipped_count=$((skipped_count + 1))
            continue
        fi

        blob=$(key_blob "${line}")
        if [ -z "${blob}" ] || grep -Fq " ${blob}" "${tmp_keys}" 2>/dev/null; then
            skipped_count=$((skipped_count + 1))
            continue
        fi

        printf '%s\n' "${line}" >>"${tmp_keys}"
        valid_count=$((valid_count + 1))
    done <<EOF
${PUB_KEY}
EOF

    if [ "${valid_count}" -eq 0 ]; then
        rm -f "${tmp_keys}"
        log_error "No valid public keys found."
        [ "${skipped_count}" -gt 0 ] && log_error "Skipped ${skipped_count} invalid or duplicate input line(s)."
        exit 1
    fi

    if [ "${OVERWRITE}" -eq 1 ]; then
        log_info "Overwriting authorized_keys with ${valid_count} key(s)."
        cp "${tmp_keys}" "${AUTH_KEYS}"
        chmod 600 "${AUTH_KEYS}"
        rm -f "${tmp_keys}"
        enable_pubkey_auth
        return 0
    fi

    added_count=0
    duplicate_count=0
    while IFS= read -r line || [ -n "${line}" ]; do
        blob=$(key_blob "${line}")
        if grep -Fq " ${blob}" "${AUTH_KEYS}" 2>/dev/null; then
            duplicate_count=$((duplicate_count + 1))
            continue
        fi
        printf '%s\n' "${line}" >>"${AUTH_KEYS}"
        added_count=$((added_count + 1))
    done <"${tmp_keys}"

    chmod 600 "${AUTH_KEYS}"
    rm -f "${tmp_keys}"

    log_info "Added ${added_count} key(s); skipped ${duplicate_count} existing key(s)."
    [ "${skipped_count}" -gt 0 ] && log_warn "Skipped ${skipped_count} invalid or duplicate input line(s)."
    enable_pubkey_auth
}

test_sshd_config() {
    sshd_bin=$(find_sshd || true)
    if [ -z "${sshd_bin}" ]; then
        log_warn "Cannot find sshd binary; skipping sshd -t validation."
        return 0
    fi

    log_info "Testing SSH configuration with ${sshd_bin} -t."
    if ! run_as_root "${sshd_bin}" -t; then
        log_error "SSH configuration test failed. Service was not restarted."
        exit 1
    fi
}

restart_sshd() {
    [ "${RESTART_SSHD}" -ne 1 ] && return 0
    test_sshd_config

    log_info "Reloading SSH service."
    if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files >/dev/null 2>&1; then
        if run_as_root systemctl reload ssh 2>/dev/null || run_as_root systemctl reload sshd 2>/dev/null; then
            log_info "SSH service reloaded."
            return 0
        fi
        if run_as_root systemctl restart ssh 2>/dev/null || run_as_root systemctl restart sshd 2>/dev/null; then
            log_info "SSH service restarted."
            return 0
        fi
    fi

    if command -v service >/dev/null 2>&1; then
        if run_as_root service ssh reload 2>/dev/null || run_as_root service sshd reload 2>/dev/null; then
            log_info "SSH service reloaded."
            return 0
        fi
        if run_as_root service ssh restart 2>/dev/null || run_as_root service sshd restart 2>/dev/null; then
            log_info "SSH service restarted."
            return 0
        fi
    fi

    log_warn "Cannot reload SSH service automatically. Please reload or restart sshd manually."
}

verify_effective_config() {
    sshd_bin=$(find_sshd || true)
    if [ -z "${sshd_bin}" ]; then
        return 0
    fi

    effective=$(
        run_as_root "${sshd_bin}" -T 2>/dev/null | awk '
            $1 == "port" { ports = ports ? ports "," $2 : $2 }
            $1 == "pubkeyauthentication" { pubkey=$2 }
            $1 == "passwordauthentication" { password=$2 }
            $1 == "kbdinteractiveauthentication" { kbd=$2 }
            END {
                if (ports) print "Port = " ports;
                if (pubkey) print "PubkeyAuthentication = " pubkey;
                if (password) print "PasswordAuthentication = " password;
                if (kbd) print "KbdInteractiveAuthentication = " kbd;
            }'
    )

    [ -n "${effective}" ] && printf '%s\n' "${effective}" | while IFS= read -r line; do log_info "${line}"; done
}

parse_options() {
    while getopts ":og:u:f:p:dh" OPT; do
        case "${OPT}" in
            o) OVERWRITE=1 ;;
            g) KEY_SOURCE="github"; KEY_ARG=${OPTARG}; ACTION_COUNT=$((ACTION_COUNT + 1)) ;;
            u) KEY_SOURCE="url"; KEY_ARG=${OPTARG}; ACTION_COUNT=$((ACTION_COUNT + 1)) ;;
            f) KEY_SOURCE="file"; KEY_ARG=${OPTARG}; ACTION_COUNT=$((ACTION_COUNT + 1)) ;;
            p) SSH_PORT=${OPTARG}; ACTION_COUNT=$((ACTION_COUNT + 1)) ;;
            d) DISABLE_PASSWORD=1; ACTION_COUNT=$((ACTION_COUNT + 1)) ;;
            h) USAGE; exit 0 ;;
            :) log_error "Option -${OPTARG} requires an argument."; USAGE; exit 1 ;;
            \?) log_error "Unknown option: -${OPTARG}"; USAGE; exit 1 ;;
        esac
    done

    if [ "${ACTION_COUNT}" -eq 0 ]; then
        USAGE
        exit 0
    fi
}

main() {
    parse_options "$@"
    detect_os

    install_keys

    [ -n "${SSH_PORT}" ] && change_port
    [ "${DISABLE_PASSWORD}" -eq 1 ] && disable_password_login

    restart_sshd
    verify_effective_config
    log_info "Done."
}

main "$@"
