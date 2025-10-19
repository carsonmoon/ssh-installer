#!/usr/bin/env bash
#=============================================================
# Updated SSH Key Installer for Debian 11–13 / Ubuntu 20.04–24.04
# Original Author: P3TERX
# Updated By: GPT-5 (ChatGPT)
# Version: 3.1
#=============================================================

VERSION=3.1
RED="\033[31m"
GREEN="\033[1;32m"
RESET="\033[0m"
INFO="[${GREEN}INFO${RESET}]"
ERROR="[${RED}ERROR${RESET}]"

[ $EUID != 0 ] && SUDO=sudo

detect_sshd_config() {
    for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/00-default.conf; do
        [ -f "$f" ] && SSHD_CONFIG="$f" && return
    done
    echo -e "${ERROR} sshd_config file not found!"
    exit 1
}

USAGE() {
    echo "
SSH Key Installer $VERSION

Usage:
  bash <(curl -fsSL git.io/key.sh) [options...] <arg>

Options:
  -o    Overwrite mode (replace all keys)
  -g    Get the public key from GitHub (argument: GitHub username)
  -u    Get the public key from a URL (argument: URL)
  -f    Get the public key from a local file (argument: file path)
  -p    Change SSH port (argument: port number)
  -d    Disable SSH password login
"
}

get_github_key() {
    [ -z "${KEY_ID}" ] && read -rp "GitHub username: " KEY_ID
    echo -e "${INFO} Getting public keys from GitHub user: ${KEY_ID}"
    PUB_KEY=$(curl -fsSL "https://github.com/${KEY_ID}.keys")
    if [[ "${PUB_KEY}" =~ "Not Found" ]] || [ -z "${PUB_KEY}" ]; then
        echo -e "${ERROR} No valid public keys found on GitHub."
        exit 1
    fi
}

get_url_key() {
    [ -z "${KEY_URL}" ] && read -rp "Public key URL: " KEY_URL
    echo -e "${INFO} Fetching key from URL..."
    PUB_KEY=$(curl -fsSL "${KEY_URL}")
    [ -z "${PUB_KEY}" ] && echo -e "${ERROR} Unable to fetch key from URL." && exit 1
}

get_local_key() {
    [ -z "${KEY_PATH}" ] && read -rp "Local key file path: " KEY_PATH
    [ ! -f "${KEY_PATH}" ] && echo -e "${ERROR} File not found: ${KEY_PATH}" && exit 1
    echo -e "${INFO} Reading public key from ${KEY_PATH} ..."
    PUB_KEY=$(cat "${KEY_PATH}")
}

install_key() {
    [ -z "${PUB_KEY}" ] && echo -e "${ERROR} SSH key content is empty." && exit 1

    SSH_DIR="${HOME}/.ssh"
    AUTH_KEYS="${SSH_DIR}/authorized_keys"

    mkdir -p "${SSH_DIR}"
    touch "${AUTH_KEYS}"
    chmod 700 "${SSH_DIR}"
    chmod 600 "${AUTH_KEYS}"

    if [ "${OVERWRITE}" == 1 ]; then
        echo -e "${INFO} Overwriting authorized_keys ..."
        echo "${PUB_KEY}" >"${AUTH_KEYS}"
        echo -e "${INFO} SSH key installed successfully (overwrite mode)."
        return
    fi

    # --- 防重复检测 ---
    echo -e "${INFO} Checking for duplicate keys..."
    key_hash=$(echo "${PUB_KEY}" | md5sum | cut -d' ' -f1)
    existing_hash=$(md5sum "${AUTH_KEYS}" 2>/dev/null | cut -d' ' -f1)

    if grep -q "$(echo "${PUB_KEY}" | head -n1 | awk '{print $2}')" "${AUTH_KEYS}" 2>/dev/null; then
        echo -e "${INFO} Key already exists in authorized_keys, skipping."
        return
    fi

    # --- 添加公钥 ---
    echo -e "${INFO} Appending SSH key ..."
    echo -e "\n${PUB_KEY}" >>"${AUTH_KEYS}"
    chmod 600 "${AUTH_KEYS}"

    grep -q "$(echo "${PUB_KEY}" | head -n1 | awk '{print $2}')" "${AUTH_KEYS}" &&
        echo -e "${INFO} SSH key installed successfully!" ||
        { echo -e "${ERROR} Failed to add SSH key."; exit 1; }
}

change_port() {
    detect_sshd_config
    echo -e "${INFO} Changing SSH port to ${SSH_PORT} ..."
    if grep -q "^#*Port " "${SSHD_CONFIG}"; then
        $SUDO sed -i "s@^#*Port .*@Port ${SSH_PORT}@" "${SSHD_CONFIG}"
    else
        echo "Port ${SSH_PORT}" | $SUDO tee -a "${SSHD_CONFIG}" >/dev/null
    fi
    echo -e "${INFO} SSH port changed successfully to ${SSH_PORT}."
    RESTART_SSHD=1
}

disable_password() {
    detect_sshd_config
    echo -e "${INFO} Disabling password login ..."
    if grep -q "^#*PasswordAuthentication" "${SSHD_CONFIG}"; then
        $SUDO sed -i "s@^#*PasswordAuthentication .*@PasswordAuthentication no@" "${SSHD_CONFIG}"
    else
        echo "PasswordAuthentication no" | $SUDO tee -a "${SSHD_CONFIG}" >/dev/null
    fi
    echo -e "${INFO} Password login disabled."
    RESTART_SSHD=1
}

while getopts "og:u:f:p:d" OPT; do
    case $OPT in
    o) OVERWRITE=1 ;;
    g) KEY_ID=$OPTARG; get_github_key; install_key ;;
    u) KEY_URL=$OPTARG; get_url_key; install_key ;;
    f) KEY_PATH=$OPTARG; get_local_key; install_key ;;
    p) SSH_PORT=$OPTARG; change_port ;;
    d) disable_password ;;
    *) USAGE; exit 1 ;;
    esac
done

if [ "$RESTART_SSHD" = 1 ]; then
    echo -e "${INFO} Restarting SSH service..."
    if command -v systemctl &>/dev/null; then
        $SUDO systemctl restart ssh || $SUDO systemctl restart sshd
    elif command -v service &>/dev/null; then
        $SUDO service ssh restart || $SUDO service sshd restart
    else
        echo -e "${ERROR} Cannot restart ssh service automatically. Please restart manually."
    fi
    echo -e "${INFO} Done."
fi
