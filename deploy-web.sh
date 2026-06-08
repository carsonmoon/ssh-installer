#!/usr/bin/env bash
set -Eeuo pipefail

# Interactive one-click Nginx/Caddy deployment helper for common Linux servers.
# Supports Debian/Ubuntu, RHEL/CentOS/Fedora-like systems, and Arch-like systems.

APP_NAME="deploy-web"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"

log() {
  printf '\033[1;34m[%s]\033[0m %s\n' "$APP_NAME" "$*"
}

warn() {
  printf '\033[1;33m[WARN]\033[0m %s\n' "$*" >&2
}

err() {
  printf '\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2
}

die() {
  err "$*"
  exit 1
}

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "请使用 root 运行：sudo bash $0"
  fi
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

prompt() {
  local var_name="$1"
  local label="$2"
  local default="${3:-}"
  local value

  if [[ -n "$default" ]]; then
    read -r -p "$label [$default]: " value
    value="${value:-$default}"
  else
    read -r -p "$label: " value
  fi

  printf -v "$var_name" '%s' "$value"
}

prompt_required() {
  local var_name="$1"
  local label="$2"
  local value

  while true; do
    read -r -p "$label: " value
    if [[ -n "$value" ]]; then
      printf -v "$var_name" '%s' "$value"
      return
    fi
    warn "该项不能为空。"
  done
}

prompt_yes_no() {
  local var_name="$1"
  local label="$2"
  local default="${3:-n}"
  local value
  local hint

  if [[ "$default" == "y" ]]; then
    hint="Y/n"
  else
    hint="y/N"
  fi

  while true; do
    read -r -p "$label [$hint]: " value
    value="${value:-$default}"
    case "$value" in
      y|Y|yes|YES) printf -v "$var_name" 'y'; return ;;
      n|N|no|NO) printf -v "$var_name" 'n'; return ;;
      *) warn "请输入 y 或 n。" ;;
    esac
  done
}

validate_domain() {
  local domain="$1"
  [[ "$domain" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]]
}

detect_pkg_manager() {
  if command_exists apt-get; then
    PKG_MANAGER="apt"
  elif command_exists dnf; then
    PKG_MANAGER="dnf"
  elif command_exists yum; then
    PKG_MANAGER="yum"
  elif command_exists pacman; then
    PKG_MANAGER="pacman"
  else
    die "未识别包管理器。当前脚本支持 apt、dnf、yum、pacman。"
  fi
}

pkg_update() {
  case "$PKG_MANAGER" in
    apt)
      apt-get update
      ;;
    dnf)
      dnf makecache
      ;;
    yum)
      yum makecache
      ;;
    pacman)
      pacman -Sy --noconfirm
      ;;
  esac
}

pkg_install() {
  local packages=("$@")

  case "$PKG_MANAGER" in
    apt)
      DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"
      ;;
    dnf)
      dnf install -y "${packages[@]}"
      ;;
    yum)
      yum install -y "${packages[@]}"
      ;;
    pacman)
      pacman -S --noconfirm --needed "${packages[@]}"
      ;;
  esac
}

install_nginx_stack() {
  log "安装 Nginx 和 Certbot..."
  pkg_update

  case "$PKG_MANAGER" in
    apt)
      pkg_install nginx certbot python3-certbot-nginx
      ;;
    dnf|yum)
      pkg_install nginx certbot python3-certbot-nginx
      ;;
    pacman)
      pkg_install nginx certbot certbot-nginx
      ;;
  esac
}

install_caddy_stack() {
  log "安装 Caddy..."
  pkg_update

  case "$PKG_MANAGER" in
    apt)
      pkg_install debian-keyring debian-archive-keyring apt-transport-https curl gnupg
      mkdir -p /usr/share/keyrings
      curl -1sLf "https://dl.cloudsmith.io/public/caddy/stable/gpg.key" | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
      curl -1sLf "https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt" >/etc/apt/sources.list.d/caddy-stable.list
      apt-get update
      pkg_install caddy
      ;;
    dnf)
      pkg_install dnf-plugins-core || pkg_install dnf5-plugins || true
      dnf -y copr enable @caddy/caddy || true
      pkg_update
      pkg_install caddy
      ;;
    yum)
      pkg_install yum-plugin-copr || pkg_install dnf-plugins-core || true
      yum -y copr enable @caddy/caddy || true
      pkg_update
      pkg_install caddy
      ;;
    pacman)
      pkg_install caddy
      ;;
  esac
}

systemctl_if_available() {
  if command_exists systemctl; then
    systemctl "$@"
  else
    return 1
  fi
}

enable_and_restart_service() {
  local service="$1"

  if command_exists systemctl; then
    systemctl enable "$service"
    systemctl restart "$service"
  else
    service "$service" restart
  fi
}

open_firewall_ports() {
  log "配置防火墙，开放 80/tcp 和 443/tcp..."

  if command_exists ufw; then
    ufw allow 80/tcp
    ufw allow 443/tcp
    if ufw status | grep -qi "inactive"; then
      local enable_ufw
      prompt_yes_no enable_ufw "检测到 UFW 未启用，是否现在启用 UFW？建议确认 SSH 规则后再启用" "n"
      if [[ "$enable_ufw" == "y" ]]; then
        ufw allow OpenSSH || true
        ufw --force enable
      else
        warn "UFW 当前未启用；规则已添加，但不会生效，直到你启用 UFW。"
      fi
    fi
    return
  fi

  if command_exists firewall-cmd; then
    if ! firewall-cmd --state >/dev/null 2>&1; then
      local enable_firewalld
      prompt_yes_no enable_firewalld "检测到 firewalld 未运行，是否现在启用 firewalld？" "n"
      if [[ "$enable_firewalld" == "y" ]]; then
        systemctl_if_available enable --now firewalld || die "启用 firewalld 失败。"
      else
        warn "firewalld 未运行，跳过防火墙配置。"
        return
      fi
    fi

    firewall-cmd --permanent --add-service=http
    firewall-cmd --permanent --add-service=https
    firewall-cmd --reload
    return
  fi

  warn "未检测到 UFW 或 firewalld。请手动确认云厂商安全组和系统防火墙已开放 80/443。"
}

backup_file_if_exists() {
  local path="$1"

  if [[ -e "$path" ]]; then
    cp -a "$path" "${path}.bak.${TIMESTAMP}"
    warn "已备份现有文件：${path}.bak.${TIMESTAMP}"
  fi
}

ensure_static_root() {
  local root="$1"
  local domain="$2"

  mkdir -p "$root"
  if [[ ! -f "$root/index.html" ]]; then
    cat >"$root/index.html" <<EOF
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${domain}</title>
</head>
<body>
  <h1>${domain} 已部署成功</h1>
</body>
</html>
EOF
  fi
}

write_nginx_config() {
  local domain="$1"
  local mode="$2"
  local backend="$3"
  local root="$4"
  local conf_path

  if [[ -d /etc/nginx/sites-available ]]; then
    conf_path="/etc/nginx/sites-available/${domain}.conf"
  else
    conf_path="/etc/nginx/conf.d/${domain}.conf"
  fi

  backup_file_if_exists "$conf_path"

  if [[ "$mode" == "proxy" ]]; then
    cat >"$conf_path" <<EOF
server {
    listen 80;
    server_name ${domain};

    location / {
        proxy_pass ${backend};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header Real-IP \$remote_addr;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF
  else
    ensure_static_root "$root" "$domain"
    cat >"$conf_path" <<EOF
server {
    listen 80;
    server_name ${domain};

    root ${root};
    index index.html index.htm;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF
  fi

  if [[ -d /etc/nginx/sites-enabled ]]; then
    ln -sfn "$conf_path" "/etc/nginx/sites-enabled/${domain}.conf"
  fi

  if [[ -e /etc/nginx/sites-enabled/default ]]; then
    local disable_default
    prompt_yes_no disable_default "是否禁用 Nginx 默认站点？" "y"
    if [[ "$disable_default" == "y" ]]; then
      mv /etc/nginx/sites-enabled/default "/etc/nginx/sites-enabled/default.bak.${TIMESTAMP}"
    fi
  fi

  nginx -t
  enable_and_restart_service nginx
}

issue_nginx_certificate() {
  local domain="$1"
  local email="$2"
  local certbot_args=(--nginx -d "$domain" --agree-tos --redirect --non-interactive)

  if [[ -n "$email" ]]; then
    certbot_args+=(--email "$email")
  else
    certbot_args+=(--register-unsafely-without-email)
  fi

  log "使用 Certbot 为 ${domain} 申请并配置 HTTPS..."
  certbot "${certbot_args[@]}"
  nginx -t
  enable_and_restart_service nginx
}

write_caddy_config() {
  local domain="$1"
  local email="$2"
  local mode="$3"
  local backend="$4"
  local root="$5"
  local conf_path="/etc/caddy/Caddyfile"

  mkdir -p /etc/caddy
  backup_file_if_exists "$conf_path"

  {
    if [[ -n "$email" ]]; then
      printf '{\n    email %s\n}\n\n' "$email"
    fi

    printf '%s {\n' "$domain"
    if [[ "$mode" == "proxy" ]]; then
      printf '    reverse_proxy %s\n' "$backend"
    else
      ensure_static_root "$root" "$domain"
      printf '    root * %s\n' "$root"
      printf '    file_server\n'
    fi
    printf '}\n'
  } >"$conf_path"

  caddy validate --config "$conf_path"
  enable_and_restart_service caddy
}

collect_inputs() {
  local runtime_choice mode_choice

  echo
  echo "请选择要部署的 Web 服务："
  echo "  1) Nginx + Certbot"
  echo "  2) Caddy 自动 HTTPS"
  while true; do
    read -r -p "选择 [1-2]: " runtime_choice
    case "$runtime_choice" in
      1) RUNTIME="nginx"; break ;;
      2) RUNTIME="caddy"; break ;;
      *) warn "请输入 1 或 2。" ;;
    esac
  done

  while true; do
    prompt_required DOMAIN "请输入域名，例如 example.com"
    if validate_domain "$DOMAIN"; then
      break
    fi
    warn "域名格式看起来不正确，请重新输入。"
  done

  prompt EMAIL "请输入 Let's Encrypt 邮箱，可留空" ""

  echo
  echo "请选择站点类型："
  echo "  1) 反向代理到后端服务"
  echo "  2) 静态网站目录"
  while true; do
    read -r -p "选择 [1-2]: " mode_choice
    case "$mode_choice" in
      1) MODE="proxy"; break ;;
      2) MODE="static"; break ;;
      *) warn "请输入 1 或 2。" ;;
    esac
  done

  if [[ "$MODE" == "proxy" ]]; then
    prompt BACKEND "请输入后端地址" "http://127.0.0.1:3000"
    STATIC_ROOT=""
  else
    BACKEND=""
    prompt STATIC_ROOT "请输入网站目录" "/var/www/${DOMAIN}/html"
  fi
}

print_summary() {
  echo
  log "部署信息确认："
  echo "  Web 服务：${RUNTIME}"
  echo "  域名：${DOMAIN}"
  echo "  邮箱：${EMAIL:-未填写}"
  if [[ "$MODE" == "proxy" ]]; then
    echo "  模式：反向代理"
    echo "  后端：${BACKEND}"
  else
    echo "  模式：静态网站"
    echo "  目录：${STATIC_ROOT}"
  fi
  echo
}

main() {
  need_root
  detect_pkg_manager
  collect_inputs
  print_summary

  local confirmed
  prompt_yes_no confirmed "确认开始部署？" "y"
  if [[ "$confirmed" != "y" ]]; then
    die "已取消。"
  fi

  open_firewall_ports

  case "$RUNTIME" in
    nginx)
      install_nginx_stack
      write_nginx_config "$DOMAIN" "$MODE" "$BACKEND" "$STATIC_ROOT"
      issue_nginx_certificate "$DOMAIN" "$EMAIL"
      ;;
    caddy)
      install_caddy_stack
      write_caddy_config "$DOMAIN" "$EMAIL" "$MODE" "$BACKEND" "$STATIC_ROOT"
      ;;
  esac

  echo
  log "部署完成： https://${DOMAIN}"
  warn "如果访问失败，请确认域名 A/AAAA 记录已解析到本机公网 IP，并且云服务器安全组开放了 80 和 443。"
}

main "$@"
