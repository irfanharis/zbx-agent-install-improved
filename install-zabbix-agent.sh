#!/usr/bin/env bash
set -euo pipefail

# ---------- Defaults ----------
ZBX_VER="${ZBX_VER:-7.0}"            # 6.0 / 6.4 / 7.0
AGENT_KIND="${AGENT_KIND:-2}"        # 1 = zabbix-agent, 2 = zabbix-agent2
ZBX_SERVER="${ZBX_SERVER:-}"         # Required
ZBX_SERVER_ACTIVE="${ZBX_SERVER_ACTIVE:-}"
ZBX_HOSTNAME="${ZBX_HOSTNAME:-}"
ZBX_PSK_HEX="${ZBX_PSK_HEX:-}"
ZBX_LISTEN_PORT="${ZBX_LISTEN_PORT:-10050}"
DRY_RUN=0
SKIP_PREFLIGHT=0
FORCE_REINSTALL=0

# ---------- Colors ----------
ok()   { echo -e "\e[32m[OK]\e[0m $*"; }
warn() { echo -e "\e[33m[WARN]\e[0m $*"; }
err()  { echo -e "\e[31m[ERR]\e[0m $*"; }
info() { echo -e "\e[36m[INFO]\e[0m $*"; }

# ---------- Cleanup on exit ----------
TEMP_FILES=()
cleanup() {
  for file in "${TEMP_FILES[@]}"; do
    [[ -f "$file" || -d "$file" ]] && rm -rf "$file" 2>/dev/null || true
  done
}
trap cleanup EXIT

# ---------- Helpers ----------
need_root() {
  if [[ $EUID -ne 0 ]]; then
    err "Script harus dijalankan dengan sudo/root."
    exit 1
  fi
}

usage() {
  cat <<EOF
Usage:
  $(basename "$0") --server <ADDR|FQDN> [options]

Options:
  --server <ADDR|FQDN>         Alamat Zabbix Server (wajib).
  --server-active <ADDR|FQDN>  Alamat untuk active checks (default: sama dengan --server).
  --hostname <NAME>            Hostname agent (default: hostname -f).
  --agent <1|2>                Pilih agent klasik (1) atau Agent2 (2). Default: 2.
  --version <6.0|6.4|7.0>      Versi repo Zabbix. Default: 7.0.
  --port <PORT>                Listen port agent. Default: 10050.
  --psk <HEX>                  Aktifkan TLS PSK dengan key HEX (min 32 hex chars).
  --dry-run                    Simulasi tanpa eksekusi command.
  --force                      Force reinstall jika agent sudah ada.
  --skip-preflight             Skip pre-flight checks.
  --uninstall                  Uninstall Zabbix Agent.
  --help                       Tampilkan bantuan ini.

Environment override:
  ZBX_VER, AGENT_KIND, ZBX_SERVER, ZBX_SERVER_ACTIVE, ZBX_HOSTNAME, ZBX_PSK_HEX, ZBX_LISTEN_PORT

Contoh:
  sudo $(basename "$0") --server 10.0.0.5
  sudo $(basename "$0") --server zbx.example.local --agent 1 --hostname vm-app-01
  sudo $(basename "$0") --server zbx.example.local --psk 8F3A... --port 10051
  sudo $(basename "$0") --dry-run --server 10.0.0.5
  sudo $(basename "$0") --uninstall
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --server) ZBX_SERVER="$2"; shift 2 ;;
      --server-active) ZBX_SERVER_ACTIVE="$2"; shift 2 ;;
      --hostname) ZBX_HOSTNAME="$2"; shift 2 ;;
      --agent) AGENT_KIND="$2"; shift 2 ;;
      --version) ZBX_VER="$2"; shift 2 ;;
      --port) ZBX_LISTEN_PORT="$2"; shift 2 ;;
      --psk) ZBX_PSK_HEX="$2"; shift 2 ;;
      --dry-run) DRY_RUN=1; shift ;;
      --force) FORCE_REINSTALL=1; shift ;;
      --skip-preflight) SKIP_PREFLIGHT=1; shift ;;
      --uninstall) uninstall_agent; exit 0 ;;
      --help|-h) usage; exit 0 ;;
      *) err "Argumen tidak dikenal: $1"; usage; exit 1 ;;
    esac
  done

  [[ -z "${ZBX_SERVER}" ]] && { err "--server wajib diisi."; usage; exit 1; }
  [[ -z "${ZBX_SERVER_ACTIVE}" ]] && ZBX_SERVER_ACTIVE="${ZBX_SERVER}"
  [[ -z "${ZBX_HOSTNAME}" ]] && ZBX_HOSTNAME="$(hostname -f 2>/dev/null || hostname)"
  
  if [[ "${AGENT_KIND}" != "1" && "${AGENT_KIND}" != "2" ]]; then
    err "--agent harus 1 atau 2"; exit 1
  fi
  
  case "${ZBX_VER}" in
    6.0|6.4|7.0) ;;
    *) err "--version harus 6.0 / 6.4 / 7.0"; exit 1 ;;
  esac
  
  if ! [[ "${ZBX_LISTEN_PORT}" =~ ^[0-9]+$ ]] || [[ "${ZBX_LISTEN_PORT}" -lt 1024 ]] || [[ "${ZBX_LISTEN_PORT}" -gt 65535 ]]; then
    err "--port harus antara 1024-65535"; exit 1
  fi
}

validate_psk() {
  if [[ -n "${ZBX_PSK_HEX}" ]]; then
    # Check if it's valid hex
    if ! [[ "${ZBX_PSK_HEX}" =~ ^[0-9A-Fa-f]+$ ]]; then
      err "PSK harus dalam format HEX (0-9, A-F)"
      exit 1
    fi
    
    # Length check
    local len=${#ZBX_PSK_HEX}
    if (( len < 32 )); then
      err "PSK minimal 32 karakter hex (16 bytes), Anda: ${len} chars"
      exit 1
    fi
    
    if (( len % 2 != 0 )); then
      err "PSK harus memiliki jumlah karakter genap, Anda: ${len} chars"
      exit 1
    fi
    
    ok "PSK validation passed: ${len} hex chars"
  fi
}

detect_os() {
  if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    OS_ID="${ID}"
    OS_VER_ID="${VERSION_ID}"
    OS_NAME="${NAME}"
  else
    err "Tidak bisa membaca /etc/os-release"; exit 1
  fi

  case "${OS_ID}" in
    ubuntu)
      PKG_MGR="apt"
      DIST_CLASS="ubuntu"
      ;;
    almalinux|rocky)
      if command -v dnf >/dev/null 2>&1; then
        PKG_MGR="dnf"
      else
        PKG_MGR="yum"
      fi
      DIST_CLASS="rhel"
      RHEL_MAJ="$(rpm -E %rhel)"
      ;;
    *)
      err "Distro tidak didukung: ${OS_NAME} (${OS_ID})"
      exit 1
      ;;
  esac

  ok "OS terdeteksi: ${OS_NAME} ${OS_VER_ID} (${DIST_CLASS})"
}

preflight_check() {
  [[ $SKIP_PREFLIGHT -eq 1 ]] && { info "Pre-flight checks di-skip"; return 0; }
  
  info "Running pre-flight checks..."
  
  # Check if agent already installed
  if systemctl is-active --quiet zabbix-agent || systemctl is-active --quiet zabbix-agent2; then
    warn "Zabbix Agent sudah terinstall dan running"
    
    if [[ $FORCE_REINSTALL -eq 1 ]]; then
      ok "Flag --force detected, akan reinstall"
    else
      read -p "Lanjutkan reinstall? (y/N): " -n 1 -r
      echo
      [[ ! $REPLY =~ ^[Yy]$ ]] && { info "Instalasi dibatalkan"; exit 0; }
    fi
  fi
  
  # Check internet connectivity
  if ! ping -c 1 -W 3 repo.zabbix.com >/dev/null 2>&1; then
    warn "Tidak bisa ping repo.zabbix.com - pastikan internet tersedia"
  else
    ok "Konektivitas ke repo.zabbix.com: OK"
  fi
  
  # Check if server is reachable
  if ! ping -c 1 -W 3 "${ZBX_SERVER}" >/dev/null 2>&1; then
    warn "Zabbix Server ${ZBX_SERVER} tidak dapat di-ping"
    warn "Instalasi akan tetap dilanjutkan, tapi pastikan server reachable nanti"
  else
    ok "Zabbix Server ${ZBX_SERVER} reachable"
  fi
  
  ok "Pre-flight checks completed"
}

run_cmd() {
  if [[ $DRY_RUN -eq 1 ]]; then
    info "[DRY-RUN] $*"
    return 0
  else
    "$@"
  fi
}

install_repo() {
  if [[ "${DIST_CLASS}" == "ubuntu" ]]; then
    UBVER="${OS_VER_ID}"
    DEB="zabbix-release_${ZBX_VER}-1+ubuntu${UBVER}_all.deb"
    URL="https://repo.zabbix.com/zabbix/${ZBX_VER}/ubuntu/pool/main/z/zabbix-release/${DEB}"

    run_cmd apt-get update -y
    run_cmd apt-get install -y wget lsb-release
    
    tmpdir="$(mktemp -d)"
    TEMP_FILES+=("$tmpdir")
    tmpdeb="${tmpdir}/${DEB}"
    
    if ! run_cmd wget -qO "${tmpdeb}" "${URL}"; then
      err "Gagal download repo paket: ${URL}"
      exit 1
    fi
    
    run_cmd dpkg -i "${tmpdeb}"
    run_cmd apt-get update -y
    ok "Repo Zabbix ${ZBX_VER} ditambahkan (Ubuntu)"

  else
    # RHEL-like
    RHEL="${RHEL_MAJ}"
    RPM_URL="https://repo.zabbix.com/zabbix/${ZBX_VER}/rhel/${RHEL}/x86_64/zabbix-release-${ZBX_VER}-1.el${RHEL}.noarch.rpm"

    run_cmd ${PKG_MGR} -y install curl || true
    
    if ! rpm -q zabbix-release >/dev/null 2>&1; then
      if ! run_cmd rpm -Uvh "${RPM_URL}" >/dev/null 2>&1; then
        err "Gagal tambah repo: ${RPM_URL}"
        exit 1
      fi
    else
      info "Zabbix repo sudah terinstall"
    fi
    
    run_cmd ${PKG_MGR} clean all -y || true
    ok "Repo Zabbix ${ZBX_VER} ditambahkan (RHEL-like)"
  fi
}

install_agent() {
  if [[ "${AGENT_KIND}" == "2" ]]; then
    PKG="zabbix-agent2"
    SVC="zabbix-agent2"
  else
    PKG="zabbix-agent"
    SVC="zabbix-agent"
  fi

  if [[ "${DIST_CLASS}" == "ubuntu" ]]; then
    DEBIAN_FRONTEND=noninteractive run_cmd apt-get install -y "${PKG}"
  else
    run_cmd ${PKG_MGR} -y install "${PKG}"
  fi
  
  ok "Paket ${PKG} berhasil terinstall"

  run_cmd systemctl daemon-reload || true
  run_cmd systemctl enable "${SVC}" >/dev/null 2>&1 || true
}

configure_agent() {
  # FIX: Path config yang benar untuk Agent2
  if [[ "${AGENT_KIND}" == "2" ]]; then
    CONF="/etc/zabbix/zabbix_agent2.conf"
    SVC="zabbix-agent2"
  else
    CONF="/etc/zabbix/zabbix_agentd.conf"
    SVC="zabbix-agent"
  fi

  if [[ ! -f "${CONF}" ]]; then
    err "File konfigurasi tidak ditemukan: ${CONF}"
    exit 1
  fi

  # Backup config
  if [[ ! -f "${CONF}.bak.original" ]]; then
    run_cmd cp -a "${CONF}" "${CONF}.bak.original"
    ok "Backup config dibuat: ${CONF}.bak.original"
  fi

  # Basic config
  if [[ $DRY_RUN -eq 0 ]]; then
    sed -i \
      -e "s/^#\?Server=.*/Server=${ZBX_SERVER}/" \
      -e "s/^#\?ServerActive=.*/ServerActive=${ZBX_SERVER_ACTIVE}/" \
      -e "s/^#\?Hostname=.*/Hostname=${ZBX_HOSTNAME}/" \
      -e "s/^#\?ListenPort=.*/ListenPort=${ZBX_LISTEN_PORT}/" \
      "${CONF}"
  else
    info "[DRY-RUN] Would update config: Server=${ZBX_SERVER}, ServerActive=${ZBX_SERVER_ACTIVE}, Hostname=${ZBX_HOSTNAME}, Port=${ZBX_LISTEN_PORT}"
  fi

  # TLS PSK configuration
  if [[ -n "${ZBX_PSK_HEX}" ]]; then
    validate_psk
    
    PSK_FILE="/etc/zabbix/zabbix_agentd.psk"
    
    if [[ $DRY_RUN -eq 0 ]]; then
      echo "${ZBX_PSK_HEX}" > "${PSK_FILE}"
      chmod 600 "${PSK_FILE}"
      chown zabbix:zabbix "${PSK_FILE}" 2>/dev/null || chown root:root "${PSK_FILE}"

      if grep -q "^#\?TLSConnect=" "${CONF}"; then
        sed -i \
          -e "s/^#\?TLSConnect=.*/TLSConnect=psk/" \
          -e "s/^#\?TLSAccept=.*/TLSAccept=psk/" \
          -e "s|^#\?TLSPSKFile=.*|TLSPSKFile=${PSK_FILE}|" \
          -e "s/^#\?TLSPSKIdentity=.*/TLSPSKIdentity=${ZBX_HOSTNAME}/" \
          "${CONF}"
      else
        cat >> "${CONF}" <<EOF

# TLS PSK Settings (auto-added)
TLSConnect=psk
TLSAccept=psk
TLSPSKFile=${PSK_FILE}
TLSPSKIdentity=${ZBX_HOSTNAME}
EOF
      fi
    else
      info "[DRY-RUN] Would configure TLS PSK with identity: ${ZBX_HOSTNAME}"
    fi
    
    ok "TLS PSK dikonfigurasi (PSK saved to ${PSK_FILE})"
  fi

  ok "Konfigurasi agent: Server=${ZBX_SERVER}, ServerActive=${ZBX_SERVER_ACTIVE}, Hostname=${ZBX_HOSTNAME}, Port=${ZBX_LISTEN_PORT}"
}

configure_selinux() {
  if command -v getenforce >/dev/null 2>&1; then
    if [[ "$(getenforce)" == "Enforcing" ]]; then
      info "SELinux dalam mode Enforcing"
      
      # Allow non-standard port if needed
      if [[ "${ZBX_LISTEN_PORT}" != "10050" ]]; then
        if command -v semanage >/dev/null 2>&1; then
          if [[ $DRY_RUN -eq 0 ]]; then
            semanage port -a -t zabbix_port_t -p tcp "${ZBX_LISTEN_PORT}" 2>/dev/null || \
              semanage port -m -t zabbix_port_t -p tcp "${ZBX_LISTEN_PORT}"
          fi
          ok "SELinux: port ${ZBX_LISTEN_PORT} dikonfigurasi"
        else
          warn "semanage tidak tersedia. Install: ${PKG_MGR} install policycoreutils-python-utils"
        fi
      fi
      
      # Allow zabbix to connect network
      if [[ $DRY_RUN -eq 0 ]]; then
        setsebool -P zabbix_can_network on 2>/dev/null || true
      fi
      ok "SELinux: zabbix_can_network enabled"
    fi
  fi
}

open_firewall() {
  # Ubuntu (ufw)
  if command -v ufw >/dev/null 2>&1; then
    if ufw status 2>/dev/null | grep -q "Status: active"; then
      run_cmd ufw allow "${ZBX_LISTEN_PORT}/tcp" || warn "Gagal membuka port ${ZBX_LISTEN_PORT} di ufw"
      ok "Firewall (ufw): port ${ZBX_LISTEN_PORT} dibuka"
    else
      info "ufw tidak aktif, skip firewall config"
    fi
  fi

  # RHEL-like (firewalld)
  if command -v firewall-cmd >/dev/null 2>&1; then
    if systemctl is-active --quiet firewalld; then
      run_cmd firewall-cmd --add-port="${ZBX_LISTEN_PORT}/tcp" --permanent || warn "Gagal add port permanent"
      run_cmd firewall-cmd --reload || true
      ok "Firewall (firewalld): port ${ZBX_LISTEN_PORT} dibuka"
    else
      info "firewalld tidak aktif, skip firewall config"
    fi
  fi
}

start_service() {
  local SVC="zabbix-agent"
  [[ "${AGENT_KIND}" == "2" ]] && SVC="zabbix-agent2"

  run_cmd systemctl restart "${SVC}"
  
  if [[ $DRY_RUN -eq 0 ]]; then
    sleep 2
    if systemctl is-active --quiet "${SVC}"; then
      ok "Service ${SVC} berhasil di-restart dan running"
    else
      err "Service ${SVC} gagal start. Check: journalctl -xeu ${SVC}"
      exit 1
    fi
  fi
  
  run_cmd systemctl enable "${SVC}" >/dev/null 2>&1 || true
}

health_check() {
  [[ $DRY_RUN -eq 1 ]] && { info "Dry-run mode, skip health check"; return 0; }
  
  local SVC="zabbix-agent$([[ ${AGENT_KIND} == 2 ]] && echo 2)"
  local LOGFILE="/var/log/zabbix/zabbix_agent$([[ ${AGENT_KIND} == 2 ]] && echo 2 || echo d).log"
  local checks_passed=0
  local checks_total=4
  
  echo
  info "=== Post-Install Health Check ==="
  echo
  
  # 1. Service running
  if systemctl is-active --quiet "${SVC}"; then
    ok "✓ Service ${SVC} running"
    ((checks_passed++))
  else
    err "✗ Service ${SVC} NOT running"
  fi
  
  # 2. Port listening
  sleep 1
  if ss -lntp 2>/dev/null | grep -q ":${ZBX_LISTEN_PORT}"; then
    ok "✓ Port ${ZBX_LISTEN_PORT} listening"
    ((checks_passed++))
  else
    warn "✗ Port ${ZBX_LISTEN_PORT} NOT listening yet (tunggu beberapa detik)"
  fi
  
  # 3. Config syntax check (Agent2 only)
  if [[ "${AGENT_KIND}" == "2" ]]; then
    if zabbix_agent2 -t agent.ping 2>/dev/null | grep -q "agent.ping"; then
      ok "✓ Config syntax valid & agent.ping OK"
      ((checks_passed++))
    else
      warn "✗ Config test failed"
    fi
  else
    ((checks_passed++))  # Skip for Agent1
  fi
  
  # 4. Server connectivity
  if timeout 3 bash -c "cat < /dev/null > /dev/tcp/${ZBX_SERVER}/10051" 2>/dev/null; then
    ok "✓ Zabbix Server ${ZBX_SERVER}:10051 reachable"
    ((checks_passed++))
  else
    warn "✗ Server ${ZBX_SERVER}:10051 tidak dapat diakses (normal jika server belum add host ini)"
  fi
  
  echo
  if [[ $checks_passed -eq $checks_total ]]; then
    ok "=== Health Check: ${checks_passed}/${checks_total} PASSED ✓ ==="
  else
    warn "=== Health Check: ${checks_passed}/${checks_total} passed (${checks_total} expected) ==="
  fi
  
  echo
  ok "Instalasi selesai! Next steps:"
  echo "  1. Di Zabbix Server, tambahkan host ini dengan:"
  echo "     - Hostname: ${ZBX_HOSTNAME}"
  echo "     - IP: $(hostname -I | awk '{print $1}')"
  echo "     - Port: ${ZBX_LISTEN_PORT}"
  [[ -n "${ZBX_PSK_HEX}" ]] && echo "     - PSK Identity: ${ZBX_HOSTNAME}"
  [[ -n "${ZBX_PSK_HEX}" ]] && echo "     - PSK: ${ZBX_PSK_HEX}"
  echo
  echo "  2. Verifikasi dengan:"
  echo "     - systemctl status ${SVC}"
  echo "     - tail -f ${LOGFILE}"
  echo "     - ss -lntp | grep ${ZBX_LISTEN_PORT}"
  echo
  echo "  3. Test dari Zabbix Server:"
  echo "     - zabbix_get -s $(hostname -I | awk '{print $1}') -p ${ZBX_LISTEN_PORT} -k agent.ping"
}

uninstall_agent() {
  need_root
  info "Uninstalling Zabbix Agent..."
  
  # Stop services
  systemctl stop zabbix-agent 2>/dev/null || true
  systemctl stop zabbix-agent2 2>/dev/null || true
  systemctl disable zabbix-agent 2>/dev/null || true
  systemctl disable zabbix-agent2 2>/dev/null || true
  
  # Detect OS for package removal
  detect_os
  
  # Remove packages
  if [[ "${DIST_CLASS}" == "ubuntu" ]]; then
    apt-get remove --purge -y zabbix-agent zabbix-agent2 zabbix-release 2>/dev/null || true
    apt-get autoremove -y 2>/dev/null || true
  else
    ${PKG_MGR} remove -y zabbix-agent zabbix-agent2 zabbix-release 2>/dev/null || true
  fi
  
  # Remove config backups and PSK
  rm -f /etc/zabbix/zabbix_agent*.conf.bak* 2>/dev/null || true
  rm -f /etc/zabbix/zabbix_agentd.psk 2>/dev/null || true
  
  # Remove firewall rules
  if command -v ufw >/dev/null 2>&1; then
    ufw delete allow 10050/tcp 2>/dev/null || true
  fi
  
  if command -v firewall-cmd >/dev/null 2>&1; then
    if systemctl is-active --quiet firewalld; then
      firewall-cmd --remove-port=10050/tcp --permanent 2>/dev/null || true
      firewall-cmd --reload 2>/dev/null || true
    fi
  fi
  
  ok "Zabbix Agent berhasil di-uninstall"
}

main() {
  need_root
  parse_args "$@"
  
  if [[ $DRY_RUN -eq 1 ]]; then
    warn "=== DRY-RUN MODE - No changes will be made ==="
    echo
  fi
  
  detect_os
  preflight_check
  install_repo
  install_agent
  configure_agent
  configure_selinux
  open_firewall
  start_service
  health_check
}

main "$@"
