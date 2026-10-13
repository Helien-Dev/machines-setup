#!/usr/bin/env bash
# Hardening + (opcional) Dokploy para VMs Ubuntu/Debian recién instaladas.
# Uso (como root, desde la consola de Proxmox o SSH):
#   bash vm-bootstrap.sh              -> setup interactivo
#   bash vm-bootstrap.sh cerrar-3000  -> cierra el puerto 3000 de Dokploy (cuando el panel ya tenga dominio+HTTPS)
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Ejecuta como root: sudo bash $0"; exit 1; }
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a

ask()    { local r; read -rp "$1 [$2]: " r; echo "${r:-$2}"; }
yes_no() { local r; read -rp "$1 [${2}]: " r; r="${r:-$2}"; [[ ${r,,} == s* || ${r,,} == y* ]]; }
step()   { echo -e "\n\e[1;36m==> $*\e[0m"; }

cerrar_3000() {
  docker service update --publish-rm "published=3000,target=3000,protocol=tcp,mode=host" dokploy
  iptables -D INPUT -p tcp --dport 3000 -j ACCEPT 2>/dev/null || true
  sed -i '/--dport 3000/d' /etc/iptables/rules.v4
  echo "Puertos publicados de dokploy: $(docker service inspect dokploy --format '{{json .Endpoint.Ports}}') (debe ser null)"
}
[[ ${1:-} == cerrar-3000 ]] && { cerrar_3000; exit 0; }

. /etc/os-release
[[ $ID == ubuntu || $ID == debian ]] || { echo "Solo Ubuntu/Debian (detectado: $ID)"; exit 1; }

# ---------- Preguntas (todo se pregunta al inicio, luego corre solo) ----------
echo "Sistema: $PRETTY_NAME | hostname actual: $(hostname)"
NEW_HOST=$(ask "Nuevo hostname (Enter = no cambiar)" "$(hostname)")
USERNAME=$(ask "Usuario administrador" "dev")
while :; do
  read -rp "Clave pública SSH de $USERNAME (ssh-ed25519 AAAA...): " PUBKEY
  echo "$PUBKEY" | ssh-keygen -lf - >/dev/null 2>&1 && break
  echo "  Clave inválida, pégala completa en una línea."
done
SET_PASS=no; yes_no "¿Ponerle contraseña a $USERNAME? (para entrar por la consola de Proxmox si falla SSH) s/n" "s" && SET_PASS=yes
TZ_NAME=$(ask "Zona horaria" "America/Bogota")
SWAP_GB=0
if ! swapon --show | grep -q .; then SWAP_GB=$(ask "Swap en GB (0 = sin swap)" "4"); else echo "Ya hay swap, se omite."; fi
CROWDSEC=no;  yes_no "¿Instalar CrowdSec + bouncer? s/n" "s" && CROWDSEC=yes
EXTRA_PORTS=$(ask "Puertos TCP extra a abrir, separados por coma (22 siempre abierto)" "")
UNATTENDED=no; yes_no "¿Actualizaciones desatendidas (seguridad + updates) y reinicio si hace falta a las 04:00? s/n" "s" && UNATTENDED=yes
WEEKLY=no;    yes_no "¿Reinicio obligatorio los lunes a las 05:00? s/n" "s" && WEEKLY=yes
DOKPLOY=no;   yes_no "¿Instalar Dokploy? s/n" "n" && DOKPLOY=yes
GUEST_AGENT=no; yes_no "¿Instalar qemu-guest-agent (VM de Proxmox)? s/n" "s" && GUEST_AGENT=yes

PORTS="22"
[[ $DOKPLOY == yes ]] && PORTS+=",80,443,3000"
[[ -n $EXTRA_PORTS ]] && PORTS+=",${EXTRA_PORTS// /}"

# ---------- 1. Sistema ----------
step "Actualizando sistema"
apt-get update -qq && apt-get upgrade -y -qq
apt-get install -y -qq sudo curl ca-certificates gnupg iptables cron

if [[ $NEW_HOST != "$(hostname)" ]]; then
  step "Hostname -> $NEW_HOST"
  OLD_HOST=$(hostname)
  hostnamectl set-hostname "$NEW_HOST"
  sed -i "s/\b$OLD_HOST\b/$NEW_HOST/g" /etc/hosts
  [[ -d /etc/cloud/cloud.cfg.d ]] && echo 'preserve_hostname: true' > /etc/cloud/cloud.cfg.d/99-hostname.cfg
fi

step "Zona horaria -> $TZ_NAME"
timedatectl set-timezone "$TZ_NAME"
systemctl restart cron 2>/dev/null || true

[[ $GUEST_AGENT == yes ]] && { step "qemu-guest-agent"; apt-get install -y -qq qemu-guest-agent; systemctl enable --now qemu-guest-agent || true; }

# ---------- 2. Usuario ----------
step "Usuario $USERNAME con sudo sin contraseña"
id "$USERNAME" &>/dev/null || adduser --disabled-password --gecos "" "$USERNAME"
usermod -aG sudo "$USERNAME"
echo "$USERNAME ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/$USERNAME"
chmod 0440 "/etc/sudoers.d/$USERNAME"
visudo -c >/dev/null
install -d -m 700 -o "$USERNAME" -g "$USERNAME" "/home/$USERNAME/.ssh"
AK="/home/$USERNAME/.ssh/authorized_keys"
touch "$AK"; grep -qxF "$PUBKEY" "$AK" || echo "$PUBKEY" >> "$AK"
chown "$USERNAME:$USERNAME" "$AK"; chmod 600 "$AK"
[[ $SET_PASS == yes ]] && passwd "$USERNAME"

# ---------- 3. SSH ----------
step "SSH: solo clave, sin root"
cat > /etc/ssh/sshd_config.d/00-hardening.conf <<'EOF'
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
ClientAliveInterval 900
ClientAliveCountMax 3
EOF
sshd -t
systemctl restart ssh 2>/dev/null || systemctl restart sshd

# ---------- 4. Swap ----------
if [[ $SWAP_GB != 0 ]]; then
  step "Swap de ${SWAP_GB}G"
  fallocate -l "${SWAP_GB}G" /swapfile
  chmod 600 /swapfile; mkswap /swapfile >/dev/null; swapon /swapfile
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
  echo 'vm.swappiness=10' > /etc/sysctl.d/99-swappiness.conf
  sysctl --system >/dev/null
fi

# ---------- 5. CrowdSec ----------
if [[ $CROWDSEC == yes ]]; then
  step "CrowdSec + bouncer iptables"
  curl -s https://install.crowdsec.net | sh
  apt-get install -y -qq crowdsec crowdsec-firewall-bouncer-iptables
  systemctl reload crowdsec || systemctl restart crowdsec
fi

# ---------- 6. Firewall ----------
step "Firewall: DROP salvo puertos $PORTS"
iptables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || iptables -A INPUT -i lo -j ACCEPT
for p in ${PORTS//,/ }; do
  iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport "$p" -j ACCEPT
done
iptables -P INPUT DROP
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
apt-get install -y -qq iptables-persistent
netfilter-persistent save
# La cadena de CrowdSec depende de un ipset que no existe al arrancar; el bouncer la recrea solo.
sed -i '/CROWDSEC/d' /etc/iptables/rules.v4

# ---------- 7. Actualizaciones ----------
if [[ $UNATTENDED == yes ]]; then
  step "Actualizaciones desatendidas"
  apt-get install -y -qq unattended-upgrades
  printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' > /etc/apt/apt.conf.d/20auto-upgrades
  if [[ $ID == ubuntu ]]; then
    UPDATES='Unattended-Upgrade::Allowed-Origins { "${distro_id}:${distro_codename}-updates"; };'
  else
    UPDATES='Unattended-Upgrade::Origins-Pattern { "origin=Debian,codename=${distro_codename}-updates"; };'
  fi
  cat > /etc/apt/apt.conf.d/52qoru-unattended <<EOF
$UPDATES
Unattended-Upgrade::Origins-Pattern { "site=packagecloud.io"; };
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
EOF
fi

if [[ $WEEKLY == yes ]]; then
  step "Reinicio semanal lunes 05:00"
  echo '0 5 * * 1 root /sbin/shutdown -r now' > /etc/cron.d/qoru-weekly-reboot
  chmod 644 /etc/cron.d/qoru-weekly-reboot
  systemctl restart cron
fi

# ---------- 8. Dokploy (después de guardar el firewall, para no persistir reglas de Docker) ----------
if [[ $DOKPLOY == yes ]]; then
  step "Instalando Dokploy"
  curl -sSL https://dokploy.com/install.sh | sh
  docker service update --env-add "TZ=$TZ_NAME" dokploy
fi

# ---------- Resumen ----------
IP=$(hostname -I | awk '{print $1}')
step "Listo"
echo "  Prueba ANTES de cerrar esta sesión:  ssh $USERNAME@$IP"
[[ $UNATTENDED == yes ]] && unattended-upgrade --dry-run --debug 2>&1 | grep -i 'allowed origins' || true
iptables -L INPUT -n | head -3
if [[ $DOKPLOY == yes ]]; then
  echo
  echo "  Dokploy: entra YA a http://$IP:3000 y crea la cuenta admin."
  echo "  Cuando el panel tenga dominio + HTTPS:  bash $0 cerrar-3000"
fi
echo "  Recomendado: reiniciar una vez (reboot) para verificar que todo levanta solo."
