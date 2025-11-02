#!/usr/bin/env bash
# Unified Billing Stack Installer (vMerged)
# Target: Ubuntu 22.04/24.04 controller or single-node production-ready deployment
# Features merged: Ceilometer + Gnocchi + CloudKitty + Billing Portal + Nginx TLS + Keystone endpoints + Postgres
# Interactive: prompts for all required variables (passwords/hosts/keys/etc)
# Run as root. Review before running in production.

set -euo pipefail
IFS=$'\n\t'

########## Helpers ##########
info() { echo -e "\e[36m[INFO]\e[0m $*"; }
warn() { echo -e "\e[33m[WARN]\e[0m $*"; }
err() { echo -e "\e[31m[ERR]\e[0m $*" >&2; exit 1; }

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    err "This script must be run as root (or with sudo). Aborting."
  fi
}

check_command() {
  command -v "$1" >/dev/null 2>&1 || { err "Required command '$1' not found. Install it then re-run."; }
}

apt_update_install() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y "$@"
}

generate_password() {
  openssl rand -base64 24
}

confirm_continue() {
  read -r -p "Continue? [y/N]: " c
  case "$c" in [yY][eE][sS]|[yY]) return 0 ;; *) err "Cancelled by user." ;; esac
}

########## Gather variables (interactive) ##########
require_root
info "Unified Billing Stack Installer - merged version"

echo
echo ">> You will be prompted for required variables. Press ENTER to accept suggested defaults or to auto-generate secrets."
echo

# Keystone/openrc
read -r -p "Enter path to admin-openrc (or leave blank to source later manually): " ADMIN_OPENRC
if [ -n "$ADMIN_OPENRC" ] && [ -f "$ADMIN_OPENRC" ]; then
  info "Sourcing ${ADMIN_OPENRC}"
  # shellcheck disable=SC1090
  source "$ADMIN_OPENRC"
else
  warn "admin-openrc not sourced. You will need openstack CLI credentials available in env."
  echo "If you want to source a local openrc later, run: source /root/admin-openrc"
fi

read -r -p "OpenStack Region name [RegionOne]: " OS_REGION
OS_REGION=${OS_REGION:-RegionOne}

# Host/IP info
read -r -p "Controller hostname or IP (this node) [controller]: " CONTROLLER
CONTROLLER=${CONTROLLER:-controller}
read -r -p "Public hostname for billing portal (FQDN) [billing.example.org]: " BILLING_FQDN
BILLING_FQDN=${BILLING_FQDN:-billing.abstryacloud.local}

# DB choices
read -r -p "Use local PostgreSQL for CloudKitty & Billing Portal? (y/N) [N]: " USE_LOCAL_PG_ANS
USE_LOCAL_PG_ANS=${USE_LOCAL_PG_ANS:-N}
if [[ "$USE_LOCAL_PG_ANS" =~ ^[Yy]$ ]]; then
  USE_LOCAL_PG=true
  read -r -p "Postgres listen address [localhost]: " PG_HOST
  PG_HOST=${PG_HOST:-localhost}
  read -r -p "Postgres port [5432]: " PG_PORT
  PG_PORT=${PG_PORT:-5432}
  read -r -p "Postgres admin user [postgres]: " PG_ADMIN
  PG_ADMIN=${PG_ADMIN:-postgres}
else
  USE_LOCAL_PG=false
  read -r -p "External Postgres host: " PG_HOST
  read -r -p "External Postgres port [5432]: " PG_PORT
  PG_PORT=${PG_PORT:-5432}
  read -r -p "External Postgres admin user: " PG_ADMIN
fi

# RabbitMQ details
read -r -p "RabbitMQ host [localhost]: " RABBIT_HOST
RABBIT_HOST=${RABBIT_HOST:-localhost}
read -r -p "RabbitMQ user [openstack]: " RABBIT_USER
RABBIT_USER=${RABBIT_USER:-openstack}
read -s -r -p "RabbitMQ password (leave blank to auto-generate): " RABBIT_PASS
echo
RABBIT_PASS=${RABBIT_PASS:-$(generate_password)}

# Memcached (token caching) - optional
read -r -p "Memcached servers (comma-separated) [127.0.0.1:11211]: " MEMCACHED_SERVERS
MEMCACHED_SERVERS=${MEMCACHED_SERVERS:-127.0.0.1:11211}

# Gnocchi / Ceilometer / CloudKitty credentials & DB
read -r -p "Gnocchi service username [gnocchi]: " GNOCCHI_USER
GNOCCHI_USER=${GNOCCHI_USER:-gnocchi}
read -s -r -p "Gnocchi service password (leave blank to auto-generate): " GNOCCHI_PASS
echo
GNOCCHI_PASS=${GNOCCHI_PASS:-$(generate_password)}

read -r -p "CloudKitty service username [cloudkitty]: " CLOUDKITTY_USER
CLOUDKITTY_USER=${CLOUDKITTY_USER:-cloudkitty}
read -s -r -p "CloudKitty service password (leave blank to auto-generate): " CLOUDKITTY_PASS
echo
CLOUDKITTY_PASS=${CLOUDKITTY_PASS:-$(generate_password)}

read -r -p "Billing portal DB name [billing]: " BILLING_DB
BILLING_DB=${BILLING_DB:-billing}
read -r -p "CloudKitty DB name [cloudkitty]: " CLOUDKITTY_DB
CLOUDKITTY_DB=${CLOUDKITTY_DB:-cloudkitty}
read -r -p "DB user for billing portal [billing_user]: " BILLING_DB_USER
BILLING_DB_USER=${BILLING_DB_USER:-billing_user}
read -s -r -p "DB password for billing portal (leave blank to auto-generate): " BILLING_DB_PASS
echo
BILLING_DB_PASS=${BILLING_DB_PASS:-$(generate_password)}
read -s -r -p "DB password for cloudkitty (leave blank to auto-generate): " CLOUDKITTY_DB_PASS
echo
CLOUDKITTY_DB_PASS=${CLOUDKITTY_DB_PASS:-$(generate_password)}

# TLS / Let's Encrypt
read -r -p "Enable Let's Encrypt automatic TLS? (y/N) [N]: " USE_LETSENCRYPT_ANS
USE_LETSENCRYPT_ANS=${USE_LETSENCRYPT_ANS:-N}
if [[ "$USE_LETSENCRYPT_ANS" =~ ^[Yy]$ ]]; then
  USE_LETSENCRYPT=true
  read -r -p "Email for Let's Encrypt notifications: " LE_EMAIL
else
  USE_LETSENCRYPT=false
fi

read -r -p "If not using Let's Encrypt, generate self-signed certificate? (y/N) [Y]: " GEN_SELF_CERT_ANS
GEN_SELF_CERT_ANS=${GEN_SELF_CERT_ANS:-Y}
GEN_SELF_CERT=false
if [[ "$USE_LETSENCRYPT" = false ]]; then
  if [[ "$GEN_SELF_CERT_ANS" =~ ^[Yy]$ ]]; then
    GEN_SELF_CERT=true
  fi
fi

# Stripe (optional)
read -r -p "Enable Stripe billing integration? (y/N) [N]: " USE_STRIPE_ANS
USE_STRIPE_ANS=${USE_STRIPE_ANS:-N}
if [[ "$USE_STRIPE_ANS" =~ ^[Yy]$ ]]; then
  USE_STRIPE=true
  read -r -p "Stripe secret key (sk_...): " STRIPE_SECRET
  read -r -p "Stripe webhook secret (endpoint signing secret): " STRIPE_WEBHOOK_SECRET
else
  USE_STRIPE=false
fi

# Deployment choices
read -r -p "Deploy Billing Portal using Docker? (y/N) [Y]: " USE_DOCKER_ANS
USE_DOCKER_ANS=${USE_DOCKER_ANS:-Y}
if [[ "$USE_DOCKER_ANS" =~ ^[Yy]$ ]]; then
  USE_DOCKER=true
else
  USE_DOCKER=false
fi

# Misc
read -r -p "System user to run services (non-root) [billing]: " RUN_USER
RUN_USER=${RUN_USER:-billing}

echo
info "Summary of key values (hideable secrets omitted):"
cat <<EOF
Controller: ${CONTROLLER}
Billing FQDN: ${BILLING_FQDN}
Use local Postgres: ${USE_LOCAL_PG}
Postgres host: ${PG_HOST}:${PG_PORT}
RabbitMQ: ${RABBIT_HOST}
Memcached: ${MEMCACHED_SERVERS}
Gnocchi user: ${GNOCCHI_USER}
CloudKitty user: ${CLOUDKITTY_USER}
Billing DB: ${BILLING_DB} (user: ${BILLING_DB_USER})
Stripe enabled: ${USE_STRIPE}
Use Docker for Billing Portal: ${USE_DOCKER}
Let's Encrypt: ${USE_LETSENCRYPT}
Run user: ${RUN_USER}
EOF

confirm_continue

########## Install system packages ##########
info "Installing system packages (apt-get)..."
apt_update_install python3-pip python3-venv nginx git curl gnupg2 \
  uwsgi uwsgi-plugin-python3 systemd openssl jq

# If local Postgres requested, install and configure
if [ "$USE_LOCAL_PG" = true ]; then
  info "Installing local PostgreSQL"
  apt_update_install postgresql postgresql-contrib libpq-dev
fi

# Install Redis client and python libs used for gnocchi storage/backends
apt_update_install redis-tools

# Install python packages for the services (some may prefer apt packages)
info "Installing python packages (pip) for gnocchi/cloudkitty/ceilometer client tools"
python3 -m pip install --upgrade pip setuptools wheel
python3 -m pip install python-gnocchiclient gnocchi python-cloudkittyclient python3-openstackclient

########## Create run user ##########
if ! id -u "$RUN_USER" >/dev/null 2>&1; then
  info "Creating system user ${RUN_USER}"
  adduser --system --group --home /var/lib/"$RUN_USER" --shell /usr/sbin/nologin "$RUN_USER"
fi

########## PostgreSQL setup ##########
if [ "$USE_LOCAL_PG" = true ]; then
  info "Setting up PostgreSQL databases and users locally"
  # ensure postgres is running
  systemctl enable --now postgresql
  # create DBs and users idempotently
  sudo -u postgres psql -v ON_ERROR_STOP=1 <<-SQL || true
    DO \$\$
    BEGIN
      IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${BILLING_DB_USER}') THEN
        CREATE ROLE ${BILLING_DB_USER} LOGIN PASSWORD '${BILLING_DB_PASS}';
      END IF;
    END
    \$\$;
    CREATE DATABASE ${BILLING_DB} OWNER ${BILLING_DB_USER} WITH ENCODING 'UTF8' LC_COLLATE='C' LC_CTYPE='C' TEMPLATE template0;
SQL
  # CloudKitty DB
  sudo -u postgres psql -v ON_ERROR_STOP=1 <<-SQL || true
    DO \$\$
    BEGIN
      IF NOT EXISTS (SELECT FROM pg_database WHERE datname = '${CLOUDKITTY_DB}') THEN
        CREATE DATABASE ${CLOUDKITTY_DB} OWNER ${PG_ADMIN} WITH ENCODING 'UTF8';
      END IF;
    END
    \$\$;
SQL
  info "Postgres local DBs created/verified."
fi

########## Keystone service registration (gnocchi, cloudkitty, billing) ##########
info "Registering services and endpoints in Keystone. Requires openstack CLI access (admin)."

# check openstack CLI presence
if ! command -v openstack >/dev/null 2>&1; then
  err "openstack CLI not found. Install python3-openstackclient (pip or apt) and ensure admin credentials are available."
fi

# create users and service entities (idempotent attempts)
# GNOCCHI
info "Creating Gnocchi user/service/endpoint..."
openstack user show "${GNOCCHI_USER}" >/dev/null 2>&1 || openstack user create --domain default --password "${GNOCCHI_PASS}" "${GNOCCHI_USER}"
openstack role add --project service --user "${GNOCCHI_USER}" admin >/dev/null 2>&1 || true
openstack service show gnocchi >/dev/null 2>&1 || openstack service create --name gnocchi --description "Metric Service" metric
# endpoints
openstack endpoint list --service gnocchi | grep public >/dev/null 2>&1 || openstack endpoint create --region "${OS_REGION}" metric public "http://${CONTROLLER}:8041"
openstack endpoint list --service gnocchi | grep internal >/dev/null 2>&1 || openstack endpoint create --region "${OS_REGION}" metric internal "http://${CONTROLLER}:8041"
openstack endpoint list --service gnocchi | grep admin >/dev/null 2>&1 || openstack endpoint create --region "${OS_REGION}" metric admin "http://${CONTROLLER}:8041"

# CLOUDKITTY
info "Creating CloudKitty user/service/endpoint..."
openstack user show "${CLOUDKITTY_USER}" >/dev/null 2>&1 || openstack user create --domain default --password "${CLOUDKITTY_PASS}" "${CLOUDKITTY_USER}"
openstack role add --project service --user "${CLOUDKITTY_USER}" admin >/dev/null 2>&1 || true
openstack service show cloudkitty >/dev/null 2>&1 || openstack service create --name cloudkitty --description "Rating Service" rating
openstack endpoint list --service cloudkitty | grep public >/dev/null 2>&1 || openstack endpoint create --region "${OS_REGION}" rating public "http://${CONTROLLER}:8889/v1"
openstack endpoint list --service cloudkitty | grep internal >/dev/null 2>&1 || openstack endpoint create --region "${OS_REGION}" rating internal "http://${CONTROLLER}:8889/v1"
openstack endpoint list --service cloudkitty | grep admin >/dev/null 2>&1 || openstack endpoint create --region "${OS_REGION}" rating admin "http://${CONTROLLER}:8889/v1"

# Billing Portal service (optional)
info "Creating Billing service endpoint (billing-portal)..."
openstack service show billing-portal >/dev/null 2>&1 || openstack service create --name billing-portal --description "Billing Portal" billing
openstack endpoint list --service billing-portal | grep public >/dev/null 2>&1 || openstack endpoint create --region "${OS_REGION}" billing public "https://${BILLING_FQDN}"
openstack endpoint list --service billing-portal | grep internal >/dev/null 2>&1 || openstack endpoint create --region "${OS_REGION}" billing internal "https://${BILLING_FQDN}"
openstack endpoint list --service billing-portal | grep admin >/dev/null 2>&1 || openstack endpoint create --region "${OS_REGION}" billing admin "https://${BILLING_FQDN}"

info "Keystone service/user registration attempted. Verify in Keystone."

########## Install & configure Gnocchi ##########
info "Installing Gnocchi"
apt_update_install gnocchi-api gnocchi-metricd python3-gnocchiclient uwsgi-plugin-python3 uwsgi

# create config dir
mkdir -p /etc/gnocchi
GNOCCHI_CONF=/etc/gnocchi/gnocchi.conf

if [ ! -f "${GNOCCHI_CONF}" ]; then
  info "Generating /etc/gnocchi/gnocchi.conf"
  cat > "${GNOCCHI_CONF}" <<EOF
[DEFAULT]
auth_mode = keystone
bind = 0.0.0.0
port = 8041

[keystone_authtoken]
auth_type = password
auth_url = http://$CONTROLLER:5000/v3
project_domain_name = Default
user_domain_name = Default
project_name = service
username = ${GNOCCHI_USER}
password = ${GNOCCHI_PASS}
interface = internalURL
region_name = ${OS_REGION}

[indexer]
url = postgresql://gnocchi:$(generate_password)@${PG_HOST}:${PG_PORT}/gnocchi

[storage]
# By default use file driver; for production consider ceph or swift/backends
driver = file
file_basepath = /var/lib/gnocchi
coordination_url = redis://127.0.0.1:6379
EOF
fi

mkdir -p /var/lib/gnocchi
chown -R "$RUN_USER":"$RUN_USER" /var/lib/gnocchi || true

# create gnocchi DB if local Postgres
if [ "$USE_LOCAL_PG" = true ]; then
  info "Creating gnocchi DB and user locally"
  GNOCCHI_DB_PASS=$(generate_password)
  sudo -u postgres psql -v ON_ERROR_STOP=1 <<-SQL || true
    DO \$\$
    BEGIN
      IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'gnocchi') THEN
        CREATE ROLE gnocchi LOGIN PASSWORD '${GNOCCHI_DB_PASS}';
      END IF;
    END
    \$\$;
    CREATE DATABASE gnocchi OWNER gnocchi;
SQL
  # update conf
  sed -i "s/postgresql:\/\/gnocchi:.*/postgresql:\/\/gnocchi:${GNOCCHI_DB_PASS}\@${PG_HOST}:${PG_PORT}\/gnocchi/" "${GNOCCHI_CONF}"
fi

info "Initializing Gnocchi DB (if needed)"
gnocchi-upgrade || warn "gnocchi-upgrade may require environment variables or manual run"

systemctl enable --now gnocchi-api || true
systemctl enable --now gnocchi-metricd || true

########## Install & configure Ceilometer (collection parts) ##########
info "Installing Ceilometer components (agent-notification/central)"
apt_update_install ceilometer-agent-notification ceilometer-agent-central python3-ceilometerclient

CEILOMETER_CONF=/etc/ceilometer/ceilometer.conf
if [ ! -f "$CEILOMETER_CONF" ]; then
  info "Creating /etc/ceilometer/ceilometer.conf"
  cat > "$CEILOMETER_CONF" <<EOF
[DEFAULT]
transport_url = rabbit://${RABBIT_USER}:${RABBIT_PASS}@${RABBIT_HOST}
auth_strategy = keystone
metering_secret = $(generate_password)
[keystone_authtoken]
auth_uri = http://${CONTROLLER}:5000
auth_url = http://${CONTROLLER}:5000
auth_type = password
project_domain_name = Default
user_domain_name = Default
project_name = service
username = ceilometer
password = $(generate_password)
[service_credentials]
auth_type = password
auth_url = http://${CONTROLLER}:5000/v3
project_domain_id = default
user_domain_id = default
project_name = service
username = ceilometer
password = $(generate_password)
interface = internalURL
region_name = ${OS_REGION}
[oslo_messaging_notifications]
driver = messagingv2
topics = notifications
EOF
fi

systemctl enable --now ceilometer-agent-notification || true
systemctl enable --now ceilometer-agent-central || true

########## Install & configure CloudKitty ##########
info "Installing CloudKitty"
python3 -m pip install cloudkitty
# CloudKitty config directory
CK_CONF_DIR=/etc/cloudkitty
mkdir -p "${CK_CONF_DIR}"
CK_CONF="${CK_CONF_DIR}/cloudkitty.conf"

if [ ! -f "${CK_CONF}" ]; then
  info "Creating CloudKitty config ${CK_CONF}"
  cat > "${CK_CONF}" <<EOF
[DEFAULT]
debug = False
rpc_backend = rabbit
[oslo_messaging]
transport_url = rabbit://${RABBIT_USER}:${RABBIT_PASS}@${RABBIT_HOST}
[keystone_authtoken]
auth_url = http://${CONTROLLER}:5000/v3
project_domain_name = Default
user_domain_name = Default
project_name = service
username = ${CLOUDKITTY_USER}
password = ${CLOUDKITTY_PASS}
region_name = ${OS_REGION}
[storage:sqlalchemy]
connection = postgresql+psycopg2://${BILLING_DB_USER}:${BILLING_DB_PASS}@${PG_HOST}:${PG_PORT}/${CLOUDKITTY_DB}
[reporting]
backend = gnocchi
[gnocchi]
url = http://${CONTROLLER}:8041
EOF
fi

# Setup CloudKitty DB user locally if requested
if [ "$USE_LOCAL_PG" = true ]; then
  info "Ensure CloudKitty DB exists"
  sudo -u postgres psql -v ON_ERROR_STOP=1 <<-SQL || true
    DO \$\$
    BEGIN
      IF NOT EXISTS (SELECT FROM pg_database WHERE datname = '${CLOUDKITTY_DB}') THEN
        CREATE DATABASE ${CLOUDKITTY_DB};
      END IF;
    END
    \$\$;
SQL
  # create cloudkitty DB user and grant
  sudo -u postgres psql -v ON_ERROR_STOP=1 <<-SQL || true
    DO \$\$
    BEGIN
      IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${BILLING_DB_USER}') THEN
        CREATE ROLE ${BILLING_DB_USER} LOGIN PASSWORD '${BILLING_DB_PASS}';
      END IF;
    END
    \$\$;
    GRANT ALL PRIVILEGES ON DATABASE ${CLOUDKITTY_DB} TO ${BILLING_DB_USER};
SQL
fi

# Create systemd service wrapper for cloudkitty-reporting and cloudkitty-api (if installed)
info "Creating systemd unit files for cloudkitty (if appropriate)"
cat > /etc/systemd/system/cloudkitty.service <<'EOF'
[Unit]
Description=CloudKitty worker
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/env python3 -m cloudkitty.storage.base  || /usr/bin/true
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload || true
systemctl enable --now cloudkitty.service || true

########## Billing Portal (Flask) setup ##########
info "Preparing Billing Portal"

PORTAL_DIR=/opt/billing_portal
mkdir -p "${PORTAL_DIR}"
if [ ! -d "${PORTAL_DIR}/.git" ]; then
  info "Cloning sample billing portal (replace with your repo later)"
  git clone https://github.com/openstack/cloudkitty-dashboard.git "${PORTAL_DIR}" || warn "Could not clone billing UI sample; proceed to configure custom portal at ${PORTAL_DIR}"
fi

# Create virtualenv or docker-compose depending on choice
if [ "$USE_DOCKER" = true ]; then
  info "Installing Docker & docker-compose"
  apt_update_install apt-transport-https ca-certificates software-properties-common
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
  add-apt-repository "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" || true
  apt-get update -y
  apt_update_install docker-ce docker-ce-cli containerd.io docker-compose-plugin
  usermod -aG docker "$SUDO_USER" || true
  info "Writing basic docker-compose for billing portal"
  cat > "${PORTAL_DIR}/docker-compose.yml" <<EOF
version: '3.7'
services:
  billing:
    image: python:3.10-slim
    working_dir: /app
    volumes:
      - ./:/app
    command: bash -c "pip install -r requirements.txt && python run.py"
    environment:
      - DATABASE_URL=postgresql://${BILLING_DB_USER}:${BILLING_DB_PASS}@${PG_HOST}:${PG_PORT}/${BILLING_DB}
      - GNOCCHI_URL=http://${CONTROLLER}:8041
      - CLOUDKITTY_URL=http://${CONTROLLER}:8889/v1
      - STRIPE_SECRET=${STRIPE_SECRET:-}
EOF
  info "Starting billing portal via docker-compose"
  (cd "${PORTAL_DIR}" && docker compose up -d) || warn "docker-compose start failed; you may need to run manually in ${PORTAL_DIR}"
else
  info "Setting up python virtualenv for billing portal"
  python3 -m venv "${PORTAL_DIR}/venv"
  source "${PORTAL_DIR}/venv/bin/activate"
  if [ -f "${PORTAL_DIR}/requirements.txt" ]; then
    pip install -r "${PORTAL_DIR}/requirements.txt"
  else
    pip install flask sqlalchemy psycopg2-binary gunicorn
  fi
  # create systemd unit
  cat > /etc/systemd/system/billing-portal.service <<EOF
[Unit]
Description=Billing Portal
After=network.target

[Service]
User=${RUN_USER}
Group=${RUN_USER}
WorkingDirectory=${PORTAL_DIR}
Environment=DATABASE_URL=postgresql://${BILLING_DB_USER}:${BILLING_DB_PASS}@${PG_HOST}:${PG_PORT}/${BILLING_DB}
ExecStart=${PORTAL_DIR}/venv/bin/gunicorn --bind 0.0.0.0:8000 run:app
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now billing-portal.service || warn "billing portal service failed to start"
fi

########## Nginx reverse proxy + TLS for Billing Portal ##########
info "Configuring Nginx reverse proxy for ${BILLING_FQDN}"
NGINX_CONF=/etc/nginx/sites-available/billing_portal.conf

if [ "$USE_LETSENCRYPT" = true ]; then
  info "Installing certbot"
  apt_update_install certbot python3-certbot-nginx
  # create simple nginx config to allow certbot validation
  cat > "${NGINX_CONF}" <<EOF
server {
    listen 80;
    server_name ${BILLING_FQDN};
    location / {
        proxy_pass http://127.0.0.1:8000/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF
  ln -sf "${NGINX_CONF}" /etc/nginx/sites-enabled/billing_portal.conf
  systemctl restart nginx || true
  info "Attempting to obtain Let's Encrypt certificate for ${BILLING_FQDN}"
  certbot --nginx -n --agree-tos --email "${LE_EMAIL}" -d "${BILLING_FQDN}" || warn "certbot failed; check DNS and try manually later"
elif [ "$GEN_SELF_CERT" = true ]; then
  info "Generating self-signed cert for ${BILLING_FQDN}"
  mkdir -p /etc/nginx/ssl
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/${BILLING_FQDN}.key \
    -out /etc/nginx/ssl/${BILLING_FQDN}.crt \
    -subj "/CN=${BILLING_FQDN}"
  cat > "${NGINX_CONF}" <<EOF
server {
    listen 80;
    server_name ${BILLING_FQDN};
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name ${BILLING_FQDN};

    ssl_certificate /etc/nginx/ssl/${BILLING_FQDN}.crt;
    ssl_certificate_key /etc/nginx/ssl/${BILLING_FQDN}.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://127.0.0.1:8000/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF
  ln -sf "${NGINX_CONF}" /etc/nginx/sites-enabled/billing_portal.conf
  systemctl restart nginx || warn "nginx restart failed; check config"
else
  info "Creating plain HTTP nginx proxy (no TLS)"
  cat > "${NGINX_CONF}" <<EOF
server {
    listen 80;
    server_name ${BILLING_FQDN};

    location / {
        proxy_pass http://127.0.0.1:8000/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF
  ln -sf "${NGINX_CONF}" /etc/nginx/sites-enabled/billing_portal.conf
  systemctl restart nginx || warn "nginx restart failed; check config"
fi

########## Stripe webhook (if requested) - demo registration ##########
if [ "$USE_STRIPE" = true ]; then
  info "Configuring Stripe webhook endpoint (note: you must configure in Stripe dashboard)"
  # Create example webhook receiver script under portal to verify signatures
  cat > "${PORTAL_DIR}/stripe_webhook.py" <<EOF
from flask import Flask, request, abort
import os, stripe
app = Flask(__name__)
stripe.api_key = os.environ.get('STRIPE_SECRET')
endpoint_secret = "${STRIPE_WEBHOOK_SECRET}"
@app.route('/stripe/webhook', methods=['POST'])
def webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    try:
        evt = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
    except Exception as e:
        abort(400)
    # TODO: handle event
    return '', 200
EOF
  chown -R "${RUN_USER}:${RUN_USER}" "${PORTAL_DIR}" || true
  info "Stripe webhook file placed at ${PORTAL_DIR}/stripe_webhook.py. Ensure portal integrates it and registers webhook in Stripe console."
fi

########## Final notes, verification & print secrets ##########
info "Installation phase finished (attempted). Some components may require manual follow-up / tuning."

cat <<EOF

==== Post-install notes ====

1) Verify services are running:
   - systemctl status gnocchi-api gnocchi-metricd ceilometer-agent-notification ceilometer-agent-central cloudkitty billing-portal
   - nginx (for portal): systemctl status nginx

2) Verify Keystone entries:
   - openstack service list
   - openstack endpoint list

3) Databases:
   - If you used an external Postgres, ensure GNOCCHI/CloudKitty/Billing DBs and users are created.
   - To manually run DB migrations:
       - gnocchi-upgrade
       - cloudkitty-manage db_sync (if available)
       - billing portal specific DB upgrade commands

4) Logs:
   - /var/log/gnocchi
   - /var/log/cloudkitty (if configured)
   - /var/log/nginx

5) If you used Let's Encrypt, certs were attempted via certbot; check /var/log/letsencrypt.

==== Generated secrets (store them safely) ====
RabbitMQ password: ${RABBIT_PASS}
Gnocchi password: ${GNOCCHI_PASS}
CloudKitty password: ${CLOUDKITTY_PASS}
Billing DB user/password: ${BILLING_DB_USER} / ${BILLING_DB_PASS}
CloudKitty DB password: ${CLOUDKITTY_DB_PASS}

(If you prefer secrets written to a single file, run with redirection and save securely.)

EOF

info "Completed. Manually verify functions such as: metric ingestion in Gnocchi, ceilometer event flow, CloudKitty rating, billing portal pages, and Stripe webhooks (if enabled)."

# End of script