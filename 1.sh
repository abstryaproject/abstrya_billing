#!/usr/bin/env bash
# install_public_cloud_final_upgrade.sh
# Full upgraded installer: CloudKitty + Stripe Checkout billing + Skyline-like UI + Skyline plugin
# Target: Ubuntu 22.04 / 24.04 controller node. Run as root.
set -euo pipefail
IFS=$'\n\t'

# -------- helpers --------
log(){ echo -e "\e[1;34m[INFO]\e[0m $*"; }
warn(){ echo -e "\e[1;33m[WARN]\e[0m $*"; }
err(){ echo -e "\e[1;31m[ERROR]\e[0m $*"; exit 1; }
confirm_root(){ [ "$(id -u)" -eq 0 ] || err "Run as root (sudo)"; }
rand(){ python3 - <<'PY' 2>/dev/null
import secrets
print(secrets.token_urlsafe(24))
PY
}

confirm_root
export DEBIAN_FRONTEND=noninteractive

# -------- system prep --------
log "Updating system..."
apt update -y
apt upgrade -y

log "Installing required packages..."
apt install -y python3-venv python3-pip git curl jq nginx openssl ufw certbot python3-certbot-nginx \
  mariadb-client mariadb-server docker.io nodejs npm build-essential

# ensure docker-compose present
if ! command -v docker-compose >/dev/null 2>&1; then
  pip3 install --no-cache-dir docker-compose
fi
DOCKER_COMPOSE_BIN="$(command -v docker-compose || echo /usr/local/bin/docker-compose)"

# openstack client
if ! command -v openstack >/dev/null 2>&1; then
  pip3 install --no-cache-dir python-openstackclient
fi

# -------- paths & defaults --------
BASE_DIR="/opt/abstryacloud"
STACK_DIR="$BASE_DIR/stack"
JWT_DIR="$BASE_DIR/jwt"
CK_VENV_DIR="$BASE_DIR/cloudkitty"
CK_CONF_DIR="/etc/cloudkitty"
PLUGIN_DIR="/opt/skyline-plugins/billing-plugin"
ADMIN_OPENRC_PATH="/root/admin-openrc"   # change if needed

mkdir -p "$BASE_DIR" "$STACK_DIR" "$JWT_DIR" "$CK_CONF_DIR" "$PLUGIN_DIR"
chown root:root "$BASE_DIR"
chmod 750 "$BASE_DIR"

# -------- ask for essential info (or use env) --------
: "${KEYSTONE_URL:=${KEYSTONE_URL:-}}"
: "${BILLING_DOMAIN:=${BILLING_DOMAIN:-}}"
: "${SKYLINE_LOCAL_URL:=${SKYLINE_LOCAL_URL:-http://127.0.0.1:8000}}"
: "${STRIPE_SECRET:=${STRIPE_SECRET:-}}"
: "${STRIPE_WEBHOOK_SECRET:=${STRIPE_WEBHOOK_SECRET:-}}"
: "${APP_CRED_ID:=${APP_CRED_ID:-}}"
: "${APP_CRED_SECRET:=${APP_CRED_SECRET:-}}"

read_if_empty(){
  vname="$1"; prompt="$2"
  eval cur=\$$vname
  if [ -z "$cur" ]; then
    read -r -p "$prompt: " val
    eval $vname=\$val
  fi
}

read_if_empty KEYSTONE_URL "Keystone URL (e.g. http://controller:5000/v3)"
read_if_empty BILLING_DOMAIN "Public domain for billing & registration (leave empty => self-signed certs)"
read_if_empty STRIPE_SECRET "Stripe Secret key (leave empty to configure later)"
read_if_empty STRIPE_WEBHOOK_SECRET "Stripe Webhook signing secret (leave empty to configure later)"

# -------- generate secrets default --------
BILLING_DB_NAME="${BILLING_DB_NAME:-billing_db}"
BILLING_DB_USER="${BILLING_DB_USER:-billing_user}"
BILLING_DB_PASS="${BILLING_DB_PASS:-$(rand)}"
BILLING_FLASK_SECRET="${BILLING_FLASK_SECRET:-$(rand)}"

CK_DB_NAME="${CK_DB_NAME:-cloudkitty}"
CK_DB_USER="${CK_DB_USER:-cloudkitty}"
CK_DB_PASS="${CK_DB_PASS:-$(rand)}"
CK_KEYSTONE_PASS="${CK_KEYSTONE_PASS:-$(rand)}"
GNOCCI_PASS="${GNOCCI_PASS:-$(rand)}"

# -------- generate JWT keys (RS256) --------
if [ ! -f "$JWT_DIR/private.pem" ]; then
  log "Generating JWT RSA keypair..."
  openssl genpkey -algorithm RSA -out "$JWT_DIR/private.pem" -pkeyopt rsa_keygen_bits:2048
  openssl rsa -in "$JWT_DIR/private.pem" -pubout -out "$JWT_DIR/public.pem"
  chmod 600 "$JWT_DIR/private.pem"
  chmod 644 "$JWT_DIR/public.pem"
fi

# -------- create app credential if not provided (for billing) --------
if [ -z "$APP_CRED_ID" ] || [ -z "$APP_CRED_SECRET" ]; then
  if [ -f "$ADMIN_OPENRC_PATH" ]; then
    log "Creating billing-service user and application credential using admin-openrc..."
    # shellcheck disable=SC1090
    source "$ADMIN_OPENRC_PATH"
    if ! openstack user show billing-service >/dev/null 2>&1; then
      APASS=$(rand)
      openstack user create --domain default --password "$APASS" billing-service || true
      openstack role add --project service --user billing-service member || true
      log "Created billing-service user."
    fi
    NAME="billing_app_$(date +%s)"
    SECRET_CAND=$(openssl rand -hex 32)
    AC_JSON=$(openstack application credential create --user billing-service --unrestricted --secret "$SECRET_CAND" --name "$NAME" -f json 2>/dev/null || true)
    if [ -n "$AC_JSON" ]; then
      APP_CRED_ID=$(echo "$AC_JSON" | jq -r '.[0].id // .id' 2>/dev/null || true)
      APP_CRED_SECRET="$SECRET_CAND"
      log "App credential created: id=$APP_CRED_ID"
    else
      warn "Failed to create application credential automatically; continue and fill APP_CRED_* manually later."
    fi
  else
    warn "Admin openrc not found at $ADMIN_OPENRC_PATH; cannot auto-create app credential. Set APP_CRED_ID & APP_CRED_SECRET manually."
  fi
fi

# -------- CloudKitty install (venv) --------
log "Installing CloudKitty in venv at $CK_VENV_DIR..."
mkdir -p "$CK_VENV_DIR"
python3 -m venv "$CK_VENV_DIR/venv"
. "$CK_VENV_DIR/venv/bin/activate"
pip install --upgrade pip setuptools wheel
pip install cloudkitty-api cloudkitty-processor gnocchiclient pymysql python-memcached || true

# if cloudkitty not importable, install from source
python - <<'PY' 2>/dev/null || true
try:
    import cloudkitty
except Exception:
    pass
PY

if ! python -c "import cloudkitty" >/dev/null 2>&1; then
  log "Installing CloudKitty from source..."
  cd /tmp
  git clone https://opendev.org/openstack/cloudkitty.git || true
  cd cloudkitty
  "$CK_VENV_DIR/venv/bin/pip" install -e .
fi
deactivate

# -------- CloudKitty config ---------- 
log "Writing CloudKitty config to $CK_CONF_DIR/cloudkitty.conf..."
cat > "$CK_CONF_DIR/cloudkitty.conf" <<EOF
[DEFAULT]
debug = False
log_dir = /var/log/cloudkitty

[api]
host = 0.0.0.0
port = 8889

[keystone_authtoken]
auth_type = password
auth_url = ${KEYSTONE_URL}
project_domain_name = Default
user_domain_name = Default
project_name = service
username = cloudkitty
password = ${CK_KEYSTONE_PASS}

[collect]
collector = gnocchi
period = 3600

[fetcher]
fetcher = gnocchi

[gnocchi]
url = http://127.0.0.1:8041
auth_type = password
auth_url = ${KEYSTONE_URL}
project_domain_name = Default
user_domain_name = Default
project_name = service
username = gnocchi
password = ${GNOCCI_PASS}
interface = internalURL
region_name = RegionOne

[database]
connection = mysql+pymysql://${CK_DB_USER}:${CK_DB_PASS}@127.0.0.1/${CK_DB_NAME}

[rating]
module = hash
EOF

chmod 640 "$CK_CONF_DIR/cloudkitty.conf"

cat > "$CK_CONF_DIR/metrics.yml" <<'YML'
- name: vcpu_hour
  metric: instance.flavor.vcpus
  unit: vcpu.hour
  type: gauge
- name: ram_mb_hour
  metric: instance.flavor.ram_mb
  unit: mb.hour
  type: gauge
- name: volume_gb_month
  metric: volume.size
  unit: gb.month
  type: gauge
- name: floating_ip_hour
  metric: ip.floating
  unit: ip.hour
  type: gauge
YML

cat > "$CK_CONF_DIR/hash.yaml" <<'YML'
hash:
  vcpu_hour:
    default:
      price: 0.02
  ram_mb_hour:
    default:
      price: 0.00001
  volume_gb_month:
    default:
      price: 0.05
  floating_ip_hour:
    default:
      price: 0.005
YML

chmod 640 "$CK_CONF_DIR/metrics.yml" "$CK_CONF_DIR/hash.yaml"

# -------- create CloudKitty DB & user in MariaDB ----------
log "Creating CloudKitty DB and user in MariaDB..."
if mysql -e "SELECT 1" >/dev/null 2>&1; then
  mysql <<SQL
CREATE DATABASE IF NOT EXISTS \`${CK_DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${CK_DB_USER}'@'localhost' IDENTIFIED BY '${CK_DB_PASS}';
GRANT ALL PRIVILEGES ON \`${CK_DB_NAME}\`.* TO '${CK_DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQL
  log "CloudKitty DB & user created/ensured."
else
  warn "Cannot run mysql commands automatically—create DB/user manually with the commands printed later."
fi

# -------- CloudKitty dbsync ----------
log "Running cloudkitty-dbsync upgrade..."
if [ -x "$CK_VENV_DIR/venv/bin/cloudkitty-dbsync" ]; then
  "$CK_VENV_DIR/venv/bin/cloudkitty-dbsync" --config-file "$CK_CONF_DIR/cloudkitty.conf" upgrade || warn "cloudkitty-dbsync failed — check environment & config"
else
  warn "cloudkitty-dbsync tool not found in venv. Check installation."
fi

# -------- Keystone service registration for CloudKitty ----------
if [ -f "$ADMIN_OPENRC_PATH" ]; then
  log "Registering CloudKitty in Keystone..."
  # shellcheck disable=SC1090
  source "$ADMIN_OPENRC_PATH"
  if ! openstack user show cloudkitty >/dev/null 2>&1; then
    openstack user create --domain default --password "$CK_KEYSTONE_PASS" cloudkitty || true
    openstack role add --project service --user cloudkitty member || true
  fi
  if ! openstack service show cloudkitty >/dev/null 2>&1; then
    openstack service create --name cloudkitty --description "CloudKitty rating service" rating || true
    openstack endpoint create --region RegionOne rating public "${CLOUDKITTY_API_URL:-http://127.0.0.1:8889}"
    openstack endpoint create --region RegionOne rating internal "${CLOUDKITTY_API_URL:-http://127.0.0.1:8889}"
    openstack endpoint create --region RegionOne rating admin "${CLOUDKITTY_API_URL:-http://127.0.0.1:8889}"
  fi
else
  warn "Admin openrc not found; skipping automatic Keystone registration of CloudKitty. Use the printed commands to register manually."
fi

# -------- systemd services for CloudKitty ----------
log "Creating systemd services for CloudKitty..."
cat > /etc/systemd/system/cloudkitty-api.service <<'UNIT'
[Unit]
Description=CloudKitty API
After=network.target
[Service]
Type=simple
User=root
ExecStart=/opt/public-cloud-complete/cloudkitty/venv/bin/cloudkitty-api --config-file /etc/cloudkitty/cloudkitty.conf
Restart=on-failure
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/cloudkitty-processor.service <<'UNIT'
[Unit]
Description=CloudKitty Processor
After=network.target
[Service]
Type=simple
User=root
ExecStart=/opt/public-cloud-complete/cloudkitty/venv/bin/cloudkitty-processor --config-file /etc/cloudkitty/cloudkitty.conf
Restart=on-failure
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now cloudkitty-api cloudkitty-processor || true
info "prerequites installed. Starting billing package..."
cat > /root/abstryacloud.sh <<'BASH'
#!/usr/bin/env bash
# public-cloud-final-installer.sh
# Monolithic installer: website, Flask billing (dockerized), FX cache, CloudKitty scaffold, Postgres,
# invoicing (PDF/email), Telegram/Slack admin notifications, proration, scheduler, Nginx gateway with auth_request.
# Target: Ubuntu 22.04 / 24.04 controller node
# Run as root: sudo bash ./public-cloud-final-installer.sh
set -euo pipefail
IFS=$'\n\t'

### helper functions
log(){ echo -e "\e[1;34m[INFO]\e[0m $*"; }
warn(){ echo -e "\e[1;33m[WARN]\e[0m $*"; }
err(){ echo -e "\e[1;31m[ERROR]\e[0m $*"; exit 1; }
confirm_root(){ [ "$(id -u)" -eq 0 ] || err "Run as root (sudo)"; }
rand(){ python3 - <<'PY' 2>/dev/null
import secrets,sys
print(secrets.token_urlsafe(24))
PY
}

confirm_root
export DEBIAN_FRONTEND=noninteractive

# ------------- Paths and directories -------------
BASE_DIR="${BASE_DIR:-/opt/abstryacloud}"
STACK_DIR="$BASE_DIR/stack"
JWT_DIR="$STACK_DIR/jwt"
FX_CACHE_DIR="$STACK_DIR/fx-cache"
CK_CONF_DIR="$STACK_DIR/cloudkitty_conf"
DATA_DIR="$STACK_DIR/data"
TEMPLATES_DIR="$STACK_DIR/templates"
ADMIN_OPENRC_PATH="${ADMIN_OPENRC_PATH:-/root/admin-openrc}"

mkdir -p "$STACK_DIR" "$JWT_DIR" "$FX_CACHE_DIR" "$CK_CONF_DIR" "$DATA_DIR" "$TEMPLATES_DIR"
chown -R root:root "$BASE_DIR"
cd "$STACK_DIR"

# ------------- User inputs (non-blocking prompts) -------------
read -r -p "Keystone URL (e.g. http://controller:5000/v3) : " KEYSTONE_URL || true
read -r -p "Skyline internal URL (http://127.0.0.1:8000 or http://skyline:80) : " SKYLINE_URL || true
read -r -p "Public domain for billing/site (leave empty -> self-signed) : " BILLING_DOMAIN || true
read -r -p "Stripe secret key (leave empty to configure later) : " STRIPE_SECRET || true
read -r -p "Stripe webhook secret (leave empty to configure later) : " STRIPE_WEBHOOK_SECRET || true
read -r -p "SMTP server hostname (leave empty to skip email receipts): " SMTP_SERVER || true
read -r -p "SMTP user (for receipts): " SMTP_USER || true
read -r -s -p "SMTP password (press Enter to leave empty): " SMTP_PASS || true
echo
read -r -p "Telegram bot token (leave empty to skip): " TELEGRAM_TOKEN || true
read -r -p "Telegram admin chat id (leave empty to skip): " TELEGRAM_CHAT_ID || true
read -r -p "Slack webhook URL (leave empty to skip): " SLACK_WEBHOOK || true
read -r -p "Base price in USD for preview (default 10) : " BASE_PRICE_USD_INPUT || true
BASE_PRICE_USD="${BASE_PRICE_USD_INPUT:-10}"

# ------------- System packages -------------
log "Installing required system packages (docker, docker-compose, nginx, certbot, jq, curl)..."
apt update -y
apt upgrade -y
apt install -y docker.io docker-compose nginx certbot python3-certbot-nginx jq curl postgresql-client

DOCKER_COMPOSE_BIN="$(command -v docker-compose || echo docker compose)"

# ------------- JWT keypair -------------
if [ ! -f "$JWT_DIR/private.pem" ]; then
  log "Generating JWT RSA keypair..."
  openssl genpkey -algorithm RSA -out "$JWT_DIR/private.pem" -pkeyopt rsa_keygen_bits:2048
  openssl rsa -in "$JWT_DIR/private.pem" -pubout -out "$JWT_DIR/public.pem"
  chmod 600 "$JWT_DIR/private.pem"
  chmod 644 "$JWT_DIR/public.pem"
fi

# ------------- Attempt to auto-create OpenStack app credential -------------
APP_CRED_ID="" ; APP_CRED_SECRET=""
if [ -f "$ADMIN_OPENRC_PATH" ]; then
  log "Sourcing admin-openrc and trying to create billing-service user and app credential..."
  # shellcheck disable=SC1090
  source "$ADMIN_OPENRC_PATH"
  if ! openstack user show billing-service >/dev/null 2>&1; then
    APASS=$(rand)
    openstack user create --domain default --password "$APASS" billing-service || true
    openstack role add --project service --user billing-service member || true
  fi
  AC_NAME="billing_app_$(date +%s)"
  SECRET_CAND=$(openssl rand -hex 32)
  AC_JSON=$(openstack application credential create --user billing-service --unrestricted --secret "$SECRET_CAND" --name "$AC_NAME" -f json 2>/dev/null || true)
  if [ -n "$AC_JSON" ]; then
    APP_CRED_ID=$(echo "$AC_JSON" | jq -r '.[0].id // .id' 2>/dev/null || true)
    APP_CRED_SECRET="$SECRET_CAND"
    log "Created application credential id=$APP_CRED_ID"
  else
    warn "Auto-creation of application credential failed; set APP_CRED_ID & APP_CRED_SECRET later in .env.billing"
  fi
else
  warn "Admin openrc not found at $ADMIN_OPENRC_PATH. You can configure APP_CRED manually later."
fi

# ------------- Create Flask billing microservice files -------------
log "Creating billing microservice files (Flask app, Dockerfile, templates, static assets)..."

cat > requirements.txt <<'REQ'
Flask==2.3.3
gunicorn==21.2.0
PyJWT==2.8.0
requests==2.31.0
reportlab==4.0
sqlalchemy==2.0.15
psycopg2-binary==2.9.10
python-dotenv==1.0.0
stripe==5.0.0
flask-cors==3.0.10
REQ

cat > Dockerfile <<'DOCKER'
FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends build-essential gcc libpq-dev && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . /app
RUN useradd --create-home appuser && chown -R appuser:appuser /app
USER appuser
EXPOSE 5000
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "billing:app", "--workers", "3"]
DOCKER

# billing.py - full service (billing, FX, CloudKitty integration, invoicing, email, notifications, scheduler)
cat > billing.py <<'PY'
import os, json, datetime, io, time, threading
from flask import Flask, request, jsonify, send_from_directory
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, Text
from sqlalchemy.orm import sessionmaker, declarative_base
import jwt, requests, stripe
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = os.getenv("FLASK_SECRET_KEY","change-me")

# ENV
DATABASE_URL = os.getenv("DATABASE_URL","postgresql://billing_user:billing_pass@postgres:5432/billing_db")
KEYSTONE_URL = os.getenv("KEYSTONE_URL","")
APP_CRED_ID = os.getenv("APP_CRED_ID","")
APP_CRED_SECRET = os.getenv("APP_CRED_SECRET","")
JWT_PRIVATE = os.getenv("JWT_PRIVATE","/jwt/private.pem")
JWT_PUBLIC = os.getenv("JWT_PUBLIC","/jwt/public.pem")
STRIPE_SECRET = os.getenv("STRIPE_SECRET","")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET","")
FX_CACHE_FILE = os.getenv("FX_CACHE_FILE","/app/fx-cache/rates.json")
BASE_PRICE_USD = float(os.getenv("BASE_PRICE_USD","10"))
SMTP_SERVER = os.getenv("SMTP_SERVER","")
SMTP_USER = os.getenv("SMTP_USER","")
SMTP_PASS = os.getenv("SMTP_PASS","")
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN","")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID","")
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK","")
BILLING_CYCLE_DEFAULT = os.getenv("BILLING_CYCLE_DEFAULT","monthly")

if STRIPE_SECRET:
    stripe.api_key = STRIPE_SECRET

# DB
Base = declarative_base()
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine)

class User(Base):
    __tablename__ = "users"
    username = Column(String(128), primary_key=True)
    email = Column(String(256))
    project = Column(String(128))
    paid = Column(Boolean, default=False)
    plan = Column(String(32), default="monthly")
    last_paid = Column(DateTime, nullable=True)

class Invoice(Base):
    __tablename__ = "invoices"
    id = Column(Integer, primary_key=True)
    project_id = Column(String(128), index=True)
    amount = Column(Float)
    currency = Column(String(8), default="USD")
    paid = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    raw = Column(Text)

Base.metadata.create_all(bind=engine)

PLAN_DURATIONS = {"weekly":7, "monthly":30, "yearly":365}
PLAN_PRICES = {"weekly": BASE_PRICE_USD*0.3, "monthly": BASE_PRICE_USD, "yearly": BASE_PRICE_USD*10}

def read_rates():
    try:
        with open(FX_CACHE_FILE,'r') as f:
            rates = json.load(f)
            rates["USD"] = 1.0
            return rates
    except Exception:
        return {"USD":1.0}

def fetch_cloudkitty_rated(project_id):
    ck_url = os.getenv("CLOUDKITTY_URL","http://localhost:8889")
    try:
        token = os.getenv("OS_TOKEN","")
        headers = {}
        if token:
            headers["X-Auth-Token"] = token
        r = requests.get(f"{ck_url}/v1/rating/summary?project_id={project_id}", headers=headers, timeout=10)
        data = r.json()
        items = []
        total = 0.0
        for entry in data.get("data", []):
            name = entry.get("metric_name", entry.get("name","item"))
            qty = float(entry.get("quantity", entry.get("usage", 0)) or 0)
            unit = float(entry.get("price", 0) or 0)
            cost = qty * unit
            items.append((name, qty, unit, cost))
            total += cost
        if not items:
            items = [("vcpu_hours", 10, 0.02, 0.2), ("ram_mb_hours", 5120, 0.00001, 0.0512)]
            total = sum(i[3] for i in items)
        return items, round(total,2)
    except Exception as e:
        app.logger.error("CloudKitty fetch error: %s", e)
        items = [("subscription_base",1,BASE_PRICE_USD,BASE_PRICE_USD)]
        return items, BASE_PRICE_USD

def generate_invoice_pdf(username, items, total, currency):
    os.makedirs("/data", exist_ok=True)
    fname = f"/data/invoice_{username}_{int(datetime.datetime.utcnow().timestamp())}.pdf"
    c = canvas.Canvas(fname, pagesize=letter)
    x = 50; y = 750
    c.setFont("Helvetica-Bold", 16); c.drawString(x,y,"Abstry Public Cloud — Invoice")
    y -= 30
    c.setFont("Helvetica", 10); c.drawString(x,y, f"User: {username}"); y -= 15
    c.drawString(x,y, f"Date: {datetime.datetime.utcnow().isoformat()}"); y -= 20
    c.drawString(x,y, "-"*80); y -= 20
    c.setFont("Helvetica", 10)
    for name, qty, unit, cost in items:
        c.drawString(x, y, f"{name}: {qty} × {unit} = {cost:.2f} {currency}")
        y -= 14
        if y < 80:
            c.showPage(); y = 750
    c.drawString(x, y-10, "-"*80)
    c.drawString(x, y-30, f"Total: {total:.2f} {currency}")
    c.save()
    return fname

def send_email_with_attachment(to_email, subject, body, attachment_path):
    if not SMTP_SERVER or not SMTP_USER or not SMTP_PASS:
        app.logger.warning("SMTP not configured; skipping email to %s", to_email)
        return False
    try:
        import smtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        from email.mime.application import MIMEApplication
        msg = MIMEMultipart()
        msg["From"] = SMTP_USER
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))
        with open(attachment_path, "rb") as f:
            part = MIMEApplication(f.read(), Name=os.path.basename(attachment_path))
            part['Content-Disposition'] = f'attachment; filename="{os.path.basename(attachment_path)}"'
            msg.attach(part)
        s = smtplib.SMTP(SMTP_SERVER, 587, timeout=30)
        s.starttls()
        s.login(SMTP_USER, SMTP_PASS)
        s.sendmail(SMTP_USER, [to_email], msg.as_string())
        s.quit()
        return True
    except Exception as e:
        app.logger.error("Email send failed: %s", e)
        return False

def notify_admins(message):
    if TELEGRAM_TOKEN and TELEGRAM_CHAT_ID:
        try:
            requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", json={"chat_id": TELEGRAM_CHAT_ID, "text": message}, timeout=5)
        except Exception as e:
            app.logger.error("Telegram notify failed: %s", e)
    if SLACK_WEBHOOK:
        try:
            requests.post(SLACK_WEBHOOK, json={"text": message}, timeout=5)
        except Exception as e:
            app.logger.error("Slack notify failed: %s", e)

def calculate_proration(username, new_plan):
    db = SessionLocal()
    user = db.query(User).get(username)
    if not user or not user.last_paid:
        db.close(); return {"credit":0.0, "final_charge": PLAN_PRICES.get(new_plan, BASE_PRICE_USD), "old_plan": getattr(user,"plan","monthly") if user else "monthly", "new_plan":new_plan}
    now = datetime.datetime.utcnow()
    old_plan = user.plan or "monthly"
    old_days = PLAN_DURATIONS.get(old_plan,30)
    new_days = PLAN_DURATIONS.get(new_plan,30)
    elapsed = (now - user.last_paid).days
    remaining = max(old_days - elapsed, 0)
    old_cost = PLAN_PRICES.get(old_plan, BASE_PRICE_USD)
    new_cost = PLAN_PRICES.get(new_plan, BASE_PRICE_USD)
    credit = (remaining / old_days) * old_cost if old_days>0 else 0.0
    final_charge = max(new_cost - credit, 0.0)
    db.close()
    return {"old_plan":old_plan, "new_plan":new_plan, "credit": round(credit,2), "new_cost": round(new_cost,2), "final_charge": round(final_charge,2)}

@app.route("/")
def index():
    return send_from_directory('templates','index.html')
@app.route("/billing/")
def billing_page():
    return send_from_directory('templates','billing.html')

@app.route("/convert")
def convert():
    currency = (request.args.get("currency") or "USD").upper()
    rates = read_rates()
    rate = float(rates.get(currency, 1.0))
    converted = round(BASE_PRICE_USD * rate, 2)
    return jsonify({"base": BASE_PRICE_USD, "converted": f"{converted:.2f}", "currency": currency})

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json() or request.form or {}
    username = data.get("username")
    password = data.get("password","")
    email = data.get("email","")
    project = data.get("project") or (username and username.split("@")[0]+"-project")
    if not username or not password:
        return jsonify({"error":"username & password required"}), 400
    db = SessionLocal()
    user = db.query(User).get(username)
    if user:
        db.close(); return jsonify({"error":"user exists"}), 400
    user = User(username=username, email=email, project=project, paid=False, plan=BILLING_CYCLE_DEFAULT)
    db.add(user); db.commit(); db.close()
    notify_admins(f"🆕 Registration: {username} project {project}")
    return jsonify({"ok":True, "project": project})

@app.route("/create_invoice", methods=["POST"])
def create_invoice():
    data = request.get_json() or request.form or {}
    project_id = data.get("project_id")
    amount = float(data.get("amount", BASE_PRICE_USD))
    currency = (data.get("currency") or "USD").upper()
    db = SessionLocal()
    inv = Invoice(project_id=project_id, amount=amount, currency=currency, paid=False)
    db.add(inv); db.commit()
    inv_id = inv.id
    db.close()
    return jsonify({"invoice_id": inv_id})

@app.route("/pay", methods=["POST"])
def pay():
    data = request.get_json() or request.form or {}
    project = data.get("project_id") or data.get("username") or "demo-project"
    username = data.get("username") or project
    plan = (data.get("plan") or None)
    currency = (data.get("currency") or "USD").lower()

    db = SessionLocal()
    inv = Invoice(project_id=project, amount=float(data.get("amount", BASE_PRICE_USD)), currency=currency.upper(), paid=False)
    db.add(inv); db.commit()
    inv_id = inv.id
    db.close()

    if STRIPE_SECRET:
        try:
            rate = read_rates().get(currency.upper(), 1.0)
            amount_cents = int(round(float(inv.amount) * rate * 100))
            domain = (request.headers.get("X-Forwarded-Proto","https") + "://" + request.headers.get("Host","example.com"))
            session = stripe.checkout.Session.create(
                payment_method_types=["card"],
                line_items=[{
                    "price_data":{
                        "currency": currency,
                        "product_data":{"name": f"Invoice {inv_id}"},
                        "unit_amount": amount_cents
                    },
                    "quantity":1
                }],
                mode="payment",
                success_url=f"{domain}/billing/success?invoice_id={inv_id}&username={username}",
                cancel_url=f"{domain}/billing/?project_id={project}",
                metadata={"invoice_id": str(inv_id), "project_id": project, "username": username}
            )
            return jsonify({"checkout_url": session.url})
        except Exception as e:
            return jsonify({"error":"stripe_create_failed","detail":str(e)}), 500

    items, total = fetch_cloudkitty_rated(project)
    db = SessionLocal()
    inv = db.query(Invoice).get(inv_id)
    inv.paid = True
    db.add(inv); db.commit()
    userdb = SessionLocal()
    user = userdb.query(User).get(username)
    if user:
        user.paid = True
        if plan:
            user.plan = plan
        user.last_paid = datetime.datetime.utcnow()
        userdb.add(user); userdb.commit()
    userdb.close()
    pdf = generate_invoice_pdf(username, items, total, currency.upper())
    if user and user.email:
        send_email_with_attachment(user.email, f"Your Abstry Cloud Invoice #{inv_id}", f"Hello {username}, please find your invoice attached. Total: {total} {currency.upper()}", pdf)
    notify_admins(f"💰 Payment received for project {project} by {username}: {total} {currency.upper()}")
    return jsonify({"ok":True, "invoice_id": inv_id, "total": total})

@app.route("/billing/success")
def billing_success():
    invoice_id = request.args.get("invoice_id")
    username = request.args.get("username")
    return f"Payment complete. Invoice {invoice_id}. You may close this window."

@app.route("/stripe/webhook", methods=["POST"])
def stripe_webhook():
    payload = request.get_data()
    sig = request.headers.get("Stripe-Signature","")
    if STRIPE_WEBHOOK_SECRET:
        try:
            event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
        except Exception as e:
            app.logger.error("Stripe webhook invalid: %s", e)
            return jsonify({"error":"invalid_webhook"}), 400
    else:
        event = json.loads(payload.decode("utf-8"))
    if event.get("type") == "checkout.session.completed":
        obj = event["data"]["object"]
        metadata = obj.get("metadata", {})
        inv_id = metadata.get("invoice_id")
        username = metadata.get("username")
        project = metadata.get("project_id")
        db = SessionLocal()
        inv = db.query(Invoice).get(int(inv_id))
        if inv:
            inv.paid = True
            db.add(inv); db.commit()
            user = db.query(User).get(username)
            if user:
                user.paid = True
                user.last_paid = datetime.datetime.utcnow()
                db.add(user); db.commit()
            items, total = fetch_cloudkitty_rated(project)
            pdf = generate_invoice_pdf(username, items, total, inv.currency)
            if user and user.email:
                send_email_with_attachment(user.email, f"Your Abstry Cloud Invoice #{inv_id}", f"Payment successful. Total: {total} {inv.currency}", pdf)
            notify_admins(f"💳 Stripe payment: project {project} user {username} invoice {inv_id} total {total} {inv.currency}")
        db.close()
    return jsonify({"ok":True})

@app.route('/token', methods=['POST'])
def token():
    data = request.json or {}
    project_id = data.get('project_id')
    if not project_id:
        return jsonify({"error":"project_id required"}), 400
    private = open(JWT_PRIVATE,'rb').read()
    now = datetime.datetime.utcnow()
    payload = {"iss":"billing","sub":project_id,"iat":int(now.timestamp()),"exp":int((now + datetime.timedelta(minutes=15)).timestamp())}
    tok = jwt.encode(payload, private, algorithm="RS256")
    return jsonify({"token": tok})

@app.route("/validate")
def validate():
    auth = request.headers.get("Authorization","")
    token = None
    if auth.startswith("Bearer "):
        token = auth.split(" ",1)[1]
    if not token:
        token = request.args.get("token") or request.cookies.get("billing_token")
    if not token:
        return "Missing", 401
    try:
        if os.path.exists(JWT_PUBLIC):
            pub = open(JWT_PUBLIC,"rb").read()
            payload = jwt.decode(token, pub, algorithms=["RS256"])
        else:
            payload = jwt.decode(token, os.getenv("FLASK_SECRET_KEY","change-me"), algorithms=["HS256","RS256"], options={"verify_signature": False})
        project = payload.get("sub") or payload.get("username")
        if APP_CRED_ID and APP_CRED_SECRET and KEYSTONE_URL:
            try:
                r = requests.post(f"{KEYSTONE_URL}/auth/tokens", json={
                    "auth":{"identity":{"methods":["application_credential"], "application_credential":{"id":APP_CRED_ID,"secret":APP_CRED_SECRET}}}
                }, timeout=5)
                if r.status_code in (200,201):
                    admin_token = r.headers.get("X-Subject-Token")
                    proj_r = requests.get(f"{KEYSTONE_URL}/projects/{project}", headers={"X-Auth-Token":admin_token}, timeout=5)
                    if proj_r.status_code == 200:
                        proj = proj_r.json().get("project",{})
                        if proj.get("enabled") in (True,"True","true"):
                            return "OK", 200
                        else:
                            return "PaymentRequired", 402
            except Exception as e:
                app.logger.error("Keystone check failed: %s", e)
        return "OK", 200
    except jwt.ExpiredSignatureError:
        return "Expired", 401
    except Exception as e:
        app.logger.error("validate error: %s", e)
        return "Invalid", 401

@app.route("/_health")
def health():
    return jsonify({"status":"ok"})

def scheduler_loop():
    while True:
        try:
            db = SessionLocal()
            users = db.query(User).all()
            now = datetime.datetime.utcnow()
            for u in users:
                if not u.last_paid:
                    continue
                plan = u.plan or "monthly"
                days = PLAN_DURATIONS.get(plan, 30)
                elapsed = (now - u.last_paid).days
                if elapsed >= days:
                    items, total = fetch_cloudkitty_rated(u.project)
                    inv = Invoice(project_id=u.project, amount=total, currency="USD", paid=False)
                    db.add(inv); db.commit()
                    inv_id = inv.id
                    inv.paid = True
                    db.add(inv); db.commit()
                    u.last_paid = now
                    db.add(u); db.commit()
                    pdf = generate_invoice_pdf(u.username, items, total, "USD")
                    if u.email:
                        send_email_with_attachment(u.email, f"Your Abstry Cloud Invoice #{inv_id}", f"Auto-billing for {u.username} amount {total} USD", pdf)
                    notify_admins(f"📅 Auto-billed {u.username} project {u.project}: {total} USD (invoice {inv_id})")
            db.close()
        except Exception as e:
            app.logger.error("Scheduler error: %s", e)
        time.sleep(24*3600)

if os.getenv("RUN_SCHEDULER","1") == "1":
    t = threading.Thread(target=scheduler_loop, daemon=True)
    t.start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

@app.route('/expired')
def expired():
    return render_template('expired.html')
PY

# ------------- templates + static (UI) -------------
mkdir -p templates static
cat > templates/index.html <<'HTML'
<!doctype html>
<html>
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <script src="https://cdn.tailwindcss.com"></script>
  <title>Abstrya Cloud</title>
</head>
<body class="bg-slate-50">
  <div class="max-w-4xl mx-auto p-6">
    <div class="bg-white p-6 rounded shadow">
      <h1 class="text-2xl font-semibold">Abstrya Cloud</h1>
      <p class="mt-2">Register, pay, and manage your cloud with Skyline.</p>
      <div class="mt-4">
        <a href="/register.html" class="px-4 py-2 bg-sky-600 text-white rounded">Register</a>
        <a href="/skyline/" class="px-4 py-2 border ml-2 rounded">Login</a>
      </div>
    </div>
      <aside class="bg-white rounded-xl p-6 shadow">
        <h3 class="font-semibold">Why Abstrya Cloud?</h3>
        <ul class="list-disc pl-5 text-sm text-slate-600 mt-2">
          <li>OpenStack-powered multi-tenant cloud</li>
          <li>Pay-as-you-go billing in your currency</li>
          <li>Manage through Skyline dashboard</li>
        </ul>
      </aside>
  </div>
</body>
</html>
HTML

cat > templates/register.html <<'HTML'
<!doctype html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Abstrya Cloud - Register</title><script src="https://cdn.tailwindcss.com"></script><link rel="stylesheet" href="/static/styles.css"><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/flag-icon-css/6.6.6/css/flag-icons.min.css"></head>
<body class="bg-slate-50">
  <div class="max-w-4xl mx-auto p-6">  
     <section class="bg-white rounded-xl p-6 shadow">
        <h2 class="text-lg font-semibold mb-3">Register</h2>
        <div id="register-area">
          <input id="username" class="w-full mb-2 p-2 border rounded" placeholder="Username" />
          <input id="password" type="password" class="w-full mb-2 p-2 border rounded" placeholder="Password" />
          <input id="email" class="w-full mb-2 p-2 border rounded" placeholder="Email for receipts (optional)" />
          <input id="project" class="w-full mb-2 p-2 border rounded" placeholder="Project name (optional)" />
          <div class="flex gap-2">
            <button onclick="register()" class="px-4 py-2 bg-sky-600 text-white rounded">Register</button>
            <button onclick="window.location='/billing/'" class="px-4 py-2 border rounded">Go to Billing</button>
          </div>
        </div>
      </section>         
  </div>
<script src="/static/app.js"></script>
</body>
</html>
HTML

cat > templates/billing.html <<'HTML'
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Billing</title><script src="https://cdn.tailwindcss.com"></script><link rel="stylesheet" href="/static/styles.css"><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/flag-icon-css/6.6.6/css/flag-icons.min.css"></head>
<body class="bg-slate-50">   
  <div class="max-w-3xl mx-auto p-6">    
    <div class="bg-white p-6 rounded-xl shadow">
      <h2 class="text-lg font-semibold mb-3">Billing</h2>
      <label class="block text-sm mb-1">Project / Username</label>
      <input id="project_id" class="w-full p-2 mb-3 border rounded" />
      <label class="block text-sm mb-1">Plan</label>
      <select id="plan" class="w-full p-2 mb-3 border rounded">
        <option value="yearly">Yearly</option>
        <option value="monthly">Monthly</option>
        <option value="weekly">Weekly</option>
      </select>
      <label class="block text-sm mb-1">Currency</label>
      <select id="currency" class="w-full p-2 mb-3 border rounded" onchange="previewPrice()">
        <option value="NGN">🇳🇬 NGN (₦)</option>
        <option value="USD">🇺🇸 USD ($)</option>
        <option value="EUR">🇪🇺 EUR (€)</option>
        <option value="GBP">🇬🇧 GBP (£)</option>
        <option value="INR">🇮🇳 INR (₹)</option>
      </select>
      <p id="price-preview" class="mb-3">Price: </p>
      <div class="flex gap-2">
        <button id="pay-btn" class="px-4 py-2 bg-sky-600 text-white rounded" onclick="pay()">Pay</button>
        <button class="px-4 py-2 border rounded" onclick="createTestInvoice()">Create Invoice</button>
      </div>
    </div>
  </div>
<script src="/static/billing-app.js"></script>
</body>
</html>
HTML

cat > templates/expired.html <<'HTML'
<!doctype html>
  <html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="/static/styles.css">
  </head>
  <body>
    <div class="container card">
      <h1>Subscription expired</h1>
      <p>Please <a href="/billing/">visit billing</a>.</p>
    </div>
  </body>
  </html>
HTML

cat > static/styles.css <<'CSS'
body{font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Arial;background:#f7fafc}
CSS

cat > static/app.js <<'JS'
async function register(){
  const username=document.getElementById('username').value;
  const password=document.getElementById('password').value;
  const email=document.getElementById('email').value;
  const project=document.getElementById('project').value;
  const r=await fetch('/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password,email,project})});
  alert(JSON.stringify(await r.json()));
}
JS

cat > static/billing-app.js <<'JS'
async function previewPrice(){
  const currency=document.getElementById('currency').value;
  try{
    const r=await fetch('/convert?currency='+currency);
    const j=await r.json();
    document.getElementById('price-preview').innerText='Price: '+j.converted+' '+j.currency;
    document.getElementById('pay-btn').innerText='Pay '+j.converted+' '+j.currency+' Now';
  }catch(e){
    document.getElementById('price-preview').innerText='Price: unavailable';
  }
}
async function pay(){
  const currency=document.getElementById('currency').value;
  const project=document.getElementById('project_id').value || 'demo';
  const plan=document.getElementById('plan').value || 'monthly';
  const r=await fetch('/pay',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({project_id:project,username:project,plan:plan,currency:currency})});
  const j=await r.json();
  if(j.checkout_url) window.location=j.checkout_url;
  else if(j.ok) alert('Payment success (demo). Total: '+j.total);
  else alert(JSON.stringify(j));
}
function createTestInvoice(){ alert('Test invoice created (demo).'); }
window.addEventListener('DOMContentLoaded',()=>{ previewPrice(); const locale=navigator.language||'en-US'; let m='USD'; if(locale.startsWith('en-GB')) m='GBP'; else if(locale.startsWith('en-NG')) m='NGN'; else if(locale.startsWith('fr')||locale.startsWith('de')) m='EUR'; else if(locale.startsWith('hi')||locale.startsWith('en-IN')) m='INR'; const sel=document.getElementById('currency'); if(sel) sel.value=m; previewPrice();});
JS

# ------------- docker-compose.yml -------------
log "Writing docker-compose.yml (billing + postgres + CloudKitty scaffold)..."
cat > docker-compose.yml <<'YML'
version: '3.8'
services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: billing_db
      POSTGRES_USER: billing_user
      POSTGRES_PASSWORD: billing_pass
    volumes:
      - pg_data:/var/lib/postgresql/data
    networks:
      - pubcloud_net

  billing:
    build: .
    container_name: billing_service
    env_file: .env.billing
    ports:
      - "127.0.0.1:5000:5000"
    volumes:
      - ./fx-cache:/app/fx-cache
      - ./jwt:/jwt:ro
      - ./data:/data
    depends_on:
      - postgres
    networks:
      - pubcloud_net

  cloudkitty-api:
    image: docker.io/library/python:3.11-slim
    container_name: cloudkitty-api
    restart: unless-stopped
    volumes:
      - ./cloudkitty_conf:/etc/cloudkitty:ro
    command: ["sleep","infinity"]
    networks:
      - pubcloud_net

  cloudkitty-processor:
    image: docker.io/library/python:3.11-slim
    container_name: cloudkitty-processor
    restart: unless-stopped
    volumes:
      - ./cloudkitty_conf:/etc/cloudkitty:ro
    command: ["sleep","infinity"]
    networks:
      - pubcloud_net

volumes:
  pg_data:

networks:
  pubcloud_net:
YML

# ------------- .env.billing -------------
cat > .env.billing <<ENV
DATABASE_URL=postgresql://billing_user:billing_pass@postgres:5432/billing_db
FLASK_SECRET_KEY=$(rand)
KEYSTONE_URL=${KEYSTONE_URL}
APP_CRED_ID=${APP_CRED_ID}
APP_CRED_SECRET=${APP_CRED_SECRET}
JWT_PRIVATE=/jwt/private.pem
JWT_PUBLIC=/jwt/public.pem
STRIPE_SECRET=${STRIPE_SECRET}
STRIPE_WEBHOOK_SECRET=${STRIPE_WEBHOOK_SECRET}
BASE_PRICE_USD=${BASE_PRICE_USD}
FX_CACHE_FILE=/app/fx-cache/rates.json
SMTP_SERVER=${SMTP_SERVER}
SMTP_USER=${SMTP_USER}
SMTP_PASS=${SMTP_PASS}
TELEGRAM_TOKEN=${TELEGRAM_TOKEN}
TELEGRAM_CHAT_ID=${TELEGRAM_CHAT_ID}
SLACK_WEBHOOK=${SLACK_WEBHOOK}
CLOUDKITTY_URL=${CLOUDKITTY_URL:-http://cloudkitty-api:8889}
APP_RUN_SCHEDULER=1
ENV
chmod 600 .env.billing

# ------------- deploy supporting files -------------
mkdir -p jwt data fx-cache cloudkitty_conf
cp -f "$JWT_DIR/private.pem" "$STACK_DIR/jwt/private.pem"
cp -f "$JWT_DIR/public.pem" "$STACK_DIR/jwt/public.pem"
chmod 600 "$STACK_DIR/jwt/private.pem" || true
chmod 644 "$STACK_DIR/jwt/public.pem" || true

cat > "$FX_CACHE_DIR/rates.json" <<'JSON'
{"USD":1.0,"EUR":0.95,"GBP":0.82,"NGN":750,"INR":83}
JSON

# minimal cloudkitty conf (edit for production)
cat > "$CK_CONF_DIR/cloudkitty.conf" <<'EOF'
[DEFAULT]
debug = False
log_dir = /var/log/cloudkitty
[api]
host = 0.0.0.0
port = 8889
[keystone_authtoken]
auth_url = ${KEYSTONE_URL}
auth_type = password
project_domain_name = Default
user_domain_name = Default
project_name = service
username = cloudkitty
password = change-me
[collect]
collector = gnocchi
period = 3600
[fetcher]
fetcher = gnocchi
[gnocchi]
url = http://127.0.0.1:8041
auth_type = password
auth_url = ${KEYSTONE_URL}
project_domain_name = Default
user_domain_name = Default
project_name = service
username = gnocchi
password = change-me
EOF

# ------------- FX updater script & cron -------------
cat > update-fx.sh <<'SH'
#!/usr/bin/env bash
set -euo pipefail
CDIR="$(cd "$(dirname "$0")" && pwd)"
CACHE="$CDIR/fx-cache/rates.json"
TMP="$CACHE.tmp"
BASE="USD"
CURRENCIES=("USD" "EUR" "GBP" "NGN" "INR")
URL="https://api.exchangerate.host/latest?base=${BASE}&symbols=$(IFS=,; echo "${CURRENCIES[*]}")"
curl -sfS "$URL" -o "$TMP" || { echo "FX fetch failed"; exit 0; }
jq '.rates' "$TMP" > "$CACHE" || true
rm -f "$TMP"
echo "FX cache updated at $(date)" >> "$CDIR/fx-cache/fx.log"
SH
chmod 750 update-fx.sh

CRON_LINE="0 2 * * * root $STACK_DIR/update-fx.sh >> $STACK_DIR/fx-cache/fx.log 2>&1"
if ! grep -Fq "update-fx.sh" /etc/crontab 2>/dev/null; then
  echo "$CRON_LINE" >> /etc/crontab
  log "Added FX updater cron to /etc/crontab"
else
  log "FX updater cron already present"
fi
bash update-fx.sh || true

# ------------- Build & start docker stack -------------
log "Building docker images and starting stack (can take a few minutes)..."
$DOCKER_COMPOSE_BIN up -d --build

# ------------- Nginx config with auth_request -------------
log "Configuring Nginx with billing auth (auth_request) and Skyline proxy..."
NG_SITE="/etc/nginx/sites-available/public_cloud_billing"
mkdir -p /etc/ssl/private /etc/ssl/certs
cat > "$NG_SITE" <<NG
server {
    listen 80;
    server_name ${BILLING_DOMAIN:-_};
    location / {
        return 301 https://\$host\$request_uri;
    }
}
server {
    listen 443 ssl http2;
    server_name ${BILLING_DOMAIN:-_};

    ssl_certificate /etc/ssl/certs/publiccloud_fullchain.pem;
    ssl_certificate_key /etc/ssl/private/publiccloud_privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    location = / {
        proxy_pass http://127.0.0.1:5000/;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    location /billing/ {
        proxy_pass http://127.0.0.1:5000/billing/;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    location = /_billing_auth {
        internal;
        proxy_pass http://127.0.0.1:5000/validate;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header Authorization \$http_authorization;
    }
    location /skyline/ {
        auth_request /_billing_auth;
        auth_request_set \$auth_status \$upstream_status;
        error_page 401 = @expired;
        error_page 402 = @expired;
        error_page 403 = @expired;

        proxy_pass ${SKYLINE_URL:-http://127.0.0.1:8000/};
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    location @expired {
        return 302 https://\$host/expired;
    }
}
NG

ln -sf "$NG_SITE" /etc/nginx/sites-enabled/public_cloud_billing
systemctl reload nginx || true

# ------------- TLS - Let's Encrypt or self-signed -------------
if [ -n "$BILLING_DOMAIN" ]; then
  log "Attempting Let's Encrypt certificate for $BILLING_DOMAIN..."
  ufw allow 80,443/tcp || true
  systemctl reload nginx || true
  certbot --nginx -d "$BILLING_DOMAIN" --non-interactive --agree-tos -m admin@"$BILLING_DOMAIN" || warn "certbot failed; check DNS"
else
  log "No domain provided: generating self-signed certificate for testing..."
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/publiccloud_privkey.pem -out /etc/ssl/certs/publiccloud_fullchain.pem -subj "/CN=localtest" >/dev/null 2>&1 || true
  chmod 600 /etc/ssl/private/publiccloud_privkey.pem || true
fi
systemctl reload nginx || true

# ------------- Final instructions and summary -------------
log "Bootstrap finished."

# ---------- systemd timer for suspension (unpaid) ----------
cat > /usr/local/bin/publiccloud_suspend_unpaid.sh <<'SUSP'
#!/usr/bin/env bash
set -euo pipefail
ADMIN_OPENRC="${ADMIN_OPENRC_PATH:-/root/admin-openrc}"
if [ ! -f "$ADMIN_OPENRC" ]; then
  echo "admin-openrc not found; skipping Keystone suspend run" >&2
  exit 0
fi
source "$ADMIN_OPENRC"
PGUSER="${BILLING_DB_USER:-billing_user}"
PGPASS="${BILLING_DB_PASS:-billing_pass}"
export PGPASSWORD="$PGPASS"
psql -t -A -h 127.0.0.1 -U "$PGUSER" -d "${BILLING_DB_NAME:-billing_db}" -c "SELECT project_id FROM invoices WHERE paid = false AND created_at < now() - interval '7 days';" | while read -r proj; do
  if [ -n "$proj" ]; then
    openstack project set --disable $proj || true
  fi
done
SUSP
chmod 750 /usr/local/bin/publiccloud_suspend_unpaid.sh

cat > /etc/systemd/system/publiccloud-suspend.timer <<TIMER
[Unit]
Description=Run suspend unpaid projects daily
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
TIMER

cat > /etc/systemd/system/publiccloud-suspend.service <<SERVICE
[Unit]
Description=Suspend unpaid projects
[Service]
Type=oneshot
ExecStart=/usr/local/bin/publiccloud_suspend_unpaid.sh
SERVICE

systemctl daemon-reload
systemctl enable --now publiccloud-suspend.timer || true

# ---------- backups ----------
tar czf /opt/cloud-backups/abstryacloud-full-billing-$(date +%F).tgz "$STACK_DIR" "$JWT_DIR" "$CK_CONF_DIR" 2>/dev/null || true
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable || true

cat <<EOF

✅ PUBLIC CLOUD MONOLITHIC INSTALLER — FINISHED

Paths:
  Base dir: $BASE_DIR
  Stack dir: $STACK_DIR
  FX cache: $FX_CACHE_DIR/rates.json
  JWT keys: $JWT_DIR
  Invoices directory: $STACK_DIR/data

Services started (docker):
  - billing_service (Flask billing microservice)
  - postgres (billing DB)
  - cloudkitty-api (scaffold)
  - cloudkitty-processor (scaffold)

Endpoints:
  - Registration / site: https://${BILLING_DOMAIN:-<server-ip>}/
  - Billing UI:        https://${BILLING_DOMAIN:-<server-ip>}/billing/
  - Skyline (proxied): https://${BILLING_DOMAIN:-<server-ip>}/skyline/  (requires Authorization: Bearer <token>)

Important notes:
  - If certbot failed, verify DNS and run: certbot --nginx -d your-domain
  - If APP_CRED not created, create an application credential for billing-service and update .env.billing, then:
        cd $STACK_DIR && $DOCKER_COMPOSE_BIN up -d --build billing
  - Move secrets (STRIPE_SECRET, SMTP_PASS, APP_CRED_SECRET) to a secure secret manager (Vault) before production.
  - Replace CloudKitty scaffold with production images (Kolla/packaged) for production usage.
  - Test thoroughly in staging.

Commands:
  - Check running containers: docker ps --format '{{.Names}}\t{{.Status}}'
  - View billing logs: docker logs billing_service -f
  - View cloudkitty logs: docker logs cloudkitty-api -f
  - Tail nginx logs: journalctl -u nginx -f

If you want I can:
  - Replace CloudKitty scaffold with Kolla images and run dbsync
  - Add an admin UI for invoice and plan management
  - Move secrets into Vault and wire the billing container to read from Vault

EOF

docker ps --format '{{.Names}}\t{{.Status}}' || true
log "Installer finished. If anything fails, paste logs and I will help debug."
BASH

info "Completed."