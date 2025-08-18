#!/usr/bin/env bash
set -euo pipefail

DB="AEDB"
APPUSER="aauser"
APPPASS="Automic123"

# --- Ensure Postgres is up (harmless if already running) ---
sudo install -d -o postgres -g postgres -m 700 /var/lib/pgsql/data
sudo install -d -o postgres -g postgres -m 775 /var/run/postgresql
if [[ ! -f /var/lib/pgsql/data/PG_VERSION ]]; then
  sudo -u postgres /usr/bin/initdb -D /var/lib/pgsql/data --encoding UTF8 --locale en_US.UTF-8
fi
sudo -u postgres /usr/bin/pg_ctl -D /var/lib/pgsql/data -l /var/lib/pgsql/logfile status \
  || sudo -u postgres /usr/bin/pg_ctl -D /var/lib/pgsql/data -l /var/lib/pgsql/logfile start
for i in {1..20}; do
  sudo -u postgres /usr/bin/pg_isready -q && break
  sleep 1
done

# --- Role: create if missing, then (re)apply password ---
if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='${APPUSER}'" | grep -q 1; then
  sudo -u postgres psql -v ON_ERROR_STOP=1 -c "CREATE ROLE ${APPUSER} LOGIN PASSWORD '${APPPASS}'"
fi
sudo -u postgres psql -v ON_ERROR_STOP=1 -c "ALTER ROLE ${APPUSER} WITH LOGIN PASSWORD '${APPPASS}'"

# --- DB: create OUTSIDE a transaction if missing ---
if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='${DB}'" | grep -q 1; then
  sudo -u postgres createdb -O "${APPUSER}" -T template0 "${DB}"
fi

# --- Required extensions ---
sudo -u postgres psql -d "${DB}" -v ON_ERROR_STOP=1 -c "CREATE EXTENSION IF NOT EXISTS pgcrypto;"
sudo -u postgres psql -d "${DB}" -v ON_ERROR_STOP=1 -c "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";"

# --- Quick verify ---
sudo -u postgres psql -d "${DB}" -Atqc "select current_database();
select version();
select extname,count(*) from pg_extension where extname in ('pgcrypto','uuid-ossp') group by 1 order by 1;"

echo "AEDB ready."
