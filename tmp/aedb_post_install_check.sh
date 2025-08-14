#!/usr/bin/env bash
set -euo pipefail

# Expected env vars:
#   DB        (e.g., AEDB)
#   APPUSER   (e.g., aauser)
#   APPPASS   (e.g., Automic123)
#   DBDIR     (e.g., /opt/automic/install/.../Automation.Platform/db/postgresql/24.4)

echo "==> Prechecks"
psql --version

echo "==> Ensure app role + DB ownership + schema privileges"
# Pass variables to psql with -v; then use :'var' inside SQL
sudo -u postgres psql -v ON_ERROR_STOP=1 \
  -v db="${DB}" -v appuser="${APPUSER}" -v apppass="${APPPASS}" <<'SQL'
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'appuser') THEN
    EXECUTE format('CREATE ROLE %I LOGIN PASSWORD %L', :'appuser', :'apppass');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'db') THEN
    EXECUTE format('CREATE DATABASE %I OWNER %I', :'db', :'appuser');
  END IF;
END $$;

\connect :db

-- Make sure owner is correct and role can create objects
DO $$
BEGIN
  EXECUTE format('ALTER DATABASE %I OWNER TO %I', :'db', :'appuser');
END $$;

ALTER DATABASE :"db" SET search_path = public;
GRANT CONNECT ON DATABASE :"db" TO :"appuser";
GRANT USAGE ON SCHEMA public TO :"appuser";
GRANT CREATE ON SCHEMA public TO :"appuser";
ALTER SCHEMA public OWNER TO :"appuser";
SQL

echo "==> Apply BASE schema (tables first, then rest)"
# Use xargs -0 to handle spaces safely
find "${DBDIR}/base" -maxdepth 1 -type f -name 'aedb_base_*_tables.sql' -print0 \
| xargs -0 -I{} sudo -u postgres psql -v ON_ERROR_STOP=1 -d "${DB}" -f {}

find "${DBDIR}/base" -maxdepth 1 -type f -name 'aedb_base_*.sql' ! -name '*_tables.sql' -print0 \
| xargs -0 -I{} sudo -u postgres psql -v ON_ERROR_STOP=1 -d "${DB}" -f {}

echo "==> Apply STEP files (sorted)"
# Sorted list via printf to avoid word-splitting
mapfile -t STEP_FILES < <(find "${DBDIR}/steps" -maxdepth 1 -type f -name 'step_*.sql' | sort)
for f in "${STEP_FILES[@]}"; do
  echo "  -> ${f}"
  sudo -u postgres psql -v ON_ERROR_STOP=1 -d "${DB}" -f "${f}"
done

echo "==> Post-checks"
sudo -u postgres psql -v ON_ERROR_STOP=1 -d "${DB}" -c "SELECT current_database() AS db, current_user AS usr, version();"
echo "==> AEDB load complete"
