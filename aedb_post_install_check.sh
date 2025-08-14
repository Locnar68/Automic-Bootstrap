cat >/tmp/aedb_post_install_check.sh <<'EOS'
#!/usr/bin/env bash
set -u

# ==== Tunables (override via env before running) ====
DB="${DB:-AEDB}"
APPUSER="${APPUSER:-aauser}"
APPPASS="${APPPASS:-Automic123}"

TS_DATA_NAME="${TS_DATA_NAME:-ae_data}"
TS_INDEX_NAME="${TS_INDEX_NAME:-ae_index}"
TS_DATA_PATH="${TS_DATA_PATH:-/pgdata/ts/AE_DATA}"
TS_INDEX_PATH="${TS_INDEX_PATH:-/pgdata/ts/AE_INDEX}"

INSTALL_ROOT="${INSTALL_ROOT:-/opt/automic/install}"
LOG="${LOG:-/tmp/aedb_post_install_check.log}"

# ==== Helpers ====
: >"$LOG"
say(){ echo -e "$*" | tee -a "$LOG"; }

PASS=0; WARN=0; FAIL=0
pass(){ PASS=$((PASS+1)); say "PASS  | $*"; }
warn(){ WARN=$((WARN+1)); say "WARN  | $*"; }
fail(){ FAIL=$((FAIL+1)); say "FAIL  | $*"; }

# Use a URL so we don't need an OS user named 'aauser'
APP_URL="postgresql://${APPUSER}:${APPPASS}@localhost:5432/${DB}"

sql_p() { sudo -u postgres psql -X -v ON_ERROR_STOP=1 -At "$@"; }
sql_app(){ PGPASSWORD="$APPPASS" psql -X -v ON_ERROR_STOP=1 -At "$@"; }

echo "=== Host & Time ===" | tee -a "$LOG"
hostname -f | sed 's/^/host: /' | tee -a "$LOG"
date | tee -a "$LOG"

echo -e "\n=== PostgreSQL Service & Readiness ===" | tee -a "$LOG"
if (systemctl is-active --quiet postgresql@16 || systemctl is-active --quiet postgresql-16 || systemctl is-active --quiet postgresql); then
  pass "postgresql service is active"
  (systemctl status postgresql@16 --no-pager || systemctl status postgresql-16 --no-pager || systemctl status postgresql --no-pager) 2>&1 | sed -n '1,10p' | tee -a "$LOG"
else
  fail "postgresql service not active"
fi

if pg_isready >/dev/null 2>&1; then
  pass "pg_isready OK"
else
  fail "pg_isready failed"
fi

ver="$(sql_p -c "SELECT version();")" || ver="<unknown>"
say "server_version: $ver"

echo -e "\n=== AEDB existence & ownership ===" | tee -a "$LOG"
db_exists="$(sql_p -c "SELECT 1 FROM pg_database WHERE datname='${DB}';")" || db_exists=""
if [[ "$db_exists" == "1" ]]; then
  pass "database ${DB} exists"
else
  fail "database ${DB} not found"
fi

owner="$(sql_p -c "SELECT pg_catalog.pg_get_userbyid(datdba) FROM pg_database WHERE datname='${DB}';")" || owner="<error>"
say "AEDB owner: ${owner}"
if [[ "$owner" == "$APPUSER" ]]; then
  pass "AEDB owned by ${APPUSER}"
else
  warn "AEDB owner is ${owner} (recommended: ${APPUSER})"
fi

echo -e "\n=== Role ${APPUSER} & connectivity ===" | tee -a "$LOG"
role_exists="$(sql_p -c "SELECT 1 FROM pg_roles WHERE rolname='${APPUSER}';")" || role_exists=""
if [[ "$role_exists" == "1" ]]; then
  pass "role ${APPUSER} exists"
else
  fail "role ${APPUSER} missing"
fi

if sql_app "$APP_URL" -c "SELECT current_user;" >/dev/null 2>&1; then
  pass "connect as ${APPUSER} to ${DB}"
else
  fail "cannot connect as ${APPUSER} to ${DB} (check pg_hba/auth)"
fi

echo -e "\n=== public schema ownership & privileges ===" | tee -a "$LOG"
pub_owner="$(sql_p -d "$DB" -c "SELECT schema_owner FROM information_schema.schemata WHERE schema_name='public';")" || pub_owner="<error>"
say "public schema owner: ${pub_owner}"
[[ "$pub_owner" == "$APPUSER" ]] && pass "public owned by ${APPUSER}" || warn "public owned by ${pub_owner} (recommended: ${APPUSER})"

# Check USAGE & CREATE via a quick capability probe
if sql_app "$APP_URL" -c "CREATE TEMP TABLE __perm_probe(i int); DROP TABLE __perm_probe;" >/dev/null 2>&1; then
  pass "app user has CREATE on schema public"
else
  fail "app user lacks CREATE on schema public"
fi

echo -e "\n=== Extensions in AEDB ===" | tee -a "$LOG"
exts="$(sql_p -d "$DB" -c "SELECT extname FROM pg_extension ORDER BY 1;")" || exts=""
echo "$exts" | sed 's/^/  - /' | tee -a "$LOG"
grep -qx "pgcrypto" <<<"$exts" && pass "pgcrypto installed" || fail "pgcrypto missing"
grep -qx "uuid-ossp" <<<"$exts" && pass "uuid-ossp installed" || fail "uuid-ossp missing"

echo -e "\n=== Tablespaces presence & defaults ===" | tee -a "$LOG"
tslist="$(sql_p -c "SELECT spcname||'|'||COALESCE(pg_tablespace_location(oid),'cluster_default') FROM pg_tablespace ORDER BY 1;")" || tslist=""
echo "$tslist" | awk -F"|" '{printf "  %-18s %s\n",$1,$2}' | tee -a "$LOG"

grep -q "^${TS_DATA_NAME}|" <<<"$tslist" && pass "tablespace ${TS_DATA_NAME} exists" || fail "tablespace ${TS_DATA_NAME} missing"
grep -q "^${TS_INDEX_NAME}|" <<<"$tslist" && pass "tablespace ${TS_INDEX_NAME} exists" || fail "tablespace ${TS_INDEX_NAME} missing"
grep -q "^${TS_DATA_NAME}|${TS_DATA_PATH}\$"  <<<"$tslist" && pass "${TS_DATA_NAME} at ${TS_DATA_PATH}"  || warn "${TS_DATA_NAME} not at ${TS_DATA_PATH}"
grep -q "^${TS_INDEX_NAME}|${TS_INDEX_PATH}\$"<<<"$tslist" && pass "${TS_INDEX_NAME} at ${TS_INDEX_PATH}" || warn "${TS_INDEX_NAME} not at ${TS_INDEX_PATH}"

db_def_ts="$(sql_p -d "$DB" -c "SHOW default_tablespace;")" || db_def_ts=""
role_def_ts="$(sql_p -d "$DB" -c "SHOW default_tablespace;")" || role_def_ts="" # same SHOW for role-in-DB unless set locally
say "DB default_tablespace: ${db_def_ts}"
[[ "$db_def_ts" == "$TS_DATA_NAME" ]] && pass "DB default_tablespace=${TS_DATA_NAME}" || warn "DB default_tablespace is '${db_def_ts}' (recommended: ${TS_DATA_NAME})"

# Try to create a table and see where it lands
if sql_app "$APP_URL" -c "DROP TABLE IF EXISTS ts_probe; CREATE TABLE ts_probe(i int);" >/dev/null 2>&1; then
  landed="$(sql_p -d "$DB" -c "SELECT COALESCE(t.spcname,'(db default)') FROM pg_class c LEFT JOIN pg_tablespace t ON c.reltablespace=t.oid WHERE c.relname='ts_probe' AND c.relkind='r';")" || landed=""
  say "ts_probe tablespace: ${landed}"
  [[ "$landed" == "$TS_DATA_NAME" || "$landed" == "(db default)" ]] && pass "scratch table created (landed: ${landed})" || warn "scratch table landed in ${landed}"
  sql_app "$APP_URL" -c "DROP TABLE IF EXISTS ts_probe;" >/dev/null 2>&1 || true
else
  fail "could not create scratch table as ${APPUSER}"
fi

echo -e "\n=== Automic media & SQL files ===" | tee -a "$LOG"
db_root="$(find "$INSTALL_ROOT" -maxdepth 6 -type d -path '*/Automation.Platform/db/postgresql' 2>/dev/null | sort | tail -n1)"
echo "db/postgresql root: ${db_root:-<not found>}" | tee -a "$LOG"
if [[ -n "${db_root:-}" ]]; then
  latest="$(find "$db_root" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | sort -V | tail -n1)"
  echo "latest version dir: ${latest:-<na>}" | tee -a "$LOG"
  if [[ -n "${latest:-}" ]]; then
    ls -1 "$db_root/$latest" | sed 's/^/  - /' | tee -a "$LOG"
    for f in uc_ddl.sql after_uc_ddl.sql create_fk_for_E.sql create_xevents.sql upd_stat.sql; do
      [[ -f "$db_root/$latest/$f" ]] && pass "found $f" || fail "missing $f"
    done
    if ls "$db_root/$latest/steps"/step_*.sql >/dev/null 2>&1; then
      pass "steps folder contains versioned SQLs"
    else
      warn "no step_*.sql files found (may be okay)"
    fi
  else
    fail "no version subdirectory under $db_root"
  fi
else
  fail "Automic media not found under ${INSTALL_ROOT}/.../Automation.Platform/db/postgresql"
fi

echo -e "\n=== UCYB* utilities & UCYBDBRT sanity ===" | tee -a "$LOG"
found_utils="$(find /opt/automic -maxdepth 4 -type f -name 'UCYB*' 2>/dev/null | sort)"
if [[ -n "$found_utils" ]]; then
  echo "$found_utils" | sed 's/^/  - /' | tee -a "$LOG"
  pass "UCYB* utilities present"
else
  warn "no UCYB* utilities under /opt/automic (engine may not be installed yet)"
fi

UCYBDBRT="$(echo "$found_utils" | grep -E '/UCYBDBRT$' | head -n1 || true)"
UCSRV_INI="$(find /opt/automic -maxdepth 6 -type f -name 'ucsrv.ini' 2>/dev/null | head -n1 || true)"
if [[ -n "$UCYBDBRT" && -n "$UCSRV_INI" ]]; then
  if "$UCYBDBRT" -c "$UCSRV_INI" -v >/dev/null 2>&1; then
    pass "UCYBDBRT -v ran with ucsrv.ini"
  else
    warn "UCYBDBRT present but -v failed (engine not fully configured yet)"
  fi
else
  warn "skipping UCYBDBRT run (missing UCYBDBRT or ucsrv.ini)"
fi

echo -e "\n=== Key AEDB table existence & counts ===" | tee -a "$LOG"
for t in OH AH USR HOST MQSRV MQSRV2; do
  exists="$(sql_app "$APP_URL" -c "SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name=lower('${t}'));" 2>/dev/null | tr -d '\r')" || exists="f"
  printf "  %-6s -> %s\n" "$t" "$exists" | tee -a "$LOG"
done
for t in OH AH USR; do
  out="$(sql_app "$APP_URL" -c "SELECT COUNT(*) FROM \"${t}\";" 2>/dev/null || true)"
  [[ -n "$out" ]] && echo "  ${t} rows: $out" | tee -a "$LOG" || echo "  ${t} rows: N/A" | tee -a "$LOG"
done

echo -e "\n=== SUMMARY ===" | tee -a "$LOG"
say "PASS=$PASS  WARN=$WARN  FAIL=$FAIL"
[[ $FAIL -eq 0 ]] && say "OVERALL: ✅ PASSED (with ${WARN} warning(s))" || say "OVERALL: ❌ FAILED ($FAIL failure(s), ${WARN} warning(s))"

echo -e "\nLog saved to: $LOG"
EOS

chmod +x /tmp/aedb_post_install_check.sh
echo "Created /tmp/aedb_post_install_check.sh"
