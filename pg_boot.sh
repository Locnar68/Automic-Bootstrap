#!/usr/bin/env bash
set -euo pipefail
# Install server + contrib
if command -v dnf >/dev/null 2>&1; then
  sudo dnf -y install postgresql16-server postgresql16-contrib || sudo dnf -y install postgresql-server postgresql-contrib
elif command -v yum >/dev/null 2>&1; then
  sudo yum -y install postgresql16-server postgresql16-contrib \
    || (sudo amazon-linux-extras enable postgresql16 && sudo yum clean metadata && sudo yum -y install postgresql16-server postgresql16-contrib) \
    || sudo yum -y install postgresql-server postgresql-contrib
elif command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update -y && sudo apt-get install -y postgresql postgresql-contrib
fi

# Init cluster if needed (PGDG provides these helpers)
sudo /usr/pgsql-16/bin/postgresql-16-setup initdb || sudo postgresql-setup --initdb || true

# Enable + start service (try common unit names)
sudo systemctl enable --now postgresql-16 || sudo systemctl enable --now postgresql || sudo systemctl enable --now 'postgresql@16-main'

# Sanity
sudo -u postgres psql -Atqc "select version();"
