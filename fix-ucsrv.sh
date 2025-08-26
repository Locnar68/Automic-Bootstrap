set -e
BIN=/opt/automic/AutomationEngine/bin
# remove any existing sqlDriverConnect lines
sudo sed -i -E "/^[[:space:]]*sqlDriverConnect[[:space:]]*=/d" "$BIN/ucsrv.ini"
# append one correct line (DB_* come from the env)
echo "sqlDriverConnect=jdbc:postgresql://${DB_IP}:5432/${DB_NAME}?sslmode=disable|${DB_USER}|${DB_PASS}|org.postgresql.Driver" | sudo tee -a "$BIN/ucsrv.ini" >/dev/null
echo "-- ucsrv.ini tail --"
tail -n 3 "$BIN/ucsrv.ini"