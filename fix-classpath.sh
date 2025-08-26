set -e
BIN=/opt/automic/AutomationEngine/bin
sudo sed -i -E "s|^sqlDriverClasspath=.*$|sqlDriverClasspath=/opt/automic/AutomationEngine/bin/lib/postgresql-jdbc.jar|" "$BIN/ucsrv.ini"
echo "== Effective JDBC settings =="
grep -E "^(sqlDriverClasspath|sqlDriverConnect)" "$BIN/ucsrv.ini" || true