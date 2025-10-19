# zbx-agent-install

📝 Cara Pakai Quick:

bash# Download script

git clone https://github.com/irfanharis/zbx-agent-install-improved.git

cd zabbix-agent-installer

chmod +x install-zabbix-agent.sh

# Basic install
sudo ./install-zabbix-agent.sh --server 10.0.0.5

# Dengan TLS PSK
PSK=$(openssl rand -hex 32)
sudo ./install-zabbix-agent.sh --server zbx.local --psk "$PSK"

# Custom port
sudo ./install-zabbix-agent.sh --server zbx.local --port 10051

# Dry-run dulu
sudo ./install-zabbix-agent.sh --server zbx.local --dry-run

# Force reinstall
sudo ./install-zabbix-agent.sh --server zbx.local --force

# Uninstall
sudo ./install-zabbix-agent.sh --uninstall
