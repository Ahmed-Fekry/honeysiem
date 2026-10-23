# Deploying a real honeypot

This guide runs [Cowrie](https://github.com/cowrie/cowrie), a medium-interaction SSH honeypot,
on a cheap cloud VM and feeds its logs into HoneySIEM.

> **Safety first.** A honeypot invites attackers in. Use a dedicated, disposable VM that holds
> no credentials, keys or data you care about, in a cloud project separate from anything real.
> Check your cloud provider's acceptable-use policy before you start.

## 1. Create the VM

Any small Linux VM works (1 vCPU / 1 GB RAM, Ubuntu 24.04). In the provider firewall:

| Port | Source | Purpose |
|------|--------|---------|
| 22   | anywhere | honeypot (Cowrie) |
| 22022 | **your IP only** | your real SSH admin access |

## 2. Move the real SSH daemon off port 22

```bash
sudo sed -i 's/^#\?Port .*/Port 22022/' /etc/ssh/sshd_config
sudo systemctl restart ssh
# reconnect with: ssh -p 22022 user@your-vm  (keep the old session open until this works)
```

## 3. Start Cowrie

```bash
sudo apt-get update && sudo apt-get install -y docker.io docker-compose-v2
git clone https://github.com/<you>/honeysiem.git && cd honeysiem/deploy
sudo docker compose up -d
sudo docker logs -f cowrie   # first attackers usually appear within minutes to hours
```

The container is hardened: read-only filesystem, all capabilities dropped,
`no-new-privileges`, and memory / process limits.

## 4. Analyse the logs

```bash
LOG=$(sudo docker volume inspect deploy_cowrie-var -f '{{ .Mountpoint }}')/log/cowrie/cowrie.json
pip install git+https://github.com/<you>/honeysiem.git
sudo cp "$LOG" ./cowrie.json && sudo chown "$USER" ./cowrie.json
honeysiem ingest cowrie.json
honeysiem detect --min-severity high
honeysiem report -o report.html
```

Ingestion is idempotent, so a cron job can re-ingest the growing log file safely:

```cron
*/15 * * * * cd ~/honeysiem-data && cp /path/to/cowrie.json . && honeysiem ingest cowrie.json && honeysiem report -o report.html
```

Download `report.html` with `scp -P 22022` and open it locally. Don't serve it from the honeypot.

## 5. Tear down

```bash
sudo docker compose down -v
```
Then destroy the VM. Never reuse a honeypot VM for anything else.
