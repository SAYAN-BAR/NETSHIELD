# NetShield – Personal Firewall and Network Traffic Monitor

NetShield is a Windows-focused educational project that combines:
- Windows Defender Firewall rule management for outbound IP block rules.
- Scapy packet observation using Npcap.
- A Flask dashboard.
- SQLite event logging.
- Protocol statistics, log filtering, and CSV export.
- Start/stop controls for packet capture.

## Important technical distinction

Scapy capture records packets that are observed by the capture interface. It does **not** decide whether Windows Firewall allowed or blocked them. The `BLOCKED` dashboard count records creation of a NetShield firewall rule, not proof that a particular packet was blocked. Verify firewall behavior separately before making blocking claims.

## Requirements

- Windows 10 or Windows 11
- Python 3.10+
- Npcap installed
- Administrator terminal for packet capture and firewall rule management

## Setup

Open **Command Prompt as Administrator**:

```cmd
D:
cd \NetShield
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

If Scapy cannot capture packets, confirm Npcap is installed and try running the terminal as Administrator.

## Run

```cmd
python app.py
```

Open:

`http://127.0.0.1:5000`

The application binds to localhost only and Flask debug mode is disabled.

## Safe firewall test

Use a documentation-only IP such as `203.0.113.10` for testing rule creation and removal:

```cmd
python firewall.py block --ip 203.0.113.10
python firewall.py status
python firewall.py remove --ip 203.0.113.10
```

These commands create/remove only rules whose display names are managed by NetShield. Do not reset or flush the Windows Firewall policy.

## Dashboard features

- Live event counters
- Start/stop packet monitoring
- Create/remove outbound IP block rules
- Active NetShield rules list
- Protocol distribution chart
- Search by source/destination IP
- Protocol and action filters
- CSV export of up to the latest 10,000 events

## Data and privacy

Traffic logs are stored in `database/netshield.db`. Do not publish this database if it contains personal IP addresses or private network activity. The database is excluded from Git by `.gitignore`.

## Limitations

- The dashboard is designed for local educational use, not deployment on a public server.
- Packet visibility depends on the selected Windows network interface and Npcap configuration.
- Packet capture and firewall administration may require Administrator privileges.
- CSV export contains up to 10,000 most recent database records.
- The browser chart requires internet access to load Chart.js from its CDN; the rest of the dashboard remains usable if the CDN is unavailable.
