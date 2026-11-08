# 🛡️ NetShield
### Windows Firewall Management and Network Traffic Monitoring System

NetShield is a Python-based cybersecurity application designed to monitor network traffic and manage Windows Defender Firewall rules through a web-based dashboard.

The project provides real-time network traffic monitoring, protocol analysis, firewall rule management, activity logging, and data export capabilities. It helps users understand network activity and manage potentially unwanted network connections through a centralized interface.

---

## 🚀 Key Features

### 1. Network Traffic Monitoring
- Captures network packets using Scapy.
- Monitors incoming and outgoing network traffic.
- Displays network activity through a web dashboard.
- Provides information about captured packets.

### 2. Windows Firewall Management
- Integrates with Windows Defender Firewall.
- Allows users to block specified IP addresses.
- Supports removing previously created firewall rules.
- Displays active firewall blocking rules.

### 3. Network Protocol Analysis
- Identifies network protocols.
- Displays protocol distribution through interactive charts.
- Uses Chart.js for graphical representation.
- Helps users understand network communication patterns.

### 4. Activity Logging
- Maintains records of network monitoring activities.
- Records firewall management operations.
- Provides access to monitoring logs.

### 5. Data Export
- Supports exporting network monitoring data into CSV format.
- Makes collected information easier to analyze and maintain.

### 6. Web-Based Dashboard
- Developed using Flask.
- Displays network statistics and firewall information.
- Includes interactive controls.
- Supports automatic dashboard refreshing.

---

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Python | Main programming language |
| Flask | Web application framework |
| Scapy | Network packet capture and analysis |
| SQLite | Database management |
| Windows Defender Firewall | Firewall rule management |
| PowerShell | Firewall command execution |
| HTML | Dashboard structure |
| CSS | Dashboard styling |
| JavaScript | Interactive functionality |
| Chart.js | Network protocol visualization |
| CSV | Data export |

---

## 📁 Project Structure

```text
NetShield/
│
├── app.py
├── packet_monitor.py
├── requirements.txt
│
├── templates/
│   └── Dashboard HTML files
│
├── static/
│   ├── css/
│   ├── js/
│   └── images/
│
├── screenshots/
│
├── documentation/
│
└── README.md
```

*Note: This is a representative structure. Adjust it to match the actual files and folders in your repository.*

---

## ⚙️ Installation and Setup

### Prerequisites

- Windows 10 or Windows 11
- Python 3.10 or later
- Administrator privileges
- Git (optional)

### Step 1: Clone the Repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

### Step 2: Navigate to the Project

```bash
cd NetShield
```

### Step 3: Create a Virtual Environment

```bash
python -m venv venv
```

### Step 4: Activate the Virtual Environment

```bash
venv\Scripts\activate
```

### Step 5: Install Dependencies

```bash
pip install -r requirements.txt
```

---

## ▶️ Running the Application

NetShield requires two processes to operate.

### Terminal 1: Start Network Monitoring

Open Command Prompt as Administrator.

Navigate to the project directory and activate the virtual environment.

Run:

```bash
python packet_monitor.py
```

This starts the network packet monitoring process.

### Terminal 2: Start the Flask Dashboard

Open another terminal and navigate to the project directory.

Activate the virtual environment and execute:

```bash
python app.py
```

Open your browser and visit:

```text
http://127.0.0.1:5000
```

The NetShield dashboard will be available locally.

---

## 🔄 How NetShield Works

1. **Packet Capture:** Scapy captures network packets from the system's network interface.
2. **Traffic Analysis:** Captured packets are analyzed to identify network protocols and traffic information.
3. **Data Management:** Network information and activity records are maintained using the application's data storage.
4. **Firewall Integration:** Python communicates with Windows Defender Firewall through PowerShell commands.
5. **Dashboard Visualization:** Flask displays network statistics, firewall rules, and protocol charts.
6. **Data Export:** Users can export available monitoring information into CSV format.

---

## 🔐 Security Considerations

- Firewall management operations require appropriate administrator privileges.
- The application is designed for Windows environments.
- Firewall rules should only be applied to authorized systems and networks.
- Network monitoring should be performed with proper authorization.
- Do not expose sensitive information, credentials, or private network data in the repository.

---

## 🎯 Project Objectives

- To understand practical network traffic monitoring.
- To implement packet capture using Python and Scapy.
- To understand Windows Defender Firewall integration.
- To develop a centralized firewall management dashboard.
- To visualize network protocols and traffic statistics.
- To improve practical cybersecurity and network administration skills.

---

## 🔮 Future Enhancements

- Advanced intrusion detection capabilities.
- Suspicious traffic identification.
- IP reputation checking.
- Automated threat detection and alerts.
- Advanced network traffic analytics.
- User authentication and role-based access control.

---

## 👨‍💻 Project Information

**Project Name:** NetShield

**Project Category:** Cybersecurity / Network Security

**Project Type:** Python-Based Web Application

**Primary Language:** Python

**Platform:** Windows

**Purpose:** Network Traffic Monitoring and Firewall Management

---

## 📜 Disclaimer

NetShield is developed for educational, learning, and authorized cybersecurity testing purposes. Users are responsible for ensuring that network monitoring and firewall operations are conducted only on systems and networks they are authorized to manage.

---

## ⭐ Acknowledgement

This project demonstrates the practical application of Python programming, network packet analysis, firewall management, and web application development in the field of cybersecurity.
