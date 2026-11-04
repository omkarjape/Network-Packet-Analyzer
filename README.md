# Network Packet Analyzer Prototype

**Department of Computer Engineering**  
**Sanjivani College of Engineering, Kopargaon**  
**Class:** TY B.Tech (SEM V) | **Course:** Computer Networks (CN CIA Activity)  

**Presented by:**
1. **Omkar Jape** (Roll No: 114)
2. **Tambe Pranav** (Roll No: 112)

**Guided by:** **Prof. P. N. Kalavadekar**

---

## 📌 Project Overview

Understanding network traffic and congestion is difficult without tools to inspect individual packets. This prototype is a **lightweight, easy-to-use Network Packet Analyzer** built using **Python, Scapy, and Flask**. It allows users to capture, examine, and analyze packets in real-time through an interactive web dashboard.

---

## 🏗️ System Components & Architecture

The architecture directly follows our presentation design:

1. **Network Interface**: Select the network adapter (Wi-Fi, Ethernet) or Demo Mode.
2. **Packet Capture Module**: Captures incoming and outgoing network packets using Python & Scapy in a background thread.
3. **Packet Analyzer**: Inspects packet headers and decodes protocols (**TCP, UDP, DNS, ICMP, HTTP, ARP**).
4. **Packet Filter**: Filters packets in real-time by Protocol, Source IP, or Destination IP.
5. **Statistics Module**: Counts total packets, summarizes protocol distribution, and calculates total data volume transferred.
6. **Dashboard (Frontend)**: Clean, responsive user interface displaying real-time packet stream, visual protocol distribution bar, packet inspection modal, and CSV export.

---

## 🚀 Dual Capture Modes

- **Demo Mode (Simulated Traffic - Safe & Default)**:  
  Generates realistic network traffic (TCP handshakes, DNS queries, ICMP pings, UDP streams) using Scapy in memory.  
  *Advantage*: Guaranteed to work smoothly during college presentations and vivas without needing administrator rights or Npcap drivers!

- **Live Capture Mode**:  
  Captures actual real-world packets on your network adapter using Scapy's packet sniffing engine.  
  *Note*: Live packet capture on Windows requires Administrator privileges or Npcap installed.

---

## 🛠️ Installation & Setup

### 1. Requirements
Ensure Python 3.9+ is installed.

### 2. Install Dependencies
Open PowerShell or Command Prompt in this folder and run:
```bash
pip install -r requirements.txt
```

### 3. Run the Application
```bash
python app.py
```

### 4. Open the Dashboard
Open your web browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 💡 How to Demonstrate (During Viva / Presentation)

1. **Start Capture**:
   - Keep mode as **Demo Mode** (or choose **Live Capture** if running as Administrator).
   - Click the green **Start Capture** button.
   - Watch packets populate the table with colored protocol badges (**TCP**, **UDP**, **DNS**, **ICMP**).

2. **Demonstrate Packet Filtering**:
   - In the **Protocol Filter** dropdown, select **DNS** to view only DNS queries.
   - Type an IP into **Source IP** (e.g., `192.168.1`) to see IP-based filtering.
   - Click **Reset Filters** to restore all packets.

3. **Inspect Packet Details**:
   - Click on any packet row in the table.
   - A modal dialog appears showing:
     - **Layer Hierarchy** (`Ethernet > IPv4 > TCP`)
     - **Source & Destination Ports**
     - **TCP Flags** (`SYN, ACK, PSH, FIN`)
     - **Payload Hex & ASCII Dump**

4. **View Real-Time Statistics**:
   - Point out the **Total Packets**, **TCP**, **UDP**, **DNS**, and **ICMP** KPI counter cards.
   - Show the dynamic **Protocol Distribution Overview** progress bar.

5. **Export to CSV**:
   - Click **Export CSV** to download `network_packet_capture.csv` for reporting or offline analysis in Excel.

---

## 📁 Project Structure

```text
Network Package Analyzer/
├── app.py                # Flask backend, Scapy analyzer & simulation engine
├── requirements.txt      # Python dependencies (Flask, Scapy)
├── README.md             # Project documentation and guide
├── templates/
│   └── index.html        # Interactive web dashboard
└── static/
    ├── css/
    │   └── style.css     # Modern network engineer UI styling
    └── js/
        └── app.js        # Dynamic UI controller (Fetch API, live polling, modal)
```
