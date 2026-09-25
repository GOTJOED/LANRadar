# NETSCANNER

**NETSCANNER** is a lightweight, cross-platform network discovery and monitoring server interface. Powered by an Nmap API backend, it enables real-time host discovery, ping testing, open port detection, and scan queue management through a dark-mode web dashboard.

---
## Preview
<img width="1906" height="908" alt="image" src="https://github.com/user-attachments/assets/7e3960fb-5387-4d52-9742-c529ad912d9c" />
<img width="1899" height="813" alt="image" src="https://github.com/user-attachments/assets/f120b35f-bb1c-48a1-9b32-f290a9d46e80" />
<img width="484" height="185" alt="image" src="https://github.com/user-attachments/assets/dda37779-5486-4684-a8dd-74d31bef8321" />
## Core Features
- **Real-Time Network Monitoring**: Continuous ping testing and live status tracking (`Connected` vs `Disconnected`).
- **Nmap API Integration**: Trigger quick, intense, or comprehensive subnet scans on demand.
- **Cross-Platform Engine**: Native launcher support for both **Linux** and **Windows** systems.
- **Queue Engine**: Asynchronous task manager for executing multiple scan groups without blocking the UI.

---

## Prerequisites

Before running the server scripts, ensure **Nmap** and **Python 3.8+** are installed on your host system.

### 1. Install System Dependencies
* **Linux (Ubuntu / Debian)**
Run in Terminal:
  ```bash
  sudo apt update && sudo apt install nmap python3-venv python3-pip -y
