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

## Prerequisites & Environment Setup

Before launching the project, ensure your host operating system has **Nmap** and **Python** installed, along with the required platform-specific package wheels (`.whl`).

### 1. Windows Setup

1. **Install Core Dependencies**:
   - **Nmap**: Download and run the installer from [Nmap.org](https://nmap.org/download.html). Ensure **Nmap** is added to your System Environment `PATH`.
   - **Python 3.8+**: Download from [Python.org](https://www.python.org/downloads/). Check **"Add Python to PATH"** during installation.

2. **Prepare Wheel Packages**:
   - Create a folder named `Windows` in the project root directory:
     ```cmd
     mkdir Windows
     ```
   - Place all required `.whl` (wheel) dependency files for Windows inside the `Windows/` folder for offline or automated package installation.

---

### 2. Linux Setup

1. **Install Core Dependencies**:
   - Run the following command in terminal to install Nmap, Python, and the `venv` module:
     ```bash
     sudo apt update && sudo apt install nmap python3 python3-venv python3-pip -y
     ```

2. **Prepare Wheel Packages**:
   - Create a folder named `Linux` in the project root directory:
     ```bash
     mkdir Linux
     ```
   - Place all required `.whl` (wheel) dependency files for Linux inside the `Linux/` folder.

---

## How the Launchers Work

Once the software prerequisites and wheel packages are in place, you do not need to manually configure virtual environments or install Python packages individually.

1. Executing **`run.bat`** (Windows) or **`run.sh`** (Linux) triggers the startup sequence.
2. The launcher automatically creates an isolated virtual environment directory named **`venv/`** in your root folder.
3. It installs all required packages directly from your local platform folder (`Windows/` or `Linux/`).
4. It initializes the backend server and launches the web dashboard at `http://localhost:5000`.

---

## Quick Start Guide

### Running on Windows
* **Via PowerShell or Command Prompt:**
  ```powershell
  .\run.bat

### Running on Linux
* **Via Terminal**
```bash
  chmod +x run.sh
./run.sh

  
