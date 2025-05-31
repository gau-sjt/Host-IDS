# Host-Based Intrusion Detection & Firewall System (Windows)

This project implements a lightweight Host Intrusion Detection System (HIDS) that captures live network traffic, detects potential intrusions using a trained ML model, and enforces automated firewall rules to block malicious IPs.

---

## Features

- ML-based intrusion detection (e.g., Random Forest, entropy-based)
- Real-time packet capture using Scapy
- Feature extraction including protocol, port, and entropy analysis
- Automatically blocks malicious IPs using Windows Firewall
- Works as a standalone Python script on any Windows machine

---

## Requirements

- **Operating System**: Windows 10 or later
- **Python**: 3.8 or newer
- **Privileges**: Administrator (for firewall rules)
- **Python packages**:
  - `scapy`
  - `pandas`
  - `joblib`
  - `scikit-learn`
  - Run the `install_firewall.bat` script as **Administrator** to install all necessary dependencies:
  Note: Ensure `npcap-1.78.exe` is placed in the same folder as `install_firewall.bat` before running the script.

## Files included

- `train_host_IDS.py`     --> Python program which creates the machine learning model using the given dataset.
- `ZoomFirewall.py`       --> Utilises the model to sniff packets in real time and detect attacks. Any attack is blocked by writing a new firewall rule.
- `install_firewall.bat`  --> Installs ncap and required dependencies.
- `start_firewall.bat`    --> File used to automate the firewall.
- `HostIDS.joblib`        --> Ready-made model ready to be used. Created using `train_host_IDS.py`.
- `simple_dataset3.csv`   --> Dataset used for training.
- `test_dataset.csv`      --> Dataset used for testing.

## Deployment

1. Open `start_firewall.bat` and modify the file path specified. (IMPORTANT)
2. Run `train_host_IDS.py` and feed in the simple dataset to train the model. If you would like to use the ready-made `HostIDS.joblib` model, this step can be skipped.
3. Once the model is obtained, update the model path in `ZoomFirewall.py`. Can be tested using `test_dataset.csv` inside `train_host_IDS.py` by following prompts.
4. Ensure the interface in `ZoomFirewall.py` (line 22) is specified appropriately.
5. Open Task Scheduler `taskschd.msc`.
6. Create Task (Not Basic Task).
    - General: Name - Firewall Protection; Run with highest privileges; Configure for Windows 10/11
    - Triggers: Begin Task - At Startup
    - Actions: New - Start a program; Program: C:\Path\Tolstart_firewall.bat
    - Conditions: Uncheck "Start the task only if computer is on AC power" if needed.
7. Settings: Allow tasks to be run on demand. Restart if failed.

