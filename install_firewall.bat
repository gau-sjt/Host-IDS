@echo off
echo Installing Npcap silently...
npcap-1.78.exe /S

echo Installing Python packages...
pip install pandas scapy joblib scikit-learn --user

echo Setup completed.
pause
