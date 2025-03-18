# INSE6170
Repo for the Project

Getting Started: How to Run the IoT Router Management Software
Prerequisites:
Windows OS (Recommended: Windows 10 or later)
Python 3.10 or later installed (Download Python)
Important: During installation, ensure to check "Add Python to PATH".
Administrative privileges (required for firewall features)

**Step 1: Clone the Repository**
Open Command Prompt or PowerShell and clone this repo clearly:
git clone <your-repository-url>
cd <repository-name>

**Step 2: Create and Activate Virtual Environment**
Run these commands to set up a clean environment clearly:

python -m venv venv
Activate virtual environment:

On Command Prompt:
venv\Scripts\activate.bat

On PowerShell:
.\venv\Scripts\Activate.ps1

**Step 3: Install Required Dependencies**
Inside your activated virtual environment, run clearly:

pip install scapy requests matplotlib
Note: tkinter is pre-installed with Python on Windows.

**Step 4: Ensure Required Directories Exist**
Create necessary directories clearly:
mkdir captures logs

**Step 5: Run the Application**
Ensure you're running your command prompt or PowerShell as an administrator due to firewall functionalities, and execute clearly:

Login-based approach (recommended):
python login.py
(Default admin credentials: admin / admin123)

Or run directly (without login):
python app.py

**Using the Application:**
Device Monitoring: Click "Refresh Devices" to list connected IoT devices.
Packet Capture: Select a device and click "Capture Packets".
Firewall Management: Select a device and click "Block Selected IP"/"Unblock Selected IP".
Intrusion Detection: Select a device and click "IPS Monitor Device".
Historical Data Visualization: Select a device and click "Show Traffic History".

**Important Notes:**
Run your command prompt or PowerShell as an administrator for firewall features to function correctly.
Always activate your virtual environment (venv) before running the application.
Default admin credentials are provided for login (admin:admin123); create new accounts as needed from the login screen.
