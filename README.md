# ThreatGuard Syslog Generator

This script serves as a generator of a push notification, when a new threat is added to ThreatGuard application. After fetching data from ThreatGuard, a new notification is created and sent to a server in form of a **syslog**.

## 💾 Install

### Requirements:
- python 3.6 or higher
- pip

Following these steps, you will download the script and prepare everything for usage.

### Linux:
1. Clone this repository

    ```bash
    git clone https://github.com/ondromalik/threatguard-syslog-push.git
    ```

2. Move to created folder

    ```bash
    cd threatguard-syslog-push
    ```

3. Install requirements from `requirements.txt`

    ```bash
    pip install -r requirements.txt
    ```

### Windows:
1. Download project in **ZIP** format
2. After downloading the file, extract the same
3. Through **Command Line** navigate to extracted folder
4. Install requirements from `requirements.txt`

    ```bash
    pip install -r requirements.txt
    ```

## 🪓 Usage

Run the script using command:

```bash
python3 TG-notification.py -u <threatguard_url> -s <server_IP> -p <server_port>
```
### Parameters:
- `threatguard-url` - URL of XML Export page of [ThreatGuard](https://portal.threatguard.cz). You can find the Export page in ThreatGuard portal <Account_name> -> Export -> Česky/Anglicky
- `server_IP` - IP address or domain name of server, where you want to send the syslog
- `server_port` - port, on which the server is listening for syslog

## 🎧 Contact
If you need an assistance, please contact support@comguard.cz