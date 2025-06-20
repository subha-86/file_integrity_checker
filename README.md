#  File Hash Reporter & Integrity Monitor

A Python desktop application that ensures **file integrity and security** by:

- Generating SHA-256 hashes for all files in a selected folder  
- Immediately emailing the hash report to your Gmail  
-  Monitoring file changes in real-time using `watchdog`  
- Sending Gmail alerts (with popup notifications) on any file modifications or deletions  
- GUI-based email credential prompt (no hardcoded passwords)

---

##  Features

| Feature                            | Description |
|------------------------------------|-------------|
| Folder Selection                | Easily browse and pick a folder to monitor |
| Hashing                         | Calculates secure SHA-256 hashes for every file |
| Instant Email Report            | Sends a full hash report to your Gmail |
| Real-Time File Monitoring       | Alerts you via Gmail if files are modified or deleted |
| Gmail Notification Support      | Works with Gmail’s popup notifications (desktop or phone) |
|   GUI Email Prompt              | No hardcoding credentials — enter Gmail & App Password in a popup |

---

##  Requirements

```bash
pip install -r requirements.txt
