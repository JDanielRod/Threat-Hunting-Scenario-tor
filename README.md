

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/JDanielRod/Threat-Hunting-Scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched DeviceFileEvents table for any file that had the string `tor` in it and discovered the user “employee” downloaded a tor installer. Activity resulted in many tor-related files being copied to desktop and creation of file named `tor-shopping.txt` on desktop. Events began at : `2026-03-23T18:48:28.7916146Z`

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "danr-threathunt"
| where InitiatingProcessAccountName == "employee"
| where FileName contains "tor"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="608" height="350" alt="image" src="https://github.com/user-attachments/assets/65d4a38b-bfb1-4ae0-9d06-22c8f15cce0d" />



<img width="611" height="131" alt="image" src="https://github.com/user-attachments/assets/a5058e4b-ba7f-4c0f-9731-328ae5e259fd" />



---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string `tor-browser-windows-x86_64-portable-15.0.7.exe`. Based on the logs returned at: `2026-03-23T18:48:28.7916146Z`, an employee on the `danr-threathunt` device ran the file `tor-browser-windows-x86_64-portable-15.0.7.exe` from the downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "danr-threathunt"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.7"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

```
<img width="587" height="383" alt="image" src="https://github.com/user-attachments/assets/d9baeea0-5900-4b85-8e8d-116e0b292e54" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched DeviceProcessEvents table for indication that user “employee” actually opened tor browser. There was evidence they did open it at: `2026-03-23T18:52:01.5369862Z`. There were several other instances for `firefox.exe` (tor) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="601" height="311" alt="image" src="https://github.com/user-attachments/assets/027bb25e-b652-4d50-8f5f-a3d966cd1ce8" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched DeviceNetworkEvents table for indication the tor browser was used to establish a connection using any of the known tor ports. At `2026-03-23T18:52:10.1303556Z`, the user `employee` on device established a connection to remote ip address `202.61.205.33` on port `9001`. Connection was initiated by the process `tor.exe`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "danr-threathunt"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001","9030","9040", "9050", "9051","9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc
```
<img width="727" height="262" alt="image" src="https://github.com/user-attachments/assets/54a751f9-09dd-40a6-ad65-ebe0affff3d5" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-03-23T18:48:28.7916146Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.7.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-15.0.7.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-03-23T18:48:28.7916146Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-15.0.7.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.7.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-15.0.7.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-03-23T18:52:01.5369862Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\firefox.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-03-23T18:52:10.1303556Z`
- **Event:** A network connection to IP `202.61.205.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. File Creation - TOR Shopping List

- **Timestamp:** ` 2026-03-23T19:04:42.07152Z`
- **Event:** The user "employee" created a file named `tor-shopping.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping.txt`

---

## Summary

On March 23, 2026, the user “employee” on device danr-threathunt performed a full lifecycle of Tor Browser usage:
  -Executed a Tor installer from the Downloads folder using a silent install command
  -Installed and staged Tor-related files on the Desktop
  -Launched the Tor Browser, spawning multiple related processes
  -Established a connection to the Tor network over port 9001, browsed a few sites
  -Created a file (“tor-shopping.txt”), indicating user activity during the Tor session

---

## Response Taken

TOR usage was confirmed on the endpoint `danr-threathunt` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
