<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/g0ldj/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user “labuser” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the create of a file called “tor-shopping-list.txt” on the Desktop.

**Query to locate events**

![image](https://github.com/user-attachments/assets/00ae0929-12a0-4a3a-a243-40af5ff10bd6)


---

### 2. Searched the `DeviceProcessEvents` Table

Search the DeviceProcessEvents table for any ProcessCommandLine that contains the string “tor-browser-windows”. Based on the logs returned we did get 1 return.

![image](https://github.com/user-attachments/assets/e00d06a5-0824-40bb-8f70-3d56512f8c0f)


**Query used to locate event:**

![image](https://github.com/user-attachments/assets/1b5f6ebe-afd2-4c11-9ef4-2b299b73425f)


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “labuser” actually opened the tor browser. There was evidence that they did open it at 2025-02-05T04:40:50.8412502Z
There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterwards


**Query used to locate events:**

![image](https://github.com/user-attachments/assets/b8c55523-6105-4e93-9334-9361b5c823c2)


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Search the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known ports. At 2025-02-05T04:24:51.1981703Z a connection was first attempted and failed and then it was followed up w/ a successful connection

![image](https://github.com/user-attachments/assets/a60405d3-f680-4b3f-b6af-eaa98e5ddb82)


**Query used to locate events:**

![image](https://github.com/user-attachments/assets/75ba45c7-95ad-406d-85f3-6ba2a67edfca)


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

Timeline of Events
1. Initial Discovery of Tor-Related Files
Timestamp: (Exact time not provided in logs)
Action: User “labuser” downloaded a Tor installer.
File Identified: tor-browser-windows-x86_64-portable-14.0.5.exe
Folder Path: Not specified
Observations: The download led to the creation of multiple Tor-related files on the Desktop, including a file named tor-shopping-list.txt.


2. Execution of the Tor Browser Installer
Timestamp: (Exact time not provided in logs)
Action: Execution of tor-browser-windows binary was detected.
Query Result: One log entry confirms the execution of the Tor installer.


3. Launch of Tor Browser and Associated Processes
Timestamp: 2025-02-05T04:40:50.8412502Z
Action: User launched the Tor browser.
Processes Spawned: firefox.exe (Tor), tor.exe, tor-browser.exe
Observations: Multiple instances of Firefox (modified for Tor) and tor.exe were observed, indicating active use of the Tor browser.


4. Network Connections Attempted via Tor
Timestamp: 2025-02-05T04:24:51.1981703Z
Action: A network connection attempt was made using Tor-related ports.
Ports Identified: 9001, 9030, 9040, 9050, 9051, 9150
Outcome: Initial connection attempt failed, but a subsequent connection was successful.
Remote IP/URL: Not specified in logs
MITRE ATT&CK Mapping
T1204.002 - User Execution: Malicious File
Execution of the Tor browser installer by user labuser.
T1071.001 - Application Layer Protocol: Web Protocols
Establishment of a Tor network connection over designated ports.
T1090.003 - Proxy: Multi-hop Proxy
Usage of Tor to obfuscate network activity.
T1005 - Data from Local System
Creation of tor-shopping-list.txt, potentially containing sensitive or illicit information.



---

## Summary

The investigation reveals that user labuser downloaded and installed the Tor browser on jordan-mde-test. The user executed the installer, which resulted in multiple Tor-related files appearing on the desktop. Shortly after, the user launched the Tor browser, leading to the execution of tor.exe and modified Firefox processes. Finally, network logs indicate that a connection attempt to a Tor network node was made, initially failing but later succeeding.
This activity suggests an attempt to anonymize internet activity, which could be an indicator of unauthorized or suspicious behavior. The presence of tor-shopping-list.txt raises further concerns about potential illicit activity.

---

## Response Taken

TOR usage was confirmed on endpoint  jordan-mde-test. The device was isolated and the user's direct manager was notified.

---
