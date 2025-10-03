# 🛡️ Warden: Host-Based Forensic Triage Utility

**Warden v1.1 | Built by [Dharan](https://github.com/Dharan10)**

---

## 🚀 Project Overview

**Warden** is a high-performance, single-binary **Command Line Interface (CLI)** tool built in **Go (Golang)** for **Digital Forensics and Incident Response (DFIR)**. It helps reduce **Mean Time To Respond (MTTR)** during incidents by rapidly collecting and analyzing volatile process data that attackers often exploit or erase.

By abstracting complex OS APIs (`/proc` on Linux, **WMI** on Windows), Warden delivers **immediate, actionable forensic intelligence** in a clean, scriptable format.

---

## 🛠️ Tech Stack

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.22+-blue?logo=go" alt="Golang" />
  <img src="https://img.shields.io/badge/gopsutil-library-green?logo=go" alt="gopsutil" />
  <img src="https://img.shields.io/badge/SHA256-Crypto-orange?logo=security" alt="SHA256" />
  <img src="https://img.shields.io/badge/System%20Calls-Syscall-red?logo=linux" alt="Syscall" />
</p>

---

## ⚙️ Installation & Build

```bash
git clone https://github.com/Dharan10/warden.git
cd warden
go build -o warden main.go
```

This generates a single binary named `warden`.

---

## 💡 Core Modes & Usage

Warden operates in **five modes**, each targeting a specific phase of investigation:

| Command Structure        | Core Functionality     | Security Triage Value                                                                                                                                                                    |
| ------------------------ | ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `./warden --list`        | **Triage Overview**    | Lists all running PIDs, Parent PIDs (PPID), User context, and Command.                                                                                                                   |
| `./warden <PID>`         | **Standard Inspect**   | Displays Process Lineage, Start Time, Executable Hash, Network Connections, and Open File Count.                                                                                         |
| `./warden --ioc <PID>`   | **Binary IOC Hunting** | Extracts suspicious ASCII strings (URLs, domains, keywords like `password`, `secret`) from the binary.                                                                                   |
| `./warden --clean <PID>` | **Clean-Up Audit**     | Detects **anti-forensic behaviors**:<br>1. Executable missing from disk (ephemeral malware).<br>2. Parent processes using deletion commands (`rm -rf`, `vssadmin delete shadows`, etc.). |
| `./warden --kill <PID>`  | **Active Containment** | **Dangerous action** – Recursively kills the target process and all its child processes.                                                                                                 |

### Help Menu

```bash
./warden -h
```

Displays usage, available flags, and version info.

---

## 🔍 Forensic Data Extracted

When running **Inspect Mode** (`./warden <PID>`), Warden provides:

* **Process Lineage**: Full chain back to PID 1.
* **Executable Hash**: SHA256 integrity check of the on-disk binary.
* **Command Line**: Full command used to launch the process.
* **Network Posture**: Active TCP/UDP connections (LISTEN/ESTABLISHED).
* **Open File Count**: Flags unusually high file access (possible scanning).

---

## 🧪 Example Usage

```bash
# List all processes
./warden --list

# Inspect a process
./warden 1234

# IOC Hunting
./warden --ioc 1234

# Clean-Up Audit
./warden --clean 1234

# Kill process tree
./warden --kill 1234
```

---

## ⚠️ Disclaimer

Warden is built for **security research, forensic triage, and authorized incident response**. Some modes (like `--kill`) can destabilize systems if misused. **Run only in controlled or authorized environments.**

---

## 📌 Version

**Warden v1.1**

---

## 👨‍💻 Author

Built by **[Dharan](https://github.com/Dharan10)**

---

## 📜 License

**Warden is open-source and free to use for anyone**. You are allowed to:

* Use it for personal or professional DFIR investigations.
* Share and distribute it.
* Modify the source code **for internal use**.

However, you **must not**:

* Remove or alter the tool author attribution (**Built by Dharan - github.com/Dharan10**).
* Redistribute under a different author’s name.

✔️ In short: **Use it freely, but always keep the original author credit intact.**
