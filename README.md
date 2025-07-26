# 🛡️ LogSleuth – Python-Based Log File Analyzer for Intrusion Detection  

**LogSleuth** is a modular Python tool designed to detect suspicious activities by analyzing server and service logs.  
It helps system administrators and security enthusiasts quickly spot **brute-force attacks**, **blacklisted IP activity**, and **unusual access patterns** across **Apache**, **SSH**, and **FTP** services.

Built for flexibility, LogSleuth can be extended to support **custom log formats** and integrates with **public IP blacklist APIs** to enhance detection accuracy.

---

## 🚀 Key Features  

- **Multi-Log Support** – Analyze Apache (`access.log`), SSH (`auth.log`), and FTP (`ftp.log`) simultaneously.  
- **Brute-Force Attack Detection** – Flags IPs with repeated failed login attempts.  
- **IP Blacklist Integration** – Checks suspicious IPs against public threat intelligence sources.  
- **Visual Analytics** – Generates easy-to-understand **graphs and summaries** for quick insights.  
- **Exportable Reports** – Outputs **CSV summaries** for further investigation and auditing.  
- **Customizable Parsing** – Add new log formats using simple **regular expressions**.  

---

## ⚙️ Tech Stack  

- **Python 3** – Core scripting language  
- **Pandas** – Data processing and analysis  
- **Regex (re)** – Pattern matching in logs  
- **Matplotlib & Seaborn** – Visualizations for insights  
- **Requests** – API integration for blacklist checking  
- **Linux System Logs** – Real-world Apache, SSH, and FTP log samples
  
---

## 📂 Output & Reports  

When executed, LogSleuth generates:  

- **CSV reports** for detected brute-force attempts, suspicious IPs, and blacklisted addresses.  
- **Visual graphs** displaying login attempts, top offending IPs, and access frequency trends.  

---

## 👨‍💻 Author  

**Paavan Shastri**  
*Cybersecurity Enthusiast | Internship Project*  

---
