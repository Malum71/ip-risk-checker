CyberRadar is a web-based cybersecurity tool that combines multiple threat intelligence sources into a single platform, similar to a lightweight fusion of VirusTotal and abuse reporting databases like AbuseIPDB.

It allows users to scan files, check IPs/domains, and review security logs in one centralized dashboard, making it easier to identify malicious activity and potential threats quickly.

🔍 Key Features
🛡️ Multi-Source Threat Intelligence
Combines results from file scanning and abuse databases into a unified view.
📁 File Analysis
Upload files and analyze them for suspicious or malicious indicators.
🌐 IP / Domain Reputation Checks
Check whether an IP address or domain has been reported for abuse or malicious behavior.
📊 Security Dashboard
Clean interface to view scan history, results, and system activity.
🗂️ Logging System
Stores and displays past scans and detection results for tracking patterns.
🧱 Project Structure
app.py – Core backend logic (API integration + routing)
templates/ – Frontend HTML pages
dashboard.html – Main overview dashboard
file_scan.html – File scanning interface
logs.html – Historical scan logs
index.html – Landing page
cyberradar.db – Local database for storing results
requirements.txt – Python dependencies
render.yaml – Deployment configuration
ngrok-stable-linux-amd64.zip – Used for local tunneling/testing
⚙️ How It Works
User uploads a file or submits an IP/domain.
The backend queries multiple threat intelligence sources.
Results are normalized into a single structured response.
Data is stored in a local database for tracking history.
The dashboard displays combined insights in real time.
🎯 Use Cases
Cybersecurity learning and experimentation
Lightweight threat intelligence aggregation
SOC-style dashboard prototype
Research and analysis of suspicious files/IPs/domains
🛠️ Tech Stack
Python (Flask-style backend)
HTML/CSS templates
SQLite database
External threat intelligence APIs
Deployment via Render / local tunneling (ngrok)
📌 Future Improvements
Add real-time API streaming (live threat feeds)
Improve correlation between multiple sources
Add authentication and user management
Enhance scoring system for threats
Build React frontend for better UX
