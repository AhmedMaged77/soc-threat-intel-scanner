# SOC Threat Intelligence Scanner

## 🔎 Overview
SOC Threat Intelligence Scanner is a cybersecurity investigation tool that allows analysts to quickly gather, analyze, and summarize threat intelligence on domains, IPs, URLs, and file hashes.  
It integrates multiple intelligence sources (VirusTotal, URLScan, AbuseIPDB, Whoisjson) and leverages AI (Gemini) to generate concise SOC-ready summaries for faster incident response.

## ⚡ Features
- 🔍 **Multi-source Intelligence**  
  Collects data from VirusTotal, AbuseIPDB, URLScan, WHOIS details.

- 🧠 **AI-Powered Summaries**  
  Uses Gemini AI to generate concise SOC briefs (malicious indicators, severity, actions, and next steps).

## ⚙️ Installation

### 1. Clone Repository
```bash
git clone https://github.com/AhmedMaged77/soc-threat-intel-scanner.git
cd soc-threat-intel-scanner
```

### 2. Backend Setup
Navigate to the backend directory and install the necessary dependencies.
```bash
cd backend
npm install
```

Create a .env file with your API keys:
```env
VT_API_KEY=your_key
URLSCAN_API_KEY=your_key
ABUSEIP_API_KEY=your_key
GEMINI_API_KEY=your_key
GEMINI_API_URL=your_key
WHOISJSON_API_KEY=your_key
```

Run the backend server:
```bash
node index.js
```
Default: http://localhost:3000

### 3. Frontend Setup
```bash
cd frontend
npm install
ng serve -o
```
Default: http://localhost:4200

## ⚡ Usage
Enter a URL, IP, domain, or file hash in the input box.
Click Scan.
